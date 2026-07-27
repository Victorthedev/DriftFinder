import json
import logging
from collections.abc import Iterator
from typing import Any

import boto3
import yaml

from driftfinder.models.enums import EncryptionAlgorithm, IaCTool
from driftfinder.models.nrm import (
    NRMVPC,
    NRMCloudTrail,
    NRMEBSVolume,
    NRMIAMPolicy,
    NRMKMSKey,
    NRMRDSInstance,
    NRMResource,
    NRMS3Bucket,
    NRMSecurityGroup,
)
from driftfinder.parsers.base import (
    BaseParser,
    analyze_iam_policy_document,
    kms_key_policy_allows_public,
)

logger = logging.getLogger(__name__)

# CloudFormation type -> NRM class name
_CF_TYPE_MAP = {
    "AWS::S3::Bucket": "s3",
    "AWS::EC2::SecurityGroup": "sg",
    "AWS::IAM::ManagedPolicy": "iam",
    "AWS::IAM::Policy": "iam",
    "AWS::RDS::DBInstance": "rds",
    "AWS::EC2::Volume": "ebs",
    "AWS::CloudTrail::Trail": "cloudtrail",
    "AWS::EC2::VPC": "vpc",
    "AWS::KMS::Key": "kms",
}


class CloudFormationParser(BaseParser):
    """
    Reads declared state from a CloudFormation stack via the AWS API.
    Requires read-only CloudFormation and STS permissions.
    """

    def __init__(
        self,
        region: str = "eu-west-1",
        account_id: str = "",
        profile: str | None = None,
    ) -> None:
        super().__init__(region=region, account_id=account_id)
        session = boto3.Session(profile_name=profile, region_name=region)
        self._cfn = session.client("cloudformation")
        # Auto-detect account_id if not provided
        if not self.account_id:
            try:
                sts = session.client("sts")
                self.account_id = sts.get_caller_identity()["Account"]
            except Exception:
                logger.debug("Could not auto-detect account_id via STS", exc_info=True)

    def supports_resource_type(self, resource_type: str) -> bool:
        return resource_type in _CF_TYPE_MAP

    def parse(self, source: str) -> Iterator[NRMResource]:
        """
        Args:
            source: CloudFormation stack name or ARN.
        """
        template = self._get_template(source)
        physical_ids = self._get_physical_ids(source)

        cf_resources = template.get("Resources", {})

        # Build flow-log index (D19): physical VPC ID -> has flow log declared
        self._flow_log_vpcs: set[str] = set()
        for _, resource_block in cf_resources.items():
            if resource_block.get("Type") == "AWS::EC2::FlowLog":
                props = resource_block.get("Properties") or {}
                resource_id_ref = props.get("ResourceId", "")
                phys = physical_ids.get(resource_id_ref, "")
                if phys:
                    self._flow_log_vpcs.add(phys)

        # Build NACL index (D21): physical VPC ID -> nacl_unrestricted_ingress bool
        nacl_vpc_map: dict[str, str] = {}   # logical NACL ID -> physical VPC ID
        nacl_unrestricted: dict[str, bool] = {}  # logical NACL ID -> has unrestricted ingress

        for logical_id, resource_block in cf_resources.items():
            if resource_block.get("Type") == "AWS::EC2::NetworkAcl":
                props = resource_block.get("Properties") or {}
                vpc_ref = props.get("VpcId", "")
                vpc_phys = physical_ids.get(vpc_ref, "")
                nacl_vpc_map[logical_id] = vpc_phys
                nacl_unrestricted[logical_id] = False

        for _, resource_block in cf_resources.items():
            if resource_block.get("Type") == "AWS::EC2::NetworkAclEntry":
                props = resource_block.get("Properties") or {}
                if props.get("Egress", False):
                    continue
                nacl_ref = props.get("NetworkAclId", "")
                if nacl_ref not in nacl_unrestricted:
                    continue
                if props.get("RuleAction", "").lower() == "allow":
                    proto = str(props.get("Protocol", ""))
                    cidr = props.get("CidrBlock", "")
                    if proto == "-1" and cidr in ("0.0.0.0/0", "::/0"):
                        nacl_unrestricted[nacl_ref] = True

        self._vpc_nacl: dict[str, bool] = {}
        for nacl_lid, vpc_pid in nacl_vpc_map.items():
            if vpc_pid:
                self._vpc_nacl[vpc_pid] = (
                    self._vpc_nacl.get(vpc_pid, False) or nacl_unrestricted.get(nacl_lid, False)
                )

        for logical_id, resource_block in cf_resources.items():
            cf_type = resource_block.get("Type", "")
            if cf_type not in _CF_TYPE_MAP:
                continue

            properties = resource_block.get("Properties") or {}
            physical_id = physical_ids.get(logical_id, logical_id)
            kind = _CF_TYPE_MAP[cf_type]

            nrm = self._build_nrm(kind, logical_id, physical_id, properties)
            if nrm is not None:
                yield nrm

    def _get_template(self, stack_name: str) -> dict:  # type: ignore[type-arg]
        response = self._cfn.get_template(StackName=stack_name, TemplateStage="Original")
        body = response["TemplateBody"]
        if isinstance(body, str):
            try:
                return json.loads(body)  # type: ignore[no-any-return]
            except json.JSONDecodeError:
                return _cfn_yaml_load(body)  # type: ignore[no-any-return]
        return body  # type: ignore[return-value]

    def _get_physical_ids(self, stack_name: str) -> dict[str, str]:
        response = self._cfn.describe_stack_resources(StackName=stack_name)
        return {r["LogicalResourceId"]: r["PhysicalResourceId"] for r in response["StackResources"]}

    def _build_nrm(
        self,
        kind: str,
        logical_id: str,
        physical_id: str,
        props: dict,  # type: ignore[type-arg]
    ) -> NRMResource | None:
        builders = {
            "s3": self._build_s3,
            "sg": self._build_sg,
            "iam": self._build_iam,
            "rds": self._build_rds,
            "ebs": self._build_ebs,
            "cloudtrail": self._build_cloudtrail,
            "vpc": self._build_vpc,
            "kms": self._build_kms,
        }
        builder = builders.get(kind)
        if builder is None:
            return None
        return builder(logical_id, physical_id, props)  # type: ignore[operator]

    # Per-type builders

    def _build_s3(
        self, logical_id: str, physical_id: str, props: dict  # type: ignore[type-arg]
    ) -> NRMS3Bucket:
        enc_config = props.get("BucketEncryption", {})
        rules = enc_config.get("ServerSideEncryptionConfiguration", [])

        sse_enabled: bool | None = None
        enc_alg: EncryptionAlgorithm | None = None

        if rules:
            sse_enabled = True
            alg = rules[0].get("ServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            enc_alg = _parse_enc_algorithm(alg)
        elif "BucketEncryption" in props:
            sse_enabled = False

        pab = props.get("PublicAccessBlockConfiguration")
        block_public_acls: bool | None = None
        ignore_public_acls: bool | None = None
        block_public_policy: bool | None = None
        restrict_public_buckets: bool | None = None
        pab_enabled: bool | None = None

        if pab is not None:
            block_public_acls = bool(pab.get("BlockPublicAcls"))
            ignore_public_acls = bool(pab.get("IgnorePublicAcls"))
            block_public_policy = bool(pab.get("BlockPublicPolicy"))
            restrict_public_buckets = bool(pab.get("RestrictPublicBuckets"))
            pab_enabled = all(
                [
                    block_public_acls,
                    ignore_public_acls,
                    block_public_policy,
                    restrict_public_buckets,
                ]
            )

        versioning_config = props.get("VersioningConfiguration", {})
        versioning_enabled: bool | None = None
        if versioning_config or "VersioningConfiguration" in props:
            versioning_enabled = versioning_config.get("Status") == "Enabled"

        logging_config = props.get("LoggingConfiguration")
        access_logging: bool | None = None
        if logging_config is not None:
            access_logging = bool(logging_config)

        # CF templates rarely embed bucket policies directly; ssl_requests_only left None
        return NRMS3Bucket(
            resource_id=physical_id,
            resource_name=logical_id,
            iac_tool=IaCTool.CLOUDFORMATION,
            region=self.region,
            account_id=self.account_id,
            server_side_encryption_enabled=sse_enabled,
            encryption_algorithm=enc_alg,
            public_access_block_enabled=pab_enabled,
            block_public_acls=block_public_acls,
            ignore_public_acls=ignore_public_acls,
            block_public_policy=block_public_policy,
            restrict_public_buckets=restrict_public_buckets,
            versioning_enabled=versioning_enabled,
            access_logging_enabled=access_logging,
        )

    def _build_sg(
        self, logical_id: str, physical_id: str, props: dict  # type: ignore[type-arg]
    ) -> NRMSecurityGroup:
        ingress = props.get("SecurityGroupIngress") or []
        egress = props.get("SecurityGroupEgress") or []

        return NRMSecurityGroup(
            resource_id=physical_id,
            resource_name=logical_id,
            iac_tool=IaCTool.CLOUDFORMATION,
            region=self.region,
            account_id=self.account_id,
            unrestricted_ssh_ingress=_cf_unrestricted_port(ingress, 22),
            unrestricted_rdp_ingress=_cf_unrestricted_port(ingress, 3389),
            unrestricted_all_traffic_ingress=_cf_unrestricted_all(ingress),
            unrestricted_all_traffic_egress=_cf_unrestricted_all(egress),
        )

    def _build_iam(
        self, logical_id: str, physical_id: str, props: dict  # type: ignore[type-arg]
    ) -> NRMIAMPolicy | None:
        policy_doc = props.get("PolicyDocument")
        if policy_doc is None:
            return None

        if isinstance(policy_doc, str):
            try:
                policy_doc = json.loads(policy_doc)
            except json.JSONDecodeError:
                logger.warning("Unparseable IAM policy document for %s", logical_id)
                return None

        analysis = analyze_iam_policy_document(policy_doc)

        return NRMIAMPolicy(
            resource_id=physical_id,
            resource_name=logical_id,
            iac_tool=IaCTool.CLOUDFORMATION,
            region=self.region,
            account_id=self.account_id,
            has_wildcard_action=analysis["has_wildcard_action"],
            has_wildcard_resource=analysis["has_wildcard_resource"],
            has_admin_access=analysis["has_admin_access"],
            has_explicit_deny=analysis["has_explicit_deny"],
            policy_document_hash=analysis["policy_document_hash"],
        )

    def _build_rds(
        self, logical_id: str, physical_id: str, props: dict  # type: ignore[type-arg]
    ) -> NRMRDSInstance:
        retention = props.get("BackupRetentionPeriod")
        return NRMRDSInstance(
            resource_id=physical_id,
            resource_name=logical_id,
            iac_tool=IaCTool.CLOUDFORMATION,
            region=self.region,
            account_id=self.account_id,
            storage_encrypted=_cf_opt_bool(props, "StorageEncrypted"),
            publicly_accessible=_cf_opt_bool(props, "PubliclyAccessible"),
            backup_retention_days=int(retention) if retention is not None else None,
            deletion_protection=_cf_opt_bool(props, "DeletionProtection"),
            multi_az=_cf_opt_bool(props, "MultiAZ"),
            auto_minor_version_upgrade=_cf_opt_bool(props, "AutoMinorVersionUpgrade"),
        )

    def _build_ebs(
        self, logical_id: str, physical_id: str, props: dict  # type: ignore[type-arg]
    ) -> NRMEBSVolume:
        return NRMEBSVolume(
            resource_id=physical_id,
            resource_name=logical_id,
            iac_tool=IaCTool.CLOUDFORMATION,
            region=self.region,
            account_id=self.account_id,
            encrypted=_cf_opt_bool(props, "Encrypted"),
        )

    def _build_cloudtrail(
        self, logical_id: str, physical_id: str, props: dict  # type: ignore[type-arg]
    ) -> NRMCloudTrail:
        cw_arn = props.get("CloudWatchLogsLogGroupArn") or ""
        kms_id = props.get("KMSKeyId") or ""

        return NRMCloudTrail(
            resource_id=physical_id,
            resource_name=logical_id,
            iac_tool=IaCTool.CLOUDFORMATION,
            region=self.region,
            account_id=self.account_id,
            multi_region_enabled=_cf_opt_bool(props, "IsMultiRegionTrail"),
            log_file_validation_enabled=_cf_opt_bool(props, "EnableLogFileValidation"),
            cloudwatch_logs_enabled=bool(cw_arn) if cw_arn else None,
            kms_encryption_enabled=bool(kms_id) if kms_id else None,
        )

    def _build_vpc(
        self, logical_id: str, physical_id: str, props: dict  # type: ignore[type-arg]
    ) -> NRMVPC:
        flow_log_vpcs: set[str] = getattr(self, "_flow_log_vpcs", set())
        vpc_nacl: dict[str, bool] = getattr(self, "_vpc_nacl", {})

        flow_enabled: bool | None = True if physical_id in flow_log_vpcs else None
        nacl_status: bool | None = vpc_nacl.get(physical_id)

        # CF has no native default SG resource; default_sg_has_no_rules stays None
        return NRMVPC(
            resource_id=physical_id,
            resource_name=logical_id,
            iac_tool=IaCTool.CLOUDFORMATION,
            region=self.region,
            account_id=self.account_id,
            flow_logs_enabled=flow_enabled,
            nacl_unrestricted_ingress=nacl_status,
        )

    def _build_kms(
        self, logical_id: str, physical_id: str, props: dict  # type: ignore[type-arg]
    ) -> NRMKMSKey:
        # CF AWS::KMS::Key does not expose KeyState as a template property;
        # key_enabled can only be determined at runtime.
        key_policy_allows_public: bool | None = None
        key_policy = props.get("KeyPolicy")
        if key_policy is not None:
            if isinstance(key_policy, str):
                try:
                    key_policy = json.loads(key_policy)
                except json.JSONDecodeError:
                    key_policy = None
            if isinstance(key_policy, dict):
                key_policy_allows_public = kms_key_policy_allows_public(key_policy)

        return NRMKMSKey(
            resource_id=physical_id,
            resource_name=logical_id,
            iac_tool=IaCTool.CLOUDFORMATION,
            region=self.region,
            account_id=self.account_id,
            key_rotation_enabled=_cf_opt_bool(props, "EnableKeyRotation"),
            key_enabled=_cf_opt_bool(props, "Enabled"),
            key_policy_allows_public_access=key_policy_allows_public,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _cfn_yaml_load(body: str) -> dict:  # type: ignore[type-arg]
    """Load a CloudFormation YAML template, tolerating intrinsic function tags."""
    loader = yaml.SafeLoader
    for tag in (
        "!Ref", "!Sub", "!GetAtt", "!Join", "!Select", "!Split",
        "!If", "!Not", "!And", "!Or", "!Equals", "!Condition",
        "!FindInMap", "!ImportValue", "!Base64", "!Cidr",
    ):
        loader.add_constructor(tag, lambda l, n: l.construct_scalar(n))  # noqa: E731
    return yaml.load(body, Loader=loader)  # noqa: S506


def _cf_opt_bool(props: dict, key: str) -> bool | None:  # type: ignore[type-arg]
    val = props.get(key)
    if val is None:
        return None
    return bool(val)


def _parse_enc_algorithm(alg: str | None) -> EncryptionAlgorithm | None:
    if not alg:
        return None
    try:
        return EncryptionAlgorithm(alg)
    except ValueError:
        return None


def _cf_unrestricted_port(rules: list[dict], port: int) -> bool | None:  # type: ignore[type-arg]
    if not rules:
        return None
    for rule in rules:
        from_port = _to_int(rule.get("FromPort"), 0)
        to_port = _to_int(rule.get("ToPort"), 0)
        protocol = str(rule.get("IpProtocol") or "").lower()
        if protocol not in ("tcp", "-1", "all"):
            continue
        if protocol == "tcp" and not (from_port <= port <= to_port):
            continue
        if rule.get("CidrIp") == "0.0.0.0/0" or rule.get("CidrIpv6") == "::/0":
            return True
    return False


def _cf_unrestricted_all(rules: list[dict]) -> bool | None:  # type: ignore[type-arg]
    if not rules:
        return None
    for rule in rules:
        protocol = str(rule.get("IpProtocol") or "").lower()
        if protocol not in ("-1", "all"):
            continue
        if rule.get("CidrIp") == "0.0.0.0/0" or rule.get("CidrIpv6") == "::/0":
            return True
    return False


def _to_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default
