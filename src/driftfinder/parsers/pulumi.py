import json
import logging
from typing import Any, Iterator

from driftfinder.models.enums import EncryptionAlgorithm, IaCTool
from driftfinder.models.nrm import (
    NRMCloudTrail,
    NRMEBSVolume,
    NRMIAMPolicy,
    NRMKMSKey,
    NRMRDSInstance,
    NRMResource,
    NRMSecurityGroup,
    NRMS3Bucket,
    NRMVPC,
)
from driftfinder.parsers.base import (
    BaseParser,
    analyze_iam_policy_document,
    has_ssl_only_policy,
)

logger = logging.getLogger(__name__)

# Pulumi type string -> handler key
_PULUMI_TYPE_MAP = {
    "aws:s3/bucket:Bucket": "s3",
    "aws:ec2/securityGroup:SecurityGroup": "sg",
    "aws:iam/policy:Policy": "iam",
    "aws:rds/instance:Instance": "rds",
    "aws:ebs/volume:Volume": "ebs",
    "aws:cloudtrail/trail:Trail": "cloudtrail",
    "aws:ec2/vpc:Vpc": "vpc",
    "aws:ec2/flowLog:FlowLog": "flowlog",
    "aws:kms/key:Key": "kms",
}


class PulumiParser(BaseParser):
    """
    Parses the JSON output of `pulumi stack export`.
    Uses outputs (not inputs) for declared state per the spec.
    Property names in Pulumi state are always camelCase.
    """

    def supports_resource_type(self, resource_type: str) -> bool:
        return resource_type in _PULUMI_TYPE_MAP

    def parse(self, source: str) -> Iterator[NRMResource]:
        """
        Args:
            source: Path to a file containing `pulumi stack export` JSON output.
        """
        with open(source) as fh:
            stack_export = json.load(fh)

        resources = stack_export.get("deployment", {}).get("resources", [])
        managed = [r for r in resources if not r.get("type", "").startswith("pulumi:")]

        # Index flow log resources before processing VPCs
        flow_log_vpcs: set[str] = set()
        for resource in managed:
            if resource.get("type") == "aws:ec2/flowLog:FlowLog":
                outputs = resource.get("outputs", {})
                vpc_id = outputs.get("vpcId") or outputs.get("resourceId", "")
                if vpc_id:
                    flow_log_vpcs.add(vpc_id)

        yield from self._parse_s3_buckets(managed)
        yield from self._parse_security_groups(managed)
        yield from self._parse_iam_policies(managed)
        yield from self._parse_rds_instances(managed)
        yield from self._parse_ebs_volumes(managed)
        yield from self._parse_cloudtrails(managed)
        yield from self._parse_vpcs(managed, flow_log_vpcs)
        yield from self._parse_kms_keys(managed)


    # S3


    def _parse_s3_buckets(self, resources: list[dict]) -> Iterator[NRMS3Bucket]:  # type: ignore[type-arg]
        for resource in resources:
            if resource.get("type") != "aws:s3/bucket:Bucket":
                continue

            outputs = resource.get("outputs", {})
            bucket_id = outputs.get("bucket") or outputs.get("id", "")
            name = _urn_name(resource.get("urn", "")) or bucket_id

            # Encryption
            sse_enabled: bool | None = None
            enc_alg: EncryptionAlgorithm | None = None
            sse_config = outputs.get("serverSideEncryptionConfiguration")
            if sse_config is not None:
                rules = sse_config.get("rules") or []
                if rules:
                    alg = (
                        rules[0]
                        .get("applyServerSideEncryptionByDefault", {})
                        .get("sseAlgorithm")
                    )
                    sse_enabled = bool(alg)
                    enc_alg = _parse_enc_algorithm(alg)
                else:
                    sse_enabled = False

            # Versioning
            versioning_enabled: bool | None = None
            mfa_delete: bool | None = None
            ver = outputs.get("versioning")
            if ver is not None:
                versioning_enabled = ver.get("enabled", False)
                mfa_delete = str(ver.get("mfaDelete", "")).upper() == "ENABLED"

            # Logging
            logging_enabled: bool | None = None
            log_config = outputs.get("loggings")
            if log_config is not None:
                logging_enabled = bool(log_config)

            # SSL policy
            ssl_only: bool | None = None
            policy_raw = outputs.get("policy") or ""
            if policy_raw:
                ssl_only = has_ssl_only_policy(policy_raw)

            yield NRMS3Bucket(
                resource_id=bucket_id,
                resource_name=name,
                iac_tool=IaCTool.PULUMI,
                region=outputs.get("region", self.region),
                account_id=self.account_id,
                server_side_encryption_enabled=sse_enabled,
                encryption_algorithm=enc_alg,
                versioning_enabled=versioning_enabled,
                mfa_delete_enabled=mfa_delete,
                access_logging_enabled=logging_enabled,
                ssl_requests_only=ssl_only,
            )


    # Security Groups


    def _parse_security_groups(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMSecurityGroup]:
        for resource in resources:
            if resource.get("type") != "aws:ec2/securityGroup:SecurityGroup":
                continue

            outputs = resource.get("outputs", {})
            sg_id = outputs.get("id", "")
            name = outputs.get("name") or _urn_name(resource.get("urn", "")) or sg_id
            ingress = outputs.get("ingress") or []
            egress = outputs.get("egress") or []

            yield NRMSecurityGroup(
                resource_id=sg_id,
                resource_name=name,
                iac_tool=IaCTool.PULUMI,
                region=self.region,
                account_id=self.account_id,
                unrestricted_ssh_ingress=_pulumi_unrestricted_port(ingress, 22),
                unrestricted_rdp_ingress=_pulumi_unrestricted_port(ingress, 3389),
                unrestricted_all_traffic_ingress=_pulumi_unrestricted_all(ingress),
                unrestricted_all_traffic_egress=_pulumi_unrestricted_all(egress),
            )


    # IAM Policies


    def _parse_iam_policies(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMIAMPolicy]:
        for resource in resources:
            if resource.get("type") != "aws:iam/policy:Policy":
                continue

            outputs = resource.get("outputs", {})
            policy_raw = outputs.get("policy", "")
            if not policy_raw:
                continue

            try:
                policy_doc = json.loads(policy_raw)
            except json.JSONDecodeError:
                logger.warning(
                    "Unparseable IAM policy for Pulumi resource %s",
                    resource.get("urn"),
                )
                continue

            analysis = analyze_iam_policy_document(policy_doc)
            resource_id = outputs.get("arn") or outputs.get("id", "")

            yield NRMIAMPolicy(
                resource_id=resource_id,
                resource_name=outputs.get("name") or _urn_name(resource.get("urn", "")),
                iac_tool=IaCTool.PULUMI,
                region=self.region,
                account_id=self.account_id,
                has_wildcard_action=analysis["has_wildcard_action"],
                has_wildcard_resource=analysis["has_wildcard_resource"],
                has_admin_access=analysis["has_admin_access"],
                has_explicit_deny=analysis["has_explicit_deny"],
                policy_document_hash=analysis["policy_document_hash"],
            )


    # RDS


    def _parse_rds_instances(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMRDSInstance]:
        for resource in resources:
            if resource.get("type") != "aws:rds/instance:Instance":
                continue

            outputs = resource.get("outputs", {})
            db_id = outputs.get("id", "")
            retention = outputs.get("backupRetentionPeriod")

            yield NRMRDSInstance(
                resource_id=db_id,
                resource_name=outputs.get("identifier") or _urn_name(resource.get("urn", "")),
                iac_tool=IaCTool.PULUMI,
                region=self.region,
                account_id=self.account_id,
                storage_encrypted=_opt_bool(outputs, "storageEncrypted"),
                publicly_accessible=_opt_bool(outputs, "publiclyAccessible"),
                backup_retention_days=int(retention) if retention is not None else None,
                deletion_protection=_opt_bool(outputs, "deletionProtection"),
                multi_az=_opt_bool(outputs, "multiAz"),
                auto_minor_version_upgrade=_opt_bool(outputs, "autoMinorVersionUpgrade"),
            )


    # EBS Volumes


    def _parse_ebs_volumes(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMEBSVolume]:
        for resource in resources:
            if resource.get("type") != "aws:ebs/volume:Volume":
                continue

            outputs = resource.get("outputs", {})
            vol_id = outputs.get("id", "")

            yield NRMEBSVolume(
                resource_id=vol_id,
                resource_name=_urn_name(resource.get("urn", "")) or vol_id,
                iac_tool=IaCTool.PULUMI,
                region=outputs.get("availabilityZone", self.region),
                account_id=self.account_id,
                encrypted=_opt_bool(outputs, "encrypted"),
            )


    # CloudTrail


    def _parse_cloudtrails(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMCloudTrail]:
        for resource in resources:
            if resource.get("type") != "aws:cloudtrail/trail:Trail":
                continue

            outputs = resource.get("outputs", {})
            trail_id = outputs.get("arn") or outputs.get("id", "")
            cw_arn = outputs.get("cloudWatchLogsGroupArn") or ""
            kms_id = outputs.get("kmsKeyId") or ""

            yield NRMCloudTrail(
                resource_id=trail_id,
                resource_name=outputs.get("name") or _urn_name(resource.get("urn", "")),
                iac_tool=IaCTool.PULUMI,
                region=self.region,
                account_id=self.account_id,
                multi_region_enabled=_opt_bool(outputs, "isMultiRegionTrail"),
                log_file_validation_enabled=_opt_bool(outputs, "enableLogFileValidation"),
                cloudwatch_logs_enabled=bool(cw_arn) if cw_arn else None,
                kms_encryption_enabled=bool(kms_id) if kms_id else None,
            )


    # VPC


    def _parse_vpcs(
        self,
        resources: list[dict],  # type: ignore[type-arg]
        flow_log_vpcs: set[str],
    ) -> Iterator[NRMVPC]:
        for resource in resources:
            if resource.get("type") != "aws:ec2/vpc:Vpc":
                continue

            outputs = resource.get("outputs", {})
            vpc_id = outputs.get("id", "")

            flow_enabled: bool | None = True if vpc_id in flow_log_vpcs else None

            yield NRMVPC(
                resource_id=vpc_id,
                resource_name=_urn_name(resource.get("urn", "")) or vpc_id,
                iac_tool=IaCTool.PULUMI,
                region=self.region,
                account_id=self.account_id,
                flow_logs_enabled=flow_enabled,
            )


    # KMS Keys


    def _parse_kms_keys(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMKMSKey]:
        for resource in resources:
            if resource.get("type") != "aws:kms/key:Key":
                continue

            outputs = resource.get("outputs", {})
            key_id = outputs.get("keyId") or outputs.get("id", "")
            key_spec = outputs.get("customerMasterKeySpec", "SYMMETRIC_DEFAULT")

            rotation: bool | None = None
            if key_spec == "SYMMETRIC_DEFAULT":
                rotation = _opt_bool(outputs, "enableKeyRotation")

            yield NRMKMSKey(
                resource_id=key_id,
                resource_name=outputs.get("description") or _urn_name(resource.get("urn", "")),
                iac_tool=IaCTool.PULUMI,
                region=self.region,
                account_id=self.account_id,
                key_rotation_enabled=rotation,
                key_enabled=_opt_bool(outputs, "isEnabled"),
            )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _urn_name(urn: str) -> str:
    """Extract the resource name from a Pulumi URN (last segment after ::)."""
    parts = urn.rsplit("::", 1)
    return parts[-1] if len(parts) > 1 else urn


def _opt_bool(outputs: dict, key: str) -> bool | None:  # type: ignore[type-arg]
    val = outputs.get(key)
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


def _pulumi_unrestricted_port(rules: list[dict], port: int) -> bool | None:  # type: ignore[type-arg]
    if not rules:
        return None
    for rule in rules:
        from_port = _to_int(rule.get("fromPort"), 0)
        to_port = _to_int(rule.get("toPort"), 0)
        protocol = str(rule.get("protocol") or "").lower()
        if protocol not in ("tcp", "-1", "all"):
            continue
        if protocol == "tcp" and not (from_port <= port <= to_port):
            continue
        cidr = rule.get("cidrBlocks") or []
        ipv6 = rule.get("ipv6CidrBlocks") or []
        if "0.0.0.0/0" in cidr or "::/0" in ipv6:
            return True
    return False


def _pulumi_unrestricted_all(rules: list[dict]) -> bool | None:  # type: ignore[type-arg]
    if not rules:
        return None
    for rule in rules:
        protocol = str(rule.get("protocol") or "").lower()
        if protocol not in ("-1", "all"):
            continue
        cidr = rule.get("cidrBlocks") or []
        ipv6 = rule.get("ipv6CidrBlocks") or []
        if "0.0.0.0/0" in cidr or "::/0" in ipv6:
            return True
    return False


def _to_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default
