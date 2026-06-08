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

_SUPPORTED = frozenset(
    {
        "aws_s3_bucket",
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_s3_bucket_public_access_block",
        "aws_s3_bucket_versioning",
        "aws_s3_bucket_logging",
        "aws_s3_bucket_policy",
        "aws_security_group",
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_db_instance",
        "aws_ebs_volume",
        "aws_cloudtrail",
        "aws_vpc",
        "aws_flow_log",
        "aws_default_security_group",
        "aws_kms_key",
    }
)


class TerraformParser(BaseParser):
    """Parses Terraform state files (schema version 4)."""

    def supports_resource_type(self, resource_type: str) -> bool:
        return resource_type in _SUPPORTED

    def parse(self, source: str) -> Iterator[NRMResource]:
        with open(source) as fh:
            state = json.load(fh)

        version = state.get("version")
        if version != 4:
            raise ValueError(
                f"Unsupported Terraform state version {version!r}. Expected 4."
            )

        managed = [r for r in state.get("resources", []) if r.get("mode") == "managed"]

        yield from self._parse_s3_buckets(managed)
        yield from self._parse_security_groups(managed)
        yield from self._parse_iam_policies(managed)
        yield from self._parse_rds_instances(managed)
        yield from self._parse_ebs_volumes(managed)
        yield from self._parse_cloudtrails(managed)
        yield from self._parse_vpcs(managed)
        yield from self._parse_kms_keys(managed)


    # S3 — two-phase accumulate-then-build for split resource format

    def _parse_s3_buckets(self, resources: list[dict]) -> Iterator[NRMS3Bucket]:  # type: ignore[type-arg]
        buckets: dict[str, dict[str, Any]] = {}

        for instance, _ in _iter_instances(resources, "aws_s3_bucket"):
            bucket_id = instance.get("id") or instance.get("bucket", "")
            if not bucket_id:
                continue
            buckets[bucket_id] = {
                "region": instance.get("region", self.region),
                "base": instance,
                "sse": None,
                "pab": None,
                "versioning": None,
                "logging": None,
                "policy": None,
            }

        for instance, _ in _iter_instances(
            resources, "aws_s3_bucket_server_side_encryption_configuration"
        ):
            bid = instance.get("bucket", "")
            if bid in buckets:
                buckets[bid]["sse"] = instance

        for instance, _ in _iter_instances(resources, "aws_s3_bucket_public_access_block"):
            bid = instance.get("bucket", "")
            if bid in buckets:
                buckets[bid]["pab"] = instance

        for instance, _ in _iter_instances(resources, "aws_s3_bucket_versioning"):
            bid = instance.get("bucket", "")
            if bid in buckets:
                buckets[bid]["versioning"] = instance

        for instance, _ in _iter_instances(resources, "aws_s3_bucket_logging"):
            bid = instance.get("bucket", "")
            if bid in buckets:
                buckets[bid]["logging"] = instance

        for instance, _ in _iter_instances(resources, "aws_s3_bucket_policy"):
            bid = instance.get("bucket", "")
            if bid in buckets:
                buckets[bid]["policy"] = instance

        for bucket_id, data in buckets.items():
            yield self._build_s3_bucket(bucket_id, data)

    def _build_s3_bucket(self, bucket_id: str, data: dict[str, Any]) -> NRMS3Bucket:
        base = data["base"]

        # Encryption: check legacy inline format first, then split resource
        sse_enabled: bool | None = None
        enc_algorithm: EncryptionAlgorithm | None = None

        legacy_rule = _get_nested(
            base, "server_side_encryption_configuration", 0, "rule", 0,
            "apply_server_side_encryption_by_default", 0,
        )
        if legacy_rule is not None:
            alg = legacy_rule.get("sse_algorithm")
            sse_enabled = bool(alg)
            enc_algorithm = _parse_enc_algorithm(alg)
        elif data["sse"] is not None:
            rule = _get_nested(
                data["sse"], "rule", 0,
                "apply_server_side_encryption_by_default", 0,
            )
            if rule is not None:
                alg = rule.get("sse_algorithm")
                sse_enabled = bool(alg)
                enc_algorithm = _parse_enc_algorithm(alg)
            else:
                sse_enabled = False

        # Public access block
        block_public_acls: bool | None = None
        ignore_public_acls: bool | None = None
        block_public_policy: bool | None = None
        restrict_public_buckets: bool | None = None
        pab_enabled: bool | None = None

        pab = data["pab"]
        if pab is not None:
            block_public_acls = bool(pab.get("block_public_acls"))
            ignore_public_acls = bool(pab.get("ignore_public_acls"))
            block_public_policy = bool(pab.get("block_public_policy"))
            restrict_public_buckets = bool(pab.get("restrict_public_buckets"))
            pab_enabled = all(
                [block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]
            )

        # Versioning
        versioning_enabled: bool | None = None
        mfa_delete: bool | None = None

        ver = data["versioning"]
        if ver is not None:
            vc = _get_nested(ver, "versioning_configuration", 0) or {}
            versioning_enabled = vc.get("status", "") == "Enabled"
            mfa_delete = str(vc.get("mfa_delete", "")).upper() == "ENABLED"

        # Logging
        logging_enabled: bool | None = None
        if data["logging"] is not None:
            logging_enabled = bool(data["logging"].get("target_bucket"))

        # SSL-only bucket policy
        ssl_only: bool | None = None
        if data["policy"] is not None:
            raw = data["policy"].get("policy", "")
            if raw:
                ssl_only = has_ssl_only_policy(raw)

        return NRMS3Bucket(
            resource_id=bucket_id,
            resource_name=bucket_id,
            iac_tool=IaCTool.TERRAFORM,
            region=data["region"],
            account_id=self.account_id,
            server_side_encryption_enabled=sse_enabled,
            encryption_algorithm=enc_algorithm,
            public_access_block_enabled=pab_enabled,
            block_public_acls=block_public_acls,
            ignore_public_acls=ignore_public_acls,
            block_public_policy=block_public_policy,
            restrict_public_buckets=restrict_public_buckets,
            versioning_enabled=versioning_enabled,
            mfa_delete_enabled=mfa_delete,
            access_logging_enabled=logging_enabled,
            ssl_requests_only=ssl_only,
        )


    # Security Groups


    def _parse_security_groups(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMSecurityGroup]:
        for instance, resource in _iter_instances(resources, "aws_security_group"):
            sg_id = instance.get("id", "")
            name = instance.get("name") or resource.get("name", sg_id)
            ingress = instance.get("ingress") or []
            egress = instance.get("egress") or []

            yield NRMSecurityGroup(
                resource_id=sg_id,
                resource_name=name,
                iac_tool=IaCTool.TERRAFORM,
                region=self.region,
                account_id=self.account_id,
                unrestricted_ssh_ingress=_tf_unrestricted_port(ingress, 22),
                unrestricted_rdp_ingress=_tf_unrestricted_port(ingress, 3389),
                unrestricted_all_traffic_ingress=_tf_unrestricted_all(ingress),
                unrestricted_all_traffic_egress=_tf_unrestricted_all(egress),
            )


    # IAM Policies


    def _parse_iam_policies(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMIAMPolicy]:
        for rtype in ("aws_iam_policy", "aws_iam_role_policy"):
            for instance, resource in _iter_instances(resources, rtype):
                raw_policy = instance.get("policy", "")
                if not raw_policy:
                    continue

                try:
                    policy_doc = json.loads(raw_policy)
                except json.JSONDecodeError:
                    logger.warning(
                        "Skipping unparseable IAM policy for resource %s",
                        resource.get("name"),
                    )
                    continue

                analysis = analyze_iam_policy_document(policy_doc)
                resource_id = instance.get("arn") or instance.get("id", "")

                yield NRMIAMPolicy(
                    resource_id=resource_id,
                    resource_name=instance.get("name") or resource.get("name", resource_id),
                    iac_tool=IaCTool.TERRAFORM,
                    region=self.region,
                    account_id=self.account_id,
                    has_wildcard_action=analysis["has_wildcard_action"],
                    has_wildcard_resource=analysis["has_wildcard_resource"],
                    has_admin_access=analysis["has_admin_access"],
                    has_explicit_deny=analysis["has_explicit_deny"],
                    policy_document_hash=analysis["policy_document_hash"],
                )


    # RDS Instances


    def _parse_rds_instances(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMRDSInstance]:
        for instance, resource in _iter_instances(resources, "aws_db_instance"):
            db_id = instance.get("id", "")
            retention = instance.get("backup_retention_period")

            yield NRMRDSInstance(
                resource_id=db_id,
                resource_name=instance.get("identifier") or resource.get("name", db_id),
                iac_tool=IaCTool.TERRAFORM,
                region=self.region,
                account_id=self.account_id,
                storage_encrypted=_opt_bool(instance, "storage_encrypted"),
                publicly_accessible=_opt_bool(instance, "publicly_accessible"),
                backup_retention_days=int(retention) if retention is not None else None,
                deletion_protection=_opt_bool(instance, "deletion_protection"),
                multi_az=_opt_bool(instance, "multi_az"),
                auto_minor_version_upgrade=_opt_bool(instance, "auto_minor_version_upgrade"),
            )


    # EBS Volumes


    def _parse_ebs_volumes(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMEBSVolume]:
        for instance, resource in _iter_instances(resources, "aws_ebs_volume"):
            vol_id = instance.get("id", "")

            yield NRMEBSVolume(
                resource_id=vol_id,
                resource_name=resource.get("name", vol_id),
                iac_tool=IaCTool.TERRAFORM,
                region=instance.get("availability_zone", self.region),
                account_id=self.account_id,
                encrypted=_opt_bool(instance, "encrypted"),
            )


    # CloudTrail


    def _parse_cloudtrails(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMCloudTrail]:
        for instance, resource in _iter_instances(resources, "aws_cloudtrail"):
            trail_id = instance.get("arn") or instance.get("id", "")
            cw_arn = instance.get("cloud_watch_logs_group_arn") or ""
            kms_id = instance.get("kms_key_id") or ""

            yield NRMCloudTrail(
                resource_id=trail_id,
                resource_name=instance.get("name") or resource.get("name", trail_id),
                iac_tool=IaCTool.TERRAFORM,
                region=self.region,
                account_id=self.account_id,
                multi_region_enabled=_opt_bool(instance, "is_multi_region_trail"),
                log_file_validation_enabled=_opt_bool(instance, "enable_log_file_validation"),
                cloudwatch_logs_enabled=bool(cw_arn) if cw_arn else None,
                kms_encryption_enabled=bool(kms_id) if kms_id else None,
            )


    # VPC — flow logs and default SG come from separate resources


    def _parse_vpcs(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMVPC]:
        flow_log_vpcs: set[str] = set()
        for instance, _ in _iter_instances(resources, "aws_flow_log"):
            vid = instance.get("vpc_id") or ""
            if vid:
                flow_log_vpcs.add(vid)

        # vpc_id -> True if default SG has any rules declared
        default_sg_has_rules: dict[str, bool] = {}
        for instance, _ in _iter_instances(resources, "aws_default_security_group"):
            vid = instance.get("vpc_id", "")
            ingress = instance.get("ingress") or []
            egress = instance.get("egress") or []
            default_sg_has_rules[vid] = bool(ingress or egress)

        for instance, resource in _iter_instances(resources, "aws_vpc"):
            vpc_id = instance.get("id", "")

            flow_enabled: bool | None = True if vpc_id in flow_log_vpcs else None
            default_sg_no_rules: bool | None = None
            if vpc_id in default_sg_has_rules:
                default_sg_no_rules = not default_sg_has_rules[vpc_id]

            yield NRMVPC(
                resource_id=vpc_id,
                resource_name=resource.get("name", vpc_id),
                iac_tool=IaCTool.TERRAFORM,
                region=self.region,
                account_id=self.account_id,
                flow_logs_enabled=flow_enabled,
                default_sg_has_no_rules=default_sg_no_rules,
            )


    # KMS Keys


    def _parse_kms_keys(
        self, resources: list[dict]  # type: ignore[type-arg]
    ) -> Iterator[NRMKMSKey]:
        for instance, resource in _iter_instances(resources, "aws_kms_key"):
            key_id = instance.get("key_id") or instance.get("id", "")
            key_spec = (
                instance.get("customer_master_key_spec")
                or instance.get("key_spec", "SYMMETRIC_DEFAULT")
            )

            # Rotation only applies to symmetric CMKs; None for asymmetric keys
            rotation: bool | None = None
            if key_spec == "SYMMETRIC_DEFAULT":
                rotation = _opt_bool(instance, "enable_key_rotation")

            yield NRMKMSKey(
                resource_id=key_id,
                resource_name=instance.get("description") or resource.get("name", key_id),
                iac_tool=IaCTool.TERRAFORM,
                region=self.region,
                account_id=self.account_id,
                key_rotation_enabled=rotation,
                key_enabled=_opt_bool(instance, "is_enabled"),
            )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _iter_instances(
    resources: list[dict],  # type: ignore[type-arg]
    resource_type: str,
) -> Iterator[tuple[dict, dict]]:  # type: ignore[type-arg]
    """Yield (attributes, resource_block) for each instance of the given type."""
    for resource in resources:
        if resource.get("type") != resource_type:
            continue
        for instance in resource.get("instances", []):
            yield instance.get("attributes", {}), resource


def _get_nested(obj: Any, *keys: str | int) -> Any:
    """Safely traverse nested dict/list using a sequence of keys or indexes."""
    current: Any = obj
    for key in keys:
        if current is None:
            return None
        try:
            current = current[key]
        except (KeyError, IndexError, TypeError):
            return None
    return current


def _opt_bool(attrs: dict, key: str) -> bool | None:  # type: ignore[type-arg]
    """Return bool if key exists and is non-null; None if absent or null."""
    val = attrs.get(key)
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


def _tf_unrestricted_port(rules: list[dict], port: int) -> bool | None:  # type: ignore[type-arg]
    """Return True if any declared rule allows unrestricted access to the given port."""
    if not rules:
        return None
    for rule in rules:
        from_port = int(rule.get("from_port") or 0)
        to_port = int(rule.get("to_port") or 0)
        protocol = str(rule.get("protocol") or "").lower()
        if protocol not in ("tcp", "-1", "all"):
            continue
        if protocol in ("tcp",) and not (from_port <= port <= to_port):
            continue
        cidr = rule.get("cidr_blocks") or []
        ipv6 = rule.get("ipv6_cidr_blocks") or []
        if "0.0.0.0/0" in cidr or "::/0" in ipv6:
            return True
    return False


def _tf_unrestricted_all(rules: list[dict]) -> bool | None:  # type: ignore[type-arg]
    """Return True if any declared rule allows all traffic from 0.0.0.0/0."""
    if not rules:
        return None
    for rule in rules:
        protocol = str(rule.get("protocol") or "").lower()
        if protocol not in ("-1", "all"):
            continue
        cidr = rule.get("cidr_blocks") or []
        ipv6 = rule.get("ipv6_cidr_blocks") or []
        if "0.0.0.0/0" in cidr or "::/0" in ipv6:
            return True
    return False
