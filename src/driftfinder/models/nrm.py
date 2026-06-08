from dataclasses import dataclass
from typing import TypeAlias

from driftfinder.models.enums import EncryptionAlgorithm, IaCTool


@dataclass(frozen=True)
class NRMBase:
    """Base fields present on every NRM resource object."""

    resource_id: str
    resource_name: str
    iac_tool: IaCTool
    region: str
    account_id: str = ""  # Not compared during drift detection; engine populates via STS


@dataclass(frozen=True)
class NRMS3Bucket(NRMBase):
    server_side_encryption_enabled: bool | None = None
    encryption_algorithm: EncryptionAlgorithm | None = None
    public_access_block_enabled: bool | None = None
    block_public_acls: bool | None = None
    ignore_public_acls: bool | None = None
    block_public_policy: bool | None = None
    restrict_public_buckets: bool | None = None
    versioning_enabled: bool | None = None
    mfa_delete_enabled: bool | None = None
    access_logging_enabled: bool | None = None
    ssl_requests_only: bool | None = None


@dataclass(frozen=True)
class NRMSecurityGroup(NRMBase):
    unrestricted_ssh_ingress: bool | None = None  # Port 22, 0.0.0.0/0 or ::/0
    unrestricted_rdp_ingress: bool | None = None  # Port 3389, 0.0.0.0/0 or ::/0
    unrestricted_all_traffic_ingress: bool | None = None  # Protocol -1, 0.0.0.0/0
    unrestricted_all_traffic_egress: bool | None = None
    egress_restricted: bool | None = None
    ingress_rules: tuple | None = None  # tuple for hashability (frozen dataclass)
    egress_rules: tuple | None = None


@dataclass(frozen=True)
class NRMIAMPolicy(NRMBase):
    has_wildcard_action: bool | None = None  # Action: *
    has_wildcard_resource: bool | None = None  # Resource: * with broad actions
    has_admin_access: bool | None = None  # AdministratorAccess equivalent
    has_explicit_deny: bool | None = None
    policy_document_hash: str | None = None  # SHA-256 of policy JSON


@dataclass(frozen=True)
class NRMRDSInstance(NRMBase):
    storage_encrypted: bool | None = None
    publicly_accessible: bool | None = None
    backup_retention_days: int | None = None
    deletion_protection: bool | None = None
    multi_az: bool | None = None
    auto_minor_version_upgrade: bool | None = None


@dataclass(frozen=True)
class NRMEBSVolume(NRMBase):
    encrypted: bool | None = None
    delete_on_termination: bool | None = None
    snapshot_encrypted: bool | None = None


@dataclass(frozen=True)
class NRMCloudTrail(NRMBase):
    multi_region_enabled: bool | None = None
    log_file_validation_enabled: bool | None = None
    cloudwatch_logs_enabled: bool | None = None
    s3_bucket_logging_enabled: bool | None = None
    kms_encryption_enabled: bool | None = None
    is_logging: bool | None = None  # Trail is actively logging


@dataclass(frozen=True)
class NRMVPC(NRMBase):
    flow_logs_enabled: bool | None = None
    default_sg_has_no_rules: bool | None = None  # Default SG must have no rules (CIS 5.5)
    nacl_unrestricted_ingress: bool | None = None


@dataclass(frozen=True)
class NRMKMSKey(NRMBase):
    key_rotation_enabled: bool | None = None  # Only applicable to symmetric CMKs
    key_enabled: bool | None = None  # KeyState == Enabled
    key_policy_allows_public_access: bool | None = None


NRMResource: TypeAlias = (
    NRMS3Bucket
    | NRMSecurityGroup
    | NRMIAMPolicy
    | NRMRDSInstance
    | NRMEBSVolume
    | NRMCloudTrail
    | NRMVPC
    | NRMKMSKey
)

# Metadata fields that are never compared during drift detection
NRM_METADATA_FIELDS = frozenset(
    {"resource_id", "resource_name", "iac_tool", "region", "account_id"}
)
