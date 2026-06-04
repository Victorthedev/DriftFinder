from dataclasses import dataclass
from typing import Optional, TypeAlias

from driftfinder.models.enums import EncryptionAlgorithm, IaCTool


@dataclass(frozen=True)
class NRMBase:
    """Base fields present on every NRM resource object."""

    resource_id: str
    resource_name: str
    iac_tool: IaCTool
    region: str
    account_id: str


@dataclass(frozen=True)
class NRMS3Bucket(NRMBase):
    server_side_encryption_enabled: Optional[bool] = None
    encryption_algorithm: Optional[EncryptionAlgorithm] = None
    public_access_block_enabled: Optional[bool] = None
    block_public_acls: Optional[bool] = None
    ignore_public_acls: Optional[bool] = None
    block_public_policy: Optional[bool] = None
    restrict_public_buckets: Optional[bool] = None
    versioning_enabled: Optional[bool] = None
    mfa_delete_enabled: Optional[bool] = None
    access_logging_enabled: Optional[bool] = None
    ssl_requests_only: Optional[bool] = None


@dataclass(frozen=True)
class NRMSecurityGroup(NRMBase):
    unrestricted_ssh_ingress: Optional[bool] = None        # Port 22, 0.0.0.0/0 or ::/0
    unrestricted_rdp_ingress: Optional[bool] = None        # Port 3389, 0.0.0.0/0 or ::/0
    unrestricted_all_traffic_ingress: Optional[bool] = None  # Protocol -1, 0.0.0.0/0
    unrestricted_all_traffic_egress: Optional[bool] = None
    egress_restricted: Optional[bool] = None
    ingress_rules: Optional[tuple] = None                  # tuple for hashability (frozen dataclass)
    egress_rules: Optional[tuple] = None


@dataclass(frozen=True)
class NRMIAMPolicy(NRMBase):
    has_wildcard_action: Optional[bool] = None             # Action: *
    has_wildcard_resource: Optional[bool] = None           # Resource: * with broad actions
    has_admin_access: Optional[bool] = None                # AdministratorAccess equivalent
    has_explicit_deny: Optional[bool] = None
    policy_document_hash: Optional[str] = None             # SHA-256 of policy JSON


@dataclass(frozen=True)
class NRMRDSInstance(NRMBase):
    storage_encrypted: Optional[bool] = None
    publicly_accessible: Optional[bool] = None
    backup_retention_days: Optional[int] = None
    deletion_protection: Optional[bool] = None
    multi_az: Optional[bool] = None
    auto_minor_version_upgrade: Optional[bool] = None


@dataclass(frozen=True)
class NRMEBSVolume(NRMBase):
    encrypted: Optional[bool] = None
    delete_on_termination: Optional[bool] = None
    snapshot_encrypted: Optional[bool] = None


@dataclass(frozen=True)
class NRMCloudTrail(NRMBase):
    multi_region_enabled: Optional[bool] = None
    log_file_validation_enabled: Optional[bool] = None
    cloudwatch_logs_enabled: Optional[bool] = None
    s3_bucket_logging_enabled: Optional[bool] = None
    kms_encryption_enabled: Optional[bool] = None
    is_logging: Optional[bool] = None                      # Trail is actively logging


@dataclass(frozen=True)
class NRMVPC(NRMBase):
    flow_logs_enabled: Optional[bool] = None
    default_sg_has_no_rules: Optional[bool] = None         # Default SG must have no rules (CIS 5.5)
    nacl_unrestricted_ingress: Optional[bool] = None


@dataclass(frozen=True)
class NRMKMSKey(NRMBase):
    key_rotation_enabled: Optional[bool] = None            # Only applicable to symmetric CMKs
    key_enabled: Optional[bool] = None                     # KeyState == Enabled
    key_policy_allows_public_access: Optional[bool] = None


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
