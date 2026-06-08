from typing import NamedTuple

from driftfinder.models.enums import Severity


class CISControl(NamedTuple):
    control_id: str
    description: str
    severity: Severity


# Key format: "ResourceType.property_name"
CIS_MAPPINGS: dict[str, CISControl] = {
    # S3 Bucket
    "NRMS3Bucket.server_side_encryption_enabled": CISControl(
        "2.1.1",
        "Ensure all S3 buckets employ encryption-at-rest",
        Severity.HIGH,
    ),
    "NRMS3Bucket.encryption_algorithm": CISControl(
        "2.1.1",
        "Ensure all S3 buckets employ encryption-at-rest",
        Severity.HIGH,
    ),
    "NRMS3Bucket.public_access_block_enabled": CISControl(
        "2.1.4",
        "Ensure that S3 Buckets are configured with Block Public Access",
        Severity.CRITICAL,
    ),
    "NRMS3Bucket.block_public_acls": CISControl(
        "2.1.4",
        "Ensure that S3 Buckets are configured with Block Public Access (BlockPublicAcls)",
        Severity.CRITICAL,
    ),
    "NRMS3Bucket.ignore_public_acls": CISControl(
        "2.1.4",
        "Ensure that S3 Buckets are configured with Block Public Access (IgnorePublicAcls)",
        Severity.CRITICAL,
    ),
    "NRMS3Bucket.block_public_policy": CISControl(
        "2.1.4",
        "Ensure that S3 Buckets are configured with Block Public Access (BlockPublicPolicy)",
        Severity.CRITICAL,
    ),
    "NRMS3Bucket.restrict_public_buckets": CISControl(
        "2.1.4",
        "Ensure that S3 Buckets are configured with Block Public Access (RestrictPublicBuckets)",
        Severity.CRITICAL,
    ),
    "NRMS3Bucket.versioning_enabled": CISControl(
        "2.1.2",
        "Ensure MFA Delete is enabled on S3 buckets",
        Severity.MEDIUM,
    ),
    "NRMS3Bucket.mfa_delete_enabled": CISControl(
        "2.1.2",
        "Ensure MFA Delete is enabled on S3 buckets",
        Severity.HIGH,
    ),
    "NRMS3Bucket.access_logging_enabled": CISControl(
        "2.1.5",
        "Ensure that S3 Buckets have Object-level logging enabled with CloudTrail",
        Severity.MEDIUM,
    ),
    "NRMS3Bucket.ssl_requests_only": CISControl(
        "2.1.1",
        "Ensure S3 bucket policy requires SSL",
        Severity.HIGH,
    ),
    # Security Group
    "NRMSecurityGroup.unrestricted_ssh_ingress": CISControl(
        "5.2",
        "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        Severity.CRITICAL,
    ),
    "NRMSecurityGroup.unrestricted_rdp_ingress": CISControl(
        "5.3",
        "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
        Severity.CRITICAL,
    ),
    "NRMSecurityGroup.unrestricted_all_traffic_ingress": CISControl(
        "5.4",
        "Ensure no security groups allow unrestricted access",
        Severity.CRITICAL,
    ),
    # IAM Policy
    "NRMIAMPolicy.has_wildcard_action": CISControl(
        "1.16",
        "Ensure IAM policies that allow full administrative privileges are not attached",
        Severity.CRITICAL,
    ),
    "NRMIAMPolicy.has_wildcard_resource": CISControl(
        "1.16",
        "Ensure IAM policies that allow full administrative privileges are not attached",
        Severity.HIGH,
    ),
    "NRMIAMPolicy.has_admin_access": CISControl(
        "1.16",
        "Ensure IAM policies that allow full administrative privileges are not attached",
        Severity.HIGH,
    ),
    # RDS Instance
    "NRMRDSInstance.storage_encrypted": CISControl(
        "2.3.1",
        "Ensure that encryption-at-rest is enabled for RDS Instances",
        Severity.CRITICAL,
    ),
    "NRMRDSInstance.publicly_accessible": CISControl(
        "2.3.2",
        "Ensure that public access is not given to RDS Instance",
        Severity.HIGH,
    ),
    "NRMRDSInstance.backup_retention_days": CISControl(
        "2.3.3",
        "Ensure that RDS clusters have backup enabled",
        Severity.MEDIUM,
    ),
    # EBS Volume
    "NRMEBSVolume.encrypted": CISControl(
        "2.2.1",
        "Ensure EBS Volume Encryption is Enabled in all Regions",
        Severity.CRITICAL,
    ),
    # CloudTrail
    "NRMCloudTrail.multi_region_enabled": CISControl(
        "3.1",
        "Ensure CloudTrail is enabled in all regions",
        Severity.HIGH,
    ),
    "NRMCloudTrail.log_file_validation_enabled": CISControl(
        "3.2",
        "Ensure CloudTrail log file validation is enabled",
        Severity.HIGH,
    ),
    "NRMCloudTrail.cloudwatch_logs_enabled": CISControl(
        "3.4",
        "Ensure CloudTrail trails are integrated with CloudWatch Logs",
        Severity.MEDIUM,
    ),
    "NRMCloudTrail.kms_encryption_enabled": CISControl(
        "3.7",
        "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
        Severity.HIGH,
    ),
    "NRMCloudTrail.is_logging": CISControl(
        "3.1",
        "Ensure CloudTrail is actively logging",
        Severity.CRITICAL,
    ),
    # VPC
    "NRMVPC.flow_logs_enabled": CISControl(
        "5.1",
        "Ensure VPC flow logging is enabled in all VPCs",
        Severity.HIGH,
    ),
    "NRMVPC.default_sg_has_no_rules": CISControl(
        "5.5",
        "Ensure the default security group of every VPC restricts all traffic",
        Severity.CRITICAL,
    ),
    # KMS Key
    "NRMKMSKey.key_rotation_enabled": CISControl(
        "3.7",
        "Ensure rotation for customer-created symmetric CMKs is enabled",
        Severity.HIGH,
    ),
    "NRMKMSKey.key_enabled": CISControl(
        "3.7",
        "Ensure KMS key is not disabled",
        Severity.CRITICAL,
    ),
    "NRMKMSKey.key_policy_allows_public_access": CISControl(
        "3.7",
        "Ensure KMS key policy does not allow public access",
        Severity.HIGH,
    ),
}
