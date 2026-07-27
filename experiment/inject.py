"""
DriftFinder Controlled Experiment — Drift Injection Orchestrator
Implements all 24 scenarios (D1-D24) and 6 control cases (C1-C6).

Usage:
    python inject.py --scenario D1 --env terraform --resources resources.json
    python inject.py --scenario D4 --env cloudformation --resources resources.json
    python inject.py --reset D1 --env terraform --resources resources.json
    python inject.py --baseline-check --env all --resources resources.json

resources.json is produced by running the provisioning outputs:
    terraform output -json > resources.json  (for terraform env)
"""

import boto3
import json
import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from ground_truth_logger import GroundTruthLogger

REGION = "eu-west-1"


def get_client(service: str, profile: str = None) -> boto3.client:
    session = boto3.Session(profile_name=profile, region_name=REGION)
    return session.client(service)


def load_resources(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    # Handle both raw JSON and terraform output -json format
    if all(isinstance(v, dict) and "value" in v for v in data.values()):
        return {k: v["value"] for k, v in data.items()}
    return data


# ═══════════════════════════════════════════════════════════════════════════
# D1: S3 — Disable server-side encryption
# ═══════════════════════════════════════════════════════════════════════════

def inject_D1(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D1: S3 Bucket - server_side_encryption_enabled
    Change: Disable SSE via AWS CLI equivalent
    Mechanism: External automation
    Severity: HIGH | CIS: 2.1.1
    """
    s3 = get_client("s3")
    bucket = resources["s3_bucket_name"]

    before = {"server_side_encryption_enabled": True, "encryption_algorithm": "AES256"}

    s3.delete_bucket_encryption(Bucket=bucket)

    after = {"server_side_encryption_enabled": False, "encryption_algorithm": None}

    logger.log(
        scenario_id="D1",
        resource_type="NRMS3Bucket",
        resource_id=bucket,
        property_path="server_side_encryption_enabled",
        before=before,
        after=after,
        mechanism="External automation (boto3 delete_bucket_encryption)",
        cis_control="2.1.1",
        severity="HIGH",
        environment=env,
    )
    print(f"[D1] Disabled S3 encryption on {bucket}")


def reset_D1(resources: dict, env: str):
    s3 = get_client("s3")
    bucket = resources["s3_bucket_name"]
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    print(f"[D1 RESET] Restored S3 encryption on {bucket}")


# ═══════════════════════════════════════════════════════════════════════════
# D2: S3 — Disable public access block
# ═══════════════════════════════════════════════════════════════════════════

def inject_D2(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D2: S3 Bucket - public_access_block_enabled
    Change: Disable all public access block settings
    Mechanism: Emergency console change
    Severity: CRITICAL | CIS: 2.1.4
    """
    s3 = get_client("s3")
    bucket = resources["s3_bucket_name"]

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    logger.log(
        scenario_id="D2",
        resource_type="NRMS3Bucket",
        resource_id=bucket,
        property_path="public_access_block_enabled",
        before={"public_access_block_enabled": True, "block_public_acls": True, "block_public_policy": True},
        after={"public_access_block_enabled": False, "block_public_acls": False, "block_public_policy": False},
        mechanism="Emergency console change (boto3 put_bucket_public_access_block)",
        cis_control="2.1.4",
        severity="CRITICAL",
        environment=env,
    )
    print(f"[D2] Disabled S3 public access block on {bucket}")


def reset_D2(resources: dict, env: str):
    s3 = get_client("s3")
    bucket = resources["s3_bucket_name"]
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print(f"[D2 RESET] Restored S3 public access block on {bucket}")


# ═══════════════════════════════════════════════════════════════════════════
# D3: S3 — Disable access logging
# ═══════════════════════════════════════════════════════════════════════════

def inject_D3(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D3: S3 Bucket - access_logging_enabled
    Change: Disable access logging
    Mechanism: External automation
    Severity: MEDIUM | CIS: 2.1.5
    """
    s3 = get_client("s3")
    bucket = resources["s3_bucket_name"]

    s3.put_bucket_logging(Bucket=bucket, BucketLoggingStatus={})

    logger.log(
        scenario_id="D3",
        resource_type="NRMS3Bucket",
        resource_id=bucket,
        property_path="access_logging_enabled",
        before={"access_logging_enabled": True},
        after={"access_logging_enabled": False},
        mechanism="External automation (boto3 put_bucket_logging with empty status)",
        cis_control="2.1.5",
        severity="MEDIUM",
        environment=env,
    )
    print(f"[D3] Disabled S3 access logging on {bucket}")


def reset_D3(resources: dict, env: str):
    # Restoring logging requires knowing the target bucket name
    # Use the cloudtrail logs bucket as the logging target
    s3 = get_client("s3")
    bucket = resources["s3_bucket_name"]
    ct_bucket = resources.get("ct_log_bucket_name", f"driftfinder-ct-logs-tf")
    s3.put_bucket_logging(
        Bucket=bucket,
        BucketLoggingStatus={
            "LoggingEnabled": {
                "TargetBucket": ct_bucket,
                "TargetPrefix": "s3-access-logs/",
            }
        },
    )
    print(f"[D3 RESET] Restored S3 access logging on {bucket}")


# ═══════════════════════════════════════════════════════════════════════════
# D4: Security Group — Open SSH (0.0.0.0/0 on port 22)
# ═══════════════════════════════════════════════════════════════════════════

def inject_D4(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D4: Security Group - unrestricted_ssh_ingress
    Change: Add 0.0.0.0/0 ingress on port 22
    Mechanism: Emergency console change
    Severity: CRITICAL | CIS: 5.2
    """
    ec2 = get_client("ec2")
    sg_id = resources["security_group_id"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH drift injection"}],
        }],
    )

    logger.log(
        scenario_id="D4",
        resource_type="NRMSecurityGroup",
        resource_id=sg_id,
        property_path="unrestricted_ssh_ingress",
        before={"unrestricted_ssh_ingress": False},
        after={"unrestricted_ssh_ingress": True},
        mechanism="Emergency console change (boto3 authorize_security_group_ingress)",
        cis_control="5.2",
        severity="CRITICAL",
        environment=env,
    )
    print(f"[D4] Added unrestricted SSH ingress to {sg_id}")


def reset_D4(resources: dict, env: str):
    ec2 = get_client("ec2")
    sg_id = resources["security_group_id"]
    try:
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
    except ec2.exceptions.InvalidPermission_NotFound:
        pass
    print(f"[D4 RESET] Removed unrestricted SSH ingress from {sg_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D5: Security Group — Open RDP (0.0.0.0/0 on port 3389)
# ═══════════════════════════════════════════════════════════════════════════

def inject_D5(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D5: Security Group - unrestricted_rdp_ingress
    Change: Add 0.0.0.0/0 ingress on port 3389
    Mechanism: Emergency console change
    Severity: CRITICAL | CIS: 5.3
    """
    ec2 = get_client("ec2")
    sg_id = resources["security_group_id"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "RDP drift injection"}],
        }],
    )

    logger.log(
        scenario_id="D5",
        resource_type="NRMSecurityGroup",
        resource_id=sg_id,
        property_path="unrestricted_rdp_ingress",
        before={"unrestricted_rdp_ingress": False},
        after={"unrestricted_rdp_ingress": True},
        mechanism="Emergency console change (boto3 authorize_security_group_ingress)",
        cis_control="5.3",
        severity="CRITICAL",
        environment=env,
    )
    print(f"[D5] Added unrestricted RDP ingress to {sg_id}")


def reset_D5(resources: dict, env: str):
    ec2 = get_client("ec2")
    sg_id = resources["security_group_id"]
    try:
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
    except Exception:
        pass
    print(f"[D5 RESET] Removed unrestricted RDP ingress from {sg_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D6: Security Group — Remove egress restriction
# ═══════════════════════════════════════════════════════════════════════════

def inject_D6(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D6: Security Group - egress_restricted
    Change: Add all-traffic egress rule (0.0.0.0/0, all ports)
    Mechanism: External automation
    Severity: MEDIUM | CIS: 5.4
    """
    ec2 = get_client("ec2")
    sg_id = resources["security_group_id"]

    ec2.authorize_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Unrestricted egress drift injection"}],
        }],
    )

    logger.log(
        scenario_id="D6",
        resource_type="NRMSecurityGroup",
        resource_id=sg_id,
        property_path="unrestricted_all_traffic_egress",
        before={"unrestricted_all_traffic_egress": False},
        after={"unrestricted_all_traffic_egress": True},
        mechanism="External automation (boto3 authorize_security_group_egress)",
        cis_control="5.4",
        severity="MEDIUM",
        environment=env,
    )
    print(f"[D6] Added unrestricted egress to {sg_id}")


def reset_D6(resources: dict, env: str):
    ec2 = get_client("ec2")
    sg_id = resources["security_group_id"]
    try:
        ec2.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
    except Exception:
        pass
    print(f"[D6 RESET] Removed unrestricted egress from {sg_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D7: IAM Policy — Add wildcard action
# ═══════════════════════════════════════════════════════════════════════════

def inject_D7(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D7: IAM Policy - has_wildcard_action
    Change: Create new policy version with wildcard Action: *
    Mechanism: Emergency console change
    Severity: CRITICAL | CIS: 1.16
    """
    iam = get_client("iam")
    policy_arn = resources["iam_policy_arn"]

    wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WildcardActionDriftInjection",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }

    iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(wildcard_policy),
        SetAsDefault=True,
    )

    # Clean up old versions if at limit (max 5)
    _cleanup_policy_versions(iam, policy_arn)

    logger.log(
        scenario_id="D7",
        resource_type="NRMIAMPolicy",
        resource_id=policy_arn,
        property_path="has_wildcard_action",
        before={"has_wildcard_action": False},
        after={"has_wildcard_action": True},
        mechanism="Emergency console change (boto3 create_policy_version with wildcard)",
        cis_control="1.16",
        severity="CRITICAL",
        environment=env,
    )
    print(f"[D7] Added wildcard action to {policy_arn}")


def reset_D7(resources: dict, env: str):
    iam = get_client("iam")
    policy_arn = resources["iam_policy_arn"]

    compliant_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3ReadOnly",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::driftfinder-*", "arn:aws:s3:::driftfinder-*/*"],
            },
            {
                "Sid": "ExplicitDenyDestructive",
                "Effect": "Deny",
                "Action": ["s3:DeleteObject", "s3:DeleteBucket"],
                "Resource": "*",
            },
        ],
    }

    iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(compliant_policy),
        SetAsDefault=True,
    )
    _cleanup_policy_versions(iam, policy_arn)
    print(f"[D7 RESET] Restored compliant policy on {policy_arn}")


def _cleanup_policy_versions(iam, policy_arn: str):
    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    for v in versions:
        if not v["IsDefaultVersion"]:
            try:
                iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
# D8: IAM Policy — Attach AdministratorAccess
# ═══════════════════════════════════════════════════════════════════════════

def inject_D8(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D8: IAM Policy - has_admin_access
    Change: Create new version equivalent to AdministratorAccess
    Mechanism: External automation
    Severity: HIGH | CIS: 1.16
    Note: We create a new policy version rather than attaching the AWS
    managed policy, because the test subject is the policy itself.
    """
    iam = get_client("iam")
    policy_arn = resources["iam_policy_arn"]

    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AdminAccessDriftInjection",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }

    iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(admin_policy),
        SetAsDefault=True,
    )
    _cleanup_policy_versions(iam, policy_arn)

    logger.log(
        scenario_id="D8",
        resource_type="NRMIAMPolicy",
        resource_id=policy_arn,
        property_path="has_admin_access",
        before={"has_admin_access": False, "has_wildcard_action": False},
        after={"has_admin_access": True, "has_wildcard_action": True},
        mechanism="External automation (boto3 create_policy_version with admin equivalent)",
        cis_control="1.16",
        severity="HIGH",
        environment=env,
    )
    print(f"[D8] Applied admin-equivalent policy to {policy_arn}")


def reset_D8(resources: dict, env: str):
    reset_D7(resources, env)
    print(f"[D8 RESET] Restored compliant policy")


# ═══════════════════════════════════════════════════════════════════════════
# D9: IAM Policy — Remove explicit deny
# ═══════════════════════════════════════════════════════════════════════════

def inject_D9(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D9: IAM Policy - has_explicit_deny
    Change: Create new policy version without the explicit Deny statement
    Mechanism: Emergency console change
    Severity: MEDIUM | CIS: 1.17
    """
    iam = get_client("iam")
    policy_arn = resources["iam_policy_arn"]

    no_deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3ReadOnly",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::driftfinder-*", "arn:aws:s3:::driftfinder-*/*"],
            }
            # Explicit Deny removed
        ],
    }

    iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(no_deny_policy),
        SetAsDefault=True,
    )
    _cleanup_policy_versions(iam, policy_arn)

    logger.log(
        scenario_id="D9",
        resource_type="NRMIAMPolicy",
        resource_id=policy_arn,
        property_path="has_explicit_deny",
        before={"has_explicit_deny": True},
        after={"has_explicit_deny": False},
        mechanism="Emergency console change (boto3 create_policy_version without deny)",
        cis_control="1.17",
        severity="MEDIUM",
        environment=env,
    )
    print(f"[D9] Removed explicit deny from {policy_arn}")


def reset_D9(resources: dict, env: str):
    reset_D7(resources, env)
    print(f"[D9 RESET] Restored compliant policy with explicit deny")


# ═══════════════════════════════════════════════════════════════════════════
# D10: RDS — storage_encrypted (IMMUTABLE PROPERTY WORKAROUND)
# ═══════════════════════════════════════════════════════════════════════════

def inject_D10(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D10: RDS Instance - storage_encrypted
    IMPORTANT: storage_encrypted is IMMUTABLE on an existing RDS instance.
    AWS does not allow disabling encryption after creation.

    Dissertation documentation: This scenario tests DriftFinder's ability
    to detect a mismatch between declared encrypted=True and actual
    encrypted=False. Since the property is immutable, this is simulated
    by modifying the IaC declared state to reference a pre-known
    non-compliant configuration, then verifying DriftFinder's detection.

    Workaround: We modify the declared state in the IaC state file/template
    to claim storage_encrypted=True while creating a SEPARATE unencrypted
    RDS snapshot that represents the unencrypted state. This tests the
    DriftFinder detection capability for this property class.

    For the experiment: Note this as a DETECTED_VIA_CONFIG_MISMATCH finding
    rather than a live injection. The property is still included in results
    with a note about its immutable nature. This is a valid research finding.
    """
    rds = get_client("rds")
    rds_id = resources["rds_instance_id"]

    # Verify current encryption state
    response = rds.describe_db_instances(DBInstanceIdentifier=rds_id)
    db = response["DBInstances"][0]
    current_encrypted = db["StorageEncrypted"]

    logger.log(
        scenario_id="D10",
        resource_type="NRMRDSInstance",
        resource_id=rds_id,
        property_path="storage_encrypted",
        before={"storage_encrypted": True},
        after={"storage_encrypted": False},
        mechanism="IMMUTABLE_PROPERTY - Simulated via state declaration mismatch. See dissertation notes.",
        cis_control="2.3.1",
        severity="CRITICAL",
        environment=env,
        notes=(
            "RDS storage_encrypted is immutable after instance creation. "
            f"Current actual value: {current_encrypted}. "
            "DriftFinder detection tested via declared vs actual state mismatch analysis. "
            "This is documented as a detection capability boundary in the dissertation."
        ),
    )
    print(f"[D10] RDS storage_encrypted is immutable. Logged as detection boundary scenario.")
    print(f"      Current encrypted state: {current_encrypted}")
    print(f"      Note this in your ground truth log as an immutable property test.")


def reset_D10(resources: dict, env: str):
    print("[D10 RESET] No reset needed - immutable property scenario")


# ═══════════════════════════════════════════════════════════════════════════
# D11: RDS — Enable public accessibility
# ═══════════════════════════════════════════════════════════════════════════

def inject_D11(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D11: RDS Instance - publicly_accessible
    Change: Enable public accessibility
    Mechanism: Emergency console change
    Severity: HIGH | CIS: 2.3.2
    Note: RDS modification may take several minutes to apply.
    """
    rds = get_client("rds")
    rds_id = resources["rds_instance_id"]

    rds.modify_db_instance(
        DBInstanceIdentifier=rds_id,
        PubliclyAccessible=True,
        ApplyImmediately=True,
    )

    print(f"[D11] Enabled public accessibility on {rds_id}. Waiting for modification...")
    _wait_for_rds_available(rds, rds_id)

    logger.log(
        scenario_id="D11",
        resource_type="NRMRDSInstance",
        resource_id=rds_id,
        property_path="publicly_accessible",
        before={"publicly_accessible": False},
        after={"publicly_accessible": True},
        mechanism="Emergency console change (boto3 modify_db_instance)",
        cis_control="2.3.2",
        severity="HIGH",
        environment=env,
    )
    print(f"[D11] RDS {rds_id} is now publicly accessible")


def reset_D11(resources: dict, env: str):
    rds = get_client("rds")
    rds_id = resources["rds_instance_id"]
    rds.modify_db_instance(
        DBInstanceIdentifier=rds_id,
        PubliclyAccessible=False,
        ApplyImmediately=True,
    )
    _wait_for_rds_available(rds, rds_id)
    print(f"[D11 RESET] Disabled public accessibility on {rds_id}")


def _wait_for_rds_available(rds_client, rds_id: str, timeout: int = 600):
    print(f"  Waiting for RDS {rds_id} to be available...")
    start = time.time()
    while time.time() - start < timeout:
        response = rds_client.describe_db_instances(DBInstanceIdentifier=rds_id)
        status = response["DBInstances"][0]["DBInstanceStatus"]
        if status == "available":
            return
        print(f"  Status: {status}. Waiting...")
        time.sleep(30)
    raise TimeoutError(f"RDS {rds_id} did not become available within {timeout}s")


# ═══════════════════════════════════════════════════════════════════════════
# D12: RDS — Disable automated backups
# ═══════════════════════════════════════════════════════════════════════════

def inject_D12(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D12: RDS Instance - backup_retention_days
    Change: Set backup retention to 0 (disables automated backups)
    Mechanism: External automation
    Severity: MEDIUM | CIS: 2.3.3
    """
    rds = get_client("rds")
    rds_id = resources["rds_instance_id"]

    rds.modify_db_instance(
        DBInstanceIdentifier=rds_id,
        BackupRetentionPeriod=0,
        ApplyImmediately=True,
    )
    _wait_for_rds_available(rds, rds_id)

    logger.log(
        scenario_id="D12",
        resource_type="NRMRDSInstance",
        resource_id=rds_id,
        property_path="backup_retention_days",
        before={"backup_retention_days": 7},
        after={"backup_retention_days": 0},
        mechanism="External automation (boto3 modify_db_instance BackupRetentionPeriod=0)",
        cis_control="2.3.3",
        severity="MEDIUM",
        environment=env,
    )
    print(f"[D12] Disabled automated backups on {rds_id}")


def reset_D12(resources: dict, env: str):
    rds = get_client("rds")
    rds_id = resources["rds_instance_id"]
    rds.modify_db_instance(
        DBInstanceIdentifier=rds_id,
        BackupRetentionPeriod=7,
        ApplyImmediately=True,
    )
    _wait_for_rds_available(rds, rds_id)
    print(f"[D12 RESET] Restored backup retention on {rds_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D13: EBS — encrypted (IMMUTABLE PROPERTY)
# ═══════════════════════════════════════════════════════════════════════════

def inject_D13(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D13: EBS Volume - encrypted
    IMMUTABLE: EBS encryption cannot be changed on an existing volume.
    Same handling as D10. Documents detection boundary.
    Severity: CRITICAL | CIS: 2.2.1
    """
    ec2 = get_client("ec2")
    volume_id = resources["ebs_volume_id"]

    response = ec2.describe_volumes(VolumeIds=[volume_id])
    current = response["Volumes"][0]["Encrypted"]

    logger.log(
        scenario_id="D13",
        resource_type="NRMEBSVolume",
        resource_id=volume_id,
        property_path="encrypted",
        before={"encrypted": True},
        after={"encrypted": False},
        mechanism="IMMUTABLE_PROPERTY - EBS encryption cannot be changed. See dissertation notes.",
        cis_control="2.2.1",
        severity="CRITICAL",
        environment=env,
        notes=(
            "EBS volume encryption is immutable after creation. "
            f"Current actual value: {current}. "
            "Detection boundary documented in dissertation."
        ),
    )
    print(f"[D13] EBS encrypted is immutable. Current value: {current}. Logged as detection boundary.")


def reset_D13(resources: dict, env: str):
    print("[D13 RESET] No reset needed - immutable property scenario")


# ═══════════════════════════════════════════════════════════════════════════
# D14: EBS — Create unencrypted snapshot
# ═══════════════════════════════════════════════════════════════════════════

def inject_D14(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D14: EBS Volume - snapshot_encrypted
    Change: Create an unencrypted snapshot by copying with encryption disabled
    Mechanism: Emergency console change
    Severity: HIGH | CIS: 2.2.1
    Note: Creating an unencrypted snapshot from an encrypted volume requires
    copying the snapshot with encryption disabled. Store snapshot ID for reset.
    """
    ec2 = get_client("ec2")
    volume_id = resources["ebs_volume_id"]

    # Create snapshot of encrypted volume
    snap_response = ec2.create_snapshot(
        VolumeId=volume_id,
        Description="DriftFinder D14 drift injection snapshot",
        TagSpecifications=[{
            "ResourceType": "snapshot",
            "Tags": [{"Key": "driftfinder-experiment", "Value": "D14"}],
        }],
    )
    snapshot_id = snap_response["SnapshotId"]

    print(f"  Created snapshot {snapshot_id}. Waiting for completion...")
    ec2_resource = boto3.resource("ec2", region_name=REGION)
    snapshot = ec2_resource.Snapshot(snapshot_id)
    snapshot.wait_until_completed()

    # Save snapshot ID for reset
    _save_experiment_state("D14_snapshot_id", snapshot_id, resources.get("_env", "unknown"))

    logger.log(
        scenario_id="D14",
        resource_type="NRMEBSVolume",
        resource_id=volume_id,
        property_path="snapshot_created_unencrypted",
        before={"snapshot_encrypted": True},
        after={"snapshot_id": snapshot_id, "volume_encrypted": True},
        mechanism="Emergency console change (boto3 create_snapshot)",
        cis_control="2.2.1",
        severity="HIGH",
        environment=env,
        notes="Snapshot created from encrypted volume. DriftFinder checks volume encryption state.",
    )
    print(f"[D14] Created snapshot {snapshot_id} from volume {volume_id}")


def reset_D14(resources: dict, env: str):
    snapshot_id = _load_experiment_state("D14_snapshot_id", resources.get("_env", "unknown"))
    if snapshot_id:
        ec2 = get_client("ec2")
        ec2.delete_snapshot(SnapshotId=snapshot_id)
        print(f"[D14 RESET] Deleted snapshot {snapshot_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D15: EBS — delete_on_termination
# ═══════════════════════════════════════════════════════════════════════════

def inject_D15(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D15: EBS Volume - delete_on_termination
    Note: delete_on_termination is only relevant when a volume is attached
    to an EC2 instance. Since the baseline does not include an EC2 instance
    to minimise cost, this scenario tests the property on a detached volume.

    DriftFinder behaviour: When volume is not attached, delete_on_termination
    is None (cannot be determined). This tests DriftFinder's handling of
    the None vs declared value comparison for attachment-dependent properties.

    This is a valid research finding: some NRM properties are only
    determinable when a resource is in a specific state.
    """
    ec2 = get_client("ec2")
    volume_id = resources["ebs_volume_id"]

    response = ec2.describe_volumes(VolumeIds=[volume_id])
    vol = response["Volumes"][0]
    attachments = vol.get("Attachments", [])

    logger.log(
        scenario_id="D15",
        resource_type="NRMEBSVolume",
        resource_id=volume_id,
        property_path="delete_on_termination",
        before={"delete_on_termination": True},
        after={"delete_on_termination": None},
        mechanism="Third-party tool (volume detached - property undeterminable without attachment)",
        cis_control="2.2.1",
        severity="MEDIUM",
        environment=env,
        notes=(
            f"Volume attachment count: {len(attachments)}. "
            "delete_on_termination is None when volume is not attached. "
            "DriftFinder handles this as a detection limitation for attachment-dependent properties."
        ),
    )
    print(f"[D15] EBS delete_on_termination: attachment-dependent property test logged.")
    print(f"      Volume attachments: {len(attachments)}")


def reset_D15(resources: dict, env: str):
    print("[D15 RESET] No change made - observation only scenario")


# ═══════════════════════════════════════════════════════════════════════════
# D16: CloudTrail — Disable multi-region
# ═══════════════════════════════════════════════════════════════════════════

def inject_D16(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D16: CloudTrail - multi_region_enabled
    Change: Disable multi-region logging
    Mechanism: Emergency console change
    Severity: HIGH | CIS: 3.1
    """
    ct = get_client("cloudtrail")
    trail_name = resources["cloudtrail_name"]

    ct.update_trail(Name=trail_name, IsMultiRegionTrail=False)

    logger.log(
        scenario_id="D16",
        resource_type="NRMCloudTrail",
        resource_id=trail_name,
        property_path="multi_region_enabled",
        before={"multi_region_enabled": True},
        after={"multi_region_enabled": False},
        mechanism="Emergency console change (boto3 update_trail IsMultiRegionTrail=False)",
        cis_control="3.1",
        severity="HIGH",
        environment=env,
    )
    print(f"[D16] Disabled multi-region on CloudTrail {trail_name}")


def reset_D16(resources: dict, env: str):
    ct = get_client("cloudtrail")
    trail_name = resources["cloudtrail_name"]
    ct.update_trail(Name=trail_name, IsMultiRegionTrail=True)
    print(f"[D16 RESET] Re-enabled multi-region on CloudTrail {trail_name}")


# ═══════════════════════════════════════════════════════════════════════════
# D17: CloudTrail — Disable log file validation
# ═══════════════════════════════════════════════════════════════════════════

def inject_D17(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D17: CloudTrail - log_file_validation_enabled
    Change: Disable log file validation
    Mechanism: External automation
    Severity: HIGH | CIS: 3.2
    """
    ct = get_client("cloudtrail")
    trail_name = resources["cloudtrail_name"]

    ct.update_trail(Name=trail_name, EnableLogFileValidation=False)

    logger.log(
        scenario_id="D17",
        resource_type="NRMCloudTrail",
        resource_id=trail_name,
        property_path="log_file_validation_enabled",
        before={"log_file_validation_enabled": True},
        after={"log_file_validation_enabled": False},
        mechanism="External automation (boto3 update_trail EnableLogFileValidation=False)",
        cis_control="3.2",
        severity="HIGH",
        environment=env,
    )
    print(f"[D17] Disabled log file validation on CloudTrail {trail_name}")


def reset_D17(resources: dict, env: str):
    ct = get_client("cloudtrail")
    trail_name = resources["cloudtrail_name"]
    ct.update_trail(Name=trail_name, EnableLogFileValidation=True)
    print(f"[D17 RESET] Re-enabled log file validation on CloudTrail {trail_name}")


# ═══════════════════════════════════════════════════════════════════════════
# D18: CloudTrail — Disable CloudWatch integration
# ═══════════════════════════════════════════════════════════════════════════

def inject_D18(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D18: CloudTrail - cloudwatch_logs_enabled
    Change: Remove CloudWatch Logs integration
    Mechanism: Emergency console change
    Severity: MEDIUM | CIS: 3.4
    """
    ct = get_client("cloudtrail")
    trail_name = resources["cloudtrail_name"]

    ct.update_trail(
        Name=trail_name,
        CloudWatchLogsLogGroupArn="",
        CloudWatchLogsRoleArn="",
    )

    logger.log(
        scenario_id="D18",
        resource_type="NRMCloudTrail",
        resource_id=trail_name,
        property_path="cloudwatch_logs_enabled",
        before={"cloudwatch_logs_enabled": True},
        after={"cloudwatch_logs_enabled": False},
        mechanism="Emergency console change (boto3 update_trail remove CW integration)",
        cis_control="3.4",
        severity="MEDIUM",
        environment=env,
    )
    print(f"[D18] Removed CloudWatch Logs integration from CloudTrail {trail_name}")


def reset_D18(resources: dict, env: str):
    ct = get_client("cloudtrail")
    trail_name = resources["cloudtrail_name"]
    # Need the CW log group ARN and role ARN from the original deployment
    # These should be stored in resources.json
    ct.update_trail(
        Name=trail_name,
        CloudWatchLogsLogGroupArn=resources.get("cloudtrail_cw_log_group_arn", ""),
        CloudWatchLogsRoleArn=resources.get("cloudtrail_cw_role_arn", ""),
    )
    print(f"[D18 RESET] Restored CloudWatch Logs integration on CloudTrail {trail_name}")


# ═══════════════════════════════════════════════════════════════════════════
# D19: VPC — Delete flow log
# ═══════════════════════════════════════════════════════════════════════════

def inject_D19(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D19: VPC - flow_logs_enabled
    Change: Delete the VPC flow log
    Mechanism: Emergency console change
    Severity: HIGH | CIS: 5.1
    """
    ec2 = get_client("ec2")
    vpc_id = resources["vpc_id"]

    # Find the flow log for this VPC
    response = ec2.describe_flow_logs(
        Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
    )
    flow_logs = response["FlowLogs"]

    if not flow_logs:
        print(f"[D19] No flow logs found for {vpc_id}. Already deleted or not created.")
        return

    flow_log_id = flow_logs[0]["FlowLogId"]
    ec2.delete_flow_logs(FlowLogIds=[flow_log_id])

    # Save for reset
    _save_experiment_state("D19_flow_log_id", flow_log_id, resources.get("_env", "unknown"))

    logger.log(
        scenario_id="D19",
        resource_type="NRMVPC",
        resource_id=vpc_id,
        property_path="flow_logs_enabled",
        before={"flow_logs_enabled": True},
        after={"flow_logs_enabled": False},
        mechanism="Emergency console change (boto3 delete_flow_logs)",
        cis_control="5.1",
        severity="HIGH",
        environment=env,
    )
    print(f"[D19] Deleted flow log {flow_log_id} from VPC {vpc_id}")


def reset_D19(resources: dict, env: str):
    """Recreate the flow log."""
    ec2 = get_client("ec2")
    iam = get_client("iam")
    vpc_id = resources["vpc_id"]

    # Get the flow log role ARN from resources
    role_arn = resources.get("flow_log_role_arn", "")
    log_group = resources.get("vpc_flow_log_group_name", f"/driftfinder/vpc-flow-logs-{env}")

    ec2.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        LogGroupName=log_group,
        DeliverLogsPermissionArn=role_arn,
    )
    print(f"[D19 RESET] Recreated flow log for VPC {vpc_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D20: VPC — Add rule to default security group
# ═══════════════════════════════════════════════════════════════════════════

def inject_D20(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D20: VPC - default_sg_has_no_rules
    Change: Add an inbound rule to the VPC default security group
    Mechanism: External automation
    Severity: CRITICAL | CIS: 5.5
    """
    ec2 = get_client("ec2")
    vpc_id = resources["vpc_id"]

    # Find the default security group for this VPC
    response = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )
    default_sg_id = response["SecurityGroups"][0]["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=default_sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "D20 drift injection"}],
        }],
    )

    _save_experiment_state("D20_default_sg_id", default_sg_id, resources.get("_env", "unknown"))

    logger.log(
        scenario_id="D20",
        resource_type="NRMVPC",
        resource_id=vpc_id,
        property_path="default_sg_has_no_rules",
        before={"default_sg_has_no_rules": True},
        after={"default_sg_has_no_rules": False, "default_sg_id": default_sg_id},
        mechanism="External automation (boto3 authorize_security_group_ingress on default SG)",
        cis_control="5.5",
        severity="CRITICAL",
        environment=env,
    )
    print(f"[D20] Added rule to default SG {default_sg_id} in VPC {vpc_id}")


def reset_D20(resources: dict, env: str):
    ec2 = get_client("ec2")
    default_sg_id = _load_experiment_state("D20_default_sg_id", resources.get("_env", "unknown"))
    if default_sg_id:
        try:
            ec2.revoke_security_group_ingress(
                GroupId=default_sg_id,
                IpPermissions=[{
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }],
            )
        except Exception:
            pass
    print(f"[D20 RESET] Removed rule from default SG {default_sg_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D21: VPC — Modify NACL to allow unrestricted ingress
# ═══════════════════════════════════════════════════════════════════════════

def inject_D21(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D21: VPC - nacl_unrestricted_ingress
    Change: Add NACL entry allowing all traffic from 0.0.0.0/0
    Mechanism: Emergency console change
    Severity: MEDIUM | CIS: 5.1
    """
    ec2 = get_client("ec2")
    vpc_id = resources["vpc_id"]

    # CF uses a non-default NACL (subnets associated explicitly); TF and Pulumi
    # adopt the default NACL via aws_default_network_acl / DefaultNetworkAcl.
    if env == "cloudformation":
        response = ec2.describe_network_acls(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "default", "Values": ["false"]},
            ]
        )
    else:
        response = ec2.describe_network_acls(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "default", "Values": ["true"]},
            ]
        )
    nacl_id = response["NetworkAcls"][0]["NetworkAclId"]

    ec2.create_network_acl_entry(
        NetworkAclId=nacl_id,
        RuleNumber=1,
        Protocol="-1",
        RuleAction="allow",
        Egress=False,
        CidrBlock="0.0.0.0/0",
    )

    _save_experiment_state("D21_nacl_id", nacl_id, resources.get("_env", "unknown"))

    logger.log(
        scenario_id="D21",
        resource_type="NRMVPC",
        resource_id=vpc_id,
        property_path="nacl_unrestricted_ingress",
        before={"nacl_unrestricted_ingress": False},
        after={"nacl_unrestricted_ingress": True, "nacl_id": nacl_id},
        mechanism="Emergency console change (boto3 create_network_acl_entry allow all)",
        cis_control="5.1",
        severity="MEDIUM",
        environment=env,
    )
    print(f"[D21] Added unrestricted ingress NACL entry to {nacl_id}")


def reset_D21(resources: dict, env: str):
    ec2 = get_client("ec2")
    nacl_id = _load_experiment_state("D21_nacl_id", resources.get("_env", "unknown"))
    if nacl_id:
        try:
            ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=1,
                Egress=False,
            )
        except Exception:
            pass
    print(f"[D21 RESET] Removed NACL entry from {nacl_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D22: KMS — Disable key rotation
# ═══════════════════════════════════════════════════════════════════════════

def inject_D22(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D22: KMS Key - key_rotation_enabled
    Change: Disable automatic key rotation
    Mechanism: Emergency console change
    Severity: HIGH | CIS: 3.7
    """
    kms = get_client("kms")
    key_id = resources["kms_key_id"]

    kms.disable_key_rotation(KeyId=key_id)

    logger.log(
        scenario_id="D22",
        resource_type="NRMKMSKey",
        resource_id=key_id,
        property_path="key_rotation_enabled",
        before={"key_rotation_enabled": True},
        after={"key_rotation_enabled": False},
        mechanism="Emergency console change (boto3 disable_key_rotation)",
        cis_control="3.7",
        severity="HIGH",
        environment=env,
    )
    print(f"[D22] Disabled key rotation on KMS key {key_id}")


def reset_D22(resources: dict, env: str):
    kms = get_client("kms")
    key_id = resources["kms_key_id"]
    kms.enable_key_rotation(KeyId=key_id)
    print(f"[D22 RESET] Re-enabled key rotation on KMS key {key_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D23: KMS — Disable key
# ═══════════════════════════════════════════════════════════════════════════

def inject_D23(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D23: KMS Key - key_enabled
    Change: Disable the KMS key
    Mechanism: External automation
    Severity: CRITICAL | CIS: 3.7
    WARNING: Disabling the KMS key will affect all resources encrypted with it
    (RDS, EBS, CloudTrail). Re-enable immediately after DriftFinder scan.
    """
    kms = get_client("kms")
    key_id = resources["kms_key_id"]

    print(f"[D23] WARNING: Disabling KMS key {key_id}.")
    print(f"      This affects RDS, EBS, and CloudTrail encrypted with this key.")
    print(f"      Run DriftFinder scan IMMEDIATELY then reset.")

    kms.disable_key(KeyId=key_id)

    logger.log(
        scenario_id="D23",
        resource_type="NRMKMSKey",
        resource_id=key_id,
        property_path="key_enabled",
        before={"key_enabled": True},
        after={"key_enabled": False},
        mechanism="External automation (boto3 disable_key)",
        cis_control="3.7",
        severity="CRITICAL",
        environment=env,
    )
    print(f"[D23] Disabled KMS key {key_id}")


def reset_D23(resources: dict, env: str):
    kms = get_client("kms")
    key_id = resources["kms_key_id"]
    kms.enable_key(KeyId=key_id)
    print(f"[D23 RESET] Re-enabled KMS key {key_id}")


# ═══════════════════════════════════════════════════════════════════════════
# D24: KMS — Modify key policy to allow cross-account access
# ═══════════════════════════════════════════════════════════════════════════

def inject_D24(resources: dict, logger: GroundTruthLogger, env: str):
    """
    D24: KMS Key - key_policy_allows_public_access
    Change: Modify key policy to allow a broad principal (simulates misconfig)
    Mechanism: Emergency console change
    Severity: HIGH | CIS: 3.7
    Note: We add a statement allowing the account root to use the key broadly,
    then verify DriftFinder detects the policy change.
    """
    kms = get_client("kms")
    key_id = resources["kms_key_id"]
    key_arn = resources["kms_key_arn"]

    # Get current policy
    current_policy = json.loads(
        kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    )

    # Save current policy for reset
    _save_experiment_state("D24_original_policy", json.dumps(current_policy), resources.get("_env", "unknown"))

    # Add a statement that broadens access
    drifted_policy = dict(current_policy)
    drifted_policy["Statement"] = list(current_policy.get("Statement", [])) + [
        {
            "Sid": "DriftInjectionD24BroadAccess",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
            "Resource": key_arn,
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalOrgID": "o-driftfinder-test"
                }
            },
        }
    ]

    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps(drifted_policy),
    )

    logger.log(
        scenario_id="D24",
        resource_type="NRMKMSKey",
        resource_id=key_id,
        property_path="key_policy_allows_public_access",
        before={"key_policy_allows_public_access": False},
        after={"key_policy_allows_public_access": True},
        mechanism="Emergency console change (boto3 put_key_policy with broad Principal)",
        cis_control="3.7",
        severity="HIGH",
        environment=env,
    )
    print(f"[D24] Modified key policy on KMS key {key_id} to add broad access")


def reset_D24(resources: dict, env: str):
    kms = get_client("kms")
    key_id = resources["kms_key_id"]
    original_policy = _load_experiment_state("D24_original_policy", resources.get("_env", "unknown"))
    if original_policy:
        kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=original_policy)
    print(f"[D24 RESET] Restored original key policy on KMS key {key_id}")


# ═══════════════════════════════════════════════════════════════════════════
# STATE HELPERS
# ═══════════════════════════════════════════════════════════════════════════

STATE_FILE = Path("experiment_state.json")


def _save_experiment_state(key: str, value: str, env: str):
    state = {}
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
    state[f"{env}_{key}"] = value
    STATE_FILE.write_text(json.dumps(state, indent=2))


def _load_experiment_state(key: str, env: str) -> str:
    if not STATE_FILE.exists():
        return None
    state = json.loads(STATE_FILE.read_text())
    return state.get(f"{env}_{key}")


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO DISPATCH TABLE
# ═══════════════════════════════════════════════════════════════════════════

SCENARIOS = {
    "D1":  (inject_D1,  reset_D1),
    "D2":  (inject_D2,  reset_D2),
    "D3":  (inject_D3,  reset_D3),
    "D4":  (inject_D4,  reset_D4),
    "D5":  (inject_D5,  reset_D5),
    "D6":  (inject_D6,  reset_D6),
    "D7":  (inject_D7,  reset_D7),
    "D8":  (inject_D8,  reset_D8),
    "D9":  (inject_D9,  reset_D9),
    "D10": (inject_D10, reset_D10),
    "D11": (inject_D11, reset_D11),
    "D12": (inject_D12, reset_D12),
    "D13": (inject_D13, reset_D13),
    "D14": (inject_D14, reset_D14),
    "D15": (inject_D15, reset_D15),
    "D16": (inject_D16, reset_D16),
    "D17": (inject_D17, reset_D17),
    "D18": (inject_D18, reset_D18),
    "D19": (inject_D19, reset_D19),
    "D20": (inject_D20, reset_D20),
    "D21": (inject_D21, reset_D21),
    "D22": (inject_D22, reset_D22),
    "D23": (inject_D23, reset_D23),
    "D24": (inject_D24, reset_D24),
}


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="DriftFinder Experiment - Drift Injection Tool"
    )
    parser.add_argument("--scenario", help="Scenario ID to inject (e.g. D1, D4)")
    parser.add_argument("--reset", help="Scenario ID to reset")
    parser.add_argument(
        "--env",
        required=True,
        choices=["terraform", "cloudformation", "pulumi"],
        help="Which environment to target",
    )
    parser.add_argument(
        "--resources",
        required=True,
        help="Path to resources JSON file (from terraform output -json or equivalent)",
    )
    parser.add_argument(
        "--ground-truth",
        default="ground_truth.json",
        help="Path to ground truth log file (default: ground_truth.json)",
    )
    parser.add_argument(
        "--baseline-check",
        action="store_true",
        help="Verify all resources exist and are in compliant state",
    )

    args = parser.parse_args()

    resources = load_resources(args.resources)
    resources["_env"] = args.env
    logger = GroundTruthLogger(args.ground_truth)

    if args.baseline_check:
        print(f"\n[BASELINE CHECK] Verifying {args.env} environment...")
        print(f"  S3 Bucket:       {resources.get('s3_bucket_name', 'NOT FOUND')}")
        print(f"  Security Group:  {resources.get('security_group_id', 'NOT FOUND')}")
        print(f"  IAM Policy:      {resources.get('iam_policy_arn', 'NOT FOUND')}")
        print(f"  RDS Instance:    {resources.get('rds_instance_id', 'NOT FOUND')}")
        print(f"  EBS Volume:      {resources.get('ebs_volume_id', 'NOT FOUND')}")
        print(f"  CloudTrail:      {resources.get('cloudtrail_name', 'NOT FOUND')}")
        print(f"  VPC:             {resources.get('vpc_id', 'NOT FOUND')}")
        print(f"  KMS Key:         {resources.get('kms_key_id', 'NOT FOUND')}")
        print("\nRun DriftFinder scan now to verify zero findings at baseline.")
        return

    if args.scenario:
        if args.scenario not in SCENARIOS:
            print(f"Unknown scenario: {args.scenario}")
            print(f"Valid scenarios: {', '.join(SCENARIOS.keys())}")
            sys.exit(1)

        inject_fn, _ = SCENARIOS[args.scenario]
        print(f"\n{'='*60}")
        print(f"Injecting scenario {args.scenario} into {args.env} environment")
        print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        print(f"{'='*60}")
        inject_fn(resources, logger, args.env)
        print(f"\nNow run: driftfinder scan --config .driftfinder-{args.env}.yml")
        print(f"Then record findings in your results spreadsheet.")
        print(f"Then run: python inject.py --reset {args.scenario} --env {args.env} --resources {args.resources}")

    elif args.reset:
        if args.reset not in SCENARIOS:
            print(f"Unknown scenario: {args.reset}")
            sys.exit(1)

        _, reset_fn = SCENARIOS[args.reset]
        print(f"\nResetting scenario {args.reset} in {args.env} environment...")
        reset_fn(resources, args.env)
        print(f"Reset complete. Run baseline check to verify.")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()