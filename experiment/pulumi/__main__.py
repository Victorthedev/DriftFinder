"""
DriftFinder Controlled Experiment - Pulumi Baseline Environment
Provisions all 8 resource types in CIS-compliant initial state.
Region: eu-west-2
"""

import json
import pulumi
import pulumi_aws as aws

config = pulumi.Config()
account_id = config.require("account_id")
db_password = config.require_secret("db_password")
region = config.get("region") or "eu-west-2"

tags = {
    "Environment": "driftfinder-experiment",
    "IaCTool": "pulumi",
}

# ── KMS KEY ─────────────────────────────────────────────────────────────────
kms_key = aws.kms.Key(
    "driftfinder-kms-test",
    description="DriftFinder experiment KMS key",
    deletion_window_in_days=7,
    enable_key_rotation=True,
    policy=pulumi.Output.from_input(account_id).apply(
        lambda aid: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{aid}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "Allow CloudTrail to use key",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": ["kms:GenerateDataKey*", "kms:DescribeKey", "kms:Decrypt"],
                    "Resource": "*",
                },
            ],
        })
    ),
    tags={**tags, "Name": "driftfinder-kms-test"},
)

kms_alias = aws.kms.Alias(
    "driftfinder-kms-alias",
    name="alias/driftfinder-test-pulumi",
    target_key_id=kms_key.key_id,
)

# ── CLOUDTRAIL LOG BUCKET ───────────────────────────────────────────────────
ct_log_bucket = aws.s3.Bucket(
    "driftfinder-ct-logs",
    bucket=pulumi.Output.concat("driftfinder-ct-logs-", account_id, "-pulumi"),
    force_destroy=True,
    tags={"Name": "driftfinder-cloudtrail-logs-pulumi"},
)

aws.s3.BucketPublicAccessBlock(
    "ct-log-public-access-block",
    bucket=ct_log_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

ct_bucket_policy = aws.s3.BucketPolicy(
    "ct-log-bucket-policy",
    bucket=ct_log_bucket.id,
    policy=pulumi.Output.all(
        bucket=ct_log_bucket.bucket,
        arn=ct_log_bucket.arn,
        account_id=account_id,
    ).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": args["arn"],
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"{args['arn']}/AWSLogs/{args['account_id']}/*",
                    "Condition": {
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                    },
                },
            ],
        })
    ),
)

# ── CLOUDWATCH LOG GROUP FOR CLOUDTRAIL ────────────────────────────────────
ct_log_group = aws.cloudwatch.LogGroup(
    "driftfinder-cloudtrail-lg",
    name="/driftfinder/cloudtrail-pulumi",
    retention_in_days=7,
)

ct_role = aws.iam.Role(
    "driftfinder-cloudtrail-cw-role",
    name="driftfinder-cloudtrail-cw-pulumi",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
)

aws.iam.RolePolicy(
    "driftfinder-cloudtrail-cw-policy",
    name="cloudtrail-cw-policy",
    role=ct_role.id,
    policy=ct_log_group.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": f"{arn}:*",
            }],
        })
    ),
)

# ── CLOUDTRAIL ──────────────────────────────────────────────────────────────
trail = aws.cloudtrail.Trail(
    "driftfinder-trail-test",
    name="driftfinder-trail-test-pulumi",
    s3_bucket_name=ct_log_bucket.bucket,
    include_global_service_events=True,
    is_multi_region_trail=True,
    enable_log_file_validation=True,
    cloud_watch_logs_group_arn=ct_log_group.arn.apply(lambda arn: f"{arn}:*"),
    cloud_watch_logs_role_arn=ct_role.arn,
    kms_key_id=kms_key.arn,
    tags={**tags, "Name": "driftfinder-trail-test-pulumi"},
    opts=pulumi.ResourceOptions(depends_on=[ct_bucket_policy]),
)

# ── TEST S3 BUCKET ──────────────────────────────────────────────────────────
s3_bucket = aws.s3.Bucket(
    "driftfinder-s3-test",
    bucket=pulumi.Output.concat("driftfinder-s3-test-", account_id, "-pulumi"),
    force_destroy=True,
    tags={**tags, "Name": "driftfinder-s3-test"},
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "driftfinder-s3-sse",
    bucket=s3_bucket.id,
    rules=[{
        "applyServerSideEncryptionByDefault": {
            "sseAlgorithm": "AES256",
        },
    }],
)

aws.s3.BucketPublicAccessBlock(
    "driftfinder-s3-pab",
    bucket=s3_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketVersioningV2(
    "driftfinder-s3-versioning",
    bucket=s3_bucket.id,
    versioning_configuration={"status": "Enabled"},
)

aws.s3.BucketLoggingV2(
    "driftfinder-s3-logging",
    bucket=s3_bucket.id,
    target_bucket=ct_log_bucket.id,
    target_prefix="s3-access-logs/",
)

# ── VPC ─────────────────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    "driftfinder-vpc-test",
    cidr_block="10.102.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**tags, "Name": "driftfinder-vpc-test"},
)

subnet_a = aws.ec2.Subnet(
    "driftfinder-subnet-a",
    vpc_id=vpc.id,
    cidr_block="10.102.1.0/24",
    availability_zone=f"{region}a",
    tags={"Name": "driftfinder-subnet-a-pulumi"},
)

subnet_b = aws.ec2.Subnet(
    "driftfinder-subnet-b",
    vpc_id=vpc.id,
    cidr_block="10.102.2.0/24",
    availability_zone=f"{region}b",
    tags={"Name": "driftfinder-subnet-b-pulumi"},
)

# ── VPC FLOW LOGS ───────────────────────────────────────────────────────────
flow_log_group = aws.cloudwatch.LogGroup(
    "driftfinder-vpc-flow-lg",
    name="/driftfinder/vpc-flow-logs-pulumi",
    retention_in_days=7,
)

flow_log_role = aws.iam.Role(
    "driftfinder-flow-log-role",
    name="driftfinder-flow-logs-pulumi",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
)

aws.iam.RolePolicy(
    "driftfinder-flow-log-policy",
    name="flow-log-policy",
    role=flow_log_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
            ],
            "Resource": "*",
        }],
    }),
)

flow_log = aws.ec2.FlowLog(
    "driftfinder-flow-log",
    vpc_id=vpc.id,
    traffic_type="ALL",
    iam_role_arn=flow_log_role.arn,
    log_destination=flow_log_group.arn,
    tags={"Name": "driftfinder-flow-log-pulumi"},
)

# ── DEFAULT SECURITY GROUP (D20) ────────────────────────────────────────────
default_sg = aws.ec2.DefaultSecurityGroup(
    "driftfinder-default-sg",
    vpc_id=vpc.id,
    ingress=[],
    egress=[],
    tags={**tags, "Name": "driftfinder-default-sg-pulumi"},
)

# ── DEFAULT NETWORK ACL (D21) ───────────────────────────────────────────────
default_nacl = aws.ec2.DefaultNetworkAcl(
    "driftfinder-default-nacl",
    default_network_acl_id=vpc.default_network_acl_id,
    ingress=[
        {
            "protocol": "6",
            "rule_no": 100,
            "action": "allow",
            "cidr_block": "0.0.0.0/0",
            "from_port": 443,
            "to_port": 443,
        },
        {
            "protocol": "6",
            "rule_no": 200,
            "action": "allow",
            "cidr_block": "0.0.0.0/0",
            "from_port": 1024,
            "to_port": 65535,
        },
    ],
    egress=[
        {
            "protocol": "-1",
            "rule_no": 100,
            "action": "allow",
            "cidr_block": "0.0.0.0/0",
            "from_port": 0,
            "to_port": 0,
        },
    ],
    tags={**tags, "Name": "driftfinder-default-nacl-pulumi"},
)

# ── SECURITY GROUP ──────────────────────────────────────────────────────────
sg = aws.ec2.SecurityGroup(
    "driftfinder-sg-test",
    name="driftfinder-sg-test-pulumi",
    description="DriftFinder experiment security group - compliant baseline",
    vpc_id=vpc.id,
    ingress=[{
        "description": "HTTPS from internal only",
        "from_port": 443,
        "to_port": 443,
        "protocol": "tcp",
        "cidr_blocks": ["10.0.0.0/8"],
    }],
    egress=[{
        "description": "HTTPS outbound only",
        "from_port": 443,
        "to_port": 443,
        "protocol": "tcp",
        "cidr_blocks": ["0.0.0.0/0"],
    }],
    tags={**tags, "Name": "driftfinder-sg-test-pulumi"},
)

# ── IAM POLICY ──────────────────────────────────────────────────────────────
iam_policy = aws.iam.Policy(
    "driftfinder-iam-test",
    name="driftfinder-iam-test-pulumi",
    description="DriftFinder experiment IAM policy - compliant baseline",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3ReadOnly",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::driftfinder-*",
                    "arn:aws:s3:::driftfinder-*/*",
                ],
            },
            {
                "Sid": "ExplicitDenyDestructive",
                "Effect": "Deny",
                "Action": ["s3:DeleteObject", "s3:DeleteBucket"],
                "Resource": "*",
            },
        ],
    }),
    tags={**tags, "Name": "driftfinder-iam-test-pulumi"},
)

# ── RDS SUBNET GROUP ────────────────────────────────────────────────────────
rds_subnet_group = aws.rds.SubnetGroup(
    "driftfinder-rds-subnet-group",
    name="driftfinder-rds-subnet-pulumi",
    subnet_ids=[subnet_a.id, subnet_b.id],
    tags={"Name": "driftfinder-rds-subnet-pulumi"},
)

# ── RDS INSTANCE ────────────────────────────────────────────────────────────
rds = aws.rds.Instance(
    "driftfinder-rds-test",
    identifier="driftfinder-rds-test-pulumi",
    engine="mysql",
    engine_version="8.0",
    instance_class="db.t3.micro",
    allocated_storage=20,
    storage_encrypted=True,
    kms_key_id=kms_key.arn,
    username="admin",
    password=db_password,
    db_subnet_group_name=rds_subnet_group.name,
    vpc_security_group_ids=[sg.id],
    publicly_accessible=False,
    backup_retention_period=7,
    deletion_protection=False,
    skip_final_snapshot=True,
    tags={**tags, "Name": "driftfinder-rds-test-pulumi"},
)

# ── EBS VOLUME ──────────────────────────────────────────────────────────────
ebs = aws.ebs.Volume(
    "driftfinder-ebs-test",
    availability_zone=f"{region}a",
    size=1,
    type="gp2",
    encrypted=True,
    kms_key_id=kms_key.arn,
    tags={**tags, "Name": "driftfinder-ebs-test-pulumi"},
)

# ── EXPORTS ─────────────────────────────────────────────────────────────────
pulumi.export("s3_bucket_name", s3_bucket.bucket)
pulumi.export("security_group_id", sg.id)
pulumi.export("iam_policy_arn", iam_policy.arn)
pulumi.export("rds_instance_id", rds.identifier)
pulumi.export("ebs_volume_id", ebs.id)
pulumi.export("cloudtrail_name", trail.name)
pulumi.export("vpc_id", vpc.id)
pulumi.export("kms_key_id", kms_key.key_id)
pulumi.export("kms_key_arn", kms_key.arn)