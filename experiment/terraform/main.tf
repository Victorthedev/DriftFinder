# experiment/terraform/main.tf
# DriftFinder Controlled Experiment - Terraform Baseline Environment
# Provisions all 8 resource types in CIS-compliant initial state
# Region: eu-west-1 (London)

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# ─── KMS KEY ───────────────────────────────────────────────────────────────
resource "aws_kms_key" "driftfinder_test" {
  description             = "DriftFinder experiment KMS key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "driftfinder-kms-test"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}

resource "aws_kms_alias" "driftfinder_test" {
  name          = "alias/driftfinder-test-terraform"
  target_key_id = aws_kms_key.driftfinder_test.key_id
}

# ─── CLOUDTRAIL LOG BUCKET ─────────────────────────────────────────────────
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "driftfinder-ct-logs-${var.account_id}-tf"
  force_destroy = true
  tags = { Name = "driftfinder-cloudtrail-logs-tf" }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket     = aws_s3_bucket.cloudtrail_logs.id
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = "arn:aws:s3:::${aws_s3_bucket.cloudtrail_logs.bucket}"
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${aws_s3_bucket.cloudtrail_logs.bucket}/AWSLogs/${var.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

# ─── CLOUDWATCH LOG GROUP FOR CLOUDTRAIL ───────────────────────────────────
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/driftfinder/cloudtrail-tf"
  retention_in_days = 7
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "driftfinder-cloudtrail-cw-tf"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "driftfinder-cloudtrail-cw-policy-tf"
  role = aws_iam_role.cloudtrail_cw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# ─── CLOUDTRAIL ────────────────────────────────────────────────────────────
resource "aws_cloudtrail" "driftfinder_test" {
  name                          = "driftfinder-trail-test"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
  kms_key_id                    = aws_kms_key.driftfinder_test.arn

  tags = {
    Name        = "driftfinder-trail-test"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# ─── TEST S3 BUCKET ────────────────────────────────────────────────────────
resource "aws_s3_bucket" "driftfinder_test" {
  bucket        = "driftfinder-s3-test-${var.account_id}-tf"
  force_destroy = true

  tags = {
    Name        = "driftfinder-s3-test"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "driftfinder_test" {
  bucket = aws_s3_bucket.driftfinder_test.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "driftfinder_test" {
  bucket                  = aws_s3_bucket.driftfinder_test.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "driftfinder_test" {
  bucket = aws_s3_bucket.driftfinder_test.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "driftfinder_test" {
  bucket        = aws_s3_bucket.driftfinder_test.id
  target_bucket = aws_s3_bucket.cloudtrail_logs.id
  target_prefix = "s3-access-logs/"
}

# ─── VPC ───────────────────────────────────────────────────────────────────
resource "aws_vpc" "driftfinder_test" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "driftfinder-vpc-test"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}

resource "aws_subnet" "a" {
  vpc_id            = aws_vpc.driftfinder_test.id
  cidr_block        = "10.100.1.0/24"
  availability_zone = "${var.region}a"
  tags              = { Name = "driftfinder-subnet-a" }
}

resource "aws_subnet" "b" {
  vpc_id            = aws_vpc.driftfinder_test.id
  cidr_block        = "10.100.2.0/24"
  availability_zone = "${var.region}b"
  tags              = { Name = "driftfinder-subnet-b" }
}

# ─── VPC FLOW LOGS ─────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/driftfinder/vpc-flow-logs-tf"
  retention_in_days = 7
}

resource "aws_iam_role" "flow_logs" {
  name = "driftfinder-flow-logs-tf"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "driftfinder-flow-logs-policy-tf"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"], Resource = "*" }]
  })
}

resource "aws_flow_log" "driftfinder_test" {
  vpc_id          = aws_vpc.driftfinder_test.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  tags            = { Name = "driftfinder-flow-log" }
}

# ─── DEFAULT SECURITY GROUP (D20) ─────────────────────────────────────────
resource "aws_default_security_group" "driftfinder_test" {
  vpc_id = aws_vpc.driftfinder_test.id
  # No ingress or egress rules — CIS 5.5 compliant

  tags = {
    Name        = "driftfinder-default-sg-tf"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}

# ─── DEFAULT NETWORK ACL (D21) ────────────────────────────────────────────
resource "aws_default_network_acl" "driftfinder_test" {
  default_network_acl_id = aws_vpc.driftfinder_test.default_network_acl_id

  ingress {
    protocol   = "6"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "6"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name        = "driftfinder-default-nacl-tf"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}

# ─── SECURITY GROUP ────────────────────────────────────────────────────────
resource "aws_security_group" "driftfinder_test" {
  name        = "driftfinder-sg-test"
  description = "DriftFinder experiment security group - compliant baseline"
  vpc_id      = aws_vpc.driftfinder_test.id

  ingress {
    description = "HTTPS from internal only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "HTTPS outbound only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "driftfinder-sg-test"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}

# ─── IAM POLICY ────────────────────────────────────────────────────────────
resource "aws_iam_policy" "driftfinder_test" {
  name        = "driftfinder-iam-test"
  description = "DriftFinder experiment IAM policy - compliant baseline"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowS3ReadOnly"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::driftfinder-*", "arn:aws:s3:::driftfinder-*/*"]
      },
      {
        Sid      = "ExplicitDenyDestructive"
        Effect   = "Deny"
        Action   = ["s3:DeleteObject", "s3:DeleteBucket"]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "driftfinder-iam-test"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}

# ─── RDS SUBNET GROUP ──────────────────────────────────────────────────────
resource "aws_db_subnet_group" "driftfinder_test" {
  name       = "driftfinder-rds-subnet-group-tf"
  subnet_ids = [aws_subnet.a.id, aws_subnet.b.id]
  tags       = { Name = "driftfinder-rds-subnet-group-tf" }
}

# ─── RDS INSTANCE ──────────────────────────────────────────────────────────
resource "aws_db_instance" "driftfinder_test" {
  identifier              = "driftfinder-rds-test"
  engine                  = "mysql"
  engine_version          = "8.4"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.driftfinder_test.arn
  username                = "admin"
  password                = var.db_password
  db_subnet_group_name    = aws_db_subnet_group.driftfinder_test.name
  vpc_security_group_ids  = [aws_security_group.driftfinder_test.id]
  publicly_accessible     = false
  backup_retention_period = 7
  deletion_protection     = false
  skip_final_snapshot     = true
  multi_az                = false

  tags = {
    Name        = "driftfinder-rds-test"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}

# ─── EBS VOLUME ────────────────────────────────────────────────────────────
resource "aws_ebs_volume" "driftfinder_test" {
  availability_zone = "${var.region}a"
  size              = 1
  type              = "gp2"
  encrypted         = true
  kms_key_id        = aws_kms_key.driftfinder_test.arn

  tags = {
    Name        = "driftfinder-ebs-test"
    Environment = "driftfinder-experiment"
    IaCTool     = "terraform"
  }
}
