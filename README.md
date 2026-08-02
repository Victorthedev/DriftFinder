# DriftFinder

A multi-IaC compliance drift detection tool for AWS, mapped to CIS AWS Foundations Benchmark v3.0.

DriftFinder is developed as part of an MSc dissertation in Data Science and Big Data Analytics at Wrexham University. It detects when live AWS infrastructure has diverged from what Terraform, CloudFormation or Pulumi declares and maps every divergence to a specific CIS control with a severity rating.

---

## What it does

DriftFinder reads your IaC state (a Terraform state file, a CloudFormation stack or a Pulumi stack export), queries the matching live AWS resources, and compares the two through a **Normalised Resource Model (NRM)** — a canonical, tool-agnostic schema that represents every security-relevant property the same way regardless of which IaC tool declared it.

Every detected divergence is reported with:
- The property that changed
- The declared value (what IaC says it should be)
- The actual value (what AWS has right now)
- The CIS AWS Foundations Benchmark v3.0 control it violates
- A severity: CRITICAL, HIGH, MEDIUM or LOW

---

## Supported tools and resources

**IaC tools:** Terraform, CloudFormation (including CDK), Pulumi

**AWS resource types:**

| Resource | CIS controls |
|---|---|
| S3 Bucket | 2.1.1, 2.1.2, 2.1.4, 2.1.5 |
| Security Group | 5.2, 5.3, 5.4 |
| IAM Policy | 1.16 |
| RDS Instance | 2.3.1, 2.3.2, 2.3.3 |
| EBS Volume | 2.2.1 |
| CloudTrail | 3.1, 3.2, 3.4, 3.7 |
| VPC | 5.1, 5.5 |
| KMS Key | 3.7 |

---

## Running locally

DriftFinder is not yet published to PyPI. Install it directly from the repository.

### Prerequisites

- Python 3.11 or later
- AWS credentials configured (environment variables, `~/.aws/credentials` or an IAM instance role)
- For Terraform: a `.tfstate` file
- For CloudFormation: a deployed stack and the stack name
- For Pulumi: `pulumi stack export > pulumi_stack_export.json`

### Install

```bash
git clone https://github.com/Victorthedev/driftfinder
cd driftfinder
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

Verify:

```bash
driftfinder --version
```

### Configure

Create a `.driftfinder.yml` in your project root. Run the interactive wizard:

```bash
driftfinder init
```

Or write it manually. Examples for each tool:

**Terraform:**
```yaml
iac_tool: terraform
state_file: path/to/terraform.tfstate
aws_region: eu-west-1
fail_on: CRITICAL
output_format: json
```

**CloudFormation:**
```yaml
iac_tool: cloudformation
stack_name: my-stack-name
aws_region: eu-west-1
fail_on: CRITICAL
output_format: json
```

**Pulumi:**
```yaml
iac_tool: pulumi
pulumi_stack: path/to/pulumi_stack_export.json
aws_region: eu-west-1
fail_on: CRITICAL
output_format: json
```

### Run a scan

```bash
driftfinder scan
```

With options:

```bash
driftfinder scan --config .driftfinder.yml --output results/my-scan --format json
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | No findings at or above the `fail_on` severity |
| `1` | Findings detected at or above the `fail_on` severity |
| `2` | Scan error (missing config, AWS auth failure, inaccessible state file) |

---

## Sample output

```
DriftFinder v1.0.0 — Scan Results
Scanned: 8 resources | Tool: terraform | Region: eu-west-1
Timestamp: 2025-09-15T14:32:01Z

FINDINGS: 2 total (1 CRITICAL, 1 HIGH)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] NRMSecurityGroup — sg-0abc123def456789
  Property:  unrestricted_ssh_ingress
  Declared:  False
  Actual:    True
  CIS:       5.2 — Ensure no security groups allow ingress from 0.0.0.0/0 to port 22

[HIGH]     NRMS3Bucket — my-production-bucket
  Property:  server_side_encryption_enabled
  Declared:  True
  Actual:    False
  CIS:       2.1.1 — Ensure all S3 buckets employ encryption-at-rest

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Report written to: drift-report.json
Exit code: 1 (CRITICAL findings detected)
```

---

## Repository structure

```
driftfinder/
├── src/driftfinder/
│   ├── cli/                  # CLI commands: init, scan, schedule, report
│   ├── core/                 # Scan engine and config model
│   ├── models/               # NRM dataclasses, DriftFinding and ScanResult
│   ├── parsers/              # Terraform, CloudFormation and Pulumi parsers
│   ├── runtime/aws/          # Live AWS queries via Boto3 (one file per resource type)
│   ├── mappers/              # CIS control mapping table and mapper
│   ├── reporters/            # JSON and HTML report generators
│   ├── scheduler/            # Crontab management for scheduled scans
│   └── utils/                # Retry logic and logging
│
├── tests/
│   ├── unit/                 # Parser and engine unit tests (moto mocks)
│   ├── integration/          # Full scan tests with mocked AWS
│   └── e2e/                  # End-to-end tests against LocalStack
│
├── experiment/               # Controlled dissertation experiment
│   ├── terraform/            # Terraform environment
│   ├── cloudformation/       # CloudFormation environment
│   ├── pulumi/               # Pulumi environment
│   ├── inject.py             # Drift injection and reset scripts
│   ├── ground_truth.py       # Ground truth logger
│   └── ground_truth.json     # Full experiment ground truth record
│
├── results/                  # Scan results from all 78 experimental runs
├── steps.txt                 # Complete experiment protocol, step by step
├── .driftfinder.yml.example  # Example config file
└── pyproject.toml
```

---

## Running the tests

```bash
pip install -e ".[dev]"
pytest tests/unit tests/integration
```

E2E tests require LocalStack:

```bash
docker-compose up localstack -d
pytest tests/e2e --localstack
```

---

## Required AWS permissions

DriftFinder is read-only. It never modifies infrastructure. The IAM principal running it needs:

```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetBucketEncryption", "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketVersioning", "s3:GetBucketLogging", "s3:GetBucketPolicy",
    "ec2:DescribeSecurityGroups", "ec2:DescribeVolumes",
    "ec2:DescribeVpcs", "ec2:DescribeFlowLogs", "ec2:DescribeNetworkAcls",
    "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRolePolicy",
    "rds:DescribeDBInstances",
    "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
    "kms:DescribeKey", "kms:GetKeyRotationStatus", "kms:GetKeyPolicy",
    "cloudformation:DescribeStackResources", "cloudformation:GetTemplate"
  ],
  "Resource": "*"
}
```

---

## Dissertation experiment

The controlled experiment provisions three identical AWS environments (one per IaC tool), injects 24 security drift scenarios across the 8 supported resource types and records whether DriftFinder detects each one. Results and ground truth are in the `experiment/` and `results/` directories. The full protocol is documented in `steps.txt`.

**Summary results:**

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| Terraform | 1.000 | 0.750 | 0.857 |
| CloudFormation | 1.000 | 0.708 | 0.829 |
| Pulumi | 1.000 | 0.750 | 0.857 |
| **Overall** | **1.000** | **0.736** | **0.848** |

Zero false positives across all 78 scans and 6 control cases.

---

## What comes next

Phase 2 (post-dissertation) plans include: async concurrent scanning, all 58 CIS controls, a TypeScript SDK, AI-assisted fix suggestions, an MCP server and a remediation command.

---

## Licence

Source code: [Apache 2.0](LICENSE)

Documentation: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
