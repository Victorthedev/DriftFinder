# DriftFinder

> Open source IaC compliance drift detection for AWS, mapped to CIS AWS Foundations Benchmark v3.0.

[![PyPI version](https://img.shields.io/pypi/v/driftfinder)](https://pypi.org/project/driftfinder/)
[![Python versions](https://img.shields.io/pypi/pyversions/driftfinder)](https://pypi.org/project/driftfinder/)
[![Licence](https://img.shields.io/badge/licence-Apache%202.0-blue)](LICENSE)
[![CI](https://github.com/Victorthedev/driftfinder/actions/workflows/ci.yml/badge.svg)](https://github.com/Victorthedev/driftfinder/actions/workflows/ci.yml)

---

## What it does

DriftFinder detects when your live AWS infrastructure has drifted from what your IaC declares. It reads your Terraform state file, CloudFormation stack or Pulumi stack export, queries the matching live AWS resources via the AWS API, and compares the two through a canonical Normalised Resource Model (NRM). Every divergence it finds is mapped to a specific CIS AWS Foundations Benchmark v3.0 control with a severity rating, and the output is structured for both human review and CI/CD pipeline consumption.

The tool is designed for teams who need continuous assurance that manual changes, hotfixes, console edits or out-of-band remediation have not quietly broken their declared security posture between deployments.

---

## Quick start

```bash
pip install driftfinder
driftfinder init
driftfinder scan
```

That's it. `init` walks you through creating a `.driftfinder.yml` config file. `scan` reads your IaC state, queries AWS and prints findings to the terminal.

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

Report written to: drift-report.json, drift-report.html
Exit code: 1 (CRITICAL findings detected)
```

---

## Why DriftFinder

The existing landscape has gaps that matter in practice:

- **driftctl** was the closest open source equivalent. It is no longer maintained.
- **AWS Config** is powerful but has no IaC awareness. It cannot tell you that a resource was declared compliant in Terraform and then changed out-of-band.
- **Checkov, tfsec and similar tools** scan IaC source code for misconfigurations, not runtime drift. They catch what you wrote wrong; they do not catch what changed after you deployed it.
- Every tool that does approach this problem is single-IaC. None normalise across Terraform, CloudFormation and Pulumi in a single scan.

DriftFinder's core contribution is the **Normalised Resource Model (NRM)**: a canonical, tool-agnostic schema that abstracts Terraform attribute paths, CloudFormation property names and Pulumi output keys into one representation. One detection engine operates across all three IaC tools using this shared model.

---

## Supported IaC tools

| Tool | Status | State source |
|---|---|---|
| Terraform | Supported | `.tfstate` file (local or S3) |
| CloudFormation | Supported | Stack name via AWS API |
| AWS CDK | Supported | CDK synthesises to CloudFormation; no special handling needed |
| Pulumi | Supported | `pulumi stack export` JSON |
| OpenTofu | Planned (Phase 2) | Same `.tfstate` format as Terraform |

---

## Supported AWS resource types and CIS controls

| Resource type | CIS controls covered | Severity |
|---|---|---|
| S3 Bucket | 2.1.1 (encryption), 2.1.2 (versioning/MFA delete), 2.1.4 (public access block), 2.1.5 (access logging) | CRITICAL to MEDIUM |
| Security Group | 5.2 (SSH ingress), 5.3 (RDP ingress), 5.4 (unrestricted traffic) | CRITICAL |
| IAM Policy | 1.16 (wildcard actions, admin access) | CRITICAL to HIGH |
| RDS Instance | 2.3.1 (storage encryption), 2.3.2 (public access), 2.3.3 (backup retention) | CRITICAL to MEDIUM |
| EBS Volume | 2.2.1 (encryption) | CRITICAL |
| CloudTrail | 3.1 (multi-region, active logging), 3.2 (log file validation), 3.4 (CloudWatch integration), 3.7 (KMS encryption) | CRITICAL to MEDIUM |
| VPC | 5.1 (flow logs), 5.5 (default security group) | CRITICAL to HIGH |
| KMS Key | 3.7 (key rotation, key enabled, public access in policy) | CRITICAL to HIGH |

---

## Architecture

DriftFinder operates as a four-layer pipeline:

```
Layer 1: IaC Parser
         Reads .tfstate / CloudFormation stack / Pulumi export
         Emits NRM objects with declared property values

Layer 2: Normalised Resource Model (NRM)
         Canonical schema for every security-relevant property
         Tool-agnostic. Immutable frozen dataclasses.

Layer 3: Runtime Query Engine
         Queries live AWS state via Boto3
         Emits matching NRM objects with actual property values

Layer 4: Drift Detection + CIS Mapper
         Compares declared vs actual NRM objects property by property
         Maps every divergence to a CIS control and severity
         Produces DriftFinding objects
```

### The Normalised Resource Model

The NRM is the core intellectual contribution of DriftFinder. Every resource type has a frozen Python dataclass with canonical property names. The same property name means the same thing regardless of which IaC tool declared it.

A key design principle: `None` and `False` are not the same thing.

- `None` means the property was not declared in the IaC source. DriftFinder skips comparison for `None` properties. This prevents false positives when a team legitimately relies on AWS defaults.
- `False` means the property was explicitly declared as false or absent. A declared `False` that does not match actual `True` is genuine drift.

This distinction is what makes the NRM correct rather than just fast.

### Parser behaviour by tool

**Terraform:** Reads the `.tfstate` JSON file (schema version 4). Handles both the legacy monolithic `aws_s3_bucket` format and the modern split format introduced in AWS provider v4 (where encryption, public access block and versioning are separate resource types). Merges all related resources into a single NRM object per bucket.

**CloudFormation:** Fetches the template via `GetTemplate` and physical resource IDs via `DescribeStackResources`. Properties absent from the template are mapped to `None` (not declared), not `False` (declared absent). CDK-generated stacks are handled identically with no CDK-specific code path required.

**Pulumi:** Reads the JSON output of `pulumi stack export`. Uses the `outputs` block, not `inputs`, because outputs represent what Pulumi actually provisioned. Handles the Pulumi v4+ AWS provider pattern where S3 sub-resources (`BucketPublicAccessBlock`, `BucketLoggingV2`, `BucketVersioningV2`) are separate resource types in the state file rather than inline properties on the main `Bucket` resource.

---

## Installation

**Requirements:** Python 3.11 or later. AWS credentials configured in the standard credential chain (environment variables, `~/.aws/credentials` or instance role).

```bash
pip install driftfinder
```

To verify the installation:

```bash
driftfinder --version
```

---

## Configuration

DriftFinder reads from a `.driftfinder.yml` file in the current directory. Run `driftfinder init` to create one interactively, or create it manually:

**Terraform:**
```yaml
iac_tool: terraform
state_file: ./terraform/terraform.tfstate
aws_region: eu-west-1
fail_on: CRITICAL
output_format: both
```

**CloudFormation:**
```yaml
iac_tool: cloudformation
stack_name: my-production-stack
aws_region: eu-west-1
fail_on: HIGH
output_format: json
```

**Pulumi:**
```yaml
iac_tool: pulumi
pulumi_stack: myorg/myproject/production
aws_region: eu-west-1
fail_on: CRITICAL
output_format: both
```

All config values can be overridden at the command line. The `fail_on` field sets the minimum severity that causes a non-zero exit code. This is the control you wire into your CI/CD pipeline.

### Full configuration reference

| Field | Type | Default | Description |
|---|---|---|---|
| `iac_tool` | string | required | `terraform`, `cloudformation` or `pulumi` |
| `state_file` | string | — | Path to `.tfstate` (Terraform only). Supports `s3://bucket/path` |
| `stack_name` | string | — | CloudFormation stack name |
| `pulumi_stack` | string | — | Pulumi stack in `org/project/stack` format |
| `aws_region` | string | `eu-west-2` | AWS region |
| `aws_profile` | string | — | Named AWS credentials profile |
| `fail_on` | string | `CRITICAL` | Minimum severity for exit code 1: `CRITICAL`, `HIGH`, `MEDIUM` or `LOW` |
| `output_format` | string | `both` | `json`, `html` or `both` |
| `output_path` | string | `drift-report` | Output file path without extension |
| `mode` | string | `default` | `default` (exits 1 on findings) or `report-only` (always exits 0) |
| `max_retries` | int | `3` | Maximum AWS API retry attempts |
| `retry_base_delay` | float | `1.0` | Base delay in seconds for exponential backoff |
| `retry_max_delay` | float | `30.0` | Maximum backoff delay in seconds |

---

## CLI commands

### `driftfinder init`

Interactive wizard that creates `.driftfinder.yml`. Validates that the state source is accessible before writing the file.

```bash
driftfinder init
driftfinder init --config .driftfinder-staging.yml
```

### `driftfinder scan`

Runs a full drift detection scan.

```bash
driftfinder scan
driftfinder scan --config .driftfinder-prod.yml
driftfinder scan --fail-on HIGH --format json --output reports/drift-$(date +%Y%m%d)
driftfinder scan --mode report-only    # never exits 1, for cron jobs
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` severity |
| `1` | Findings detected at or above `--fail-on` severity |
| `2` | Scan error (config not found, AWS auth failure, inaccessible state file) |

### `driftfinder schedule`

Creates a crontab entry for continuous scheduled scanning.

```bash
driftfinder schedule --interval 15m --config .driftfinder.yml --output ./drift-reports
driftfinder schedule --interval 1h --config .driftfinder.yml --output ./drift-reports
```

Scheduled scans always run in `report-only` mode so the cron job itself never fails. Output files are dated for easy archival. Run `driftfinder unschedule` to remove the crontab entry.

### `driftfinder unschedule`

Removes the DriftFinder crontab entry.

```bash
driftfinder unschedule
```

### `driftfinder report`

Re-renders a previous JSON scan result into HTML (or vice versa). Useful for generating audit-ready HTML from a stored JSON report without re-running the scan.

```bash
driftfinder report --input drift-report.json --format html --output drift-report
```

---

## CI/CD integration

### GitHub Actions

```yaml
- name: DriftFinder scan
  run: |
    pip install driftfinder
    driftfinder scan --config .driftfinder.yml --fail-on HIGH --format json --output drift-report
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    AWS_DEFAULT_REGION: eu-west-1

- name: Upload drift report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: drift-report
    path: drift-report.*
```

### GitLab CI

```yaml
drift-check:
  image: python:3.11
  script:
    - pip install driftfinder
    - driftfinder scan --fail-on CRITICAL --format json --output drift-report
  artifacts:
    when: always
    paths:
      - drift-report.json
      - drift-report.html
```

### General pattern

DriftFinder exits `1` when findings meet the `--fail-on` threshold, which causes most CI systems to fail the job. Pair this with `--format json` to store the report as a build artifact for audit evidence. Use `--mode report-only` if you want to capture findings without blocking the pipeline.

---

## Output formats

### JSON

Structured output suitable for downstream processing, archival and audit evidence. The `findings` array contains one object per detected drift:

```json
{
  "scan_timestamp": "2025-09-15T14:32:01Z",
  "iac_tool": "terraform",
  "state_source": "s3://my-tf-state/prod/terraform.tfstate",
  "resources_scanned": 8,
  "resources_with_drift": 2,
  "compliant": false,
  "scan_duration_seconds": 12.4,
  "critical_count": 1,
  "high_count": 1,
  "medium_count": 0,
  "low_count": 0,
  "findings": [
    {
      "resource_type": "NRMSecurityGroup",
      "resource_id": "sg-0abc123def456789",
      "resource_name": "web-sg",
      "iac_tool": "terraform",
      "property_path": "unrestricted_ssh_ingress",
      "declared_value": false,
      "actual_value": true,
      "drift_type": "MODIFIED",
      "severity": "CRITICAL",
      "cis_controls": ["5.2"],
      "cis_description": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
      "detected_at": "2025-09-15T14:32:01Z"
    }
  ]
}
```

### HTML

A self-contained audit report suitable for sharing with security or compliance teams. Includes colour-coded severity badges, a summary section and a sortable findings table.

---

## Required IAM permissions

DriftFinder is read-only. It never modifies your infrastructure. Attach the following least-privilege policy to the role or user running DriftFinder:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketEncryption",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeNetworkAcls",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRolePolicy",
        "rds:DescribeDBInstances",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:GetKeyPolicy",
        "cloudformation:DescribeStackResources",
        "cloudformation:GetTemplate"
      ],
      "Resource": "*"
    }
  ]
}
```

DriftFinder never stores credentials. It reads from the standard AWS credential chain: environment variables, `~/.aws/credentials` or an IAM instance role. The `aws_profile` config field accepts a profile name only, never keys.

---

## Validated experiment results

DriftFinder v1.0.0 was validated through a controlled experiment as part of an MSc dissertation in Data Science and Big Data Analytics. Three identical AWS environments were provisioned (one per IaC tool), 24 security drift scenarios were injected across 8 resource types and DriftFinder was run against each environment.

### Results summary

| Environment | TP | FN | FP | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| Terraform | 18 | 6 | 0 | 2 | 1.000 | 0.750 | 0.857 | 0.000 |
| CloudFormation | 17 | 7 | 0 | 2 | 1.000 | 0.708 | 0.829 | 0.000 |
| Pulumi | 18 | 6 | 0 | 2 | 1.000 | 0.750 | 0.857 | 0.000 |
| **Overall** | **53** | **19** | **0** | **6** | **1.000** | **0.736** | **0.848** | **0.000** |

**Precision of 1.000** means every finding DriftFinder raised was genuine drift. Zero false positives across all 72 scenarios and 6 control cases.

**Recall of 0.736** means DriftFinder caught 73.6% of injected scenarios. The 19 false negatives are all explained by structural constraints, not tool deficiencies:

- **D1 (S3 encryption):** AWS has enforced AES-256 default encryption on all new buckets since 2023. Disabling it is a no-op; the API auto-restores it. DriftFinder correctly reads the live state.
- **D10 (RDS encryption) and D13 (EBS encryption):** Encryption is immutable on existing resources. It cannot be changed without replacing the resource entirely.
- **D11 (RDS public access):** Requires an internet gateway attached to the VPC. All three experiment VPCs were private by design.
- **D14 (EBS unencrypted snapshot) and D15 (EBS delete-on-termination):** These properties are outside the NRM comparison path for the current version, or require an attached EC2 instance that was not part of the baseline.
- **D20 CloudFormation (default security group):** CloudFormation has no `AWS::EC2::DefaultSecurityGroup` resource type. There is no way to declare intent for the default SG in a CF template, so DriftFinder correctly emits `None` and skips comparison.

The experiment ran against AWS `eu-west-1` using Terraform 1.6, CloudFormation and Pulumi v6 with the AWS provider v6.

---

## Security

DriftFinder is designed with a security-first stance:

- **Read-only by design.** No write permissions are required or used at any point.
- **No telemetry.** DriftFinder does not collect or transmit any usage data.
- **No internet access required** beyond standard AWS API endpoints.
- **No credential storage.** Credentials are never written to disk or logged.
- **Input validation** via Pydantic for all config and CLI inputs. State files are parsed with `yaml.safe_load`, never `yaml.load`.
- **Dependency scanning** via `pip-audit` on every CI run.

To report a security vulnerability, please open a GitHub private security advisory at `https://github.com/Victorthedev/driftfinder/security/advisories/new`. We acknowledge within 72 hours and aim to patch CRITICAL issues within 30 days.

---

## Roadmap

DriftFinder is built in two phases. Phase 1 (current release, v1.0.0) proves the concept with a controlled research experiment. Phase 2 extends the tool for production adoption by the DevSecOps community.

### Phase 1 — Current (v1.0.0)

- Three IaC tools: Terraform, CloudFormation (including CDK) and Pulumi
- Eight AWS resource types covering the CIS controls most commonly violated in practice
- CLI with `init`, `scan`, `schedule`, `unschedule` and `report` commands
- JSON and HTML output
- Exponential backoff with jitter for AWS API rate limiting
- Cron-based scheduled scanning for continuous monitoring
- CI/CD integration via exit codes
- 80%+ test coverage across unit and integration tests

### Phase 2 — Planned

#### v1.1.0 — Performance and coverage

- `asyncio` + `ProcessPoolExecutor` for concurrent resource scanning across large environments
- Token bucket rate limiter with per-service AWS API limits
- All 58 CIS AWS Foundations Benchmark v3.0 controls (up from the current subset applicable to 8 resource types)
- Immutable NRM enforcement via frozen dataclasses at runtime

#### v1.2.0 — TypeScript SDK

- `@driftfinder/sdk` published to npm
- Full TypeScript reimplementation of the NRM, parsers, runtime queries and detection engine
- AWS SDK v3 for JavaScript
- Worker threads for CPU-bound parsing isolation
- Same JSON output schema as the Python CLI for interoperability

#### v1.3.0 — AI fix suggestions

- `--ai-fix` flag attaches a structured remediation suggestion to each finding
- `--ai-explain` generates a plain-English explanation of each finding for non-technical stakeholders
- Supports Anthropic (Claude) and OpenAI (GPT-4o) via user-supplied API keys
- Suggestions are always advisory; DriftFinder never auto-applies fixes

#### v1.4.0 — MCP server

- `driftfinder mcp-server` exposes DriftFinder as an MCP tool
- Enables Claude, Cursor and other MCP clients to run drift scans inline during development
- `scan_drift` and `get_compliance_status` tools exposed via stdio transport

#### v1.5.0 — Remediation mode

- `driftfinder remediate` command applies IaC fixes idempotently
- Dependency graph (DAG) ensures resources are remediated in safe order
- Every remediation action requires explicit confirmation or `--yes` flag
- State-file locking via DynamoDB or Redis mutex prevents concurrent remediation conflicts

#### v2.0.0 — Multi-cloud

- Plugin architecture for GCP and Azure adapters
- Community contribution targets with documented extension interfaces
- SBOM generation via CycloneDX on every release
- Signed releases via sigstore/cosign

### Version scheme

```
1.0.0 — Phase 1 complete (3 tools, 8 resource types, dissertation experiment validated)
1.1.0 — Async + rate limiting + all 58 CIS controls
1.2.0 — TypeScript SDK on npm
1.3.0 — AI fix suggestions
1.4.0 — MCP server
1.5.0 — Remediation mode
2.0.0 — Azure and GCP adapters
```

---

## Repository structure

```
driftfinder/
├── src/driftfinder/
│   ├── cli/                  # Click CLI: init, scan, schedule, unschedule, report
│   ├── core/                 # Engine orchestration and config model
│   ├── models/               # NRM dataclasses, DriftFinding and ScanResult models
│   ├── parsers/              # Terraform, CloudFormation and Pulumi state parsers
│   ├── runtime/aws/          # Boto3 queries for each resource type
│   ├── mappers/              # CIS control mapping table and mapper
│   ├── reporters/            # JSON and HTML report generators
│   ├── scheduler/            # Crontab management
│   └── utils/                # Retry logic and structured logging
├── tests/
│   ├── unit/                 # Isolated unit tests with moto mocks
│   ├── integration/          # Full scan tests with mocked AWS
│   └── e2e/                  # End-to-end tests against LocalStack
├── experiment/               # Controlled experiment: inject scripts, ground truth and results
├── docs/adr/                 # Architecture Decision Records
├── .driftfinder.yml.example  # Example configuration
├── docker-compose.yml        # LocalStack for local E2E testing
└── pyproject.toml
```

---

## Contributing

Contributions are welcome. The areas where community help would have the most impact are:

- New AWS resource type adapters (Lambda, ECS, ElastiCache, etc.)
- Additional CIS control mappings for existing resource types
- TypeScript SDK implementation (Phase 2)
- Azure and GCP adapters (Phase 2)
- Real-world `.tfstate`, CloudFormation template and Pulumi export fixture files for edge cases

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, how to add a new resource type adapter, how to add new CIS mappings and the test requirements for PRs.

### Development setup

```bash
git clone https://github.com/Victorthedev/driftfinder
cd driftfinder
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

Run the test suite (no AWS credentials required):

```bash
pytest tests/unit tests/integration
```

Run E2E tests against LocalStack:

```bash
docker-compose up localstack -d
pytest tests/e2e --localstack
```

---

## Technology stack

| Concern | Choice |
|---|---|
| Language | Python 3.11+ |
| CLI | Click 8.x |
| Data models | Pydantic v2 (findings and config), frozen dataclasses (NRM) |
| AWS SDK | Boto3 1.34+ |
| Retry handling | botocore retry config + tenacity |
| Config parsing | PyYAML |
| HTML reports | Jinja2 |
| Testing | pytest 7.x + moto 4.x + LocalStack |
| Linting | ruff |
| Type checking | mypy strict |
| Formatting | black |
| Build | hatch |

---

## Licence

DriftFinder source code is licensed under the [Apache License 2.0](LICENSE).

Documentation is licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).

---

*Built as part of an MSc dissertation in Data Science and Big Data Analytics at Wrexham University.*
