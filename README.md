# DriftFinder

A multi-IaC security drift detection tool for AWS, with findings mapped to CIS AWS Foundations Benchmark v3.0.0 controls where one exists.

DriftFinder is developed as part of an MSc dissertation in Data Science and Big Data Analytics at Wrexham University. It detects when live AWS infrastructure has diverged from what Terraform, CloudFormation or Pulumi declares, rates every divergence by severity and maps it to the matching CIS control when the benchmark has one.

---

## What it does

DriftFinder reads your IaC state (a Terraform state file, a CloudFormation stack or a Pulumi stack export), queries the matching live AWS resources, and compares the two through a **Normalised Resource Model (NRM)** - a canonical, tool-agnostic schema that represents every security-relevant property the same way regardless of which IaC tool declared it.

Every detected divergence is reported with:
- The property that changed
- The declared value (what IaC says it should be)
- The actual value (what AWS has right now)
- The CIS AWS Foundations Benchmark v3.0.0 control it violates, when the benchmark has one
- A severity: CRITICAL, HIGH, MEDIUM or LOW

---

## Supported tools and resources

**IaC tools:** Terraform, CloudFormation (including CDK), Pulumi

**AWS resource types:**

| Resource | CIS v3.0.0 controls | Also checked (no CIS v3.0.0 control) |
|---|---|---|
| S3 Bucket | 2.1.1 (deny HTTP), 2.1.2 (MFA delete), 2.1.4 (Block Public Access) | Default encryption, versioning, server access logging |
| Security Group | 5.2 (ingress from 0.0.0.0/0 to admin ports) | Unrestricted egress |
| IAM Policy | 1.16 (full `*:*` admin privileges) | Explicit deny removed |
| RDS Instance | 2.3.1 (encryption at rest), 2.3.3 (public access) | Backup retention |
| EBS Volume | 2.2.1 (EBS encryption) | |
| CloudTrail | 3.1 (enabled in all regions), 3.2 (log file validation), 3.5 (KMS encryption) | CloudWatch Logs integration (removed from CIS after v1.4.0) |
| VPC | 3.7 (flow logs), 5.1 (network ACL ingress), 5.4 (default security group) | |
| KMS Key | 3.6 (key rotation) | Key disabled, key policy allows any principal |

Control numbers follow CIS AWS Foundations Benchmark v3.0.0, cross-checked against the [AWS Security Hub mapping of CIS requirements](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html). Properties with no CIS control are still reported with a severity, and with an empty CIS list.

---

## Two ways to run DriftFinder

DriftFinder can be run in a Docker container or installed natively. Both give the same `driftfinder` command and the same experiment command. Only the installation differs.

| | Docker | Native install |
|---|---|---|
| Best for | Reproducing the paper's experiment | Everyday use, scheduled scans |
| What you install | Docker only | Python, plus Terraform and Pulumi for the experiment |
| Versions | Fixed inside the image | You install the pinned versions below |

Docker is the recommended way to reproduce the experiment because every tool version is fixed inside the image. The native install is fully supported, and the experiment checks your installed versions before it starts.

### Pinned versions

The experiment was run with these exact versions. The Docker image contains them. For a native install, matching them gives the closest reproduction, but only the versions that can change results are required:

- **Required:** Python 3.11 or later, Terraform and Pulumi installed, and the exact Terraform AWS provider and Pulumi AWS provider versions. The two providers write the declared state that DriftFinder reads, so a different version can change results even when AWS has not changed. The Terraform provider version is enforced by the lock file. The Pulumi provider version comes from the `pulumi-aws` package in `requirements.lock`.
- **Recommended:** everything else in the table. Other versions are reported as a warning, recorded in `run.json` and the run continues.

| Component | Version |
|---|---|
| Python | 3.13 |
| Terraform | 1.13.3 |
| Terraform AWS provider | 5.63.1 (locked in `experiment/terraform/.terraform.lock.hcl`) |
| Pulumi CLI | 3.250.0 |
| Pulumi AWS provider | 7.35.0 (installed automatically by the `pulumi-aws` package) |
| Python packages | Exact versions with hashes in `requirements.lock` |

Using DriftFinder only as a scanning tool (no experiment) needs Python 3.11 or later and no Terraform or Pulumi.

---

## Option 1: Docker

### Build the image

```bash
git clone https://github.com/Victorthedev/driftfinder
cd driftfinder
docker build -t driftfinder .
```

### Start DriftFinder

Run this from the folder you want to work in (for example your IaC project). It opens a shell inside the container where `driftfinder` and `driftfinder-experiment` are ready to use.

**macOS:**
```bash
docker run -it --rm \
  -v "$PWD":/work \
  -v "$HOME/.aws":/home/driftfinder/.aws:ro \
  driftfinder
```

**Linux** (the `--user` flag keeps files you create owned by you):
```bash
docker run -it --rm --user "$(id -u):$(id -g)" \
  -v "$PWD":/work \
  -v "$HOME/.aws":/home/driftfinder/.aws:ro \
  driftfinder
```

**Windows (PowerShell):**
```powershell
docker run -it --rm `
  -v "${PWD}:/work" `
  -v "$env:USERPROFILE\.aws:/home/driftfinder/.aws:ro" `
  driftfinder
```

To pass credentials as environment variables instead of mounting `.aws`, replace the `.aws` line with `-e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN` (and `-e AWS_PROFILE` if you use profiles).

Inside the container, use DriftFinder exactly as described in [Using DriftFinder](#using-driftfinder) and [Reproducing the experiment](#reproducing-the-experiment).

Things to know:
- Your current folder appears as `/work` inside the container. Files written there (configs, reports, experiment results) stay on your machine after you exit. Anything written elsewhere in the container is discarded.
- `driftfinder schedule` does not work inside a container because the container stops when you exit. For scheduled scans, use the native install, or have your host's cron (or Windows Task Scheduler) run `docker run --rm ... driftfinder driftfinder scan`.

---

## Option 2: Native install

### 1. Install the prerequisites

For scanning only, install Python 3.11 or later. For the experiment, install the pinned versions:

| | macOS | Linux | Windows |
|---|---|---|---|
| Python 3.13 | [python.org](https://www.python.org/downloads/) installer or `brew install python@3.13` | Your package manager or [python.org](https://www.python.org/downloads/) | [python.org](https://www.python.org/downloads/) installer |
| Terraform 1.13.3 | Download from [releases.hashicorp.com/terraform/1.13.3](https://releases.hashicorp.com/terraform/1.13.3/) and put `terraform` on your PATH | Same | Same (`terraform.exe`) |
| Pulumi 3.250.0 | `curl -fsSL https://get.pulumi.com \| sh -s -- --version 3.250.0` | Same | Download the 3.250.0 Windows zip from [github.com/pulumi/pulumi/releases](https://github.com/pulumi/pulumi/releases/tag/v3.250.0) and put it on your PATH |

Check them:

```bash
python3.13 --version     # Windows: py -3.13 --version
terraform version
pulumi version
```

Use `python3.13` (Windows: `py -3.13`) rather than plain `python3` or `python`. On macOS, `python3` is usually Apple's built-in Python 3.9 even when 3.13 is installed, and on Windows `python` may point to a different version.

### 2. Install DriftFinder

**macOS and Linux:**
```bash
git clone https://github.com/Victorthedev/driftfinder
cd driftfinder
python3.13 -m venv .venv
source .venv/bin/activate
pip install --require-hashes --no-deps -r requirements.lock
pip install --no-deps -e .
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/Victorthedev/driftfinder
cd driftfinder
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install --require-hashes --no-deps -r requirements.lock
pip install --no-deps -e .
```

After activating the virtual environment, `python` refers to the right version, so the remaining commands in this README use plain `python`.

`requirements.lock` installs the exact package versions used in the experiment, including Pulumi's Python SDK and the test tools. For scanning only, `pip install -e .` is enough and accepts newer compatible versions.

Verify:

```bash
driftfinder --version
```

---

## Using DriftFinder

These commands are the same in Docker and in a native install.

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

**Pulumi** (export the stack first with `pulumi stack export --file pulumi_stack_export.json`):
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

[HIGH]     NRMVPC — vpc-0abc123def456789
  Property:  flow_logs_enabled
  Declared:  True
  Actual:    False
  CIS:       3.7 — Ensure VPC flow logging is enabled in all VPCs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Report written to: drift-report.json
Exit code: 1 (CRITICAL findings detected)
```

---

## Reproducing the experiment

The experiment provisions three identical AWS environments (one per IaC tool), injects 24 security drift scenarios across the 8 supported resource types, scans after each one and records whether DriftFinder detected it. The experiment runner carries out the whole protocol automatically.

**[`steps.txt`](steps.txt) is the step-by-step guide:** the commands to run, what the runner does at every step and the full table of 24 scenarios with their expected severity and CIS control. This section is the command reference.

**Warning:** the experiment creates real, billable AWS resources in `eu-west-1`. Use a dedicated test account, not a production one.

### Commands

| Docker | Native | What it does |
|---|---|---|
| `driftfinder-experiment preflight` | `python experiment/run.py preflight` | Checks tool versions, AWS access, account settings and leftover resources. Creates nothing. |
| `driftfinder-experiment run` | `python experiment/run.py run` | Runs the full experiment, uploads results and tears everything down |
| `driftfinder-experiment resume <run folder>` | `python experiment/run.py resume <run folder>` | Continues an interrupted run |
| `driftfinder-experiment teardown <run folder>` | `python experiment/run.py teardown <run folder>` | Deletes everything a run created |

Useful options for `run`:

| Option | Effect |
|---|---|
| `--envs terraform cloudformation pulumi` | Run a subset of environments |
| `--scenarios D1 D4` | Run a subset of scenarios. A short check of D1 and D4 on Terraform takes about 15 minutes. |
| `--keep` | Leave the resources running at the end instead of tearing down |
| `--no-upload` | Keep results on your machine only |
| `--results-bucket NAME` | Upload results to this S3 bucket (default `driftfinder-results-<account id>`, created if missing) |
| `--yes` | Skip the confirmation prompt (for unattended runs) |

### What the runner does

1. **Preflight:** stops if a version that can change results differs (see [Pinned versions](#pinned-versions)), if experiment resources from an earlier run still exist or if the region lacks room for three VPCs. Other version differences are reported and recorded. It also records account settings that can affect results, such as AWS Organizations membership, EBS default encryption and account-wide S3 Block Public Access.
2. **Provision** the Terraform, CloudFormation and Pulumi environments. Pulumi uses a local state backend, so no Pulumi account is needed.
3. **Baseline scans**, which must show zero findings before any drift is injected.
4. **For each scenario and environment:** inject the drift and log the ground truth, wait 30 seconds, scan, record whether the drift was detected, reset, then require a clean scan before moving on. If the environment is not clean after a reset, the run stops so that no scenario is affected by an earlier one.
5. **Control scans** C1 to C6 on the clean environments.
6. **Summary** of precision, recall and F1 per environment and overall.
7. **Teardown** of all three environments, followed by a check that nothing was left behind.

### How results are scored

Scoring is automatic. No result is typed by hand.

- **Detected (TP):** the scan contains a finding that matches the ground truth on resource, property and direction of change. The matched finding is stored in `ground_truth.json`.
- **Missed (FN):** no such finding.
- **False positive (FP):** any finding in a scenario scan that is neither the injected property nor one of that scenario's derived properties below, and any finding in a control scan. Each distinct resource and property counts once per scan.
- **Derived properties** are properties the injected change itself also alters, so they are not counted as false positives:

| Scenario | Derived properties | Why |
|---|---|---|
| D1 | `encryption_algorithm` | Removing the encryption configuration also removes its algorithm |
| D2 | `block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets` | The injection sets all four flags to false |
| D7 | `has_wildcard_resource`, `has_admin_access`, `has_explicit_deny`, `policy_document_hash` | The policy is replaced with `Action: *`, `Resource: *` and no deny statement |
| D8 | `has_wildcard_action`, `has_wildcard_resource`, `has_explicit_deny`, `policy_document_hash` | Same replacement document as D7 |
| D9 | `policy_document_hash` | Removing the deny statement changes the document |

- **Injected or not:** every ground truth entry records whether drift actually reached the account. It is `false` for D1 when AWS keeps the bucket encrypted (checked after the call), D14 when the new snapshot is encrypted (checked after the call; AWS encrypts every snapshot of an encrypted volume), D11 when AWS rejects the change, D10 and D13 (immutable properties) and D15 (observation only).
- **Two recall figures** are reported: over all scenarios, and over scenarios where drift was actually injected. The second measures detection of drift that really existed.
- **Severity and CIS** are recorded twice: the expected values from the scenario design and the values DriftFinder reported. The summary counts how many detections had the expected severity and CIS control. Nine scenarios (D1, D3, D6, D9, D12, D15, D18, D23, D24) test security drift that has no CIS v3.0.0 control. For those, the expected CIS control is none, and a detection matches when DriftFinder reports no CIS control.

Results are uploaded to S3 after every step, so nothing is lost if the run stops. The results bucket is not deleted by teardown.

### Time and cost

A full run takes several hours, mostly waiting for RDS instances to be created, modified and deleted. It typically costs a few US dollars. After teardown, the three KMS keys stay in "Pending deletion" for 7 days, the minimum AWS allows. This is expected.

### Permissions

The runner creates and deletes resources in CloudFormation, EC2 and VPC, RDS, S3, IAM (roles and policies), KMS, CloudTrail and CloudWatch Logs, and reads from STS, Service Quotas, Organizations and AWS Config. The simplest setup is an IAM user with `AdministratorAccess` in a dedicated test account.

### Output

Each run writes a folder under `experiment-runs/<run id>/` in your current directory:

| Path | Contents |
|---|---|
| `run.json` | Tool versions, account settings, options and timings |
| `run.log` | Full log of the run |
| `ground_truth.json` | Every injection and its detection result |
| `results_summary.json` | Precision, both recall figures and F1 per environment and overall, plus every scenario result with expected and reported severity and CIS |
| `outcomes.json` | TP, TP* (detected but without the expected CIS control), FN or FN (no drift) per scenario and environment |
| `scans/` | Every baseline, scenario and control scan |
| `clean/` | The clean scan after every reset |
| `resources_<env>.json` | IDs of the resources created in each environment |
| `teardown.json` | Teardown result and any leftover resources |

### Published results

The results reported in the paper are in `results/` (the 78 scan reports) and `experiment/ground_truth.json`.

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| Terraform | 1.000 | 0.750 | 0.857 |
| CloudFormation | 1.000 | 0.708 | 0.829 |
| Pulumi | 1.000 | 0.750 | 0.857 |
| **Overall** | **1.000** | **0.736** | **0.848** |

Zero false positives across all 78 scans and 6 control cases.

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
│   └── integration/          # Full scan tests with mocked AWS
│
├── experiment/               # Controlled experiment
│   ├── terraform/            # Terraform environment
│   ├── cloudformation/       # CloudFormation environment
│   ├── pulumi/               # Pulumi environment
│   ├── run.py                # Experiment runner (preflight, run, resume, teardown)
│   ├── inject.py             # Drift injection and reset for scenarios D1 to D24
│   ├── ground_truth_logger.py  # Ground truth logger
│   └── ground_truth.json     # Ground truth record of the published run
│
├── results/                  # Scan results from all 78 published experimental runs
├── steps.txt                 # Experiment protocol, step by step
├── Dockerfile                # Image with every pinned tool version
├── requirements.lock         # Exact Python package versions with hashes
├── .driftfinder.yml.example  # Example config file
└── pyproject.toml
```

---

## Running the tests

These work in Docker and in a native install:

```bash
pytest tests/unit tests/integration
```

---

## Required AWS permissions for scanning

DriftFinder is read-only when scanning. It never modifies infrastructure. The IAM principal running it needs:

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

Running the experiment needs broader permissions. See [Permissions](#permissions).

---

## What comes next

Phase 2 (post-dissertation) plans include: async concurrent scanning, all 58 CIS controls, a TypeScript SDK, AI-assisted fix suggestions, an MCP server and a remediation command.

---

## Licence

Source code: [Apache 2.0](LICENSE)

Documentation: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
