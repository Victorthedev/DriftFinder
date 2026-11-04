# Changelog

All notable changes to DriftFinder are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-04

Documentation and version number only. No other code changes and no data changes. The published results were produced with 1.0.0.

### Changed
- README corrected to match the paper: removed an out-of-date scan timing note, updated the planned next steps and added how to cite the release.
- Release title changed to match the paper, and the citation metadata now includes the Zenodo DOI.

## [1.0.0] - 2026-11-02

First release, accompanying the paper and its experiment package.

### Added
- Property-level drift detection for AWS resources declared in Terraform, CloudFormation (including CDK) and Pulumi, through a Normalised Resource Model covering eight resource types: S3 bucket, security group, IAM policy, RDS instance, EBS volume, CloudTrail trail, VPC and KMS key.
- Findings mapped to CIS AWS Foundations Benchmark v3.0.0 controls where one exists, with a severity on every finding.
- `driftfinder init`, `scan`, `schedule` and `report` commands, JSON and HTML reports, and exit codes that can fail a CI/CD pipeline by severity.
- Experiment runner (`experiment/run.py`) with `preflight`, `run`, `resume`, `teardown`, `benchmark` and `rescore-native` commands, automatic scoring against the ground truth and verified clean environments after every reset.
- Comparison with each IaC tool's own drift check (`terraform plan -refresh-only`, CloudFormation drift detection and `pulumi refresh --preview-only`) on the same scenarios.
- Docker image with every tool version pinned, a hashed `requirements.lock` for native installs and CI on Linux, macOS and Windows.
- Complete output of the reported experiment run and scan benchmark in `results/`.

### Fixed
- A scan in which a declared resource cannot be queried is reported as incomplete and exits with code 2, instead of being reported as compliant.

### Security
- Dependencies updated to versions without known vulnerabilities.
- The experiment runner masks values Terraform marks as sensitive before saving Terraform's raw output.
