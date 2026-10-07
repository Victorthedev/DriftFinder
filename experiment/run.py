import argparse
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError, WaiterError

EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_DIR = EXPERIMENT_DIR.parent
sys.path.insert(0, str(EXPERIMENT_DIR))

import inject  # noqa: E402
from ground_truth_logger import GroundTruthLogger  # noqa: E402

REGION = inject.REGION
ENVS = ["terraform", "cloudformation", "pulumi"]
SUFFIX = {"terraform": "tf", "cloudformation": "cf", "pulumi": "pulumi"}
NAME_SUFFIX = {"terraform": "", "cloudformation": "-cf", "pulumi": "-pulumi"}
KMS_ALIAS_SUFFIX = {"terraform": "terraform", "cloudformation": "cf", "pulumi": "pulumi"}
RDS_SUBNET_GROUPS = {
    "terraform": "driftfinder-rds-subnet-group-tf",
    "cloudformation": "driftfinder-rds-subnet-cf",
    "pulumi": "driftfinder-rds-subnet-pulumi",
}
CONTROLS = [
    ("C1", "terraform"), ("C2", "cloudformation"), ("C3", "pulumi"),
    ("C4", "terraform"), ("C5", "cloudformation"), ("C6", "pulumi"),
]
CF_STACK = "driftfinder-experiment-cf"
PULUMI_STACK = "driftfinder-experiment"
PINNED_PYTHON = "3.13"
MINIMUM_PYTHON = (3, 11)
PINNED_TOOLS = {"terraform": "1.13.3", "pulumi": "3.250.0"}
RESULT_AFFECTING_PACKAGES = {"pulumi-aws"}
LOCK_IGNORE = {"pip", "setuptools", "wheel"}
CLEAN_ATTEMPTS = 5
CLEAN_DELAY_SECONDS = 30
CF_OUTPUT_KEYS = {
    "S3BucketName": "s3_bucket_name",
    "SecurityGroupId": "security_group_id",
    "IAMPolicyArn": "iam_policy_arn",
    "RDSInstanceId": "rds_instance_id",
    "EBSVolumeId": "ebs_volume_id",
    "CloudTrailName": "cloudtrail_name",
    "VPCId": "vpc_id",
    "KMSKeyId": "kms_key_id",
    "KMSKeyArn": "kms_key_arn",
    "CTLogBucketName": "ct_log_bucket_name",
    "CloudTrailCWLogGroupArn": "cloudtrail_cw_log_group_arn",
    "CloudTrailCWRoleArn": "cloudtrail_cw_role_arn",
    "FlowLogRoleArn": "flow_log_role_arn",
    "VPCFlowLogGroupName": "vpc_flow_log_group_name",
}
UPLOAD_SKIP = {"secrets.json", ".terraform", "pulumi-backend"}
DERIVED_PROPERTIES = {
    "D1": {"encryption_algorithm"},
    "D2": {"block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"},
    "D7": {"has_wildcard_resource", "has_admin_access", "has_explicit_deny", "policy_document_hash"},
    "D8": {"has_wildcard_action", "has_wildcard_resource", "has_explicit_deny", "policy_document_hash"},
    "D9": {"policy_document_hash"},
}


class RunAborted(Exception):
    pass


class Tee:
    def __init__(self, path: Path):
        self.file = open(path, "a", encoding="utf-8")
        self.stream = sys.stdout

    def write(self, text):
        self.stream.write(text)
        self.file.write(text)

    def flush(self):
        self.stream.flush()
        self.file.flush()


def log(message: str):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {message}", flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path, default=None):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def stream(args, cwd=None, env=None, input_text=None, check=True) -> int:
    log("$ " + " ".join(str(a) for a in args))
    proc = subprocess.Popen(
        [str(a) for a in args],
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if input_text is not None:
        proc.stdin.write(input_text)
        proc.stdin.close()
    for line in proc.stdout:
        sys.stdout.write(line)
    rc = proc.wait()
    if check and rc != 0:
        raise RunAborted(f"Command failed with exit code {rc}: {' '.join(str(a) for a in args)}")
    return rc


def capture(args, cwd=None, env=None) -> str:
    result = subprocess.run(
        [str(a) for a in args], cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8"
    )
    if result.returncode != 0:
        sys.stdout.write(result.stderr)
        raise RunAborted(f"Command failed with exit code {result.returncode}: {' '.join(str(a) for a in args)}")
    return result.stdout


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def check_versions():
    from packaging.markers import Marker
    from packaging.utils import canonicalize_name

    versions = {"python": platform.python_version()}
    blocking = []
    warnings = []
    if sys.version_info[:2] < MINIMUM_PYTHON:
        blocking.append(f"Python {versions['python']} (DriftFinder needs {'.'.join(map(str, MINIMUM_PYTHON))} or later)")
    elif not versions["python"].startswith(PINNED_PYTHON + "."):
        warnings.append(f"Python {versions['python']} (experiment used {PINNED_PYTHON}.x)")

    for tool, expected in PINNED_TOOLS.items():
        if not shutil.which(tool):
            versions[tool] = None
            blocking.append(f"{tool} not found on PATH (experiment used {expected})")
            continue
        if tool == "terraform":
            found = json.loads(capture(["terraform", "version", "-json"]))["terraform_version"]
        else:
            found = capture(["pulumi", "version"]).strip().lstrip("v")
        versions[tool] = found
        if found != expected:
            warnings.append(f"{tool} {found} (experiment used {expected})")

    pattern = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*(?:;\s*(.*?))?\s*\\?$")
    packages = {}
    for line in (REPO_DIR / "requirements.lock").read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        name, expected, marker = match.groups()
        name = canonicalize_name(name)
        if name in LOCK_IGNORE or (marker and not Marker(marker).evaluate()):
            continue
        try:
            found = metadata.version(name)
        except metadata.PackageNotFoundError:
            found = None
        packages[name] = found
        if found != expected:
            message = f"Python package {name} {found or 'not installed'} (experiment used {expected})"
            (blocking if name in RESULT_AFFECTING_PACKAGES else warnings).append(message)
    versions["packages"] = packages

    try:
        versions["driftfinder"] = metadata.version("driftfinder")
    except metadata.PackageNotFoundError:
        versions["driftfinder"] = None
        blocking.append("driftfinder is not installed (run: pip install --no-deps -e .)")
    return versions, blocking, warnings


def resource_names(account: str) -> dict:
    return {
        "rds": [f"driftfinder-rds-test{NAME_SUFFIX[e]}" for e in ENVS],
        "rds_subnet_groups": list(RDS_SUBNET_GROUPS.values()),
        "buckets": [f"driftfinder-{kind}-{account}-{SUFFIX[e]}" for e in ENVS for kind in ("s3-test", "ct-logs")],
        "iam_policies": [f"driftfinder-iam-test{NAME_SUFFIX[e]}" for e in ENVS],
        "iam_roles": [f"driftfinder-{kind}-{SUFFIX[e]}" for e in ENVS for kind in ("cloudtrail-cw", "flow-logs")],
        "trails": [f"driftfinder-trail-test{NAME_SUFFIX[e]}" for e in ENVS],
        "kms_aliases": [f"alias/driftfinder-test-{KMS_ALIAS_SUFFIX[e]}" for e in ENVS],
    }


def find_leftovers(session, account: str) -> list:
    names = resource_names(account)
    found = []

    cf = session.client("cloudformation")
    try:
        stack = cf.describe_stacks(StackName=CF_STACK)["Stacks"][0]
        found.append(f"CloudFormation stack {CF_STACK} ({stack['StackStatus']})")
    except ClientError as exc:
        if "does not exist" not in str(exc):
            raise

    rds = session.client("rds")
    for rds_id in names["rds"]:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=rds_id)
            found.append(f"RDS instance {rds_id}")
        except ClientError as exc:
            if error_code(exc) != "DBInstanceNotFound":
                raise
    for group in names["rds_subnet_groups"]:
        try:
            rds.describe_db_subnet_groups(DBSubnetGroupName=group)
            found.append(f"RDS subnet group {group}")
        except ClientError as exc:
            if error_code(exc) != "DBSubnetGroupNotFoundFault":
                raise

    s3 = session.client("s3")
    for bucket in names["buckets"]:
        try:
            s3.head_bucket(Bucket=bucket)
            found.append(f"S3 bucket {bucket}")
        except ClientError as exc:
            code = error_code(exc)
            if code in ("403", "Forbidden"):
                found.append(f"S3 bucket {bucket} (name taken by another account)")
            elif code not in ("404", "NoSuchBucket", "NotFound"):
                raise

    iam = session.client("iam")
    for policy in names["iam_policies"]:
        try:
            iam.get_policy(PolicyArn=f"arn:aws:iam::{account}:policy/{policy}")
            found.append(f"IAM policy {policy}")
        except ClientError as exc:
            if error_code(exc) != "NoSuchEntity":
                raise
    for role in names["iam_roles"]:
        try:
            iam.get_role(RoleName=role)
            found.append(f"IAM role {role}")
        except ClientError as exc:
            if error_code(exc) != "NoSuchEntity":
                raise

    trails = session.client("cloudtrail").describe_trails(trailNameList=names["trails"])["trailList"]
    found.extend(f"CloudTrail trail {t['Name']}" for t in trails)

    aliases = []
    for page in session.client("kms").get_paginator("list_aliases").paginate():
        aliases.extend(a["AliasName"] for a in page["Aliases"])
    found.extend(f"KMS alias {a}" for a in names["kms_aliases"] if a in aliases)

    logs = session.client("logs")
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix="/driftfinder/"):
        found.extend(f"Log group {g['logGroupName']}" for g in page["logGroups"])

    vpcs = session.client("ec2").describe_vpcs(
        Filters=[{"Name": "tag:Environment", "Values": ["driftfinder-experiment"]}]
    )["Vpcs"]
    found.extend(f"VPC {v['VpcId']}" for v in vpcs)
    return found


def account_settings(session, account: str) -> dict:
    settings = {}

    def attempt(key, fn):
        try:
            settings[key] = fn()
        except ClientError as exc:
            settings[key] = f"unknown ({error_code(exc)})"

    ec2 = session.client("ec2")
    attempt("ebs_encryption_by_default", lambda: ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"])

    def s3_account_block():
        try:
            return session.client("s3control").get_public_access_block(AccountId=account)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as exc:
            if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise

    attempt("s3_account_public_access_block", s3_account_block)

    def organization():
        try:
            org = session.client("organizations").describe_organization()["Organization"]
            return {"member": True, "id": org["Id"]}
        except ClientError as exc:
            if error_code(exc) == "AWSOrganizationsNotInUseException":
                return {"member": False}
            raise

    attempt("organization", organization)
    attempt(
        "config_recorders",
        lambda: len(session.client("config").describe_configuration_recorders()["ConfigurationRecorders"]),
    )

    def vpc_capacity():
        used = len(ec2.describe_vpcs()["Vpcs"])
        quotas = session.client("service-quotas")
        try:
            limit = quotas.get_service_quota(ServiceCode="vpc", QuotaCode="L-F678F1CE")["Quota"]["Value"]
        except ClientError:
            limit = 5
        return {"used": used, "limit": int(limit)}

    attempt("vpcs", vpc_capacity)
    return settings


def preflight(session, allow_version_mismatch: bool, check_leftovers: bool = True):
    log("Preflight: checking tool versions")
    versions, version_blocking, version_warnings = check_versions()
    for name in ("python", "terraform", "pulumi", "driftfinder"):
        log(f"  {name}: {versions.get(name)}")
    log(f"  Python packages checked against requirements.lock: {len(versions['packages'])}")

    blocking = []
    if version_warnings:
        log("Versions that differ from the experiment (recorded in run.json, the run continues):")
        for warning in version_warnings:
            log(f"  - {warning}")
    if version_blocking:
        log("Versions that can change results:")
        for problem in version_blocking:
            log(f"  - {problem}")
        if not allow_version_mismatch:
            blocking.append("Fix the versions listed above, or pass --allow-version-mismatch to run anyway.")

    log("Preflight: checking AWS identity")
    identity = session.client("sts").get_caller_identity()
    account = identity["Account"]
    log(f"  Account {account} as {identity['Arn']}, region {REGION}")

    log("Preflight: checking account settings")
    settings = account_settings(session, account)
    for key, value in settings.items():
        log(f"  {key}: {value}")
    org = settings.get("organization")
    if isinstance(org, dict) and org.get("member"):
        log("  Note: account is in an AWS Organization. Service control policies may block or revert injections.")
    vpcs = settings.get("vpcs")
    if isinstance(vpcs, dict) and vpcs["limit"] - vpcs["used"] < len(ENVS):
        blocking.append(f"Not enough VPC capacity in {REGION}: {vpcs['used']} of {vpcs['limit']} used, 3 needed.")

    if check_leftovers:
        log("Preflight: checking for leftover experiment resources")
        leftovers = find_leftovers(session, account)
        if leftovers:
            for item in leftovers:
                log(f"  - {item}")
            blocking.append("Leftover experiment resources exist. Tear down the previous run first.")
        else:
            log("  None found")

    return {"account": account, "arn": identity["Arn"], "versions": versions,
            "version_differences": version_blocking + version_warnings,
            "account_settings": settings}, blocking


class Run:
    def __init__(self, run_dir: Path, session):
        self.dir = run_dir
        self.session = session
        self.meta = read_json(run_dir / "run.json", {})
        self.progress = read_json(run_dir / "progress.json", {"done": [], "current": None})
        self.secrets = read_json(run_dir / "secrets.json")
        self.uploaded = {}
        self.logger = GroundTruthLogger(str(run_dir / "ground_truth.json"))
        inject.STATE_FILE = run_dir / "experiment_state.json"

    @property
    def account(self):
        return self.meta["account"]

    @property
    def work(self):
        return self.dir / "work"

    def save_meta(self):
        write_json(self.dir / "run.json", self.meta)

    def save_progress(self):
        write_json(self.dir / "progress.json", self.progress)

    def resources(self, env: str) -> dict:
        data = read_json(self.dir / f"resources_{env}.json")
        if data is None:
            raise RunAborted(f"No resources recorded for {env}")
        return {**data, "_env": env}

    def config_path(self, env: str) -> Path:
        return self.dir / "configs" / f".driftfinder-{env}.yml"

    def tool_env(self) -> dict:
        env = os.environ.copy()
        env.update({
            "AWS_DEFAULT_REGION": REGION,
            "AWS_REGION": REGION,
            "PYTHONUTF8": "1",
            "TF_IN_AUTOMATION": "1",
            "TF_VAR_account_id": self.account,
            "TF_VAR_db_password": self.secrets["db_password"],
            "TF_VAR_region": REGION,
            "PULUMI_BACKEND_URL": (self.work / "pulumi-backend").as_uri(),
            "PULUMI_CONFIG_PASSPHRASE": self.secrets["pulumi_passphrase"],
            "PULUMI_PYTHON_CMD": sys.executable,
            "PULUMI_SKIP_UPDATE_CHECK": "true",
        })
        return env

    def step(self, unit: str, fn):
        if unit in self.progress["done"]:
            return
        self.progress["current"] = unit
        self.save_progress()
        fn()
        self.progress["done"].append(unit)
        self.progress["current"] = None
        self.save_progress()
        self.upload()

    def upload(self):
        bucket = self.meta.get("results_bucket")
        if not bucket:
            return
        s3 = self.session.client("s3")
        for path in sorted(self.dir.rglob("*")):
            rel = path.relative_to(self.dir)
            if path.is_dir() or UPLOAD_SKIP.intersection(rel.parts):
                continue
            mtime = path.stat().st_mtime
            if self.uploaded.get(rel) == mtime:
                continue
            s3.upload_file(str(path), bucket, f"{self.meta['run_id']}/{rel.as_posix()}")
            self.uploaded[rel] = mtime


def copy_iac(source: Path, target: Path):
    if not target.exists():
        shutil.copytree(
            source,
            target,
            ignore=shutil.ignore_patterns(".terraform", "*.tfstate", "*.tfstate.*", "__pycache__", "Pulumi.*.yaml"),
        )


def write_scan_config(run: Run, env: str, source: dict):
    config = {"iac_tool": env, "aws_region": REGION, "fail_on": "LOW", "output_format": "json", **source}
    path = run.config_path(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")


def provision_terraform(run: Run):
    work = run.work / "terraform"
    copy_iac(EXPERIMENT_DIR / "terraform", work)
    env = run.tool_env()
    stream(["terraform", "init", "-input=false", "-no-color"], cwd=work, env=env)
    stream(["terraform", "apply", "-auto-approve", "-input=false", "-no-color"], cwd=work, env=env)
    outputs = json.loads(capture(["terraform", "output", "-json", "-no-color"], cwd=work, env=env))
    write_json(run.dir / "resources_terraform.json", {k: v["value"] for k, v in outputs.items()})
    write_scan_config(run, "terraform", {"state_file": str(work / "terraform.tfstate")})


def cf_failure_reasons(cf) -> str:
    events = cf.describe_stack_events(StackName=CF_STACK)["StackEvents"]
    failed = [e for e in events if e["ResourceStatus"].endswith("FAILED")]
    return "; ".join(f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}" for e in failed[:5])


def provision_cloudformation(run: Run):
    cf = run.session.client("cloudformation")
    try:
        status = cf.describe_stacks(StackName=CF_STACK)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" not in str(exc):
            raise
        status = None
    if status is None:
        log(f"Creating CloudFormation stack {CF_STACK}")
        cf.create_stack(
            StackName=CF_STACK,
            TemplateBody=(EXPERIMENT_DIR / "cloudformation" / "baseline.yaml").read_text(encoding="utf-8"),
            Parameters=[
                {"ParameterKey": "AccountId", "ParameterValue": run.account},
                {"ParameterKey": "DBPassword", "ParameterValue": run.secrets["db_password"]},
            ],
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )
    elif status != "CREATE_COMPLETE" and status != "CREATE_IN_PROGRESS":
        raise RunAborted(f"CloudFormation stack {CF_STACK} is in state {status}")
    log("Waiting for CloudFormation stack to finish creating")
    try:
        cf.get_waiter("stack_create_complete").wait(
            StackName=CF_STACK, WaiterConfig={"Delay": 30, "MaxAttempts": 120}
        )
    except WaiterError as exc:
        raise RunAborted(f"CloudFormation stack failed: {cf_failure_reasons(cf)}") from exc
    outputs = cf.describe_stacks(StackName=CF_STACK)["Stacks"][0]["Outputs"]
    write_json(
        run.dir / "resources_cloudformation.json",
        {CF_OUTPUT_KEYS.get(o["OutputKey"], o["OutputKey"]): o["OutputValue"] for o in outputs},
    )
    write_scan_config(run, "cloudformation", {"stack_name": CF_STACK})


def provision_pulumi(run: Run):
    work = run.work / "pulumi"
    copy_iac(EXPERIMENT_DIR / "pulumi", work)
    (run.work / "pulumi-backend").mkdir(parents=True, exist_ok=True)
    env = run.tool_env()
    stream(["pulumi", "stack", "select", "--create", PULUMI_STACK, "--non-interactive"], cwd=work, env=env)
    stream(["pulumi", "config", "set", "account_id", run.account, "--non-interactive"], cwd=work, env=env)
    stream(["pulumi", "config", "set", "region", REGION, "--non-interactive"], cwd=work, env=env)
    stream(
        ["pulumi", "config", "set", "--secret", "db_password", "--non-interactive"],
        cwd=work, env=env, input_text=run.secrets["db_password"],
    )
    stream(["pulumi", "up", "--yes", "--skip-preview", "--non-interactive"], cwd=work, env=env)
    outputs = json.loads(capture(["pulumi", "stack", "output", "--json", "--non-interactive"], cwd=work, env=env))
    write_json(run.dir / "resources_pulumi.json", outputs)
    export_path = run.dir / "pulumi_stack_export.json"
    stream(["pulumi", "stack", "export", "--file", export_path, "--non-interactive"], cwd=work, env=env)
    write_scan_config(run, "pulumi", {"pulumi_stack": str(export_path)})


PROVISIONERS = {
    "terraform": provision_terraform,
    "cloudformation": provision_cloudformation,
    "pulumi": provision_pulumi,
}


def scan(run: Run, env: str, name: str, folder: str = "scans") -> list:
    base = run.dir / folder / name
    base.parent.mkdir(parents=True, exist_ok=True)
    rc = stream(
        [sys.executable, "-c", "from driftfinder.cli.main import cli; cli()",
         "scan", "--config", run.config_path(env), "--output", base, "--format", "json"],
        env=run.tool_env(),
        check=False,
    )
    report = Path(f"{base}.json")
    if rc not in (0, 1) or not report.exists():
        raise RunAborted(f"DriftFinder scan failed for {env} ({name}) with exit code {rc}")
    return json.loads(report.read_text(encoding="utf-8"))["findings"]


def describe(findings: list) -> str:
    return ", ".join(f"{f['resource_id']}.{f['property_path']}" for f in findings)


def wait_clean(run: Run, env: str, label: str, folder: str = "clean"):
    for attempt in range(1, CLEAN_ATTEMPTS + 1):
        name = label if attempt == 1 else f"{label}_retry{attempt - 1}"
        findings = scan(run, env, name, folder)
        if not findings:
            log(f"Clean: {env} has no findings ({name})")
            return
        log(f"Not clean yet ({attempt}/{CLEAN_ATTEMPTS}): {describe(findings)}")
        if attempt < CLEAN_ATTEMPTS:
            time.sleep(CLEAN_DELAY_SECONDS)
    raise RunAborted(f"{env} still has findings after {label}: {describe(findings)}")


def same_resource(finding_id: str, truth_id: str) -> bool:
    return (
        finding_id == truth_id
        or finding_id.endswith(f"/{truth_id}")
        or truth_id.endswith(f"/{finding_id}")
    )


def score(run: Run, scenario_id: str, env: str, findings: list):
    entry = next(
        (e for e in run.logger.data["entries"] if e["scenario_id"] == scenario_id and e["environment"] == env),
        None,
    )
    if entry is None:
        raise RunAborted(f"No ground truth was logged for {scenario_id} [{env}]")
    prop = entry["property_path"]
    after = entry.get("after") or {}

    def on_resource(f):
        return f["resource_type"] == entry["resource_type"] and same_resource(f["resource_id"], entry["resource_id"])

    match = next(
        (f for f in findings
         if on_resource(f) and f["property_path"] == prop and (prop not in after or f["actual_value"] == after[prop])),
        None,
    )
    allowed = {prop} | DERIVED_PROPERTIES.get(scenario_id, set())
    source = f"{scenario_id}:{env}"
    run.logger.remove_entries_from_source(source)
    if match:
        run.logger.record_result(
            scenario_id, env, detected=True,
            detected_severity=match["severity"], detected_cis=match["cis_controls"],
            matched_finding=match,
        )
    else:
        run.logger.record_result(scenario_id, env, detected=False)
    record_false_positives(
        run, env, [f for f in findings if not (on_resource(f) and f["property_path"] in allowed)], source
    )


def record_false_positives(run: Run, env: str, findings: list, source: str):
    seen = set()
    for f in findings:
        key = (f["resource_id"], f["property_path"])
        if key in seen:
            continue
        seen.add(key)
        run.logger.record_false_positive(
            f["resource_id"], env, f["property_path"], f["severity"], f["cis_controls"], source=source
        )


def run_scenario(run: Run, scenario_id: str, env: str):
    inject_fn, reset_fn = inject.SCENARIOS[scenario_id]
    resources = run.resources(env)
    log(f"=== {scenario_id} [{env}]: inject")
    inject_fn(resources, run.logger, env)
    log(f"Waiting {run.meta['settle_seconds']}s before scanning")
    time.sleep(run.meta["settle_seconds"])
    findings = scan(run, env, f"{scenario_id}_{env}")
    score(run, scenario_id, env, findings)
    log(f"=== {scenario_id} [{env}]: reset")
    reset_fn(resources, env)
    wait_clean(run, env, f"after_{scenario_id}_{env}")


def run_control(run: Run, control_id: str, env: str):
    log(f"=== {control_id} [{env}]: control scan")
    findings = scan(run, env, f"{control_id}_{env}")
    source = f"{control_id}:{env}"
    run.logger.remove_entries_from_source(source)
    run.logger.record_control(control_id, env, len(findings))
    record_false_positives(run, env, findings, source)


def recover(run: Run):
    unit = run.progress.get("current")
    if not unit:
        return
    scenario_id, _, env = unit.partition(":")
    if scenario_id in inject.SCENARIOS:
        log(f"Recovering interrupted step {unit}: resetting and verifying clean state")
        try:
            inject.SCENARIOS[scenario_id][1](run.resources(env), env)
        except Exception as exc:
            log(f"Reset during recovery raised {type(exc).__name__}: {exc}")
        wait_clean(run, env, f"recover_{scenario_id}_{env}")


def write_summary(run: Run):
    run.logger.print_summary()
    run.logger.export_for_dissertation(str(run.dir / "results_summary.json"))
    outcomes = {}
    for e in run.logger.data["entries"]:
        if not e["scenario_id"].startswith("D"):
            continue
        result = e["driftfinder_result"]
        label = result["classification"]
        if label == "TP" and not GroundTruthLogger.cis_matches(e):
            label = "TP*"
        if label == "FN" and not e.get("injected", True):
            label = "FN (no drift)"
        outcomes.setdefault(e["scenario_id"], {})[e["environment"]] = label
    ordered = {sid: outcomes[sid] for sid in inject.SCENARIOS if sid in outcomes}
    write_json(run.dir / "outcomes.json", ordered)
    envs = run.meta["envs"]
    fps = [e for e in run.logger.data["entries"] if e["scenario_id"] == "FP"]
    print(f"\nFalse positives: {len(fps)}")
    for e in fps:
        print(f"  {e.get('source')}: {e['resource_id']}.{e['property_path']}")
    print("\n" + "Scenario".ljust(10) + "".join(env[:14].ljust(16) for env in envs))
    for sid, row in ordered.items():
        print(sid.ljust(10) + "".join(row.get(env, "-").ljust(16) for env in envs))


def ensure_results_bucket(session, bucket: str):
    s3 = session.client("s3")
    try:
        s3.head_bucket(Bucket=bucket)
        return
    except ClientError as exc:
        code = error_code(exc)
        if code in ("403", "Forbidden"):
            raise RunAborted(f"Results bucket {bucket} exists but is not accessible from this account")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise
    log(f"Creating results bucket {bucket}")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )


def empty_bucket(s3, bucket: str):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            for i in range(0, len(objects), 1000):
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects[i:i + 1000], "Quiet": True})
    except ClientError as exc:
        if error_code(exc) != "NoSuchBucket":
            raise


def best_effort(description: str, fn):
    try:
        fn()
    except Exception as exc:
        log(f"  {description} skipped: {type(exc).__name__}: {exc}")


def teardown(run: Run) -> bool:
    log("Teardown: starting")
    session = run.session
    ec2 = session.client("ec2")
    kms = session.client("kms")
    failures = []
    known = {env: read_json(run.dir / f"resources_{env}.json") for env in ENVS}

    for env, res in known.items():
        if not res:
            continue
        best_effort(f"Re-enabling KMS key for {env}", lambda r=res: kms.enable_key(KeyId=r["kms_key_id"]))
        flow_logs = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [res["vpc_id"]]}])["FlowLogs"]
        if flow_logs:
            best_effort(
                f"Deleting flow logs for {env}",
                lambda f=flow_logs: ec2.delete_flow_logs(FlowLogIds=[x["FlowLogId"] for x in f]),
            )

    snapshots = ec2.describe_snapshots(
        OwnerIds=["self"], Filters=[{"Name": "tag-key", "Values": ["driftfinder-experiment"]}]
    )["Snapshots"]
    for snap in snapshots:
        best_effort(f"Deleting snapshot {snap['SnapshotId']}", lambda s=snap: ec2.delete_snapshot(SnapshotId=s["SnapshotId"]))

    env_vars = run.tool_env() if run.secrets else None

    tf_work = run.work / "terraform"
    if (tf_work / "terraform.tfstate").exists():
        log("Teardown: Terraform")
        rc = stream(["terraform", "destroy", "-auto-approve", "-input=false", "-no-color"],
                    cwd=tf_work, env=env_vars, check=False)
        if rc != 0:
            failures.append("terraform destroy failed")

    cf = session.client("cloudformation")
    try:
        cf.describe_stacks(StackName=CF_STACK)
        stack_exists = True
    except ClientError as exc:
        if "does not exist" not in str(exc):
            raise
        stack_exists = False
    if stack_exists:
        log("Teardown: CloudFormation")
        s3 = session.client("s3")
        cf_res = known.get("cloudformation") or {}
        cf_buckets = [f"driftfinder-{kind}-{run.account}-cf" for kind in ("s3-test", "ct-logs")]
        if cf_res.get("cloudtrail_name"):
            best_effort("Stopping CloudFormation trail logging",
                        lambda: session.client("cloudtrail").stop_logging(Name=cf_res["cloudtrail_name"]))
        deleted = False
        for attempt in range(3):
            for bucket in cf_buckets:
                best_effort(f"Emptying {bucket}", lambda b=bucket: empty_bucket(s3, b))
            cf.delete_stack(StackName=CF_STACK)
            try:
                cf.get_waiter("stack_delete_complete").wait(
                    StackName=CF_STACK, WaiterConfig={"Delay": 30, "MaxAttempts": 120}
                )
                deleted = True
                break
            except WaiterError:
                log(f"  CloudFormation delete attempt {attempt + 1} failed: {cf_failure_reasons(cf)}")
        if not deleted:
            failures.append("CloudFormation stack delete failed")

    pu_work = run.work / "pulumi"
    if pu_work.exists() and (run.work / "pulumi-backend").exists() and env_vars:
        log("Teardown: Pulumi")
        rc = stream(["pulumi", "destroy", "--stack", PULUMI_STACK, "--yes", "--skip-preview", "--non-interactive"],
                    cwd=pu_work, env=env_vars, check=False)
        if rc != 0:
            failures.append("pulumi destroy failed")

    logs = session.client("logs")
    for sweep in range(1, 4):
        log("Teardown: removing log groups recreated by in-flight log delivery")
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix="/driftfinder/"):
            for group in page["logGroups"]:
                best_effort(f"Deleting log group {group['logGroupName']}",
                            lambda g=group: logs.delete_log_group(logGroupName=g["logGroupName"]))
        log("Teardown: checking for leftover resources")
        leftovers = find_leftovers(session, run.account)
        if sweep == 3 or not leftovers or not all(item.startswith("Log group ") for item in leftovers):
            break
        log("  Only log groups remain, waiting 120s for late log delivery before sweeping again")
        time.sleep(120)
    for item in leftovers:
        log(f"  LEFTOVER: {item}")
    write_json(run.dir / "teardown.json",
               {"finished_at": now_iso(), "failures": failures, "leftovers": leftovers})
    ok = not failures and not leftovers
    log("Teardown: complete, nothing left behind" if ok else "Teardown: INCOMPLETE, see LEFTOVER and failures above")
    return ok


def execute(run: Run) -> bool:
    envs = run.meta["envs"]
    recover(run)
    for env in envs:
        run.step(f"provision:{env}", lambda e=env: PROVISIONERS[e](run))
    for env in envs:
        run.step(f"baseline:{env}", lambda e=env: wait_clean(run, e, f"baseline_{e}", folder="scans"))
    for scenario_id in run.meta["scenarios"]:
        for env in envs:
            run.step(f"{scenario_id}:{env}", lambda s=scenario_id, e=env: run_scenario(run, s, e))
    for control_id, env in CONTROLS:
        if env in envs:
            run.step(f"{control_id}:{env}", lambda c=control_id, e=env: run_control(run, c, e))
    run.step("summary", lambda: write_summary(run))
    return True


def drive(run: Run, keep: bool) -> int:
    completed = False
    try:
        completed = execute(run)
        run.meta["completed_at"] = now_iso()
        run.save_meta()
    except KeyboardInterrupt:
        log("Interrupted. Resources are left running so the run can be resumed.")
        log(f"Resume: python {Path(__file__).name} resume {run.dir}")
        log(f"Tear down: python {Path(__file__).name} teardown {run.dir}")
        run.upload()
        return 130
    except Exception as exc:
        log(f"RUN ABORTED: {type(exc).__name__}: {exc}")
        traceback.print_exc(file=sys.stdout)
        run.meta.setdefault("aborts", []).append({"at": now_iso(), "step": run.progress.get("current"), "error": str(exc)})
        run.save_meta()
    run.upload()
    if keep:
        log(f"--keep set: resources left running. Tear down with: python {Path(__file__).name} teardown {run.dir}")
        return 0 if completed else 1
    torn_down = teardown(run)
    run.upload()
    return 0 if completed and torn_down else 1


def attach_log(run_dir: Path):
    run_dir.mkdir(parents=True, exist_ok=True)
    sys.stdout = Tee(run_dir / "run.log")


def confirm(args, envs, scenarios) -> bool:
    if args.yes:
        return True
    print(
        f"\nThis creates billable AWS resources in {REGION} for: {', '.join(envs)}"
        f"\n(RDS db.t3.micro, KMS keys, CloudTrail trails, VPC flow logs per environment)."
        f"\nScenarios: {len(scenarios)} x {len(envs)} environments. A full run takes several hours."
        f"\nEverything is torn down at the end unless --keep is given.\n"
    )
    return input("Type 'yes' to continue: ").strip().lower() == "yes"


def cmd_preflight(args) -> int:
    session = boto3.Session(region_name=REGION)
    _, blocking = preflight(session, args.allow_version_mismatch)
    for reason in blocking:
        log(f"BLOCKED: {reason}")
    log("Preflight passed" if not blocking else "Preflight failed")
    return 0 if not blocking else 1


def cmd_run(args) -> int:
    envs = args.envs or ENVS
    scenarios = args.scenarios or list(inject.SCENARIOS)
    unknown = [s for s in scenarios if s not in inject.SCENARIOS]
    if unknown:
        print(f"Unknown scenarios: {', '.join(unknown)}")
        return 2
    scenarios = [s for s in inject.SCENARIOS if s in scenarios]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(args.output_dir or Path.cwd() / "experiment-runs" / run_id).resolve()
    if (run_dir / "run.json").exists():
        print(f"{run_dir} already contains a run. Use: resume {run_dir}")
        return 2

    session = boto3.Session(region_name=REGION)
    report, blocking = preflight(session, args.allow_version_mismatch)
    if blocking:
        for reason in blocking:
            log(f"BLOCKED: {reason}")
        return 1
    bucket = None if args.no_upload else (args.results_bucket or f"driftfinder-results-{report['account']}")
    if not confirm(args, envs, scenarios):
        print("Cancelled.")
        return 1

    attach_log(run_dir)
    if bucket:
        ensure_results_bucket(session, bucket)
    write_json(run_dir / "secrets.json", {
        "db_password": secrets.token_urlsafe(24),
        "pulumi_passphrase": secrets.token_urlsafe(32),
    })
    write_json(run_dir / "run.json", {
        "run_id": run_id,
        "started_at": now_iso(),
        "region": REGION,
        "envs": envs,
        "scenarios": scenarios,
        "settle_seconds": args.settle_seconds,
        "clean_attempts": CLEAN_ATTEMPTS,
        "clean_delay_seconds": CLEAN_DELAY_SECONDS,
        "results_bucket": bucket,
        "platform": platform.platform(),
        "in_docker": Path("/.dockerenv").exists(),
        "image": os.environ.get("DRIFTFINDER_IMAGE"),
        **report,
    })
    run = Run(run_dir, session)
    log(f"Run {run_id} started. Output: {run_dir}")
    if bucket:
        log(f"Results are uploaded to s3://{bucket}/{run_id}/")
    return drive(run, args.keep)


def cmd_resume(args) -> int:
    run_dir = Path(args.run_dir).resolve()
    if not (run_dir / "run.json").exists():
        print(f"No run found in {run_dir}")
        return 2
    attach_log(run_dir)
    session = boto3.Session(region_name=REGION)
    report, blocking = preflight(session, args.allow_version_mismatch, check_leftovers=False)
    run = Run(run_dir, session)
    if report["account"] != run.account:
        blocking.append(f"Credentials are for account {report['account']} but the run used {run.account}")
    if blocking:
        for reason in blocking:
            log(f"BLOCKED: {reason}")
        return 1
    run.meta.setdefault("resumed_at", []).append(now_iso())
    run.save_meta()
    log(f"Resuming run {run.meta['run_id']} ({len(run.progress['done'])} steps already done)")
    return drive(run, args.keep)


def cmd_teardown(args) -> int:
    run_dir = Path(args.run_dir).resolve()
    if not (run_dir / "run.json").exists():
        print(f"No run found in {run_dir}")
        return 2
    attach_log(run_dir)
    run = Run(run_dir, boto3.Session(region_name=REGION))
    ok = teardown(run)
    run.upload()
    return 0 if ok else 1


def main() -> int:
    os.environ["AWS_DEFAULT_REGION"] = REGION
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Runs the DriftFinder controlled experiment end to end (protocol in steps.txt).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("preflight", help="Check versions, AWS access and leftovers without creating anything")
    p.add_argument("--allow-version-mismatch", action="store_true")
    p.set_defaults(fn=cmd_preflight)

    p = sub.add_parser("run", help="Provision, run every scenario, upload results and tear down")
    p.add_argument("--output-dir", help="Run folder (default: ./experiment-runs/<run id>)")
    p.add_argument("--envs", nargs="+", choices=ENVS, help="Subset of environments")
    p.add_argument("--scenarios", nargs="+", help="Subset of scenarios, e.g. D1 D4")
    p.add_argument("--results-bucket", help="S3 bucket for results (default: driftfinder-results-<account>)")
    p.add_argument("--no-upload", action="store_true", help="Keep results locally only")
    p.add_argument("--settle-seconds", type=int, default=30, help="Wait between injecting and scanning")
    p.add_argument("--keep", action="store_true", help="Do not tear down at the end")
    p.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    p.add_argument("--allow-version-mismatch", action="store_true")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("resume", help="Continue an interrupted run")
    p.add_argument("run_dir")
    p.add_argument("--keep", action="store_true")
    p.add_argument("--allow-version-mismatch", action="store_true")
    p.set_defaults(fn=cmd_resume)

    p = sub.add_parser("teardown", help="Destroy everything a run created")
    p.add_argument("run_dir")
    p.set_defaults(fn=cmd_teardown)

    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
