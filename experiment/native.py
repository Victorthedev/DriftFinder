import hashlib
import json
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

EXPERIMENT_DIR = Path(__file__).resolve().parent
MAPPING_PATH = EXPERIMENT_DIR / "native_mapping.json"
TOOL_FOR_ENV = {"terraform": "terraform", "cloudformation": "cloudformation", "pulumi": "pulumi"}
CF_DRIFT_TIMEOUT_SECONDS = 600
CF_POLL_SECONDS = 5
CF_STATUSES = ["IN_SYNC", "MODIFIED", "DELETED", "NOT_CHECKED"]
CHECK_ATTEMPTS = 3
CHECK_RETRY_SECONDS = 30


def mapping_info() -> dict:
    data = MAPPING_PATH.read_bytes()
    return {"path": "experiment/native_mapping.json", "sha256": hashlib.sha256(data).hexdigest()}


def load_mapping() -> dict:
    return json.loads(MAPPING_PATH.read_text(encoding="utf-8"))


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _top_level_changes(before: dict, after: dict) -> list:
    keys = set(before) | set(after)
    return sorted(k for k in keys if before.get(k) != after.get(k))


def _fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:16]


def parse_terraform(show_text: str) -> dict:
    changes = []
    for entry in json.loads(show_text).get("resource_drift", []) or []:
        change = entry.get("change", {})
        before, after = change.get("before") or {}, change.get("after")
        if after is None:
            changes.append([entry["address"], "deleted", "deleted"])
            continue
        for attribute in _top_level_changes(before, after):
            changes.append([entry["address"], attribute, _fingerprint(after.get(attribute))])
    return {"changes": changes}


def parse_cloudformation(raw: dict) -> dict:
    status = raw["detection_status"]
    if status["DetectionStatus"] == "DETECTION_FAILED":
        return {"error": f"DETECTION_FAILED: {status.get('DetectionStatusReason', '')}", "changes": []}
    changes, not_checked = [], []
    for d in raw["resource_drifts"]:
        logical = d["LogicalResourceId"]
        state = d["StackResourceDriftStatus"]
        if state == "DELETED":
            changes.append([logical, "deleted", "deleted"])
        elif state == "MODIFIED":
            grouped = {}
            for diff in d.get("PropertyDifferences", []):
                top = diff["PropertyPath"].lstrip("/").split("/")[0]
                grouped.setdefault(top, []).append([diff["PropertyPath"], diff.get("ActualValue")])
            changes.extend([logical, top, _fingerprint(sorted(v))] for top, v in sorted(grouped.items()))
        elif state == "NOT_CHECKED":
            not_checked.append(logical)
    return {"changes": changes, "not_checked": sorted(not_checked)}


def parse_pulumi(stdout: str) -> dict:
    changes = []
    for step in json.loads(stdout).get("steps", []) or []:
        urn = step.get("urn", "")
        if not urn or "::pulumi:pulumi:Stack::" in urn or "::pulumi:providers:" in urn:
            continue
        old, new = step.get("oldState"), step.get("newState")
        op = step.get("op", "")
        name = _pulumi_resource_name(urn)
        if new is None and old is not None or op in ("delete", "deleted", "discard", "read-discard"):
            changes.append([name, "deleted", "deleted"])
            continue
        keys = set((step.get("detailedDiff") or {}).keys()) | set(step.get("diffReasons") or [])
        if not keys and old and new:
            keys = set(_top_level_changes(old.get("outputs") or {}, new.get("outputs") or {}))
        outputs = (new or {}).get("outputs") or {}
        for top in sorted({k.split(".")[0].split("[")[0] for k in keys}):
            changes.append([name, top, _fingerprint(outputs.get(top))])
    return {"changes": changes}


def _terraform(run, label: str, raw_dir: Path) -> dict:
    work = run.work / "terraform"
    env = run.tool_env()
    plan = work / f"native-{label}.tfplan"
    commands = [
        ["terraform", "plan", "-refresh-only", "-input=false", "-no-color", "-lock=false",
         "-detailed-exitcode", f"-out={plan.name}"],
        ["terraform", "show", "-json", plan.name],
    ]
    plan_run = subprocess.run(commands[0], cwd=work, env=env, capture_output=True, text=True, encoding="utf-8")
    _write(raw_dir / f"{label}_terraform.txt", plan_run.stdout + plan_run.stderr)
    if plan_run.returncode not in (0, 2):
        plan.unlink(missing_ok=True)
        return {"command": " ".join(commands[0]), "error": f"terraform plan exit code {plan_run.returncode}"}
    show = subprocess.run(commands[1], cwd=work, env=env, capture_output=True, text=True, encoding="utf-8")
    plan.unlink(missing_ok=True)
    if show.returncode != 0:
        return {"command": " ".join(commands[0]), "error": f"terraform show exit code {show.returncode}: {show.stderr}"}
    _write(raw_dir / f"{label}_terraform.json", show.stdout)
    return {"command": " ".join(commands[0]), **parse_terraform(show.stdout), "exit_code": plan_run.returncode}


def _cloudformation(run, label: str, raw_dir: Path, stack: str) -> dict:
    cf = run.session.client("cloudformation")
    command = f"detect_stack_drift(StackName={stack}) and describe_stack_resource_drifts"
    detection_id = cf.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    deadline = time.monotonic() + CF_DRIFT_TIMEOUT_SECONDS
    while True:
        status = cf.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        if status["DetectionStatus"] in ("DETECTION_COMPLETE", "DETECTION_FAILED"):
            break
        if time.monotonic() > deadline:
            return {"command": command, "error": f"drift detection timed out after {CF_DRIFT_TIMEOUT_SECONDS}s"}
        time.sleep(CF_POLL_SECONDS)
    drifts, token = [], None
    while True:
        kwargs = {"StackName": stack, "StackResourceDriftStatusFilters": CF_STATUSES}
        if token:
            kwargs["NextToken"] = token
        page = cf.describe_stack_resource_drifts(**kwargs)
        drifts.extend(page["StackResourceDrifts"])
        token = page.get("NextToken")
        if not token:
            break
    raw = {"detection_status": status, "resource_drifts": drifts}
    _write(raw_dir / f"{label}_cloudformation.json", json.dumps(raw, indent=2, default=str))
    return {"command": command, **parse_cloudformation(json.loads(json.dumps(raw, default=str)))}


def _pulumi_resource_name(urn: str) -> str:
    return urn.split("::")[-1]


def _pulumi(run, label: str, raw_dir: Path, stack: str) -> dict:
    work = run.work / "pulumi"
    command = ["pulumi", "refresh", "--preview-only", "--json", "--non-interactive", "--stack", stack]
    result = subprocess.run(command, cwd=work, env=run.tool_env(), capture_output=True, text=True, encoding="utf-8")
    _write(raw_dir / f"{label}_pulumi.json", result.stdout)
    if result.stderr:
        _write(raw_dir / f"{label}_pulumi.txt", result.stderr)
    if result.returncode != 0:
        return {"command": " ".join(command), "error": f"pulumi exit code {result.returncode}: {result.stderr[-2000:]}"}
    return {"command": " ".join(command), **parse_pulumi(result.stdout), "exit_code": result.returncode}


def _attempt(run, tool: str, label: str, raw_dir: Path, stack_names: dict) -> dict:
    try:
        if tool == "terraform":
            return _terraform(run, label, raw_dir)
        if tool == "cloudformation":
            return _cloudformation(run, label, raw_dir, stack_names["cloudformation"])
        return _pulumi(run, label, raw_dir, stack_names["pulumi"])
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def check(run, env: str, label: str, stack_names: dict) -> dict:
    tool = TOOL_FOR_ENV[env]
    raw_dir = run.dir / "native" / "raw"
    attempt = 0
    while True:
        attempt += 1
        started = time.monotonic()
        result = _attempt(run, tool, label, raw_dir, stack_names)
        if "error" not in result or attempt == CHECK_ATTEMPTS:
            break
        print(f"  Native check attempt {attempt} failed ({result['error'][:200]}), retrying in {CHECK_RETRY_SECONDS}s", flush=True)
        time.sleep(CHECK_RETRY_SECONDS)
    result.update({
        "attempts": attempt,
        "tool": tool,
        "env": env,
        "label": label,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 2),
        "ok": "error" not in result,
    })
    result.setdefault("changes", [])
    _write(run.dir / "native" / f"{label}_{env}.json", json.dumps(result, indent=2, default=str))
    return result


def reparse(run_dir: Path):
    parsers = {
        "terraform": lambda text: parse_terraform(text),
        "cloudformation": lambda text: parse_cloudformation(json.loads(text)),
        "pulumi": lambda text: parse_pulumi(text),
    }
    for path in sorted((run_dir / "native").glob("*.json")):
        result = json.loads(path.read_text(encoding="utf-8"))
        raw = run_dir / "native" / "raw" / f"{result['label']}_{result['env']}.json"
        if not result.get("ok") or not raw.exists():
            continue
        result.update(parsers[result["tool"]](raw.read_text(encoding="utf-8")))
        _write(path, json.dumps(result, indent=2, default=str))


def _load(run_dir: Path, label: str, env: str):
    path = run_dir / "native" / f"{label}_{env}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _pairs(result) -> set:
    return {tuple(c[:2]) for c in (result or {}).get("changes", [])}


def _values(result) -> dict:
    return {tuple(c[:2]): (c[2] if len(c) > 2 else None) for c in (result or {}).get("changes", [])}


def score(run_dir: Path, entries: list, scenario_order: list, envs: list, controls: list) -> dict:
    mapping = load_mapping()
    summary = {}
    table = {}
    for env in envs:
        tool = TOOL_FOR_ENV[env]
        baseline = _load(run_dir, "baseline", env)
        clean_checks = [("baseline", baseline)] if baseline else []
        background = _pairs(baseline)
        background_values = _values(baseline)
        baseline_pairs = set(background)
        counts = {k: 0 for k in ("detected", "missed", "no_drift", "not_declared", "not_checked", "error")}
        scenario_other, control_other, durations, persistent, not_checked_all = 0, 0, [], [], set()
        resource_level_detected = 0
        for result in [baseline]:
            if result and result.get("ok"):
                durations.append(result["duration_seconds"])
                not_checked_all.update(result.get("not_checked", []))
        for sid in scenario_order:
            entry = next((e for e in entries if e["scenario_id"] == sid and e["environment"] == env), None)
            result = _load(run_dir, sid, env)
            target = mapping[tool].get(sid)
            outcome = {"tool": tool, "gives_severity": False, "gives_cis": False}
            if result is None or entry is None:
                continue
            durations.append(result["duration_seconds"])
            not_checked_all.update(result.get("not_checked", []))
            reported = _pairs(result)
            values = _values(result)
            new = reported - background
            on_target = {
                p for p in reported
                if target and p[0] == target["resource"] and p[1] in target["attributes"]
                and (p not in background or values.get(p) != background_values.get(p))
            }
            on_resource = {p for p in new if target and p[0] == target["resource"]} | on_target
            other = sorted(new - on_target)
            if not result.get("ok"):
                status = "error"
            elif target is None:
                status = "not_declared"
            elif not entry.get("injected", True):
                status = "no_drift"
            elif tool == "cloudformation" and target["resource"] in result.get("not_checked", []):
                status = "not_checked"
            elif on_target:
                status = "detected"
            else:
                status = "missed"
            if status in ("detected", "missed") and on_resource:
                resource_level_detected += 1
            counts[status] += 1
            scenario_other += len(other)
            outcome.update({
                "status": status,
                "target": target,
                "reported_on_target": sorted(on_target),
                "reported_on_target_resource": sorted(on_resource),
                "other_changes": other,
                "error": result.get("error"),
                "duration_seconds": result["duration_seconds"],
            })
            entry.setdefault("native_results", {})[tool] = outcome
            table.setdefault(sid, {})[env] = {
                "driftfinder": entry["driftfinder_result"]["classification"]
                if entry.get("injected", True) or entry["driftfinder_result"]["classification"] != "FN"
                else "FN (no drift)",
                "native": status,
            }
            after = _load(run_dir, f"after_{sid}", env)
            if after and after.get("ok"):
                durations.append(after["duration_seconds"])
                not_checked_all.update(after.get("not_checked", []))
                for pair in sorted(_pairs(after) - baseline_pairs - {tuple(p["change"]) for p in persistent}):
                    persistent.append({"change": list(pair), "first_seen_after": sid})
                background = _pairs(after)
                background_values = _values(after)
                clean_checks.append((f"after_{sid}", after))
        for control_id, control_env in controls:
            if control_env != env:
                continue
            result = _load(run_dir, control_id, env)
            if not result:
                continue
            durations.append(result["duration_seconds"])
            new = _pairs(result) - background
            control_other += len(new)
            entry = next((e for e in entries if e["scenario_id"] == control_id and e["environment"] == env), None)
            if entry is not None:
                entry.setdefault("native_results", {})[tool] = {
                    "tool": tool, "status": "error" if not result.get("ok") else ("clean" if not new else "changes_reported"),
                    "other_changes": sorted(new), "error": result.get("error"),
                    "duration_seconds": result["duration_seconds"],
                }
        seen_in_clean = set().union(*(_pairs(r) for _, r in clean_checks if r)) if clean_checks else set()
        attempted = counts["detected"] + counts["missed"]
        summary[tool] = {
            "environment": env,
            **counts,
            "detection_rate_where_drift_injected_and_declared": round(counts["detected"] / attempted, 4) if attempted else None,
            "resource_level_detections": resource_level_detected,
            "other_changes_in_scenario_runs": scenario_other,
            "other_changes_in_control_scans": control_other,
            "changes_seen_in_any_clean_check": sorted(seen_in_clean),
            "persistent_changes": persistent,
            "duration_seconds": {
                "checks": len(durations),
                "median": round(statistics.median(durations), 2) if durations else None,
                "min": min(durations) if durations else None,
                "max": max(durations) if durations else None,
            },
            "not_checked_resources": sorted(not_checked_all) if tool == "cloudformation" else None,
            "gives_severity": False,
            "gives_cis": False,
        }
    return {"mapping": mapping_info(), "per_tool": summary, "per_scenario": table}
