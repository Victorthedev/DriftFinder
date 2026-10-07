"""
DriftFinder Controlled Experiment — Ground Truth Logger
Records every drift injection as a structured entry for evaluation.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class GroundTruthLogger:
    """
    Records ground truth entries for the controlled experiment.
    Each entry corresponds to one scenario in one environment.
    Used to calculate precision, recall and F1 after DriftFinder scans.
    """

    def __init__(self, path: str = "ground_truth.json"):
        self.path = Path(path)
        self._load()

    def _load(self):
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
        else:
            self.data = {"entries": [], "created_at": datetime.now(timezone.utc).isoformat()}

    def _save(self):
        self.path.write_text(json.dumps(self.data, indent=2, default=str))

    def log(
        self,
        scenario_id: str,
        resource_type: str,
        resource_id: str,
        property_path: str,
        before: dict,
        after: dict,
        mechanism: str,
        cis_control: str,
        severity: str,
        environment: str,
        notes: Optional[str] = None,
        injected: bool = True,
    ):
        entry = {
            "scenario_id": scenario_id,
            "environment": environment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "resource_type": resource_type,
            "resource_id": resource_id,
            "property_path": property_path,
            "before": before,
            "after": after,
            "mechanism": mechanism,
            "cis_control": cis_control,
            "severity": severity,
            "notes": notes,
            "injected": injected,
            # These are filled in after running DriftFinder
            "driftfinder_result": {
                "detected": None,           # True / False
                "finding_id": None,         # DriftFinder finding ID if detected
                "detected_severity": None,  # What DriftFinder reported
                "detected_cis": None,       # CIS controls DriftFinder reported
                "classification": None,     # TP / FP / FN
            },
        }

        # Remove duplicate entry if it exists (re-run scenario)
        self.data["entries"] = [
            e for e in self.data["entries"]
            if not (e["scenario_id"] == scenario_id and e["environment"] == environment)
        ]

        self.data["entries"].append(entry)
        self._save()
        print(f"  Ground truth logged: {scenario_id} [{environment}] — {property_path}")

    def record_result(
        self,
        scenario_id: str,
        environment: str,
        detected: bool,
        finding_id: Optional[str] = None,
        detected_severity: Optional[str] = None,
        detected_cis: Optional[list] = None,
        matched_finding: Optional[dict] = None,
    ):
        """
        Record DriftFinder's scan result for a scenario.
        Call this after running DriftFinder for each scenario.
        """
        for entry in self.data["entries"]:
            if entry["scenario_id"] == scenario_id and entry["environment"] == environment:
                entry["driftfinder_result"]["detected"] = detected
                entry["driftfinder_result"]["finding_id"] = finding_id
                entry["driftfinder_result"]["detected_severity"] = detected_severity
                entry["driftfinder_result"]["detected_cis"] = detected_cis
                entry["driftfinder_result"]["matched_finding"] = matched_finding

                # Classify
                if detected:
                    entry["driftfinder_result"]["classification"] = "TP"
                else:
                    entry["driftfinder_result"]["classification"] = "FN"

                self._save()
                print(f"  Result recorded: {scenario_id} [{environment}] — {'TP' if detected else 'FN'}")
                return

        print(f"  WARNING: No ground truth entry found for {scenario_id} [{environment}]")

    def record_false_positive(
        self,
        resource_id: str,
        environment: str,
        property_path: str,
        detected_severity: str,
        detected_cis: list,
        source: Optional[str] = None,
    ):
        """Record a false positive finding from DriftFinder (not in ground truth)."""
        entry = {
            "scenario_id": "FP",
            "environment": environment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "resource_id": resource_id,
            "property_path": property_path,
            "source": source,
            "driftfinder_result": {
                "detected": True,
                "detected_severity": detected_severity,
                "detected_cis": detected_cis,
                "classification": "FP",
            },
        }
        self.data["entries"].append(entry)
        self._save()
        print(f"  False positive recorded: {resource_id}.{property_path} [{environment}]")

    def remove_entries_from_source(self, source: str):
        self.data["entries"] = [e for e in self.data["entries"] if e.get("source") != source]
        self._save()

    def record_control(self, scenario_id: str, environment: str, findings_count: int):
        self.data["entries"] = [
            e for e in self.data["entries"]
            if not (e["scenario_id"] == scenario_id and e["environment"] == environment)
        ]
        self.data["entries"].append({
            "scenario_id": scenario_id,
            "environment": environment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "resource_type": "CONTROL",
            "resource_id": "all",
            "property_path": "baseline",
            "before": {},
            "after": {},
            "mechanism": "Control case — clean baseline, no drift injected",
            "cis_control": "ALL",
            "severity": "N/A",
            "notes": "Expected: 0 findings. Any finding here is a false positive.",
            "driftfinder_result": {
                "detected": findings_count > 0,
                "finding_id": None,
                "detected_severity": None,
                "detected_cis": None,
                "classification": "TN" if findings_count == 0 else "NOT_CLEAN",
            },
        })
        self._save()
        print(f"  Control recorded: {scenario_id} [{environment}]: {findings_count} findings")

    @staticmethod
    def cis_matches(entry: dict) -> bool:
        expected = entry.get("cis_control")
        reported = entry.get("driftfinder_result", {}).get("detected_cis") or []
        return not reported if expected is None else expected in reported

    def compute_metrics(self, environment: Optional[str] = None) -> dict:
        """
        Compute precision, recall and F1 from recorded results.
        Implements: Precision = |TP| / (|TP| + |FP|)
                    Recall = |TP| / (|TP| + |FN|)
                    F1 = 2 * P * R / (P + R)
        """
        entries = self.data["entries"]
        if environment:
            entries = [e for e in entries if e.get("environment") == environment]

        def classified(label, subset):
            return sum(1 for e in subset if e.get("driftfinder_result", {}).get("classification") == label)

        def f1_score(p, r):
            return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0

        scenarios = [e for e in entries if e.get("scenario_id", "").startswith("D")]
        injected = [e for e in scenarios if e.get("injected", True)]

        tp = classified("TP", entries)
        fp = classified("FP", entries)
        fn = classified("FN", entries)
        tp_injected = classified("TP", injected)
        fn_injected = classified("FN", injected)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        recall_injected = tp_injected / (tp_injected + fn_injected) if (tp_injected + fn_injected) > 0 else 0.0

        detected = [e for e in scenarios if e.get("driftfinder_result", {}).get("classification") == "TP"]
        severity_matches = sum(
            1 for e in detected if e["driftfinder_result"].get("detected_severity") == e.get("severity")
        )
        cis_matches = sum(1 for e in detected if self.cis_matches(e))

        return {
            "environment": environment or "all",
            "total_scenarios": len(scenarios),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1_score(precision, recall), 4),
            "scenarios_with_drift_injected": len(injected),
            "scenarios_without_drift": len(scenarios) - len(injected),
            "tp_where_drift_injected": tp_injected,
            "fn_where_drift_injected": fn_injected,
            "recall_where_drift_injected": round(recall_injected, 4),
            "f1_where_drift_injected": round(f1_score(precision, recall_injected), 4),
            "detections_with_expected_severity": severity_matches,
            "detections_with_expected_cis": cis_matches,
        }

    def print_summary(self):
        """Print experiment summary with metrics per environment."""
        print("\n" + "="*70)
        print("DRIFTFINDER EXPERIMENT RESULTS SUMMARY")
        print("="*70)

        def show(metrics):
            print(f"  Scenarios:  {metrics['total_scenarios']} "
                  f"({metrics['scenarios_with_drift_injected']} with drift injected, "
                  f"{metrics['scenarios_without_drift']} without)")
            print(f"  TP: {metrics['tp']}  FP: {metrics['fp']}  FN: {metrics['fn']}")
            print(f"  Precision:  {metrics['precision']:.4f}")
            print(f"  Recall:     {metrics['recall']:.4f} (all scenarios)")
            print(f"  Recall:     {metrics['recall_where_drift_injected']:.4f} (scenarios with drift injected)")
            print(f"  F1 Score:   {metrics['f1']:.4f} (all scenarios)")
            print(f"  F1 Score:   {metrics['f1_where_drift_injected']:.4f} (scenarios with drift injected)")
            print(f"  Detections with expected severity: {metrics['detections_with_expected_severity']} of {metrics['tp']}")
            print(f"  Detections with expected CIS control: {metrics['detections_with_expected_cis']} of {metrics['tp']}")

        for env in ["terraform", "cloudformation", "pulumi"]:
            print(f"\n{env.upper()}")
            show(self.compute_metrics(env))

        print(f"\nOVERALL")
        show(self.compute_metrics())
        print("="*70)

    def export_for_dissertation(self, output_path: str = "dissertation_results.json"):
        """Export clean results table for dissertation analysis."""
        results = []
        for entry in self.data["entries"]:
            if not entry.get("scenario_id", "").startswith("D"):
                continue
            result = entry.get("driftfinder_result", {})
            detected = result.get("classification") == "TP"
            results.append({
                "scenario_id": entry["scenario_id"],
                "environment": entry["environment"],
                "resource_type": entry["resource_type"],
                "property_path": entry["property_path"],
                "mechanism": entry["mechanism"],
                "injected": entry.get("injected", True),
                "detected": result.get("detected"),
                "classification": result.get("classification"),
                "expected_severity": entry["severity"],
                "reported_severity": result.get("detected_severity"),
                "severity_matches": detected and result.get("detected_severity") == entry["severity"],
                "expected_cis": entry["cis_control"],
                "reported_cis": result.get("detected_cis"),
                "cis_matches": detected and self.cis_matches(entry),
                "matched_finding": result.get("matched_finding"),
                "notes": entry.get("notes"),
            })

        output = {
            "experiment_metadata": {
                "tool": "DriftFinder",
                "environments": ["terraform", "cloudformation", "pulumi"],
                "scenarios": 24,
                "controls": 6,
                "region": "eu-west-1",
                "exported_at": datetime.now(timezone.utc).isoformat(),
            },
            "metrics_per_environment": {
                env: self.compute_metrics(env)
                for env in ["terraform", "cloudformation", "pulumi"]
            },
            "overall_metrics": self.compute_metrics(),
            "results": results,
        }

        Path(output_path).write_text(json.dumps(output, indent=2, default=str))
        print(f"\nDissertation results exported to {output_path}")
        return output