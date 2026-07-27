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
    ):
        """Record a false positive finding from DriftFinder (not in ground truth)."""
        entry = {
            "scenario_id": "FP",
            "environment": environment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "resource_id": resource_id,
            "property_path": property_path,
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

        tp = sum(1 for e in entries if e.get("driftfinder_result", {}).get("classification") == "TP")
        fp = sum(1 for e in entries if e.get("driftfinder_result", {}).get("classification") == "FP")
        fn = sum(1 for e in entries if e.get("driftfinder_result", {}).get("classification") == "FN")

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        return {
            "environment": environment or "all",
            "total_scenarios": len([e for e in entries if e.get("scenario_id", "").startswith("D")]),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    def print_summary(self):
        """Print experiment summary with metrics per environment."""
        print("\n" + "="*70)
        print("DRIFTFINDER EXPERIMENT RESULTS SUMMARY")
        print("="*70)

        for env in ["terraform", "cloudformation", "pulumi"]:
            metrics = self.compute_metrics(env)
            print(f"\n{env.upper()}")
            print(f"  Scenarios:  {metrics['total_scenarios']}")
            print(f"  TP: {metrics['tp']}  FP: {metrics['fp']}  FN: {metrics['fn']}")
            print(f"  Precision:  {metrics['precision']:.4f}")
            print(f"  Recall:     {metrics['recall']:.4f}")
            print(f"  F1 Score:   {metrics['f1']:.4f}")

        print(f"\nOVERALL")
        overall = self.compute_metrics()
        print(f"  TP: {overall['tp']}  FP: {overall['fp']}  FN: {overall['fn']}")
        print(f"  Precision:  {overall['precision']:.4f}")
        print(f"  Recall:     {overall['recall']:.4f}")
        print(f"  F1 Score:   {overall['f1']:.4f}")
        print("="*70)

    def export_for_dissertation(self, output_path: str = "dissertation_results.json"):
        """Export clean results table for dissertation analysis."""
        results = []
        for entry in self.data["entries"]:
            if not entry.get("scenario_id", "").startswith("D"):
                continue
            result = entry.get("driftfinder_result", {})
            results.append({
                "scenario_id": entry["scenario_id"],
                "environment": entry["environment"],
                "resource_type": entry["resource_type"],
                "property_path": entry["property_path"],
                "cis_control": entry["cis_control"],
                "severity": entry["severity"],
                "mechanism": entry["mechanism"],
                "detected": result.get("detected"),
                "classification": result.get("classification"),
                "detected_severity": result.get("detected_severity"),
                "detected_cis": result.get("detected_cis"),
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