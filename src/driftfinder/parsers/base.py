import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Iterator

from driftfinder.models.nrm import NRMResource


class BaseParser(ABC):
    """Abstract base for all IaC state parsers."""

    def __init__(self, region: str = "eu-west-2", account_id: str = "") -> None:
        self.region = region
        self.account_id = account_id

    @abstractmethod
    def parse(self, source: str) -> Iterator[NRMResource]:
        """
        Parse IaC state and yield NRM resource objects.

        Args:
            source: File path (Terraform/Pulumi) or stack name (CloudFormation).

        Yields:
            NRMResource objects with declared property values populated.
            Absent properties are None; explicitly-set falsy values are False.
        """
        ...

    @abstractmethod
    def supports_resource_type(self, resource_type: str) -> bool:
        """Return True if this parser handles the given IaC resource type string."""
        ...


# ---------------------------------------------------------------------------
# Shared policy analysis helpers used by all three parsers
# ---------------------------------------------------------------------------


def analyze_iam_policy_document(policy_doc: dict) -> dict:  # type: ignore[type-arg]
    """
    Analyse a parsed IAM policy document and return a dict of NRM IAM booleans.
    Works on any dict representing a valid IAM policy regardless of IaC source.
    """
    has_wildcard_action = False
    has_wildcard_resource = False
    has_explicit_deny = False
    is_admin = False

    for statement in policy_doc.get("Statement", []):
        effect = statement.get("Effect", "")

        if effect == "Deny":
            has_explicit_deny = True
            continue

        if effect != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions:
            has_wildcard_action = True

        if "*" in resources:
            has_wildcard_resource = True

        if "*" in actions and "*" in resources:
            is_admin = True

    canonical = json.dumps(policy_doc, sort_keys=True, separators=(",", ":"))
    doc_hash = hashlib.sha256(canonical.encode()).hexdigest()

    return {
        "has_wildcard_action": has_wildcard_action,
        "has_wildcard_resource": has_wildcard_resource,
        "has_admin_access": is_admin,
        "has_explicit_deny": has_explicit_deny,
        "policy_document_hash": doc_hash,
    }


def has_ssl_only_policy(policy_json: str) -> bool:
    """
    Return True if the bucket policy enforces SSL-only access.
    Looks for a Deny statement with aws:SecureTransport: false condition.
    """
    try:
        policy = json.loads(policy_json)
    except (json.JSONDecodeError, TypeError):
        return False

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Deny":
            continue
        condition = statement.get("Condition", {})
        bool_cond = condition.get("Bool", {})
        secure_transport = bool_cond.get("aws:SecureTransport")
        if secure_transport is not None and str(secure_transport).lower() == "false":
            return True

    return False
