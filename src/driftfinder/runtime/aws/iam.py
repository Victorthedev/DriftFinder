import json
import logging
import urllib.parse

from botocore.exceptions import ClientError

from driftfinder.models.nrm import NRMIAMPolicy, NRMResource
from driftfinder.parsers.base import analyze_iam_policy_document
from driftfinder.runtime.base import BaseResourceQuerier, ResourceNotFoundError
from driftfinder.utils.retry import aws_retry

logger = logging.getLogger(__name__)


class IAMQuerier(BaseResourceQuerier):
    """
    Queries IAM managed policies by ARN.
    Inline role policies (resource_id format: role_name:policy_name) are
    not yet supported in Phase 1 and will log a warning.
    """

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        super().__init__(session, region, account_id)
        self._iam = session.client("iam")  # type: ignore[union-attr]

    def query(self, declared: NRMResource) -> NRMResource:
        assert isinstance(declared, NRMIAMPolicy)
        resource_id = declared.resource_id

        if resource_id.startswith("arn:aws:iam:"):
            return self._query_managed_policy(declared, resource_id)

        # Inline policy: resource_id is role_name:policy_name
        if ":" in resource_id:
            role_name, policy_name = resource_id.split(":", 1)
            return self._query_inline_policy(declared, role_name, policy_name)

        logger.warning(
            "IAM resource_id '%s' is neither an ARN nor a role:policy pair; skipping.",
            resource_id,
        )
        return declared  # Return declared unchanged if we cannot query

    @aws_retry()
    def _query_managed_policy(self, declared: NRMIAMPolicy, arn: str) -> NRMIAMPolicy:
        try:
            policy_resp = self._iam.get_policy(PolicyArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                raise ResourceNotFoundError("NRMIAMPolicy", arn) from exc
            raise

        version_id = policy_resp["Policy"]["DefaultVersionId"]
        version_resp = self._iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
        policy_doc = version_resp["PolicyVersion"]["Document"]

        # The AWS API URL-encodes the document for some policy types
        if isinstance(policy_doc, str):
            policy_doc = json.loads(urllib.parse.unquote(policy_doc))

        analysis = analyze_iam_policy_document(policy_doc)
        return NRMIAMPolicy(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=self.region,
            account_id=self.account_id or declared.account_id,
            has_wildcard_action=analysis["has_wildcard_action"],
            has_wildcard_resource=analysis["has_wildcard_resource"],
            has_admin_access=analysis["has_admin_access"],
            has_explicit_deny=analysis["has_explicit_deny"],
            policy_document_hash=analysis["policy_document_hash"],
        )

    @aws_retry()
    def _query_inline_policy(
        self, declared: NRMIAMPolicy, role_name: str, policy_name: str
    ) -> NRMIAMPolicy:
        try:
            resp = self._iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                raise ResourceNotFoundError("NRMIAMPolicy", f"{role_name}:{policy_name}") from exc
            raise

        policy_doc = resp["PolicyDocument"]
        if isinstance(policy_doc, str):
            policy_doc = json.loads(urllib.parse.unquote(policy_doc))

        analysis = analyze_iam_policy_document(policy_doc)
        return NRMIAMPolicy(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=self.region,
            account_id=self.account_id or declared.account_id,
            has_wildcard_action=analysis["has_wildcard_action"],
            has_wildcard_resource=analysis["has_wildcard_resource"],
            has_admin_access=analysis["has_admin_access"],
            has_explicit_deny=analysis["has_explicit_deny"],
            policy_document_hash=analysis["policy_document_hash"],
        )
