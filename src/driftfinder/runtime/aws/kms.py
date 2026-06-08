import json
import logging

from botocore.exceptions import ClientError

from driftfinder.models.nrm import NRMKMSKey, NRMResource
from driftfinder.runtime.base import BaseResourceQuerier, ResourceNotFoundError
from driftfinder.utils.retry import aws_retry

logger = logging.getLogger(__name__)

_SYMMETRIC_KEY_SPEC = "SYMMETRIC_DEFAULT"


class KMSQuerier(BaseResourceQuerier):

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        super().__init__(session, region, account_id)
        self._kms = session.client("kms", region_name=region)  # type: ignore[union-attr]

    def query(self, declared: NRMResource) -> NRMResource:
        assert isinstance(declared, NRMKMSKey)
        return self._build(declared)

    @aws_retry()
    def _build(self, declared: NRMKMSKey) -> NRMKMSKey:
        try:
            resp = self._kms.describe_key(KeyId=declared.resource_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                raise ResourceNotFoundError("NRMKMSKey", declared.resource_id) from exc
            raise

        meta = resp["KeyMetadata"]
        key_state = meta.get("KeyState", "")
        key_enabled = key_state == "Enabled"
        key_spec = meta.get("KeySpec", "")

        # Rotation is only meaningful for symmetric CMKs; left None for asymmetric keys so the engine does not flag false drift on key types that cannot rotate.
        rotation_enabled: bool | None = None
        if key_spec == _SYMMETRIC_KEY_SPEC:
            rotation_enabled = self._get_rotation_enabled(declared.resource_id)

        key_policy_allows_public = self._get_policy_allows_public(declared.resource_id)

        return NRMKMSKey(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=self.region,
            account_id=self.account_id or declared.account_id,
            key_enabled=key_enabled,
            key_rotation_enabled=rotation_enabled,
            key_policy_allows_public_access=key_policy_allows_public,
        )

    @aws_retry()
    def _get_rotation_enabled(self, key_id: str) -> bool | None:
        try:
            resp = self._kms.get_key_rotation_status(KeyId=key_id)
            return bool(resp.get("KeyRotationEnabled"))
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NotFoundException", "UnsupportedOperationException"):
                return None
            raise

    @aws_retry()
    def _get_policy_allows_public(self, key_id: str) -> bool:
        try:
            resp = self._kms.get_key_policy(KeyId=key_id, PolicyName="default")
            policy_str = resp.get("Policy", "{}")
            policy = json.loads(policy_str)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return False
            raise

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal", {})
            # Principal: "*" or Principal: {"AWS": "*"} means any principal (public access)
            if principal == "*":
                return True
            if isinstance(principal, dict):
                aws_principal = principal.get("AWS", "")
                if aws_principal == "*" or (isinstance(aws_principal, list) and "*" in aws_principal):
                    return True
        return False
