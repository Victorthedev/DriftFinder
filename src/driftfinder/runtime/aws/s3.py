import json
import logging

from botocore.exceptions import ClientError

from driftfinder.models.enums import EncryptionAlgorithm
from driftfinder.models.nrm import NRMResource, NRMS3Bucket
from driftfinder.parsers.base import has_ssl_only_policy
from driftfinder.runtime.base import BaseResourceQuerier, ResourceNotFoundError
from driftfinder.utils.retry import aws_retry

logger = logging.getLogger(__name__)


class S3Querier(BaseResourceQuerier):

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        super().__init__(session, region, account_id)
        self._s3 = session.client("s3")  # type: ignore[union-attr]

    def query(self, declared: NRMResource) -> NRMResource:
        assert isinstance(declared, NRMS3Bucket)
        bucket = declared.resource_id
        return self._build(declared, bucket)

    def _build(self, declared: NRMS3Bucket, bucket: str) -> NRMS3Bucket:
        # --- Encryption ---
        sse_enabled, enc_alg = self._get_encryption(bucket)

        # --- Public access block ---
        block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets = (
            self._get_public_access_block(bucket)
        )
        pab_enabled: bool | None = None
        if any(v is not None for v in [block_public_acls, ignore_public_acls,
                                        block_public_policy, restrict_public_buckets]):
            pab_enabled = all([block_public_acls, ignore_public_acls,
                               block_public_policy, restrict_public_buckets])

        # --- Versioning ---
        versioning_enabled, mfa_delete = self._get_versioning(bucket)

        # --- Logging ---
        access_logging = self._get_logging(bucket)

        # --- SSL-only policy ---
        ssl_only = self._get_ssl_policy(bucket)

        return NRMS3Bucket(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=declared.region,
            account_id=self.account_id or declared.account_id,
            server_side_encryption_enabled=sse_enabled,
            encryption_algorithm=enc_alg,
            public_access_block_enabled=pab_enabled,
            block_public_acls=block_public_acls,
            ignore_public_acls=ignore_public_acls,
            block_public_policy=block_public_policy,
            restrict_public_buckets=restrict_public_buckets,
            versioning_enabled=versioning_enabled,
            mfa_delete_enabled=mfa_delete,
            access_logging_enabled=access_logging,
            ssl_requests_only=ssl_only,
        )

    @aws_retry()
    def _get_encryption(self, bucket: str) -> tuple[bool, EncryptionAlgorithm | None]:
        try:
            resp = self._s3.get_bucket_encryption(Bucket=bucket)
            rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                alg = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                try:
                    return True, EncryptionAlgorithm(alg)
                except (ValueError, TypeError):
                    return True, None
            return False, None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("NoSuchBucket",):
                raise ResourceNotFoundError("NRMS3Bucket", bucket) from exc
            if code in ("ServerSideEncryptionConfigurationNotFoundError",
                        "NoSuchConfiguration"):
                return False, None
            raise

    @aws_retry()
    def _get_public_access_block(
        self, bucket: str
    ) -> tuple[bool | None, bool | None, bool | None, bool | None]:
        try:
            resp = self._s3.get_public_access_block(Bucket=bucket)
            cfg = resp.get("PublicAccessBlockConfiguration", {})
            return (
                bool(cfg.get("BlockPublicAcls")),
                bool(cfg.get("IgnorePublicAcls")),
                bool(cfg.get("BlockPublicPolicy")),
                bool(cfg.get("RestrictPublicBuckets")),
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                return False, False, False, False
            if code == "NoSuchBucket":
                raise ResourceNotFoundError("NRMS3Bucket", bucket) from exc
            raise

    @aws_retry()
    def _get_versioning(self, bucket: str) -> tuple[bool, bool]:
        resp = self._s3.get_bucket_versioning(Bucket=bucket)
        versioning = resp.get("Status", "") == "Enabled"
        mfa_delete = resp.get("MFADelete", "") == "Enabled"
        return versioning, mfa_delete

    @aws_retry()
    def _get_logging(self, bucket: str) -> bool:
        resp = self._s3.get_bucket_logging(Bucket=bucket)
        return "LoggingEnabled" in resp

    @aws_retry()
    def _get_ssl_policy(self, bucket: str) -> bool:
        try:
            resp = self._s3.get_bucket_policy(Bucket=bucket)
            return has_ssl_only_policy(resp.get("Policy", ""))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return False
            raise
