import logging

from botocore.exceptions import ClientError

from driftfinder.models.nrm import NRMCloudTrail, NRMResource
from driftfinder.runtime.base import BaseResourceQuerier, ResourceNotFoundError
from driftfinder.utils.retry import aws_retry

logger = logging.getLogger(__name__)


class CloudTrailQuerier(BaseResourceQuerier):

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        super().__init__(session, region, account_id)
        self._ct = session.client("cloudtrail", region_name=region)  # type: ignore[union-attr]

    def query(self, declared: NRMResource) -> NRMResource:
        assert isinstance(declared, NRMCloudTrail)
        return self._build(declared)

    @aws_retry()
    def _build(self, declared: NRMCloudTrail) -> NRMCloudTrail:
        try:
            resp = self._ct.describe_trails(
                trailNameList=[declared.resource_id],
                includeShadowTrails=False,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TrailNotFoundException":
                raise ResourceNotFoundError("NRMCloudTrail", declared.resource_id) from exc
            raise

        trails = resp.get("trailList", [])
        if not trails:
            raise ResourceNotFoundError("NRMCloudTrail", declared.resource_id)

        trail = trails[0]
        trail_arn = trail.get("TrailARN", declared.resource_id)

        is_logging = self._get_is_logging(trail_arn)

        cloudwatch_enabled = bool(trail.get("CloudWatchLogsLogGroupArn"))
        kms_enabled = bool(trail.get("KmsKeyId") or trail.get("KMSKeyId"))

        # S3 bucket logging: the trail records events to an S3 bucket by definition.
        # "S3 bucket logging" here means the S3 bucket used by the trail has its own
        # access logging turned on. That requires a separate S3 API call which is out
        # of scope for Phase 1 — left None (absent from IaC, not False).
        s3_bucket_logging: bool | None = None

        return NRMCloudTrail(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=self.region,
            account_id=self.account_id or declared.account_id,
            multi_region_enabled=trail.get("IsMultiRegionTrail"),
            log_file_validation_enabled=trail.get("LogFileValidationEnabled"),
            is_logging=is_logging,
            cloudwatch_logs_enabled=cloudwatch_enabled,
            kms_encryption_enabled=kms_enabled,
            s3_bucket_logging_enabled=s3_bucket_logging,
        )

    @aws_retry()
    def _get_is_logging(self, trail_arn: str) -> bool | None:
        try:
            status = self._ct.get_trail_status(Name=trail_arn)
            return bool(status.get("IsLogging"))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TrailNotFoundException":
                return None
            raise
