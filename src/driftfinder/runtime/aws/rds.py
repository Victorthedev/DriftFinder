import logging

from botocore.exceptions import ClientError

from driftfinder.models.nrm import NRMRDSInstance, NRMResource
from driftfinder.runtime.base import BaseResourceQuerier, ResourceNotFoundError
from driftfinder.utils.retry import aws_retry

logger = logging.getLogger(__name__)


class RDSQuerier(BaseResourceQuerier):
    """
    Queries RDS DB instances only (not Aurora clusters).
    Aurora clusters use a different API (describe_db_clusters) and are
    out of scope for Phase 1.
    """

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        super().__init__(session, region, account_id)
        self._rds = session.client("rds", region_name=region)  # type: ignore[union-attr]

    def query(self, declared: NRMResource) -> NRMResource:
        assert isinstance(declared, NRMRDSInstance)
        return self._build(declared)

    @aws_retry()
    def _build(self, declared: NRMRDSInstance) -> NRMRDSInstance:
        try:
            resp = self._rds.describe_db_instances(
                DBInstanceIdentifier=declared.resource_id
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBInstanceNotFound":
                raise ResourceNotFoundError("NRMRDSInstance", declared.resource_id) from exc
            raise

        instances = resp.get("DBInstances", [])
        if not instances:
            raise ResourceNotFoundError("NRMRDSInstance", declared.resource_id)

        db = instances[0]
        return NRMRDSInstance(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=self.region,
            account_id=self.account_id or declared.account_id,
            storage_encrypted=db.get("StorageEncrypted"),
            publicly_accessible=db.get("PubliclyAccessible"),
            backup_retention_days=db.get("BackupRetentionPeriod"),
            deletion_protection=db.get("DeletionProtection"),
            multi_az=db.get("MultiAZ"),
            auto_minor_version_upgrade=db.get("AutoMinorVersionUpgrade"),
        )
