import logging

from botocore.exceptions import ClientError

from driftfinder.models.nrm import NRMEBSVolume, NRMResource
from driftfinder.runtime.base import BaseResourceQuerier, ResourceNotFoundError
from driftfinder.utils.retry import aws_retry

logger = logging.getLogger(__name__)


class EBSQuerier(BaseResourceQuerier):

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        super().__init__(session, region, account_id)
        self._ec2 = session.client("ec2", region_name=region)  # type: ignore[union-attr]

    def query(self, declared: NRMResource) -> NRMResource:
        assert isinstance(declared, NRMEBSVolume)
        return self._build(declared)

    @aws_retry()
    def _build(self, declared: NRMEBSVolume) -> NRMEBSVolume:
        try:
            resp = self._ec2.describe_volumes(VolumeIds=[declared.resource_id])
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVolume.NotFound":
                raise ResourceNotFoundError("NRMEBSVolume", declared.resource_id) from exc
            raise

        volumes = resp.get("Volumes", [])
        if not volumes:
            raise ResourceNotFoundError("NRMEBSVolume", declared.resource_id)

        volume = volumes[0]

        delete_on_termination: bool | None = None
        attachments = volume.get("Attachments", [])
        if attachments:
            delete_on_termination = bool(attachments[0].get("DeleteOnTermination"))

        snapshot_encrypted = self._get_snapshot_encrypted(declared.resource_id)

        return NRMEBSVolume(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=self.region,
            account_id=self.account_id or declared.account_id,
            encrypted=volume.get("Encrypted"),
            delete_on_termination=delete_on_termination,
            snapshot_encrypted=snapshot_encrypted,
        )

    @aws_retry()
    def _get_snapshot_encrypted(self, volume_id: str) -> bool | None:
        resp = self._ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [volume_id]}])
        snapshots = resp.get("Snapshots", [])
        if not snapshots:
            return None
        return any(s.get("Encrypted", False) for s in snapshots)
