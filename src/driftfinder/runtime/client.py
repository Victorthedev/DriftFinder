import logging
from typing import Optional

import boto3
from botocore.config import Config

from driftfinder.models.nrm import (
    NRMCloudTrail,
    NRMEBSVolume,
    NRMIAMPolicy,
    NRMKMSKey,
    NRMRDSInstance,
    NRMResource,
    NRMSecurityGroup,
    NRMS3Bucket,
    NRMVPC,
)
from driftfinder.runtime.aws.cloudtrail import CloudTrailQuerier
from driftfinder.runtime.aws.ebs import EBSQuerier
from driftfinder.runtime.aws.iam import IAMQuerier
from driftfinder.runtime.aws.kms import KMSQuerier
from driftfinder.runtime.aws.rds import RDSQuerier
from driftfinder.runtime.aws.s3 import S3Querier
from driftfinder.runtime.aws.security_group import SecurityGroupQuerier
from driftfinder.runtime.aws.vpc import VPCQuerier
from driftfinder.runtime.base import BaseResourceQuerier

logger = logging.getLogger(__name__)

# botocore retry is disabled here; @aws_retry handles all retry logic
_BOTO_CONFIG = Config(
    retries={"max_attempts": 1, "mode": "standard"},
    connect_timeout=10,
    read_timeout=30,
)


def create_session(
    profile: Optional[str] = None,
    region: str = "eu-west-2",
) -> boto3.Session:
    return boto3.Session(profile_name=profile, region_name=region)


class AWSRuntimeQuerier:
    """
    Dispatches runtime queries to the correct per-resource-type querier.
    Holds one boto3 session shared across all queriers.
    """

    def __init__(
        self,
        region: str = "eu-west-2",
        profile: Optional[str] = None,
        account_id: str = "",
    ) -> None:
        self.region = region
        self._session = create_session(profile=profile, region=region)

        # Fetch account_id from STS if not supplied
        self.account_id = account_id
        if not self.account_id:
            try:
                sts = self._session.client("sts", config=_BOTO_CONFIG)
                self.account_id = sts.get_caller_identity()["Account"]
            except Exception as exc:
                logger.warning("Could not determine AWS account ID: %s", exc)

        querier_args = dict(session=self._session, region=region, account_id=self.account_id)

        self._queriers: dict[type, BaseResourceQuerier] = {
            NRMS3Bucket: S3Querier(**querier_args),
            NRMSecurityGroup: SecurityGroupQuerier(**querier_args),
            NRMIAMPolicy: IAMQuerier(**querier_args),
            NRMRDSInstance: RDSQuerier(**querier_args),
            NRMEBSVolume: EBSQuerier(**querier_args),
            NRMCloudTrail: CloudTrailQuerier(**querier_args),
            NRMVPC: VPCQuerier(**querier_args),
            NRMKMSKey: KMSQuerier(**querier_args),
        }

    def query(self, declared: NRMResource) -> NRMResource:
        querier = self._queriers.get(type(declared))
        if querier is None:
            raise ValueError(f"No runtime querier registered for {type(declared).__name__}")
        return querier.query(declared)
