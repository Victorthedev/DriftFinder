import logging

from botocore.exceptions import ClientError

from driftfinder.models.nrm import NRMVPC, NRMResource
from driftfinder.runtime.base import BaseResourceQuerier, ResourceNotFoundError
from driftfinder.utils.retry import aws_retry

logger = logging.getLogger(__name__)


class VPCQuerier(BaseResourceQuerier):

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        super().__init__(session, region, account_id)
        self._ec2 = session.client("ec2", region_name=region)  # type: ignore[union-attr]

    def query(self, declared: NRMResource) -> NRMResource:
        assert isinstance(declared, NRMVPC)
        return self._build(declared)

    @aws_retry()
    def _build(self, declared: NRMVPC) -> NRMVPC:
        vpc_id = declared.resource_id
        self._assert_vpc_exists(vpc_id)

        flow_logs_enabled = self._get_flow_logs_enabled(vpc_id)
        default_sg_has_no_rules = self._get_default_sg_has_no_rules(vpc_id)
        nacl_unrestricted_ingress = self._get_nacl_unrestricted_ingress(vpc_id)

        return NRMVPC(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=self.region,
            account_id=self.account_id or declared.account_id,
            flow_logs_enabled=flow_logs_enabled,
            default_sg_has_no_rules=default_sg_has_no_rules,
            nacl_unrestricted_ingress=nacl_unrestricted_ingress,
        )

    @aws_retry()
    def _assert_vpc_exists(self, vpc_id: str) -> None:
        try:
            resp = self._ec2.describe_vpcs(VpcIds=[vpc_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                raise ResourceNotFoundError("NRMVPC", vpc_id) from exc
            raise
        if not resp.get("Vpcs"):
            raise ResourceNotFoundError("NRMVPC", vpc_id)

    @aws_retry()
    def _get_flow_logs_enabled(self, vpc_id: str) -> bool:
        resp = self._ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )
        logs = resp.get("FlowLogs", [])
        return any(fl.get("FlowLogStatus") == "ACTIVE" for fl in logs)

    @aws_retry()
    def _get_default_sg_has_no_rules(self, vpc_id: str) -> bool:
        resp = self._ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )
        sgs = resp.get("SecurityGroups", [])
        if not sgs:
            return True  # No default SG found — treat as no rules (safe default)
        sg = sgs[0]
        ingress = sg.get("IpPermissions", [])
        egress = sg.get("IpPermissionsEgress", [])
        return len(ingress) == 0 and len(egress) == 0

    @aws_retry()
    def _get_nacl_unrestricted_ingress(self, vpc_id: str) -> bool:
        resp = self._ec2.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        for nacl in resp.get("NetworkAcls", []):
            for entry in nacl.get("Entries", []):
                if entry.get("Egress"):
                    continue
                if entry.get("RuleAction") != "allow":
                    continue
                cidr = entry.get("CidrBlock", "")
                ipv6 = entry.get("Ipv6CidrBlock", "")
                if cidr == "0.0.0.0/0" or ipv6 == "::/0":
                    return True
        return False
