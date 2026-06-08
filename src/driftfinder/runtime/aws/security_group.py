import logging

from botocore.exceptions import ClientError

from driftfinder.models.nrm import NRMResource, NRMSecurityGroup
from driftfinder.runtime.base import BaseResourceQuerier, ResourceNotFoundError
from driftfinder.utils.retry import aws_retry

logger = logging.getLogger(__name__)


class SecurityGroupQuerier(BaseResourceQuerier):

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        super().__init__(session, region, account_id)
        self._ec2 = session.client("ec2", region_name=region)  # type: ignore[union-attr]

    def query(self, declared: NRMResource) -> NRMResource:
        assert isinstance(declared, NRMSecurityGroup)
        return self._build(declared)

    @aws_retry()
    def _build(self, declared: NRMSecurityGroup) -> NRMSecurityGroup:
        try:
            resp = self._ec2.describe_security_groups(GroupIds=[declared.resource_id])
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                raise ResourceNotFoundError("NRMSecurityGroup", declared.resource_id) from exc
            raise

        sgs = resp.get("SecurityGroups", [])
        if not sgs:
            raise ResourceNotFoundError("NRMSecurityGroup", declared.resource_id)

        sg = sgs[0]
        ingress = sg.get("IpPermissions", [])
        egress = sg.get("IpPermissionsEgress", [])

        return NRMSecurityGroup(
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=declared.iac_tool,
            region=self.region,
            account_id=self.account_id or declared.account_id,
            unrestricted_ssh_ingress=_unrestricted_port(ingress, 22),
            unrestricted_rdp_ingress=_unrestricted_port(ingress, 3389),
            unrestricted_all_traffic_ingress=_unrestricted_all(ingress),
            unrestricted_all_traffic_egress=_unrestricted_all(egress),
        )


def _unrestricted_port(rules: list, port: int) -> bool:  # type: ignore[type-arg]
    for rule in rules:
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 0)
        protocol = rule.get("IpProtocol", "").lower()
        if protocol not in ("tcp", "-1"):
            continue
        if protocol == "tcp" and not (from_port <= port <= to_port):
            continue
        for ip in rule.get("IpRanges", []):
            if ip.get("CidrIp") == "0.0.0.0/0":
                return True
        for ip in rule.get("Ipv6Ranges", []):
            if ip.get("CidrIpv6") == "::/0":
                return True
    return False


def _unrestricted_all(rules: list) -> bool:  # type: ignore[type-arg]
    for rule in rules:
        if rule.get("IpProtocol") != "-1":
            continue
        for ip in rule.get("IpRanges", []):
            if ip.get("CidrIp") == "0.0.0.0/0":
                return True
        for ip in rule.get("Ipv6Ranges", []):
            if ip.get("CidrIpv6") == "::/0":
                return True
    return False
