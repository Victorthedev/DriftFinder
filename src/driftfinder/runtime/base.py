from abc import ABC, abstractmethod

from driftfinder.models.nrm import NRMResource


class ResourceNotFoundError(Exception):
    """Raised when a declared resource no longer exists in AWS."""

    def __init__(self, resource_type: str, resource_id: str) -> None:
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(f"{resource_type} '{resource_id}' not found in AWS")


class BaseResourceQuerier(ABC):
    """Abstract base for all per-resource-type AWS runtime queriers."""

    def __init__(self, session: object, region: str, account_id: str = "") -> None:
        self._session = session  # boto3.Session
        self.region = region
        self.account_id = account_id

    @abstractmethod
    def query(self, declared: NRMResource) -> NRMResource:
        """
        Query the live AWS state for the resource identified by declared.resource_id.

        Returns an NRM object with actual AWS-observed values.
        Raises ResourceNotFoundError if the resource no longer exists.
        """
        ...
