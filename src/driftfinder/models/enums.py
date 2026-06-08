from enum import StrEnum


class IaCTool(StrEnum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    PULUMI = "pulumi"


class DriftType(StrEnum):
    MODIFIED = "MODIFIED"  # Property exists in both; declared != actual
    DELETED = "DELETED"  # Property declared in IaC; absent in AWS
    UNMANAGED = "UNMANAGED"  # Property present in AWS; not declared in IaC


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OutputFormat(StrEnum):
    JSON = "json"
    HTML = "html"
    BOTH = "both"


class ScanMode(StrEnum):
    DEFAULT = "default"  # Exits non-zero when findings meet --fail-on threshold
    REPORT_ONLY = "report-only"  # Always exits zero; used by cron jobs


class FailOn(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EncryptionAlgorithm(StrEnum):
    NONE = "NONE"
    AES256 = "AES256"
    AWS_KMS = "aws:kms"
