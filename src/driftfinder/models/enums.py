from enum import Enum


class IaCTool(str, Enum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    PULUMI = "pulumi"


class DriftType(str, Enum):
    MODIFIED = "MODIFIED"      # Property exists in both; declared != actual
    DELETED = "DELETED"        # Property declared in IaC; absent in AWS
    UNMANAGED = "UNMANAGED"    # Property present in AWS; not declared in IaC


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OutputFormat(str, Enum):
    JSON = "json"
    HTML = "html"
    BOTH = "both"


class ScanMode(str, Enum):
    DEFAULT = "default"          # Exits non-zero when findings meet --fail-on threshold
    REPORT_ONLY = "report-only"  # Always exits zero; used by cron jobs


class FailOn(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EncryptionAlgorithm(str, Enum):
    NONE = "NONE"
    AES256 = "AES256"
    AWS_KMS = "aws:kms"
