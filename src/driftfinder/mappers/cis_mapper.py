from driftfinder.mappers.cis_mappings import CIS_MAPPINGS, CISControl


class CISMapper:
    """
    Looks up the CIS AWS Foundations Benchmark v3.0 control for a given
    NRM resource type and property name.
    """

    def get_control(self, resource_type: str, field_name: str) -> CISControl | None:
        """
        Return the CISControl for (resource_type, field_name), or None if unmapped.

        Args:
            resource_type: NRM class name, e.g. "NRMS3Bucket"
            field_name:    NRM property name, e.g. "server_side_encryption_enabled"
        """
        key = f"{resource_type}.{field_name}"
        return CIS_MAPPINGS.get(key)

    def all_controls_for_type(self, resource_type: str) -> dict[str, CISControl]:
        """Return all mappings for a given resource type keyed by field name."""
        prefix = f"{resource_type}."
        return {
            key[len(prefix) :]: control
            for key, control in CIS_MAPPINGS.items()
            if key.startswith(prefix)
        }
