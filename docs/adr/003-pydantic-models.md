# ADR-003: None vs False for Undeclared Properties

**Status:** Accepted  
**Date:** 2026-06-04

## Context

IaC templates frequently omit properties that have AWS default values.
A CloudFormation template without `ServerSideEncryptionConfiguration` may still
result in an encrypted bucket if an account-level default is set.

## Decision

- `None` = property was not declared in the IaC source (absence of intent)
- `False` = property was explicitly declared as disabled or absent

When `declared_value is None`, the drift engine skips the comparison for that
property. This prevents false positives from properties the author chose not to
declare (relying on defaults), which they may have done intentionally.

## Consequences

- Reduces false positives for CloudFormation templates that rely on AWS defaults
- Requires parsers to be precise: only set a property to `False` when the IaC
  source explicitly sets it to a falsy value, not when the property is absent
- A WARNING-level finding type (`DriftType.UNMANAGED`) is used when a property
  is `None` in declared state but non-compliant in actual state — this surfaces
  the risk without calling it drift
