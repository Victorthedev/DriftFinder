# ADR-001: Python First, TypeScript Second

**Status:** Accepted  
**Date:** 2026-06-04

## Context

DriftFinder needs to ship a dissertation proof-of-concept before a production tool.
The researcher has professional Python/AWS experience. A TypeScript SDK broadens
adoption in Node.js CI/CD pipelines (GitHub Actions, CDK tooling, etc.).

## Decision

Phase 1 is Python-only (`pip install driftfinder`).
Phase 2 adds a TypeScript SDK (`@driftfinder/sdk`) as a full reimplementation,
not a wrapper around the Python CLI.

## Consequences

- Phase 1 ships faster with a single language
- TypeScript SDK must duplicate the NRM and detection engine. This is intentional
  as it proves the NRM schema is language-portable (a dissertation contribution)
- Python 3.11+ minimum gives us modern union types and frozen dataclasses
