# ADR-002: NRM Design — Frozen Dataclasses

**Status:** Accepted  
**Date:** 2026-06-04

## Context

The Normalised Resource Model needs to represent declared and actual resource state.
Choices: Pydantic models, plain dicts, TypedDicts, or dataclasses.

## Decision

NRM objects use `@dataclass(frozen=True)`. Findings and config use Pydantic v2.

## Consequences

- Frozen dataclasses are hashable and immutable — once a declared or actual NRM
  object is created, it cannot be mutated, preventing accidental state corruption
- Pydantic is reserved for I/O boundary types (config files, JSON output) where
  runtime validation and serialisation matter
- The NRM schema is the core research contribution; frozen dataclasses make the
  immutability guarantee explicit and enforceable at the Python level
