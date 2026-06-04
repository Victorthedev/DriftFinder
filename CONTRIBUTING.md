# Contributing to DriftFinder

## Development setup

```bash
git clone https://github.com/wikiwoo/driftfinder
cd driftfinder
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Running tests

```bash
pytest tests/unit tests/integration          # no AWS credentials needed
pytest tests/e2e --localstack                # requires: docker-compose up localstack -d
```

## Adding a new resource type adapter

1. Add the NRM dataclass in `src/driftfinder/models/nrm.py`
2. Add CIS mappings in `src/driftfinder/mappers/cis_mappings.py`
3. Add the runtime querier in `src/driftfinder/runtime/aws/<resource>.py`
4. Add the Terraform type mapping in `src/driftfinder/parsers/terraform.py`
5. Add the CloudFormation type mapping in `src/driftfinder/parsers/cloudformation.py`
6. Add the Pulumi type mapping in `src/driftfinder/parsers/pulumi.py`
7. Add unit tests for all of the above
8. Add fixture files in `tests/fixtures/`

## Adding a new IaC parser

1. Create `src/driftfinder/parsers/<tool>.py` implementing `BaseParser`
2. Register the parser in `src/driftfinder/core/engine.py`
3. Add fixture files and unit tests

## Commit message format

```
type(scope): short description

body (optional)

Co-Authored-By: ...
```

Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`

## Code style

- Line length: 100
- Formatter: black
- Linter: ruff
- Type checker: mypy --strict (no untyped code)
- All public functions must have type annotations
