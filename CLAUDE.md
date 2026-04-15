# Python Automation Rules

## Standards
- Type hints on all function signatures.
- Docstrings on public functions (Google style).
- pathlib.Path over os.path for file operations.
- f-strings over .format() or concatenation.

## Automation Patterns
- Scripts must be idempotent: safe to run multiple times with same result.
- Log to stderr, output data to stdout. Enables piping.
- Config via environment variables or .env files. Never hardcoded paths.
- Handle file not found, permission errors, and network timeouts explicitly.
- Use argparse for CLI parameters. Include --dry-run flag for destructive operations.

## Data Processing
- pandas for tabular data. Read with explicit dtypes.
- Use context managers (with statements) for all file I/O.
- Large files: process in chunks. Never load entirely into memory without checking size.
- Save intermediate results for pipelines with 3+ steps.

## Dependencies
- requirements.txt or pyproject.toml for all dependencies. Pin versions.
- Virtual environments per project. Never install globally except CLI tools.

## Testing
- pytest for all tests. Name test files test_*.py.
- Test the happy path and at least one error case per function.
