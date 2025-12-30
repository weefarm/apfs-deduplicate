# CrowCI Pipelines for apfs-deduplicate

This directory contains CrowCI pipeline configurations for the apfs-deduplicate Python project.

## Pipeline Structure

### Pipeline Files

- **`lint.yaml`**: Code quality and validation
  - Python syntax checking and compilation
  - Flake8 linting with custom rules
  - MyPy type checking
  - Shell script linting
  - YAML configuration validation
  - Import sorting validation

- **`test.yaml`**: Comprehensive testing
  - Python unit tests with coverage reporting
  - Integration tests with file operations
  - Test script validation
  - Performance benchmarking
  - Cross-platform compatibility checks

- **`build.yaml`**: Packaging and security
  - Python wheel and source distribution building
  - Package validation with Twine
  - Security scanning with Bandit
  - Dependency vulnerability checking
  - License compliance validation
  - Secret scanning with Gitleaks

- **`deploy.yaml`**: Release and mirroring
  - Release readiness validation
  - Release archive creation
  - PyPI upload simulation
  - GitHub release preparation
  - **GitHub repository mirroring**

### Pipeline Flow

```
lint.yaml → test.yaml → build.yaml → deploy.yaml
```

Each pipeline depends on the previous one, ensuring proper validation order and that only quality code reaches deployment.

### Triggers

All pipelines trigger on:
- **Push to main branch**
- **Pull requests**

The `deploy.yaml` pipeline only runs on pushes to main (production releases) and includes GitHub mirroring.

## Repository Mirroring

The `deploy.yaml` pipeline automatically mirrors commits to the GitHub repository:

- **Trigger**: Only on pushes to `main` branch
- **Target**: `git@github.com:weefarm/apfs-deduplicate.git`
- **Authentication**: Uses SSH key configured for GitHub access
- **Force Push**: Uses `--force` to ensure mirror stays in sync

This ensures the GitHub repository remains an up-to-date mirror of the primary Forgejo repository.

## Project Context

The apfs-deduplicate project is a Python tool for deduplicating files on APFS filesystems using copy-on-write capabilities. The pipelines are tailored for:

- **Python development**: Focus on code quality, type checking, and testing
- **Security**: Comprehensive scanning for vulnerabilities and secrets
- **Packaging**: Building distributable packages for PyPI
- **macOS/APFS specific**: Validates APFS-specific functionality

## Environment Variables

The pipelines use standard CrowCI environment variables and don't require special configuration beyond what's already set up in the CrowCI StatefulSet.

## Security

- Repository access is restricted to authorized users
- Secrets scanning prevents accidental commits of sensitive data
- All validation runs in isolated containers
- Security scans check for vulnerabilities in dependencies