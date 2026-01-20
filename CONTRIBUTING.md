# Contributing to ArgosCCF

First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to ArgosCCF. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Code of Conduct

This project is open source and we want to allow everyone to participate. Please be respectful and professional in all interactions.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for ArgosCCF. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

*   **Use a clear and descriptive title** for the issue to identify the problem.
*   **Describe the exact steps which reproduce the problem** in as many details as possible.
*   **Provide specific examples** to demonstrate the steps.
*   **Describe the behavior you observed** after following the steps.

### Pull Requests

*   Fork the repo and create your branch from `main`.
*   If you've added code that should be tested, add tests.
*   Ensure the test suite passes.
*   Make sure your code lints.
*   Issue that pull request!

## Coding Standards

*   **Style**: We follow standard PowerShell best practices. Use `PSScriptAnalyzer` to verify your code.
*   **Naming**: Use `Verb-Noun` syntax for all public functions. Private functions/helpers need not follow this strictly but should be descriptive.
*   **Documentation**: All public functions must have Comment-Based Help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`).

## Testing

We use [Pester](https://pester.dev/) for testing. Please ensure all existing tests pass and write new tests for your contributions.

```powershell
Invoke-Pester ./Tests
```
