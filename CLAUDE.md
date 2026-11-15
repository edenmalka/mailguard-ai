# CLAUDE.md

Project rules for working on MailGuard AI.

## Workflow

- Work in small, testable steps.
- Explain each step briefly before writing code.
- Wait for approval before starting the next step.
- Never claim something works without testing it. Report test results as they are, including failures.

## Security

- Use secure engineering practices.
- Never hardcode secrets (API keys, tokens, passwords). Load them from environment variables or a secrets manager, and keep them out of version control.
- Never expose private email data in logs, error messages, test fixtures, or commits.

## Code Quality

- Keep code, comments, and documentation in English.
- Prefer simple, maintainable solutions over clever or complex ones.
