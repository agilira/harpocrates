# Contributing to Harpocrates

First, thank you for considering contributing to Harpocrates. We appreciate the time and effort you are willing to invest. This document outlines the guidelines for contributing to the project to ensure a smooth and effective process for everyone involved.

## How to Contribute

We welcome contributions in various forms, including:
- Reporting bugs
- Suggesting enhancements
- Improving documentation
- Submitting code changes

### Reporting Bugs

If you encounter a bug, please open an issue on our GitHub repository. A well-documented bug report is crucial for a swift resolution. Please include the following information:

- **Go Version**: The output of `go version`.
- **Operating System**: Your OS and version (e.g., Ubuntu 22.04, macOS 12.6).
- **Clear Description**: A concise but detailed description of the bug.
- **Steps to Reproduce**: A minimal, reproducible example that demonstrates the issue. This could be a small Go program.
- **Expected vs. Actual Behavior**: What you expected to happen and what actually occurred.
- **Logs or Error Messages**: Any relevant logs or error output, formatted as code blocks.

### Suggesting Enhancements

If you have an idea for a new feature or an improvement to an existing one, please open an issue to start a discussion. This allows us to align on the proposal before any significant development work begins.

## Requirements for Acceptable Contributions

All contributions must meet the following mandatory requirements:

### Code Quality Standards
- **Makefile Compliance**: All code must pass `make check` which includes:
  - Go formatting (`gofmt`, `goimports`)
  - Linting (`golint`, `go vet`)
  - Security analysis (`gosec`, `govulncheck`)
  - Static analysis (`staticcheck`, CodeQL)
- **Documentation**: Public functions and types must have proper Go documentation comments

### Security Requirements
- **Security Review**: All cryptographic changes require security review
- **Vulnerability Scanning**: Code must pass `govulncheck` vulnerability scanning
- **Input Validation**: All public APIs must validate inputs and handle errors securely
- **Memory Safety**: No unsafe operations without explicit security justification
- **Side-Channel Resistance**: Cryptographic code must consider timing attack resistance

### Testing Requirements
- **All Tests Must Pass**: Run `make test` - all tests must pass before submission
- **Security Checks**: Run `make security` - no security issues allowed
- **Code Coverage**: Minimum 90% test coverage for new code
- **Quality Gates**: All `make check` targets must pass

### Legal Requirements - Developer Certificate of Origin (DCO)

#### Philosophy
We welcome contributions from everyone - creativity is not bound by titles or credentials. However, final implementation decisions remain with the AGILira team to ensure project coherence and security standards.

#### Developer Certificate of Origin
By contributing to this project, you certify that:

1. The contribution was created in whole or in part by you and you have the right to submit it under the open source license indicated in the file; or
2. The contribution is based upon previous work that, to the best of your knowledge, is covered under an appropriate open source license and you have the right under that license to submit that work with modifications, whether created in whole or in part by you; or
3. The contribution was provided directly to you by some other person who certified (1), (2) or (3) and you have not modified it.
4. You understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information you submit with it, including your sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.

#### How to Sign Your Commits
All commits must be signed off to indicate acceptance of the DCO:

```bash
git commit -s -m "Your commit message"
```

Or add manually:
```bash
git commit -m "Your commit message

Signed-off-by: Your Name <your.email@example.com>"
```

#### Additional Legal Requirements
- **License Compliance**: All contributions must be compatible with Mozilla Public License 2.0
- **Copyright Headers**: New files must include proper copyright headers
- **No Proprietary Code**: Contributions must not include proprietary or copyrighted code
- **AGILira Decision Authority**: Final implementation decisions remain with AGILira team

## Development Process

1.  **Fork the Repository**: Start by forking the main Harpocrates repository to your own GitHub account.
2.  **Clone Your Fork**: Clone your forked repository to your local machine.
    ```bash
    git clone https://github.com/YOUR_USERNAME/harpocrates.git
    cd harpocrates
    ```
3.  **Create a Branch**: Create a new branch for your changes. Use a descriptive name (e.g., `fix/security-validation` or `feature/key-rotation`).
    ```bash
    git checkout -b your-branch-name
    ```
4.  **Make Changes**: Write your code following the requirements above.
5.  **Run Quality Checks**: Ensure your code meets all quality standards by running:
    ```bash
    make test        # Run all tests
    make lint        # Run linting and formatting checks
    make security    # Run security analysis
    make check       # Run all quality checks
    ```
8.  **Sign and Commit Your Changes**: Use DCO sign-off with conventional commit format:
    ```bash
    git commit -s -m "feat: Add HKDF key derivation support

    - Implement RFC 5869 compliant HKDF-SHA256
    - Add comprehensive security tests
    - Include fuzz testing for edge cases
    - Update documentation and examples

    Signed-off-by: Your Name <your.email@example.com>"
    ```
9.  **Push to Your Fork**: Push your changes to your forked repository.
    ```bash
    git push origin your-branch-name
    ```
10. **Open a Pull Request**: Open a pull request from your branch to the `main` branch, ensuring all CI checks pass.

## Coding Standards

### Go Style Guidelines
- Follow [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use meaningful variable and function names
- Prefer composition over inheritance
- Keep functions small and focused (max 50 lines recommended)
- Use Go modules for dependency management

### Error Handling
- Always handle errors explicitly
- Use structured errors with proper error codes
- Provide context in error messages
- Avoid panic() in library code

### Security Coding Practices
- Validate all inputs at API boundaries
- Use secure random number generation (`crypto/rand`)
- Clear sensitive data from memory when possible
- Avoid timing-dependent operations in cryptographic code
- Use constant-time comparisons for sensitive data

### Documentation Standards
- All public APIs must have godoc comments
- Include usage examples in complex functions
- Document security considerations for cryptographic functions
- Keep README.md updated with new features

## Pull Request Guidelines

- **One PR per Feature**: Each pull request should address a single bug or feature
- **Clear Description**: Explain the "what" and "why" of your changes
- **Passing Tests**: Ensure that the full test suite passes with `make test`
- **Security Review**: Cryptographic changes require additional security review
- **Documentation**: Update relevant documentation (in-code comments, `README.md`, or `docs/` directory)
- **Performance**: Include benchmarks for performance-critical changes
- **Breaking Changes**: Clearly document any breaking API changes

## Security Vulnerability Reports

For security vulnerabilities, please follow our [Security Policy](SECURITY.md):
- Use GitHub Security Advisories for private reporting
- Email security@agilira.com for urgent issues
- Allow 90 days for coordinated disclosure

Thank you for helping make Harpocrates better!
