# Contributing to MrWhoOidc

Thank you for your interest in contributing to MrWhoOidc! We welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and considerate
- Welcome newcomers and help them get started
- Focus on what is best for the community
- Show empathy towards other community members
- Accept constructive criticism gracefully

## Getting Started

1. **Read the Documentation**
   - [README.md](README.md) - Project overview and quick start
   - [Developer Guide](docs/developer-guide.md) - Integration details
   - [Architecture Documentation](docs/) - Technical documentation

2. **Set Up Your Environment**
   - See [Development Setup](#development-setup) below

3. **Find an Issue**
   - Browse [open issues](https://github.com/popicka70/mrwhooidc/issues)
   - Look for `good first issue` or `help wanted` labels
   - Ask questions in [Discussions](https://github.com/popicka70/mrwhooidc/discussions)

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating an issue
3. **Include:**
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Docker version, etc.)
   - Relevant logs (sanitized, no secrets!)

### Suggesting Features

1. **Check existing issues** and [Discussions](https://github.com/popicka70/mrwhooidc/discussions)
2. **Use the feature request template**
3. **Explain:**
   - The problem your feature solves
   - Your proposed solution
   - Why it would be valuable to the community
   - Any implementation ideas

### Code Contributions

We welcome:
- Bug fixes
- New features (discuss first in an issue)
- Documentation improvements
- Test coverage improvements
- Performance optimizations
- Security enhancements

## Development Setup

### Prerequisites

- **.NET 10 SDK**
- **Docker** 20.10+ and **Docker Compose** V2+
- **PostgreSQL** 16+ if you are not using Docker
- **Git** for version control
- **Visual Studio 2022**, **VS Code**, or **Rider**

### Clone and Build

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/mrwhooidc.git
cd mrwhooidc

# Add upstream remote
git remote add upstream https://github.com/popicka70/mrwhooidc.git

# Build the solution
dotnet build

# Run tests
dotnet test
```

### Local Development

For the public repo itself, the usual contribution workflows are:

```bash
# update docs / packages / demos in this repo
dotnet build ./MrWhoOidc.Client.sln
```

If you are validating deployment examples, use the Docker Compose assets in this repository:

```bash
./scripts/generate-cert.sh localhost changeit
cp .env.example .env
docker compose up -d
```

### Project Structure

```
MrWho/
├── docs/                      # public operational and integration documentation
├── demos/                     # demo applications and sample API
├── src/MrWhoOidc.Client/      # public .NET client package
├── src/MrWhoOidc.Security/    # public .NET security helpers
├── scripts/                   # certificate generation and health tooling
├── docker-compose*.yml        # public deployment assets
└── website/                   # static GitHub Pages site
```

## Coding Standards

### General Guidelines

- Follow **C# coding conventions** and **.NET best practices**
- Use **meaningful variable and method names**
- Write **clean, readable code** with appropriate comments
- Keep methods **focused and concise** (Single Responsibility Principle)
- Handle errors appropriately with **structured logging**

### Specific Rules

1. **No External OIDC Libraries**
   - Do NOT add OpenIddict or Microsoft.Identity dependencies
   - Implement OIDC/OAuth protocols directly

2. **Project Separation**
   - Core domain logic → `MrWhoOidc.Auth`
   - HTTP endpoints/UI → `MrWhoOidc.WebAuth`
   - Security utilities → `MrWhoOidc.Security`

3. **Public repo quality**
   - Keep docs aligned with the currently shipping product line
   - Do not leave internal planning notes in long-lived public docs
   - Prefer runnable, copy-paste-safe examples over aspirational examples

4. **Security**
   - Use **Argon2id or BCrypt** for password hashing
   - Never log secrets, passwords, or refresh tokens
   - Validate all OIDC/OAuth parameters
   - Emit RFC-compliant error responses

5. **Testing**
   - Write **unit tests** for new features
   - Include **integration tests** for OIDC flows
   - Ensure **existing tests pass** before submitting PR
   - Aim for **80%+ code coverage** on new code

### Code Formatting

```bash
dotnet format
dotnet format --verify-no-changes
```

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style/formatting (no logic changes)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, tooling

**Examples:**

```
feat(auth): add device authorization flow (RFC 8628)

Implements device code grant for IoT devices and TV apps.
Adds /device-authorization and /device-token endpoints.

Closes #123
```

```
fix(token): handle refresh token rotation edge case

Fixes issue where concurrent refresh requests could
invalidate all tokens.

Fixes #456
```

```
docs(readme): update quick start with ARM64 instructions

Clarifies deployment steps for Apple Silicon Macs.
```

### Commit Best Practices

- Use **present tense** ("add feature" not "added feature")
- Use **imperative mood** ("move cursor to..." not "moves cursor to...")
- Keep **subject line under 72 characters**
- Reference **issue numbers** in footer
- Write **meaningful commit messages** (not "fix stuff" or "wip")

## Pull Request Process

### Before Submitting

1. **Create a feature branch**
   ```bash
   git checkout -b feature/device-auth-flow
   ```

2. **Make your changes** following coding standards

3. **Write/update tests**
   ```bash
   dotnet test
   ```

4. **Update documentation** if needed (README, docs/, code comments)

5. **Format your code**
   ```bash
   dotnet format
   ```

6. **Commit your changes** following commit guidelines

7. **Sync with upstream**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### Submitting the PR

1. **Push to your fork**
   ```bash
   git push origin feature/device-auth-flow
   ```

2. **Create Pull Request** on GitHub

3. **Fill out the PR template** with:
   - Description of changes
   - Related issue number(s)
   - Testing performed
   - Screenshots (if UI changes)
   - Breaking changes (if any)

4. **Wait for review**
   - Address reviewer comments
   - Make requested changes
   - Push updates to same branch (PR auto-updates)

### PR Requirements

- ✅ All tests must pass
- ✅ Code coverage maintained or improved
- ✅ No merge conflicts with `main`
- ✅ Documentation updated if needed
- ✅ Commit messages follow guidelines
- ✅ Code follows project conventions
- ✅ At least one maintainer approval

### After Merge

- Delete your feature branch
- Sync your fork with upstream
- Celebrate! 🎉

## Testing

### Running Tests

```bash
# Run all tests
dotnet test

# Run specific test project
dotnet test MrWhoOidc.UnitTests

# Run with coverage
dotnet test --collect:"XPlat Code Coverage"
```

### Writing Tests

- Place tests in `MrWhoOidc.UnitTests/`
- Use **MSTest** framework
- Follow **Arrange-Act-Assert** pattern
- Use meaningful test names: `MethodName_Scenario_ExpectedBehavior`

Example:

```csharp
[TestMethod]
public async Task TokenEndpoint_WithExpiredAuthCode_ReturnsInvalidGrant()
{
    // Arrange
    var expiredCode = CreateExpiredAuthorizationCode();
    
    // Act
    var result = await _tokenHandler.HandleAsync(expiredCode);
    
    // Assert
    Assert.AreEqual("invalid_grant", result.Error);
}
```

### Integration Tests

For E2E OIDC flows, see examples in `MrWhoOidc.UnitTests/Integration/`

## Documentation

### When to Update Documentation

- Adding new features → Update relevant docs
- Changing configuration → Update `docs/configuration-reference.md`
- Breaking changes → Update `CHANGELOG.md` and migration guide
- Bug fixes affecting user behavior → Update troubleshooting

### Documentation Standards

- Use **clear, concise language**
- Include **code examples** where applicable
- Add **screenshots** for UI changes
- Keep **Quick Start guide** up to date
- Test all documented commands/steps

### Building Documentation Locally

Documentation is in Markdown format in `/docs` directory. View in any Markdown viewer or GitHub.

## Community

### Getting Help

- **Discussions**: [GitHub Discussions](https://github.com/popicka70/mrwhooidc/discussions) for Q&A
- **Issues**: [GitHub Issues](https://github.com/popicka70/mrwhooidc/issues) for bugs/features
- **Documentation**: [docs/](docs/) for guides and references

### Staying Updated

- Watch the repository for updates
- Check [CHANGELOG.md](CHANGELOG.md) for changes
- Follow releases for new versions

## License

By contributing to MrWhoOidc, you agree that your contributions will be licensed under the same [MIT License](LICENSE) that covers the project.

---

**Thank you for contributing to MrWhoOidc!** 🙏

Your contributions help make identity and authentication accessible to everyone.

If you have questions about contributing, feel free to ask in [Discussions](https://github.com/popicka70/mrwhooidc/discussions).
