# MrWhoOidc.Client Migration Plan

## Overview

This document outlines the migration of `MrWhoOidc.Client` (and its dependency `MrWhoOidc.Security`) from the private `MrWhoOidc` repository to the public `MrWho` repository. The goal is to make these packages available as free, open-source NuGet packages.

**Migration Date:** January 2, 2026  
**Status:** Planning Phase

---

## Table of Contents

1. [Scope & Objectives](#scope--objectives)
2. [Current State Analysis](#current-state-analysis)
3. [Target Repository Structure](#target-repository-structure)
4. [Migration Steps](#migration-steps)
5. [GitHub Actions Workflows](#github-actions-workflows)
6. [NuGet Package Configuration](#nuget-package-configuration)
7. [Documentation Updates](#documentation-updates)
8. [Testing Strategy](#testing-strategy)
9. [Rollout Checklist](#rollout-checklist)
10. [Post-Migration Tasks](#post-migration-tasks)

---

## Scope & Objectives

### In Scope

- Copy `MrWhoOidc.Client` project to `MrWho` repository
- Copy `MrWhoOidc.Security` project (dependency of Client)
- Set up GitHub Actions for CI/CD build pipeline
- Configure NuGet package publishing to nuget.org
- Update package metadata for open-source distribution
- Create solution file for the client packages
- Add necessary documentation

### Out of Scope

- Removing packages from `MrWhoOidc` repository (phase 2)
- Breaking changes to existing API surface
- Server-side components
- Unit tests migration (phase 2 consideration)

### Objectives

1. **Open-Source Availability**: Make client libraries freely available under MIT license
2. **Public NuGet Packages**: Publish to nuget.org for easy consumption
3. **Independent Versioning**: Allow client packages to version independently from server
4. **Community Contributions**: Enable external contributions to client libraries

---

## Current State Analysis

### MrWhoOidc.Client

**Location:** `MrWhoOidc/MrWhoOidc.Client/`

**Project Structure:**
```
MrWhoOidc.Client/
├── Authorization/
│   ├── AuthorizationCallbackResult.cs
│   ├── AuthorizationRequestContext.cs
│   ├── AuthorizationRequestOptions.cs
│   ├── IMrWhoAuthorizationManager.cs
│   └── MrWhoAuthorizationManager.cs
├── DependencyInjection/
├── Discovery/
│   ├── IMrWhoDiscoveryClient.cs
│   ├── MrWhoDiscoveryClient.cs
│   └── MrWhoDiscoveryDocument.cs
├── Http/
├── Jwks/
├── Logout/
│   ├── BackchannelLogoutValidationResult.cs
│   ├── FrontChannelLogoutOptions.cs
│   ├── FrontChannelLogoutRequest.cs
│   ├── IMrWhoLogoutManager.cs
│   └── MrWhoLogoutManager.cs
├── Options/
├── Properties/
├── Tokens/
│   ├── ClientCredentialsRequest.cs
│   ├── IMrWhoClientCredentialsManager.cs
│   ├── IMrWhoOnBehalfOfManager.cs
│   ├── IMrWhoTokenClient.cs
│   ├── MrWhoClientCredentialsManager.cs
│   ├── MrWhoOnBehalfOfManager.cs
│   ├── MrWhoTokenClient.cs
│   ├── TokenExchangeRequest.cs
│   └── TokenResult.cs
├── Class1.cs
├── MrWhoOidc.Client.csproj
├── MrWhoOidcClientDefaults.cs
└── README.md
```

**Current Package Configuration:**
- Target Framework: `net10.0`
- Package ID: `MrWhoOidc.Client`
- Version: `0.1.0`
- Repository URL: Points to private `MrWhoOidc` repo

**Dependencies:**
- `Microsoft.Extensions.Caching.Memory` (10.0.1)
- `Microsoft.Extensions.Http` (10.0.1)
- `Microsoft.Extensions.Http.Resilience` (10.1.0)
- `Microsoft.Extensions.Logging.Abstractions` (10.0.1)
- `Microsoft.Extensions.Options.ConfigurationExtensions` (10.0.1)
- `System.IdentityModel.Tokens.Jwt` (8.15.0)
- **Project Reference:** `MrWhoOidc.Security`

### MrWhoOidc.Security

**Location:** `MrWhoOidc/MrWhoOidc.Security/`

**Project Structure:**
```
MrWhoOidc.Security/
├── DPoP.cs
├── DPoPProofGenerator.cs
└── MrWhoOidc.Security.csproj
```

**Current Package Configuration:**
- Target Framework: `net10.0`
- No NuGet package metadata (needs to be added)

**Dependencies:**
- `System.IdentityModel.Tokens.Jwt` (8.15.0)
- `Microsoft.AspNetCore.App` (FrameworkReference)

---

## Target Repository Structure

After migration, the `MrWho` repository will have this structure:

```
MrWho/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── workflows/
│   │   ├── build.yml              # NEW: CI build workflow
│   │   ├── release.yml            # NEW: NuGet publish workflow
│   │   └── codeql.yml             # NEW: Security scanning (optional)
│   └── REPOSITORY_METADATA.md
├── certs/
├── demos/
├── docs/
│   ├── admin-guide.md
│   ├── configuration-reference.md
│   ├── ... (existing docs)
│   ├── client-sdk-guide.md        # NEW: Client SDK documentation
│   └── mrwhooidc-client-migration-plan.md  # This document
├── scripts/
├── src/                            # NEW: Source code directory
│   ├── MrWhoOidc.Client/          # Migrated project
│   │   ├── Authorization/
│   │   ├── DependencyInjection/
│   │   ├── Discovery/
│   │   ├── Http/
│   │   ├── Jwks/
│   │   ├── Logout/
│   │   ├── Options/
│   │   ├── Properties/
│   │   ├── Tokens/
│   │   ├── MrWhoOidc.Client.csproj
│   │   ├── MrWhoOidcClientDefaults.cs
│   │   └── README.md
│   └── MrWhoOidc.Security/        # Migrated project
│       ├── DPoP.cs
│       ├── DPoPProofGenerator.cs
│       └── MrWhoOidc.Security.csproj
├── tests/                          # NEW: Test projects (future)
│   └── .gitkeep
├── .env.example
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── docker-compose*.yml
├── LICENSE
├── MrWho.sln                       # NEW: Solution file
├── Directory.Build.props           # NEW: Shared build properties
├── Directory.Packages.props        # NEW: Central package management
├── nuget.config                    # NEW: NuGet configuration
├── README.md
├── SECURITY.md
└── version.json                    # NEW: Nerdbank.GitVersioning (optional)
```

---

## Migration Steps

### Step 1: Create Directory Structure

```powershell
# In MrWho repository root
mkdir src
mkdir src/MrWhoOidc.Client
mkdir src/MrWhoOidc.Security
mkdir tests
```

### Step 2: Copy Source Files

Copy the following from `MrWhoOidc` to `MrWho/src`:

```powershell
# Copy MrWhoOidc.Client (excluding bin/obj)
Copy-Item -Path "MrWhoOidc/MrWhoOidc.Client/*" -Destination "MrWho/src/MrWhoOidc.Client/" -Recurse -Exclude "bin","obj"

# Copy MrWhoOidc.Security (excluding bin/obj)
Copy-Item -Path "MrWhoOidc/MrWhoOidc.Security/*" -Destination "MrWho/src/MrWhoOidc.Security/" -Recurse -Exclude "bin","obj"
```

### Step 3: Create Solution File

Create `MrWho.sln` in the repository root:

```xml
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "MrWhoOidc.Client", "src\MrWhoOidc.Client\MrWhoOidc.Client.csproj", "{GUID-CLIENT}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "MrWhoOidc.Security", "src\MrWhoOidc.Security\MrWhoOidc.Security.csproj", "{GUID-SECURITY}"
EndProject
Global
    GlobalSection(SolutionConfigurationPlatforms) = preSolution
        Debug|Any CPU = Debug|Any CPU
        Release|Any CPU = Release|Any CPU
    EndGlobalSection
    GlobalSection(ProjectConfigurationPlatforms) = postSolution
        {GUID-CLIENT}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
        {GUID-CLIENT}.Debug|Any CPU.Build.0 = Debug|Any CPU
        {GUID-CLIENT}.Release|Any CPU.ActiveCfg = Release|Any CPU
        {GUID-CLIENT}.Release|Any CPU.Build.0 = Release|Any CPU
        {GUID-SECURITY}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
        {GUID-SECURITY}.Debug|Any CPU.Build.0 = Debug|Any CPU
        {GUID-SECURITY}.Release|Any CPU.ActiveCfg = Release|Any CPU
        {GUID-SECURITY}.Release|Any CPU.Build.0 = Release|Any CPU
    EndGlobalSection
EndGlobal
```

### Step 4: Create Directory.Build.props

Create shared build properties at repository root:

```xml
<Project>
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>
    
    <!-- Package metadata -->
    <Authors>MrWho Platform Team</Authors>
    <Company>MrWho</Company>
    <Copyright>Copyright © 2025-2026 MrWho Contributors</Copyright>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
    <PackageProjectUrl>https://github.com/popicka70/MrWho</PackageProjectUrl>
    <RepositoryUrl>https://github.com/popicka70/MrWho</RepositoryUrl>
    <RepositoryType>git</RepositoryType>
    
    <!-- Source Link for debugging -->
    <PublishRepositoryUrl>true</PublishRepositoryUrl>
    <EmbedUntrackedSources>true</EmbedUntrackedSources>
    <IncludeSymbols>true</IncludeSymbols>
    <SymbolPackageFormat>snupkg</SymbolPackageFormat>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.SourceLink.GitHub" Version="8.0.0" PrivateAssets="All"/>
  </ItemGroup>
</Project>
```

### Step 5: Create Directory.Packages.props (Central Package Management)

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <!-- Core dependencies -->
    <PackageVersion Include="Microsoft.Extensions.Caching.Memory" Version="9.0.0" />
    <PackageVersion Include="Microsoft.Extensions.Http" Version="9.0.0" />
    <PackageVersion Include="Microsoft.Extensions.Http.Resilience" Version="9.0.0" />
    <PackageVersion Include="Microsoft.Extensions.Logging.Abstractions" Version="9.0.0" />
    <PackageVersion Include="Microsoft.Extensions.Options.ConfigurationExtensions" Version="9.0.0" />
    <PackageVersion Include="System.IdentityModel.Tokens.Jwt" Version="8.3.0" />
    
    <!-- Build tooling -->
    <PackageVersion Include="Microsoft.SourceLink.GitHub" Version="8.0.0" />
  </ItemGroup>
</Project>
```

> **Note:** Downgrading from net10.0 to net9.0 and adjusting package versions to stable releases for broader compatibility. This can be updated later.

### Step 6: Update Project Files

#### MrWhoOidc.Client.csproj (Updated)

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
    <GeneratePackageOnBuild>true</GeneratePackageOnBuild>
    <PackageId>MrWhoOidc.Client</PackageId>
    <Description>Client SDK for integrating .NET applications with OIDC providers. Features discovery caching, token management, JAR/JARM support, DPoP, and logout handling.</Description>
    <PackageTags>oidc;oauth2;openid-connect;authentication;authorization;token-client;discovery;jwks;dpop</PackageTags>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <PackageIcon>icon.png</PackageIcon>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.Extensions.Caching.Memory" />
    <PackageReference Include="Microsoft.Extensions.Http" />
    <PackageReference Include="Microsoft.Extensions.Http.Resilience" />
    <PackageReference Include="Microsoft.Extensions.Logging.Abstractions" />
    <PackageReference Include="Microsoft.Extensions.Options.ConfigurationExtensions" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\MrWhoOidc.Security\MrWhoOidc.Security.csproj" />
  </ItemGroup>

  <ItemGroup>
    <None Include="README.md" Pack="true" PackagePath="/" />
    <None Include="../../assets/icon.png" Pack="true" PackagePath="/" Condition="Exists('../../assets/icon.png')" />
  </ItemGroup>
</Project>
```

#### MrWhoOidc.Security.csproj (Updated)

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
    <GeneratePackageOnBuild>true</GeneratePackageOnBuild>
    <PackageId>MrWhoOidc.Security</PackageId>
    <Description>Security utilities for OIDC/OAuth2 including DPoP proof generation and validation.</Description>
    <PackageTags>oidc;oauth2;security;dpop;jwt</PackageTags>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <PackageIcon>icon.png</PackageIcon>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" />
  </ItemGroup>

  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>

  <ItemGroup>
    <None Include="README.md" Pack="true" PackagePath="/" />
    <None Include="../../assets/icon.png" Pack="true" PackagePath="/" Condition="Exists('../../assets/icon.png')" />
  </ItemGroup>
</Project>
```

### Step 7: Update .gitignore

Add the following to `.gitignore`:

```gitignore
# Build outputs
**/bin/
**/obj/
**/out/

# NuGet
*.nupkg
*.snupkg
.nuget/

# IDE
.vs/
*.user
*.suo
.idea/

# Test results
**/TestResults/
```

---

## GitHub Actions Workflows

### Build Workflow (.github/workflows/build.yml)

```yaml
name: Build

on:
  push:
    branches: [main, develop]
    paths:
      - 'src/**'
      - '*.props'
      - '*.sln'
  pull_request:
    branches: [main]
    paths:
      - 'src/**'
      - '*.props'
      - '*.sln'

env:
  DOTNET_SKIP_FIRST_TIME_EXPERIENCE: true
  DOTNET_CLI_TELEMETRY_OPTOUT: true

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        dotnet-version: ['8.0.x', '9.0.x']
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup .NET ${{ matrix.dotnet-version }}
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: ${{ matrix.dotnet-version }}

      - name: Restore dependencies
        run: dotnet restore MrWho.sln

      - name: Build
        run: dotnet build MrWho.sln --configuration Release --no-restore

      - name: Test
        run: dotnet test MrWho.sln --configuration Release --no-build --verbosity normal
        if: hashFiles('tests/**/*.csproj') != ''

      - name: Pack
        run: dotnet pack MrWho.sln --configuration Release --no-build --output ./artifacts

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: nuget-packages-${{ matrix.dotnet-version }}
          path: ./artifacts/*.nupkg
          retention-days: 7
```

### Release Workflow (.github/workflows/release.yml)

```yaml
name: Release to NuGet

on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to publish (e.g., 1.0.0)'
        required: true
        type: string

permissions:
  contents: read
  packages: write

env:
  DOTNET_SKIP_FIRST_TIME_EXPERIENCE: true
  DOTNET_CLI_TELEMETRY_OPTOUT: true

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: nuget-publish
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '9.0.x'

      - name: Determine version
        id: version
        run: |
          if [ "${{ github.event_name }}" == "release" ]; then
            VERSION="${{ github.event.release.tag_name }}"
            VERSION="${VERSION#v}"
          else
            VERSION="${{ github.event.inputs.version }}"
          fi
          echo "version=$VERSION" >> $GITHUB_OUTPUT
          echo "Publishing version: $VERSION"

      - name: Restore dependencies
        run: dotnet restore MrWho.sln

      - name: Build
        run: dotnet build MrWho.sln --configuration Release --no-restore /p:Version=${{ steps.version.outputs.version }}

      - name: Pack
        run: |
          dotnet pack src/MrWhoOidc.Security/MrWhoOidc.Security.csproj \
            --configuration Release \
            --no-build \
            --output ./artifacts \
            /p:PackageVersion=${{ steps.version.outputs.version }}
          
          dotnet pack src/MrWhoOidc.Client/MrWhoOidc.Client.csproj \
            --configuration Release \
            --no-build \
            --output ./artifacts \
            /p:PackageVersion=${{ steps.version.outputs.version }}

      - name: Push to NuGet.org
        run: |
          dotnet nuget push ./artifacts/*.nupkg \
            --api-key ${{ secrets.NUGET_API_KEY }} \
            --source https://api.nuget.org/v3/index.json \
            --skip-duplicate

      - name: Push to GitHub Packages
        run: |
          dotnet nuget push ./artifacts/*.nupkg \
            --api-key ${{ secrets.GITHUB_TOKEN }} \
            --source https://nuget.pkg.github.com/popicka70/index.json \
            --skip-duplicate

      - name: Upload release artifacts
        uses: actions/upload-artifact@v4
        with:
          name: nuget-packages-${{ steps.version.outputs.version }}
          path: ./artifacts/*.*nupkg
          retention-days: 90
```

---

## NuGet Package Configuration

### Create nuget.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
```

### GitHub Repository Settings

1. **Create Environment:** `nuget-publish`
   - Add required reviewers (optional)
   - Add protection rules

2. **Add Secrets:**
   - `NUGET_API_KEY` - API key from nuget.org with push permissions

### NuGet.org Setup

1. **Create/Login to nuget.org account**
2. **Reserve Package IDs:**
   - `MrWhoOidc.Client`
   - `MrWhoOidc.Security`
3. **Generate API Key:**
   - Scope: Push new packages and package versions
   - Glob pattern: `MrWhoOidc.*`
   - Expiration: 365 days (set reminder to rotate)

---

## Documentation Updates

### New Files to Create

1. **`docs/client-sdk-guide.md`** - Comprehensive usage guide
2. **`src/MrWhoOidc.Security/README.md`** - Package-specific readme
3. **`assets/icon.png`** - NuGet package icon (128x128 PNG)

### Files to Update

1. **`README.md`** - Add NuGet badges and client SDK section
2. **`CHANGELOG.md`** - Add migration entry
3. **`CONTRIBUTING.md`** - Add build instructions for client packages

### README.md Badge Section

```markdown
[![NuGet - MrWhoOidc.Client](https://img.shields.io/nuget/v/MrWhoOidc.Client?label=MrWhoOidc.Client&logo=nuget)](https://www.nuget.org/packages/MrWhoOidc.Client/)
[![NuGet - MrWhoOidc.Security](https://img.shields.io/nuget/v/MrWhoOidc.Security?label=MrWhoOidc.Security&logo=nuget)](https://www.nuget.org/packages/MrWhoOidc.Security/)
```

---

## Testing Strategy

### Local Build Verification

```powershell
# Clone fresh and build
git clone https://github.com/popicka70/MrWho.git
cd MrWho
dotnet restore
dotnet build --configuration Release
dotnet pack --configuration Release --output ./artifacts
```

### Package Verification

```powershell
# Install local package for testing
dotnet new console -n TestConsumer
cd TestConsumer
dotnet add package MrWhoOidc.Client --source ../artifacts
```

### Integration Testing (Future)

- Add test project consuming the packages
- Verify against running MrWhoOidc server
- Automated integration tests in CI

---

## Rollout Checklist

### Pre-Migration

- [ ] Review and approve this plan
- [ ] Create nuget.org account (if not exists)
- [ ] Reserve package IDs on nuget.org
- [ ] Generate and securely store NUGET_API_KEY
- [ ] Create `assets/icon.png` (package icon)
- [ ] Review licensing - ensure MIT is appropriate

### Migration Execution

- [ ] Create `src/` directory structure
- [ ] Copy `MrWhoOidc.Client` source files
- [ ] Copy `MrWhoOidc.Security` source files
- [ ] Remove `Class1.cs` if it's placeholder code
- [ ] Create `MrWho.sln`
- [ ] Create `Directory.Build.props`
- [ ] Create `Directory.Packages.props`
- [ ] Create `nuget.config`
- [ ] Update `.gitignore`
- [ ] Update project files with new configuration
- [ ] Fix relative project references
- [ ] Create `src/MrWhoOidc.Security/README.md`
- [ ] Local build verification

### CI/CD Setup

- [ ] Create `.github/workflows/build.yml`
- [ ] Create `.github/workflows/release.yml`
- [ ] Configure `nuget-publish` environment in GitHub
- [ ] Add `NUGET_API_KEY` secret
- [ ] Verify build workflow passes
- [ ] Test release workflow with pre-release version

### Documentation

- [ ] Create `docs/client-sdk-guide.md`
- [ ] Update `README.md` with NuGet badges
- [ ] Update `CHANGELOG.md`
- [ ] Update `CONTRIBUTING.md`

### First Release

- [ ] Create GitHub release (e.g., `v1.0.0`)
- [ ] Verify packages published to nuget.org
- [ ] Verify packages work in clean project
- [ ] Announce availability

---

## Post-Migration Tasks

### Phase 2 Considerations

1. **Deprecate in MrWhoOidc:** Update MrWhoOidc to reference public NuGet packages instead of local projects
2. **Test Migration:** Add unit tests from MrWhoOidc to MrWho
3. **Documentation Sync:** Ensure docs in both repos are consistent
4. **Version Strategy:** Define semantic versioning policy

### Maintenance

- Monitor NuGet download stats
- Set up Dependabot for dependency updates
- Review and triage community issues
- Rotate NUGET_API_KEY annually

### Future Enhancements

- Add .NET MAUI / Blazor examples
- Source generator for configuration validation
- Additional authentication flows
- Performance benchmarks

---

## References

- [NuGet Package Publishing](https://docs.microsoft.com/nuget/nuget-org/publish-a-package)
- [GitHub Actions for .NET](https://docs.microsoft.com/dotnet/devops/github-actions-overview)
- [Central Package Management](https://docs.microsoft.com/nuget/consume-packages/central-package-management)
- [Source Link](https://docs.microsoft.com/dotnet/standard/library-guidance/sourcelink)

---

*Last Updated: January 2, 2026*
