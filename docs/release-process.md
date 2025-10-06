# Release Process Documentation

## Overview

This document defines the formal release process for Harpocrates, including versioning strategy, security release procedures, and quality gates required for production deployments.

## Versioning Strategy

### Semantic Versioning (SemVer)

Harpocrates follows [Semantic Versioning 2.0.0](https://semver.org/) specification:

- **MAJOR.MINOR.PATCH** (e.g., 1.2.3)
- **MAJOR**: Breaking API changes or incompatible modifications
- **MINOR**: New functionality in a backward-compatible manner  
- **PATCH**: Backward-compatible bug fixes and security patches

### Version Examples
- `1.0.0` - Initial stable release
- `1.1.0` - New features (e.g., additional key derivation functions)
- `1.0.1` - Security patch or bug fix
- `2.0.0` - Breaking changes (e.g., API restructuring)

### Pre-release Versions
- **Alpha**: `1.1.0-alpha.1` - Early development, unstable API
- **Beta**: `1.1.0-beta.1` - Feature complete, testing phase
- **Release Candidate**: `1.1.0-rc.1` - Production-ready candidate

## Release Types

### 1. Regular Release
- **Frequency**: Monthly or feature-driven
- **Content**: New features, improvements, non-critical fixes
- **Testing**: Full test suite, performance benchmarks
- **Timeline**: 2-week development + 1-week testing

### 2. Security Release
- **Trigger**: Security vulnerabilities (CVE assignments)
- **Priority**: Critical (48h), High (7d), Medium/Low (30d)
- **Process**: Expedited testing, coordinated disclosure
- **Notification**: Security advisories, user notifications

### 3. Hotfix Release
- **Trigger**: Critical production issues
- **Timeline**: Same-day for P0, 48h for P1
- **Scope**: Minimal changes, targeted fixes only
- **Validation**: Reduced test suite, focus on regression prevention

## Release Process Workflow

### Phase 1: Preparation
1. **Version Planning**
   - Define release scope and version number
   - Create release milestone in GitHub
   - Update CHANGELOG.md with planned features

2. **Code Freeze**
   - Merge deadline for new features
   - Branch protection: only bug fixes allowed
   - Feature flags disabled for incomplete work

3. **Pre-release Testing**
   - Complete test suite execution (100% pass rate required)
   - Security scan validation (all tools: gosec, CodeQL, govulncheck)
   - Performance benchmark comparison (no regressions)
   - Red team security testing execution

### Phase 2: Quality Assurance
1. **Automated Validation**
   ```bash
   # Complete security and quality validation
   make security    # gosec, staticcheck, govulncheck
   make test        # Full test suite with race detection
   make fuzz        # Fuzz testing execution
   make benchmark   # Performance validation
   ```

2. **Manual Review**
   - Code review completion (100% coverage)
   - Security review for cryptographic changes
   - Documentation accuracy verification
   - API compatibility validation

3. **Integration Testing**
   - NEMESIS vault integration testing
   - Cross-platform compatibility (Linux, Windows, macOS)
   - Dependency compatibility validation
   - HSM plugin integration testing (if applicable)

### Phase 3: Release Execution
1. **Tag Creation**
   ```bash
   # Create signed release tag
   git tag -s v1.2.3 -m "Release v1.2.3: [Brief description]"
   git push origin v1.2.3
   ```

2. **Release Artifacts**
   - Automated GitHub release creation
   - Go module publication to proxy.golang.org
   - Cryptographic signatures for release assets
   - Release notes generation from CHANGELOG.md

3. **Release Validation**
   - Module availability verification (`go get github.com/agilira/harpocrates@v1.2.3`)
   - Signature verification confirmation
   - Release note accuracy review

### Phase 4: Post-Release
1. **Deployment Monitoring**
   - Download statistics monitoring
   - User feedback collection
   - Security vulnerability reporting channel monitoring

2. **Documentation Updates**
   - API documentation updates (if applicable)
   - Security analysis documentation updates
   - Integration guide updates for breaking changes

## Security Release Procedures

### Critical Security Vulnerabilities (CVSS ≥ 7.0)

#### Timeline: 48 Hours Maximum
1. **Hour 0**: Vulnerability confirmed and triaged
2. **Hour 2**: Security team assembled, impact assessment
3. **Hour 6**: Fix development and testing initiated  
4. **Hour 24**: Fix validation and security review completed
5. **Hour 36**: Release preparation and testing
6. **Hour 48**: Security release published

#### Process
1. **Private Development**
   - Fix development in private repository fork
   - Limited access: security team + core maintainers only
   - No public discussion until release

2. **Coordinated Disclosure**
   - Security advisory draft preparation
   - Affected user notification (if contact available)
   - CVE assignment coordination (if applicable)

3. **Emergency Release**
   - Expedited testing: focus on regression prevention
   - Security-only changes: minimal surface area
   - Immediate publication upon validation completion

### High/Medium Severity (CVSS 4.0-6.9)
- **Timeline**: 7 days for High, 30 days for Medium
- **Process**: Standard release process with security priority
- **Communication**: Security advisory + release notes

### Low Severity (CVSS < 4.0)
- **Timeline**: Next regular release cycle
- **Process**: Standard development workflow
- **Documentation**: Mention in release notes

## Quality Gates

### Mandatory Requirements
All releases must pass these quality gates:

1. **Test Coverage**: ≥90% statement coverage
2. **Security Scans**: Zero high-severity findings
3. **Performance**: No regressions >5% from baseline
4. **Documentation**: All public APIs documented
5. **Compatibility**: Backward compatibility maintained (non-major releases)

### Security-Specific Gates
1. **Vulnerability Scanning**: Clean govulncheck report
2. **Static Analysis**: Clean CodeQL + gosec reports
3. **Red Team Testing**: All security tests passing
4. **Cryptographic Review**: Security team approval for crypto changes

### Performance Gates
1. **Benchmark Validation**: All benchmarks within 5% of baseline
2. **Memory Usage**: No memory leaks detected
3. **Concurrent Safety**: Race condition testing passed
4. **Load Testing**: High-throughput scenarios validated

## Release Artifacts

### Primary Artifacts
1. **Go Module**: Published to Go module proxy
2. **Git Tag**: Signed with GPG key
3. **Release Notes**: Comprehensive changelog
4. **Security Advisory**: For security releases

### Signatures and Verification
1. **GPG Signatures**: All tags signed with project GPG key
2. **Checksums**: SHA256 hashes for all artifacts
3. **Provenance**: SLSA-compliant build attestation (planned)

### Verification Process
```bash
# Verify release signature
git tag -v v1.2.3

# Verify module checksum
go mod download -json github.com/agilira/harpocrates@v1.2.3
```

## Rollback Procedures

### Immediate Rollback (Critical Issues)
1. **Detection**: Automated monitoring or user reports
2. **Decision**: Within 2 hours of confirmed critical issue
3. **Execution**: 
   - Retract problematic version: `go mod edit -retract=v1.2.3`
   - Emergency patch release with fix
   - Public communication about the issue

### Planned Rollback (Compatibility Issues)
1. **Deprecation Notice**: Minimum 30 days advance notice
2. **Migration Guide**: Clear upgrade/downgrade instructions
3. **Support Window**: Extended support for previous version

## Communication Plan

### Release Announcements
1. **GitHub Releases**: Primary announcement channel
2. **Documentation**: Updated API documentation and guides
3. **Security Advisories**: For security-related releases
4. **Community**: Developer community notifications (if applicable)

### Emergency Communications
1. **Security Issues**: Immediate security advisory publication
2. **Critical Bugs**: GitHub issue with hotfix timeline
3. **Service Disruption**: Status page updates (if applicable)

## Compliance and Audit Trail

### Release Documentation
- All releases documented in CHANGELOG.md
- Security releases tracked with CVE references
- Decision rationale for emergency releases documented

### Audit Requirements
- Complete git history preservation
- Signed commits for security-critical changes
- Release approval documentation (security team sign-off)

### Retention Policy
- Release artifacts: Permanently retained
- Build logs: Minimum 2 years
- Security incident documentation: Minimum 5 years

---

**Document Version**: 1.0  
**Effective Date**: October 6, 2025  
**Next Review**: January 6, 2026  
**Owner**: AGILira Security Team  
**Approved By**: [Release Manager Name]