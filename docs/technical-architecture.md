# Qualys QScanner for AWS CodeBuild: Technical Architecture

This document provides a deep dive into the technical architecture of the Qualys QScanner integration for AWS CodeBuild, including component interactions, data flows, and deployment patterns.

## Architecture Overview

The integration provides seamless vulnerability scanning within AWS CodeBuild pipelines, leveraging native AWS services for credential management, report storage, and event-driven notifications.

```mermaid
graph TB
    subgraph "AWS CodeBuild"
        CB[CodeBuild Project]
        BP[Buildspec]
        ENV[Environment Variables]
    end

    subgraph "Qualys Integration"
        QS[QScanner Binary]
        QR[QScannerRunner]
        FMT[Output Formatter]
    end

    subgraph "AWS Services"
        SM[Secrets Manager]
        S3[S3 Bucket]
        EB[EventBridge]
        SH[Security Hub]
        RG[Report Groups]
    end

    subgraph "Qualys Platform"
        QP[Qualys API Gateway]
        QDB[Vulnerability Database]
    end

    CB --> BP
    BP --> ENV
    ENV --> SM
    BP --> QR
    QR --> QS
    QR --> FMT
    QS --> QP
    QP --> QDB
    QR --> S3
    QR --> EB
    QR --> SH
    QR --> RG
```

## Component Architecture

### QScannerRunner

The core component responsible for binary management and scan orchestration.

```mermaid
classDiagram
    class QScannerRunner {
        -config: QScannerConfig
        -binaryPath: string
        -workDir: string
        -accessToken: string
        +setup(): Promise~void~
        +scanImage(options): Promise~QScannerResult~
        +scanRepo(options): Promise~QScannerResult~
        +parseSarifReport(path): VulnerabilitySummary
        -downloadFile(url, dest): Promise~void~
        -executeQScanner(args): Promise~QScannerResult~
        -buildCommonArgs(options): string[]
    }

    class QScannerConfig {
        +authMethod: AuthMethod
        +accessToken: string
        +pod: string
        +proxy: string
    }

    class ContainerScanOptions {
        +imageId: string
        +storageDriver: string
        +platform: string
        +mode: string
        +scanTypes: string[]
    }

    class RepoScanOptions {
        +scanPath: string
        +excludeDirs: string[]
        +excludeFiles: string[]
        +offlineScan: boolean
    }

    class QScannerResult {
        +exitCode: number
        +success: boolean
        +policyResult: string
        +outputDir: string
        +reportFile: string
    }

    QScannerRunner --> QScannerConfig
    QScannerRunner --> ContainerScanOptions
    QScannerRunner --> RepoScanOptions
    QScannerRunner --> QScannerResult
```

## Scan Execution Flow

### Container Scan Flow

```mermaid
sequenceDiagram
    participant CB as CodeBuild
    participant SM as Secrets Manager
    participant QR as QScannerRunner
    participant QS as QScanner Binary
    participant QP as Qualys Platform
    participant S3 as S3 Bucket
    participant EB as EventBridge

    CB->>SM: Fetch QUALYS_ACCESS_TOKEN
    SM-->>CB: Return token
    CB->>QR: Initialize with config
    QR->>QR: Download & verify binary
    QR->>QS: Execute scan command
    QS->>QP: Authenticate (JWT)
    QP-->>QS: Auth token
    QS->>QS: Analyze container layers
    QS->>QP: Upload inventory
    QP->>QP: Match against vuln DB
    QP-->>QS: Vulnerability report
    QS->>QR: Return results
    QR->>QR: Parse SARIF report
    QR->>S3: Upload reports
    QR->>EB: Send completion event
    QR-->>CB: Return exit code
```

### Code Scan Flow

```mermaid
sequenceDiagram
    participant CB as CodeBuild
    participant SM as Secrets Manager
    participant QR as QScannerRunner
    participant QS as QScanner Binary
    participant QP as Qualys Platform
    participant S3 as S3 Bucket

    CB->>SM: Fetch QUALYS_ACCESS_TOKEN
    SM-->>CB: Return token
    CB->>QR: Initialize with config
    QR->>QR: Download & verify binary
    QR->>QS: Execute repo scan
    QS->>QS: Parse dependency files
    Note over QS: package.json, pom.xml,<br/>requirements.txt, go.mod, etc.
    QS->>QS: Detect secrets
    QS->>QP: Upload SBOM
    QP->>QP: Match dependencies
    QP-->>QS: SCA results
    QS->>QR: Return results
    QR->>S3: Upload SARIF + SBOM
    QR-->>CB: Return exit code
```

## Binary Management

The binary download and verification process ensures integrity and security.

```mermaid
flowchart TD
    A[Start Setup] --> B{Binary Exists?}
    B -->|Yes| C[Skip Download]
    B -->|No| D[Download qscanner.gz]
    D --> E[Calculate SHA256]
    E --> F{Checksum Match?}
    F -->|No| G[Delete File]
    G --> H[Throw Error]
    F -->|Yes| I[Gunzip Binary]
    I --> J[chmod +x]
    C --> K[Verify Platform]
    J --> K
    K --> L{linux-amd64?}
    L -->|No| M[Throw Platform Error]
    L -->|Yes| N[Setup Complete]
```

## AWS Integration Architecture

### Secrets Manager Integration

```mermaid
flowchart LR
    subgraph "Secret Storage"
        SM[Secrets Manager]
        SEC[(Qualys Secret)]
    end

    subgraph "CodeBuild"
        CB[Build Environment]
        ENV[Environment Variables]
    end

    subgraph "Secret Formats"
        JSON["JSON: {accessToken, pod}"]
        PLAIN["Plain String: token"]
    end

    SM --> SEC
    SEC --> JSON
    SEC --> PLAIN
    JSON --> ENV
    PLAIN --> ENV
    ENV --> CB
```

### S3 Report Storage

```mermaid
flowchart TD
    subgraph "Scan Output"
        SARIF[SARIF Report]
        JSON[JSON Results]
        SBOM[SBOM Files]
    end

    subgraph "S3 Structure"
        BUCKET[Report Bucket]
        PREFIX["/{project}/{build}/{timestamp}/"]
        FILES["*.sarif.json, *.json"]
    end

    SARIF --> BUCKET
    JSON --> BUCKET
    SBOM --> BUCKET
    BUCKET --> PREFIX
    PREFIX --> FILES
```

### EventBridge Integration

```mermaid
flowchart LR
    subgraph "Event Source"
        CB[CodeBuild Scan]
        EVENT[Scan Completion Event]
    end

    subgraph "EventBridge"
        BUS[Event Bus]
        RULE[Event Rule]
    end

    subgraph "Targets"
        SNS[SNS Topic]
        LAMBDA[Lambda Function]
        SQS[SQS Queue]
    end

    CB --> EVENT
    EVENT --> BUS
    BUS --> RULE
    RULE --> SNS
    RULE --> LAMBDA
    RULE --> SQS
```

### Security Hub Integration

```mermaid
flowchart TB
    subgraph "Scan Results"
        SARIF[SARIF Report]
        FINDINGS[Parsed Findings]
    end

    subgraph "Finding Mapping"
        SEV[Severity Mapping]
        CVE[CVE References]
        PKG[Package Info]
    end

    subgraph "Security Hub"
        SH[Security Hub API]
        ASFF[ASFF Format]
        DASH[Dashboard]
    end

    SARIF --> FINDINGS
    FINDINGS --> SEV
    FINDINGS --> CVE
    FINDINGS --> PKG
    SEV --> ASFF
    CVE --> ASFF
    PKG --> ASFF
    ASFF --> SH
    SH --> DASH
```

Security Hub finding mapping:

| Qualys Severity | Security Hub Label | Normalized Score |
|-----------------|-------------------|------------------|
| 5 (Critical) | CRITICAL | 90 |
| 4 (High) | HIGH | 70 |
| 3 (Medium) | MEDIUM | 40 |
| 2 (Low) | LOW | 20 |
| 1 (Info) | INFORMATIONAL | 0 |

## CloudFormation Deployment Architecture

```mermaid
flowchart TB
    subgraph "CloudFormation Stack"
        CFN[Template]
    end

    subgraph "Created Resources"
        SECRET[Secrets Manager Secret]
        BUCKET[S3 Bucket]
        ROLE[IAM Role]
        PROJECT[CodeBuild Project]
        RULE[EventBridge Rule]
    end

    subgraph "IAM Permissions"
        SM_PERM[secrets:GetSecretValue]
        S3_PERM[s3:PutObject, GetObject]
        EB_PERM[events:PutEvents]
        ECR_PERM[ecr:GetAuthorizationToken]
        LOG_PERM[logs:CreateLogStream]
    end

    CFN --> SECRET
    CFN --> BUCKET
    CFN --> ROLE
    CFN --> PROJECT
    CFN --> RULE

    ROLE --> SM_PERM
    ROLE --> S3_PERM
    ROLE --> EB_PERM
    ROLE --> ECR_PERM
    ROLE --> LOG_PERM
```

## Scan Types and Capabilities

### Container Scanning

```mermaid
flowchart TD
    subgraph "Input Sources"
        LOCAL[Local Docker]
        ECR[Amazon ECR]
        DOCKER[Docker Hub]
        REGISTRY[Private Registry]
    end

    subgraph "Analysis"
        OS[OS Packages]
        APP[Application Deps]
        SECRETS[Secret Detection]
        MALWARE[Malware Analysis]
    end

    subgraph "Output"
        VULN[Vulnerabilities]
        SBOM[SBOM]
        POLICY[Policy Result]
    end

    LOCAL --> OS
    ECR --> OS
    DOCKER --> OS
    REGISTRY --> OS

    OS --> APP
    APP --> SECRETS
    SECRETS --> MALWARE

    MALWARE --> VULN
    MALWARE --> SBOM
    MALWARE --> POLICY
```

### Code/SCA Scanning

```mermaid
flowchart TD
    subgraph "Supported Languages"
        JS[JavaScript/TypeScript]
        PY[Python]
        JAVA[Java/Kotlin]
        GO[Go]
        RUST[Rust]
        DOTNET[.NET]
        RUBY[Ruby]
        PHP[PHP]
    end

    subgraph "Dependency Files"
        PKG[package.json]
        REQ[requirements.txt]
        POM[pom.xml]
        GOMOD[go.mod]
        CARGO[Cargo.toml]
    end

    subgraph "Analysis"
        PARSE[Parse Dependencies]
        MATCH[Match CVEs]
        LICENSE[License Check]
    end

    JS --> PKG
    PY --> REQ
    JAVA --> POM
    GO --> GOMOD
    RUST --> CARGO

    PKG --> PARSE
    REQ --> PARSE
    POM --> PARSE
    GOMOD --> PARSE
    CARGO --> PARSE

    PARSE --> MATCH
    MATCH --> LICENSE
```

## Exit Code Flow

```mermaid
flowchart TD
    SCAN[Scan Execution] --> EXIT{Exit Code}

    EXIT -->|0| SUCCESS[SUCCESS<br/>Build Passes]
    EXIT -->|1| ERROR[GENERIC_ERROR<br/>Build Fails]
    EXIT -->|2| PARAM[INVALID_PARAMETER<br/>Build Fails]
    EXIT -->|11-21| SCAN_ERR[SCAN_FAILED<br/>Build Fails]
    EXIT -->|30-39| OUTPUT_ERR[OUTPUT_ERROR<br/>Build Fails]
    EXIT -->|42| DENY[POLICY_DENY<br/>Build Fails]
    EXIT -->|43| AUDIT[POLICY_AUDIT<br/>Build Passes*]

    AUDIT --> NOTE[*Configurable via<br/>FAIL_ON_POLICY_DENY]
```

## Threshold Evaluation

```mermaid
flowchart TD
    RESULTS[Scan Results] --> PARSE[Parse SARIF]
    PARSE --> COUNT[Count by Severity]
    COUNT --> CRIT{Critical > MAX?}
    CRIT -->|Yes| FAIL[Threshold Failed]
    CRIT -->|No| HIGH{High > MAX?}
    HIGH -->|Yes| FAIL
    HIGH -->|No| MED{Medium > MAX?}
    MED -->|Yes| FAIL
    MED -->|No| LOW{Low > MAX?}
    LOW -->|Yes| FAIL
    LOW -->|No| PASS[Threshold Passed]
```

## Security Considerations

```mermaid
flowchart TB
    subgraph "Credential Security"
        SM[Secrets Manager]
        ENV[Env Var Injection]
        MASK[Log Masking]
    end

    subgraph "Binary Security"
        HTTPS[HTTPS Only]
        SHA256[Checksum Verification]
        NOREDIRECT[Block HTTP Redirects]
    end

    subgraph "Network Security"
        TLS[TLS 1.2+]
        PROXY[Proxy Support]
        VPC[VPC Endpoints]
    end

    SM --> ENV
    ENV --> MASK

    HTTPS --> SHA256
    SHA256 --> NOREDIRECT

    TLS --> PROXY
    PROXY --> VPC
```

## Deployment Patterns

### Single Project Pattern

```mermaid
flowchart LR
    REPO[Source Repo] --> CB[CodeBuild]
    CB --> SCAN[QScanner]
    SCAN --> S3[Reports]
```

### Pipeline Integration Pattern

```mermaid
flowchart LR
    REPO[Source Repo] --> PIPE[CodePipeline]
    PIPE --> BUILD[Build Stage]
    BUILD --> SCAN[Scan Stage]
    SCAN --> TEST[Test Stage]
    TEST --> DEPLOY[Deploy Stage]
    SCAN --> GATE{Policy Gate}
    GATE -->|Pass| TEST
    GATE -->|Fail| STOP[Stop Pipeline]
```

### Multi-Account Pattern

```mermaid
flowchart TB
    subgraph "Security Account"
        SM[Secrets Manager]
        S3[Report Bucket]
    end

    subgraph "Dev Account"
        CB1[CodeBuild Dev]
    end

    subgraph "Prod Account"
        CB2[CodeBuild Prod]
    end

    SM --> CB1
    SM --> CB2
    CB1 --> S3
    CB2 --> S3
```

## Performance Considerations

| Operation | Typical Duration |
|-----------|-----------------|
| Binary Download | 5-10 seconds |
| Container Scan (small image) | 30-60 seconds |
| Container Scan (large image) | 2-5 minutes |
| Code Scan (small repo) | 10-30 seconds |
| Code Scan (large repo) | 1-3 minutes |
| S3 Upload | 1-5 seconds |

## Troubleshooting Decision Tree

```mermaid
flowchart TD
    START[Scan Failed] --> EC{Exit Code?}

    EC -->|1| CHECK_LOG[Check Build Logs]
    EC -->|2| CHECK_PARAMS[Verify Parameters]
    EC -->|42| CHECK_POLICY[Review Policy Tags]
    EC -->|Network| CHECK_NET[Check Connectivity]

    CHECK_LOG --> LOG_ERR{Error Type?}
    LOG_ERR -->|Auth| FIX_AUTH[Verify Token]
    LOG_ERR -->|Binary| FIX_BIN[Redownload Binary]
    LOG_ERR -->|Timeout| FIX_TIME[Increase Timeout]

    CHECK_PARAMS --> PARAM_ERR{Invalid?}
    PARAM_ERR -->|POD| FIX_POD[Check POD Value]
    PARAM_ERR -->|Image| FIX_IMG[Verify Image ID]

    CHECK_NET --> NET_ERR{Issue?}
    NET_ERR -->|VPC| FIX_VPC[Configure NAT/Endpoints]
    NET_ERR -->|Proxy| FIX_PROXY[Set PROXY Variable]
```

## Related Documentation

- [README.md](../README.md) - Quick start and configuration reference
- [Qualys QScanner Documentation](https://www.qualys.com/docs/qualys-container-security-user-guide.pdf)
- [AWS CodeBuild Documentation](https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html)
