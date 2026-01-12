# Qualys QScanner for AWS CodeBuild: Technical Architecture

Technical architecture documentation for the Qualys QScanner integration with AWS CodeBuild.

## Architecture Overview

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
        KMS[KMS Key]
        SM[Secrets Manager]
        S3[S3 Report Bucket]
        S3L[S3 Logging Bucket]
        SH[Security Hub]
        RG[Report Groups]
    end

    subgraph "Qualys Platform"
        QP[Qualys API Gateway]
        QDB[Vulnerability Database]
    end

    CB --> BP
    BP --> ENV
    KMS --> SM
    SM --> ENV
    BP --> QR
    QR --> QS
    QR --> FMT
    QS --> QP
    QP --> QDB
    QR --> S3
    S3 --> S3L
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
    participant KMS as KMS
    participant SM as Secrets Manager
    participant QR as QScannerRunner
    participant QS as QScanner Binary
    participant QP as Qualys Platform
    participant S3 as S3 Bucket

    CB->>SM: Fetch QUALYS_ACCESS_TOKEN
    SM->>KMS: Decrypt secret
    KMS-->>SM: Decrypted value
    SM-->>CB: Return token
    CB->>QR: Initialize with config
    QR->>QR: Download & verify binary (SHA256)
    QR->>QS: Execute scan command
    QS->>QP: Authenticate
    QP-->>QS: Auth token
    QS->>QS: Analyze container layers
    QS->>QP: Upload inventory
    QP->>QP: Match against vuln DB
    QP-->>QS: Vulnerability report
    QS->>QR: Return results
    QR->>QR: Parse SARIF report
    QR->>S3: Upload reports (encrypted)
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
    Note over QS: package.json, pom.xml,<br/>requirements.txt, go.mod
    QS->>QS: Detect secrets
    QS->>QP: Upload SBOM
    QP->>QP: Match dependencies
    QP-->>QS: SCA results
    QS->>QR: Return results
    QR->>S3: Upload SARIF + SBOM
    QR-->>CB: Return exit code
```

## Binary Management

```mermaid
flowchart TD
    A[Start Setup] --> B{Binary Exists?}
    B -->|Yes| C[Skip Download]
    B -->|No| D[Download qscanner.gz via HTTPS]
    D --> E[Calculate SHA256]
    E --> F{Checksum Match?}
    F -->|No| G[Delete File]
    G --> H[Throw Error]
    F -->|Yes| I[Gunzip Binary]
    I --> J[chmod 755]
    C --> K[Verify Platform]
    J --> K
    K --> L{linux-amd64?}
    L -->|No| M[Throw Platform Error]
    L -->|Yes| N[Setup Complete]
```

## CloudFormation Resource Architecture

```mermaid
flowchart TB
    subgraph "CloudFormation Stack"
        CFN[Template]
    end

    subgraph "Security Resources"
        KMS[KMS Key<br/>Auto-rotation enabled]
        SECRET[Secrets Manager Secret<br/>KMS encrypted]
    end

    subgraph "Storage Resources"
        LOGBUCKET[S3 Logging Bucket<br/>Versioned, Encrypted]
        BUCKET[S3 Report Bucket<br/>Versioned, Encrypted, Logged]
    end

    subgraph "Compute Resources"
        ROLE[IAM Role<br/>Least privilege]
        PROJECT[CodeBuild Project]
    end

    CFN --> KMS
    CFN --> SECRET
    CFN --> LOGBUCKET
    CFN --> BUCKET
    CFN --> ROLE
    CFN --> PROJECT

    KMS --> SECRET
    LOGBUCKET --> BUCKET
    SECRET --> PROJECT
    BUCKET --> PROJECT
    ROLE --> PROJECT
```

## Security Architecture

### Encryption at Rest

```mermaid
flowchart LR
    subgraph "KMS"
        KEY[CMK with Rotation]
    end

    subgraph "Secrets Manager"
        SECRET[Qualys Credentials]
    end

    subgraph "S3"
        BUCKET[Report Bucket<br/>AES-256]
        LOGS[Logging Bucket<br/>AES-256]
    end

    KEY --> SECRET
    BUCKET --> LOGS
```

### IAM Permission Boundaries

```mermaid
flowchart TD
    subgraph "CodeBuild Role Permissions"
        LOGS[logs:CreateLogGroup<br/>logs:CreateLogStream<br/>logs:PutLogEvents]
        SM[secretsmanager:GetSecretValue]
        S3[s3:PutObject<br/>s3:GetObject]
        CB[codebuild:CreateReport<br/>codebuild:UpdateReport]
        ECR[ecr:GetAuthorizationToken<br/>ecr:BatchGetImage]
        SH[securityhub:BatchImportFindings]
    end

    subgraph "Resource Scope"
        LOGS_RES["/aws/codebuild/qualys-*"]
        SM_RES["qualys-*-credentials"]
        S3_RES["qualys-*-reports-*/*"]
        CB_RES["qualys-*"]
    end

    LOGS --> LOGS_RES
    SM --> SM_RES
    S3 --> S3_RES
    CB --> CB_RES
```

## Multi-Region Deployment (StackSets)

```mermaid
flowchart TB
    subgraph "Management Account"
        SS[StackSet: qualys-codebuild]
    end

    subgraph "us-east-1"
        KMS1[KMS Key]
        SM1[Secret]
        S3_1[Report Bucket]
        CB1[CodeBuild Project]
    end

    subgraph "us-west-2"
        KMS2[KMS Key]
        SM2[Secret]
        S3_2[Report Bucket]
        CB2[CodeBuild Project]
    end

    subgraph "eu-west-1"
        KMS3[KMS Key]
        SM3[Secret]
        S3_3[Report Bucket]
        CB3[CodeBuild Project]
    end

    SS --> KMS1
    SS --> KMS2
    SS --> KMS3
    KMS1 --> SM1
    KMS2 --> SM2
    KMS3 --> SM3
    SM1 --> CB1
    SM2 --> CB2
    SM3 --> CB3
    CB1 --> S3_1
    CB2 --> S3_2
    CB3 --> S3_3
```

Each region receives:
- Independent KMS key with rotation
- Region-specific Secrets Manager secret
- Dedicated S3 buckets (reports + logging)
- CodeBuild project named `qualys-codebuild-{type}-{region}`

## Security Hub Integration

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

### Severity Mapping

| Qualys Severity | Security Hub Label | Normalized Score |
|-----------------|-------------------|------------------|
| 5 (Critical) | CRITICAL | 90 |
| 4 (High) | HIGH | 70 |
| 3 (Medium) | MEDIUM | 40 |
| 2 (Low) | LOW | 20 |
| 1 (Info) | INFORMATIONAL | 0 |

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

## Deployment Patterns

### Single Account

```mermaid
flowchart LR
    CFN[CloudFormation] --> STACK[Stack]
    STACK --> CB[CodeBuild Project]
    CB --> SCAN[Scan]
    SCAN --> S3[S3 Reports]
```

### Multi-Account via StackSets

```mermaid
flowchart TB
    subgraph "Management Account"
        SS[StackSet]
    end

    subgraph "OU: Production"
        PROD1[Account 1]
        PROD2[Account 2]
    end

    subgraph "OU: Development"
        DEV1[Account 3]
        DEV2[Account 4]
    end

    SS -->|SERVICE_MANAGED| PROD1
    SS -->|SERVICE_MANAGED| PROD2
    SS -->|SERVICE_MANAGED| DEV1
    SS -->|SERVICE_MANAGED| DEV2
```

### CodePipeline Integration

```mermaid
flowchart LR
    REPO[Source] --> BUILD[Build Stage]
    BUILD --> SCAN[Qualys Scan Stage]
    SCAN --> GATE{Policy Check}
    GATE -->|Pass| TEST[Test Stage]
    GATE -->|Fail| STOP[Pipeline Stopped]
    TEST --> DEPLOY[Deploy Stage]
```

## Supported Languages (Code Scanning)

| Language | Dependency Files |
|----------|-----------------|
| JavaScript/TypeScript | package.json, package-lock.json, yarn.lock |
| Python | requirements.txt, Pipfile, setup.py |
| Java/Kotlin | pom.xml, build.gradle |
| Go | go.mod, go.sum |
| Rust | Cargo.toml, Cargo.lock |
| .NET | *.csproj, packages.config |
| Ruby | Gemfile, Gemfile.lock |
| PHP | composer.json, composer.lock |

## Troubleshooting

```mermaid
flowchart TD
    START[Scan Failed] --> EC{Exit Code?}

    EC -->|1| CHECK_LOG[Check Build Logs]
    EC -->|2| CHECK_PARAMS[Verify Parameters]
    EC -->|42| CHECK_POLICY[Review Policy Tags]
    EC -->|Network| CHECK_NET[Check Connectivity]

    CHECK_LOG --> LOG_ERR{Error Type?}
    LOG_ERR -->|Auth| FIX_AUTH[Verify Token in Secrets Manager]
    LOG_ERR -->|Binary| FIX_BIN[Check SHA256 / Redownload]
    LOG_ERR -->|Timeout| FIX_TIME[Increase SCAN_TIMEOUT]

    CHECK_PARAMS --> PARAM_ERR{Invalid?}
    PARAM_ERR -->|POD| FIX_POD[Verify POD value]
    PARAM_ERR -->|Image| FIX_IMG[Verify IMAGE_ID format]

    CHECK_NET --> NET_ERR{Issue?}
    NET_ERR -->|VPC| FIX_VPC[Configure NAT Gateway]
    NET_ERR -->|Proxy| FIX_PROXY[Set PROXY env var]
```

## Related Documentation

- [README.md](../README.md) - Quick start and configuration
- [Qualys Container Security User Guide](https://www.qualys.com/docs/qualys-container-security-user-guide.pdf)
- [AWS CodeBuild Documentation](https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html)
- [AWS StackSets Documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html)
