# Qualys QScanner for AWS CodeBuild

Integrate Qualys vulnerability scanning into your AWS CodeBuild pipelines. Scan container images and source code for security vulnerabilities, secrets, and compliance issues.

## Features

- **Container Image Scanning**: Scan Docker images for OS and application vulnerabilities
- **Code/SCA Scanning**: Scan source code for vulnerable dependencies
- **AWS Security Hub**: Import findings directly to Security Hub
- **SARIF Reports**: Native CodeBuild report group integration
- **Professional Output**: Formatted console output with severity tables
- **Policy Evaluation**: Use Qualys policies to gate builds
- **Threshold Gates**: Fail builds based on vulnerability counts
- **Multi-Region Deployment**: StackSets for org-wide rollout
- **Enterprise Security**: KMS encryption, S3 versioning, access logging

## Quick Start

### Option 1: Buildspec Templates

Copy a buildspec template to your project:

```bash
cp buildspec/container-scan.yml buildspec.yml
```

### Option 2: CloudFormation (Single Account)

```bash
aws cloudformation deploy \
  --template-file cloudformation/codebuild-project.yaml \
  --stack-name qualys-codebuild \
  --parameter-overrides \
    ProjectName=qualys-codebuild \
    ScanType=container \
    QualysPod=US1 \
    QualysAccessToken=YOUR_TOKEN \
  --capabilities CAPABILITY_NAMED_IAM
```

### Option 3: StackSets (Multi-Region/Org-Wide)

```bash
aws cloudformation create-stack-set \
  --stack-set-name qualys-codebuild \
  --template-body file://cloudformation/stackset-template.yaml \
  --parameters \
    ParameterKey=QualysPod,ParameterValue=US1 \
    ParameterKey=QualysAccessToken,ParameterValue=YOUR_TOKEN \
    ParameterKey=ScanType,ParameterValue=container \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_IAM

aws cloudformation create-stack-instances \
  --stack-set-name qualys-codebuild \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-east-1 us-west-2 eu-west-1
```

## Running a Scan

```bash
# Container scan
aws codebuild start-build \
  --project-name qualys-codebuild-container-us-east-1 \
  --environment-variables-override name=IMAGE_ID,value=nginx:latest

# Code scan (with source configured)
aws codebuild start-build --project-name qualys-codebuild-code-us-east-1
```

## Console Output

```
╔══════════════════════════════════════════════════════════════════════╗
║  QUALYS QSCANNER FOR AWS CODEBUILD                                   ║
║  Scan Type: CONTAINER                                                ║
║  Target: myapp:latest                                                ║
╚══════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────┐
│ VULNERABILITY SUMMARY                            │
├──────────────────────────────────────────────────┤
│ Critical           2 ██                          │
│ High               5 █████                       │
│ Medium            12 ████████████                │
│ Low                8 ████████                    │
│ Informational      3 ███                         │
├──────────────────────────────────────────────────┤
│ TOTAL             30                             │
└──────────────────────────────────────────────────┘

TOP VULNERABILITIES
────────────────────────────────────────────────────────────────────────────────
SEV       PACKAGE                  CVE                 TITLE
────────────────────────────────────────────────────────────────────────────────
CRITICAL  openssl                  CVE-2024-0001       Buffer overflow in...
CRITICAL  libcurl                  CVE-2024-0002       Remote code execut...
HIGH      nodejs                   CVE-2024-0003       Prototype pollution
────────────────────────────────────────────────────────────────────────────────

  ✓ POLICY RESULT: ALLOW

THRESHOLD EVALUATION
──────────────────────────────────────────────────
  Critical     2/5  ✓ PASS
  High         5/10 ✓ PASS
──────────────────────────────────────────────────

╔══════════════════════════════════════════════════╗
║  ✓ SCAN PASSED                                   ║
╚══════════════════════════════════════════════════╝
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `QUALYS_ACCESS_TOKEN` | Yes* | Qualys API access token |
| `QUALYS_SECRET_ARN` | Yes* | Secrets Manager secret ARN |
| `QUALYS_POD` | Yes | Platform (US1, US2, EU1, EU2, CA1, etc.) |
| `IMAGE_ID` | Container | Image to scan |
| `SCAN_PATH` | Code | Path to scan (default: `.`) |
| `SCAN_MODE` | No | `get-report`, `evaluate-policy` |
| `SCAN_TYPES` | No | `pkg,secret,malware` |
| `POLICY_TAGS` | No | Policy tags for evaluation |
| `MAX_CRITICAL` | No | Threshold for critical vulns |
| `MAX_HIGH` | No | Threshold for high vulns |
| `REPORT_BUCKET` | No | S3 bucket for reports |
| `SEND_TO_SECURITY_HUB` | No | `true` to enable |

*One of `QUALYS_ACCESS_TOKEN` or `QUALYS_SECRET_ARN` is required.

### Supported Qualys Pods

US1, US2, US3, US4, EU1, EU2, CA1, IN1, AU1, UK1, AE1, KSA1

## Security Features

All CloudFormation templates include enterprise security controls:

| Feature | Implementation |
|---------|---------------|
| Secrets Encryption | KMS CMK with automatic rotation |
| S3 Encryption | AES-256 server-side encryption |
| S3 Versioning | Enabled with lifecycle policies |
| S3 Access Logging | Dedicated logging bucket |
| S3 Public Access | Blocked on all buckets |
| IAM Permissions | Least privilege, scoped to resources |

## AWS Integrations

### Security Hub

Findings are imported to AWS Security Hub in ASFF format:

| Qualys Severity | Security Hub Label | Normalized Score |
|-----------------|-------------------|------------------|
| 5 (Critical) | CRITICAL | 90 |
| 4 (High) | HIGH | 70 |
| 3 (Medium) | MEDIUM | 40 |
| 2 (Low) | LOW | 20 |
| 1 (Info) | INFORMATIONAL | 0 |

### CodeBuild Report Groups

SARIF reports are uploaded to CodeBuild Report Groups automatically. View findings in the CodeBuild console under the "Reports" tab.

### S3 Reports

Reports are stored in versioned S3 buckets with the structure:
```
s3://{bucket}/{project}/{timestamp}/*.json
```

## CloudFormation Templates

| Template | Description |
|----------|-------------|
| `codebuild-project.yaml` | Standalone CodeBuild project with full security controls |
| `codepipeline-action.yaml` | Reusable CodePipeline action |
| `stackset-template.yaml` | Multi-region org-wide deployment |

### Resources Created

Each deployment creates:
- KMS key with automatic rotation
- Secrets Manager secret (KMS encrypted)
- S3 report bucket (versioned, encrypted, logging enabled)
- S3 logging bucket
- CodeBuild project
- IAM role with scoped permissions

## Project Structure

```
qualys-codebuild/
├── src/
│   ├── common/
│   │   ├── qscanner/
│   │   │   └── QScannerRunner.ts
│   │   ├── aws/
│   │   │   ├── secrets.ts
│   │   │   ├── s3.ts
│   │   │   ├── eventbridge.ts
│   │   │   └── securityhub.ts
│   │   ├── output/
│   │   │   └── formatter.ts
│   │   └── types.ts
│   ├── container-scan/
│   │   └── index.ts
│   └── code-scan/
│       └── index.ts
├── buildspec/
│   ├── container-scan.yml
│   └── code-scan.yml
├── cloudformation/
│   ├── codebuild-project.yaml
│   ├── codepipeline-action.yaml
│   └── stackset-template.yaml
└── docs/
    └── technical-architecture.md
```

## Requirements

- AWS CodeBuild with **x86_64** compute type
- Linux environment
- Docker (for container scanning)
- Network access to Qualys API

## Development

```bash
npm install
npm run build
npm run lint
```

## License

Apache-2.0
