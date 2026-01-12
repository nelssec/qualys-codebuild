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
- **CodePipeline Integration**: Reusable scan stages for pipelines
- **AWS Native**: Secrets Manager, S3, EventBridge integration

## Quick Start

### Option 1: Use the Buildspec Templates

```bash
cp buildspec/container-scan.yml buildspec.yml
```

### Option 2: Deploy with CloudFormation

```bash
aws cloudformation deploy \
  --template-file cloudformation/codebuild-project.yaml \
  --stack-name qualys-scanner \
  --parameter-overrides \
    ProjectName=my-scanner \
    ScanType=container \
    QualysPod=US1 \
    QualysAccessToken=YOUR_TOKEN \
  --capabilities CAPABILITY_NAMED_IAM
```

### Option 3: Add to CodePipeline

```bash
aws cloudformation deploy \
  --template-file cloudformation/codepipeline-action.yaml \
  --stack-name qualys-pipeline-action \
  --parameter-overrides \
    QualysPod=US1 \
    QualysSecretArn=arn:aws:secretsmanager:... \
    EnableSecurityHub=true \
  --capabilities CAPABILITY_NAMED_IAM
```

## Console Output

The integration provides professional formatted output in CodeBuild logs:

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
| `QUALYS_POD` | Yes | Platform (US1, EU1, etc.) |
| `IMAGE_ID` | Container | Image to scan |
| `SCAN_PATH` | Code | Path to scan (default: `.`) |
| `SCAN_MODE` | No | `get-report`, `evaluate-policy` |
| `SCAN_TYPES` | No | `pkg,secret,malware` |
| `POLICY_TAGS` | No | Policy tags for evaluation |
| `MAX_CRITICAL` | No | Threshold for critical vulns |
| `MAX_HIGH` | No | Threshold for high vulns |
| `REPORT_BUCKET` | No | S3 bucket for reports |
| `SEND_TO_SECURITY_HUB` | No | `true` to enable |
| `SEND_EVENTBRIDGE_NOTIFICATION` | No | `true` to enable |

## AWS Integrations

### Security Hub

Import findings directly to AWS Security Hub:

```yaml
env:
  variables:
    SEND_TO_SECURITY_HUB: "true"
```

Findings appear in Security Hub with:
- Severity mapping (Critical, High, Medium, Low)
- CVE identifiers and references
- Package and version information
- Remediation guidance

### CodeBuild Report Groups

SARIF reports are automatically uploaded to CodeBuild Report Groups:

```yaml
reports:
  qualys-sarif-reports:
    files:
      - '**/*-Report.sarif.json'
    file-format: SARIFZIP
```

View findings in the CodeBuild console under the "Reports" tab.

### S3 Reports

```yaml
env:
  variables:
    REPORT_BUCKET: "my-security-reports"
```

### EventBridge Notifications

```yaml
env:
  variables:
    SEND_EVENTBRIDGE_NOTIFICATION: "true"
```

## CodePipeline Integration

Deploy the CodePipeline action template:

```bash
aws cloudformation deploy \
  --template-file cloudformation/codepipeline-action.yaml \
  --stack-name qualys-pipeline \
  --parameter-overrides \
    QualysSecretArn=arn:aws:secretsmanager:us-east-1:123456789:secret:qualys \
    EnableSecurityHub=true \
  --capabilities CAPABILITY_NAMED_IAM
```

Add to your pipeline:

```yaml
- Name: SecurityScan
  Actions:
    - Name: QualysCodeScan
      ActionTypeId:
        Category: Test
        Owner: AWS
        Provider: CodeBuild
        Version: '1'
      Configuration:
        ProjectName: qualys-pipeline-code-scan
      InputArtifacts:
        - Name: SourceOutput
      OutputArtifacts:
        - Name: ScanReports
```

## CloudFormation Templates

| Template | Description |
|----------|-------------|
| `codebuild-project.yaml` | Standalone CodeBuild project |
| `codepipeline-action.yaml` | Reusable CodePipeline action |

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
├── scripts/
│   └── qscanner-codebuild.sh
├── buildspec/
│   ├── container-scan.yml
│   └── code-scan.yml
├── cloudformation/
│   ├── codebuild-project.yaml
│   └── codepipeline-action.yaml
├── docs/
│   └── technical-architecture.md
└── README.md
```

## Plugin vs Code Approach

**AWS CodeBuild does not have a plugin marketplace** like Jenkins or GitHub Actions. Integration options:

| Approach | Status | Description |
|----------|--------|-------------|
| Buildspec Templates | ✅ Included | Copy-paste YAML templates |
| Shell Script | ✅ Included | Curl and run in any buildspec |
| CloudFormation | ✅ Included | Infrastructure as code |
| CodePipeline Action | ✅ Included | Reusable pipeline stages |
| AWS Marketplace | Future | Partner solution listing |

## Requirements

- AWS CodeBuild with **x86_64** compute type
- Linux environment
- Docker (for container scanning)
- Network access to Qualys API

## Development

```bash
npm install
npm run build
npm run container-scan
npm run code-scan
```

## License

Apache-2.0
