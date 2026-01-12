import {
  SecurityHubClient,
  BatchImportFindingsCommand,
  AwsSecurityFinding,
  Severity,
} from '@aws-sdk/client-securityhub';
import { SarifReport } from '../types';

let client: SecurityHubClient | null = null;

function getClient(): SecurityHubClient {
  if (!client) {
    client = new SecurityHubClient({});
  }
  return client;
}

export interface SecurityHubOptions {
  accountId: string;
  region: string;
  productArn?: string;
  generatorId?: string;
}

function mapSeverityToSecurityHub(qualysSeverity: number): Severity {
  switch (qualysSeverity) {
    case 5:
      return { Label: 'CRITICAL', Normalized: 90 };
    case 4:
      return { Label: 'HIGH', Normalized: 70 };
    case 3:
      return { Label: 'MEDIUM', Normalized: 40 };
    case 2:
      return { Label: 'LOW', Normalized: 20 };
    default:
      return { Label: 'INFORMATIONAL', Normalized: 0 };
  }
}

export async function importFindingsToSecurityHub(
  sarifReport: SarifReport,
  target: string,
  scanType: 'container' | 'code',
  options: SecurityHubOptions
): Promise<{ imported: number; failed: number }> {
  const securityHubClient = getClient();
  const findings: AwsSecurityFinding[] = [];

  const productArn =
    options.productArn ||
    `arn:aws:securityhub:${options.region}:${options.accountId}:product/${options.accountId}/default`;

  const generatorId = options.generatorId || 'qualys-qscanner';
  const now = new Date().toISOString();

  for (const run of sarifReport.runs || []) {
    const ruleSeverityMap = new Map<string, number>();

    if (run.tool?.driver?.rules) {
      for (const rule of run.tool.driver.rules) {
        const severity = rule.properties?.severity as number | undefined;
        if (rule.id && severity !== undefined) {
          ruleSeverityMap.set(rule.id, severity);
        }
      }
    }

    for (const result of run.results || []) {
      let severity = result.properties?.severity as number | undefined;
      if (severity === undefined && result.ruleId) {
        severity = ruleSeverityMap.get(result.ruleId);
      }
      if (severity === undefined) {
        severity = result.level === 'error' ? 5 : result.level === 'warning' ? 3 : 2;
      }

      const qid = result.properties?.qid as number | undefined;
      const cves = result.properties?.cves as string[] | undefined;
      const packageName = result.properties?.packageName as string | undefined;
      const installedVersion = result.properties?.installedVersion as string | undefined;
      const fixedVersion = result.properties?.fixedVersion as string | undefined;

      const finding: AwsSecurityFinding = {
        SchemaVersion: '2018-10-08',
        Id: `qualys-${scanType}-${qid || result.ruleId}-${Date.now()}`,
        ProductArn: productArn,
        GeneratorId: generatorId,
        AwsAccountId: options.accountId,
        Types: [
          scanType === 'container'
            ? 'Software and Configuration Checks/Vulnerabilities/CVE'
            : 'Software and Configuration Checks/Vulnerabilities/SCA',
        ],
        CreatedAt: now,
        UpdatedAt: now,
        Severity: mapSeverityToSecurityHub(severity),
        Title: result.message?.text?.substring(0, 256) || `Vulnerability ${result.ruleId}`,
        Description:
          result.message?.text ||
          `Vulnerability found in ${packageName || 'unknown package'}`,
        Resources: [
          {
            Type: scanType === 'container' ? 'Container' : 'Other',
            Id: target,
            Details: {
              Other: {
                ScanType: scanType,
                Target: target,
                ...(packageName && { PackageName: packageName }),
                ...(installedVersion && { InstalledVersion: installedVersion }),
                ...(fixedVersion && { FixedVersion: fixedVersion }),
              },
            },
          },
        ],
        ProductFields: {
          'qualys/QID': qid?.toString() || '',
          'qualys/RuleId': result.ruleId || '',
          'qualys/ScanType': scanType,
          ...(cves && cves.length > 0 && { 'qualys/CVEs': cves.join(',') }),
        },
        RecordState: 'ACTIVE',
        Workflow: {
          Status: 'NEW',
        },
      };

      if (cves && cves.length > 0) {
        finding.Vulnerabilities = cves.map((cve) => ({
          Id: cve,
          VulnerablePackages: packageName
            ? [
                {
                  Name: packageName,
                  Version: installedVersion || 'unknown',
                  Remediation: fixedVersion ? `Upgrade to ${fixedVersion}` : undefined,
                },
              ]
            : undefined,
        }));
      }

      findings.push(finding);
    }
  }

  if (findings.length === 0) {
    console.log('[SecurityHub] No findings to import');
    return { imported: 0, failed: 0 };
  }

  console.log(`[SecurityHub] Importing ${findings.length} findings...`);

  let imported = 0;
  let failed = 0;
  const batchSize = 100;

  for (let i = 0; i < findings.length; i += batchSize) {
    const batch = findings.slice(i, i + batchSize);

    const command = new BatchImportFindingsCommand({
      Findings: batch,
    });

    const response = await securityHubClient.send(command);
    imported += response.SuccessCount || 0;
    failed += response.FailedCount || 0;

    if (response.FailedFindings && response.FailedFindings.length > 0) {
      console.log(`[SecurityHub] Failed findings in batch: ${response.FailedFindings.length}`);
      for (const f of response.FailedFindings.slice(0, 3)) {
        console.log(`  - ${f.Id}: ${f.ErrorMessage}`);
      }
    }
  }

  console.log(`[SecurityHub] Import complete: ${imported} imported, ${failed} failed`);
  return { imported, failed };
}

export function buildSecurityHubOptionsFromEnv(): SecurityHubOptions | null {
  const accountId = process.env.AWS_ACCOUNT_ID || process.env.CODEBUILD_BUILD_ARN?.split(':')[4];
  const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;

  if (!accountId || !region) {
    return null;
  }

  return {
    accountId,
    region,
    productArn: process.env.SECURITY_HUB_PRODUCT_ARN,
    generatorId: process.env.SECURITY_HUB_GENERATOR_ID || 'qualys-qscanner-codebuild',
  };
}
