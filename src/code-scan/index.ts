import * as fs from 'fs';
import * as path from 'path';
import { QScannerRunner } from '../common/qscanner/QScannerRunner';
import { getQualysSecret } from '../common/aws/secrets';
import { uploadReports } from '../common/aws/s3';
import { sendScanCompletionEvent, buildEventFromEnvironment } from '../common/aws/eventbridge';
import {
  importFindingsToSecurityHub,
  buildSecurityHubOptionsFromEnv,
} from '../common/aws/securityhub';
import {
  printBanner,
  printSummaryTable,
  printTopVulnerabilities,
  printThresholdResult,
  printPolicyResult,
  printFinalStatus,
  printReportLocations,
} from '../common/output/formatter';
import {
  QScannerConfig,
  RepoScanOptions,
  VulnerabilitySummary,
  ThresholdConfig,
} from '../common/types';

interface CodeScanConfig {
  pod: string;
  accessToken?: string;
  secretArn?: string;
  scanPath: string;
  excludeDirs?: string[];
  excludeFiles?: string[];
  offlineScan?: boolean;
  mode?: 'inventory-only' | 'scan-only' | 'get-report' | 'evaluate-policy';
  scanTypes?: string[];
  policyTags?: string[];
  timeout?: number;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  outputDir?: string;
  reportBucket?: string;
  reportPrefix?: string;
  sendEventBridgeNotification?: boolean;
  eventBusName?: string;
  sendToSecurityHub?: boolean;
  thresholds?: ThresholdConfig;
}

function getConfigFromEnv(): CodeScanConfig {
  const pod = process.env.QUALYS_POD;
  if (!pod) {
    throw new Error('QUALYS_POD environment variable is required');
  }

  return {
    pod,
    accessToken: process.env.QUALYS_ACCESS_TOKEN,
    secretArn: process.env.QUALYS_SECRET_ARN,
    scanPath: process.env.SCAN_PATH || process.env.CODEBUILD_SRC_DIR || '.',
    excludeDirs: process.env.EXCLUDE_DIRS?.split(',').map((s) => s.trim()),
    excludeFiles: process.env.EXCLUDE_FILES?.split(',').map((s) => s.trim()),
    offlineScan: process.env.OFFLINE_SCAN === 'true',
    mode: (process.env.SCAN_MODE as CodeScanConfig['mode']) || 'get-report',
    scanTypes: process.env.SCAN_TYPES?.split(',').map((s) => s.trim()),
    policyTags: process.env.POLICY_TAGS?.split(',').map((s) => s.trim()),
    timeout: process.env.SCAN_TIMEOUT ? parseInt(process.env.SCAN_TIMEOUT, 10) : undefined,
    logLevel: process.env.LOG_LEVEL as CodeScanConfig['logLevel'],
    outputDir: process.env.OUTPUT_DIR || path.join(process.cwd(), 'qualys-reports'),
    reportBucket: process.env.REPORT_BUCKET,
    reportPrefix: process.env.REPORT_PREFIX,
    sendEventBridgeNotification: process.env.SEND_EVENTBRIDGE_NOTIFICATION === 'true',
    eventBusName: process.env.EVENT_BUS_NAME,
    sendToSecurityHub: process.env.SEND_TO_SECURITY_HUB === 'true',
    thresholds: {
      maxCritical: process.env.MAX_CRITICAL ? parseInt(process.env.MAX_CRITICAL, 10) : undefined,
      maxHigh: process.env.MAX_HIGH ? parseInt(process.env.MAX_HIGH, 10) : undefined,
      maxMedium: process.env.MAX_MEDIUM ? parseInt(process.env.MAX_MEDIUM, 10) : undefined,
      maxLow: process.env.MAX_LOW ? parseInt(process.env.MAX_LOW, 10) : undefined,
      failOnPolicyDeny: process.env.FAIL_ON_POLICY_DENY !== 'false',
    },
  };
}

async function main(): Promise<void> {
  const config = getConfigFromEnv();

  printBanner('code', config.scanPath);

  let accessToken = config.accessToken;
  if (!accessToken && config.secretArn) {
    const secret = await getQualysSecret(config.secretArn);
    accessToken = secret.accessToken;
  }

  if (!accessToken) {
    throw new Error(
      'Qualys access token is required. Set QUALYS_ACCESS_TOKEN or QUALYS_SECRET_ARN'
    );
  }

  const qscannerConfig: QScannerConfig = {
    authMethod: 'access-token',
    accessToken,
    pod: config.pod,
  };

  const runner = new QScannerRunner(qscannerConfig);
  await runner.setup();

  const scanOptions: RepoScanOptions = {
    scanPath: config.scanPath,
    mode: config.mode || 'get-report',
    excludeDirs: config.excludeDirs,
    excludeFiles: config.excludeFiles,
    offlineScan: config.offlineScan,
    scanTypes: config.scanTypes as RepoScanOptions['scanTypes'],
    format: ['json', 'sarif'],
    reportFormat: ['sarif', 'json'],
    outputDir: config.outputDir,
    policyTags: config.policyTags,
    timeout: config.timeout,
    logLevel: config.logLevel,
  };

  console.log('Starting scan...\n');
  const result = await runner.scanRepo(scanOptions);

  let summary: VulnerabilitySummary = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };

  let sarifReport = null;
  if (result.reportFile && fs.existsSync(result.reportFile)) {
    const parsed = runner.parseSarifReport(result.reportFile);
    summary = parsed.summary;
    sarifReport = parsed.report;
  }

  printSummaryTable(summary);

  if (sarifReport && summary.total > 0) {
    printTopVulnerabilities(sarifReport, 10);
  }

  printPolicyResult(result.policyResult);

  let thresholdsPassed = true;
  const failureReasons: string[] = [];

  if (
    config.thresholds &&
    (config.thresholds.maxCritical !== undefined ||
      config.thresholds.maxHigh !== undefined ||
      config.thresholds.maxMedium !== undefined ||
      config.thresholds.maxLow !== undefined)
  ) {
    const thresholdResult = printThresholdResult(summary, config.thresholds);
    thresholdsPassed = thresholdResult.passed;
    failureReasons.push(...thresholdResult.reasons);
  }

  const reportLocations: { type: string; path: string }[] = [];

  if (config.reportBucket && result.outputDir) {
    const uploads = await uploadReports(result.outputDir, config.reportBucket, config.reportPrefix);
    for (const upload of uploads) {
      reportLocations.push({ type: 'S3', path: upload.location });
    }
  }

  if (result.reportFile) {
    reportLocations.push({ type: 'SARIF', path: result.reportFile });
  }
  if (result.scanResultFile) {
    reportLocations.push({ type: 'JSON', path: result.scanResultFile });
  }

  if (reportLocations.length > 0) {
    printReportLocations(reportLocations);
  }

  if (config.sendToSecurityHub && sarifReport) {
    const securityHubOptions = buildSecurityHubOptionsFromEnv();
    if (securityHubOptions) {
      await importFindingsToSecurityHub(sarifReport, config.scanPath, 'code', securityHubOptions);
    }
  }

  const policyPassed =
    result.policyResult !== 'DENY' || config.thresholds?.failOnPolicyDeny === false;

  if (!policyPassed) {
    failureReasons.push('Policy evaluation returned DENY');
  }

  if (!result.success && result.exitCode !== 42 && result.exitCode !== 43) {
    failureReasons.push(`Scanner error (exit code: ${result.exitCode})`);
  }

  const scanPassed = result.success && thresholdsPassed && policyPassed;

  if (config.sendEventBridgeNotification) {
    const eventOptions = buildEventFromEnvironment(
      'code',
      config.scanPath,
      scanPassed ? 'PASSED' : 'FAILED',
      result.policyResult,
      summary,
      reportLocations.find((r) => r.type === 'S3')?.path
    );
    eventOptions.eventBusName = config.eventBusName;
    await sendScanCompletionEvent(eventOptions);
  }

  printFinalStatus(scanPassed, failureReasons);

  process.exit(scanPassed ? 0 : 1);
}

main().catch((err) => {
  console.error('\nFatal error:', err.message);
  process.exit(1);
});
