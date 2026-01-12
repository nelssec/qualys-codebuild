"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const QScannerRunner_1 = require("../common/qscanner/QScannerRunner");
const secrets_1 = require("../common/aws/secrets");
const s3_1 = require("../common/aws/s3");
const eventbridge_1 = require("../common/aws/eventbridge");
const securityhub_1 = require("../common/aws/securityhub");
const formatter_1 = require("../common/output/formatter");
function getConfigFromEnv() {
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
        mode: process.env.SCAN_MODE || 'get-report',
        scanTypes: process.env.SCAN_TYPES?.split(',').map((s) => s.trim()),
        policyTags: process.env.POLICY_TAGS?.split(',').map((s) => s.trim()),
        timeout: process.env.SCAN_TIMEOUT ? parseInt(process.env.SCAN_TIMEOUT, 10) : undefined,
        logLevel: process.env.LOG_LEVEL,
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
async function main() {
    const config = getConfigFromEnv();
    (0, formatter_1.printBanner)('code', config.scanPath);
    let accessToken = config.accessToken;
    if (!accessToken && config.secretArn) {
        const secret = await (0, secrets_1.getQualysSecret)(config.secretArn);
        accessToken = secret.accessToken;
    }
    if (!accessToken) {
        throw new Error('Qualys access token is required. Set QUALYS_ACCESS_TOKEN or QUALYS_SECRET_ARN');
    }
    const qscannerConfig = {
        authMethod: 'access-token',
        accessToken,
        pod: config.pod,
    };
    const runner = new QScannerRunner_1.QScannerRunner(qscannerConfig);
    await runner.setup();
    const scanOptions = {
        scanPath: config.scanPath,
        mode: config.mode || 'get-report',
        excludeDirs: config.excludeDirs,
        excludeFiles: config.excludeFiles,
        offlineScan: config.offlineScan,
        scanTypes: config.scanTypes,
        format: ['json', 'sarif'],
        reportFormat: ['sarif', 'json'],
        outputDir: config.outputDir,
        policyTags: config.policyTags,
        timeout: config.timeout,
        logLevel: config.logLevel,
    };
    console.log('Starting scan...\n');
    const result = await runner.scanRepo(scanOptions);
    let summary = {
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
    (0, formatter_1.printSummaryTable)(summary);
    if (sarifReport && summary.total > 0) {
        (0, formatter_1.printTopVulnerabilities)(sarifReport, 10);
    }
    (0, formatter_1.printPolicyResult)(result.policyResult);
    let thresholdsPassed = true;
    const failureReasons = [];
    if (config.thresholds &&
        (config.thresholds.maxCritical !== undefined ||
            config.thresholds.maxHigh !== undefined ||
            config.thresholds.maxMedium !== undefined ||
            config.thresholds.maxLow !== undefined)) {
        const thresholdResult = (0, formatter_1.printThresholdResult)(summary, config.thresholds);
        thresholdsPassed = thresholdResult.passed;
        failureReasons.push(...thresholdResult.reasons);
    }
    const reportLocations = [];
    if (config.reportBucket && result.outputDir) {
        const uploads = await (0, s3_1.uploadReports)(result.outputDir, config.reportBucket, config.reportPrefix);
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
        (0, formatter_1.printReportLocations)(reportLocations);
    }
    if (config.sendToSecurityHub && sarifReport) {
        const securityHubOptions = (0, securityhub_1.buildSecurityHubOptionsFromEnv)();
        if (securityHubOptions) {
            await (0, securityhub_1.importFindingsToSecurityHub)(sarifReport, config.scanPath, 'code', securityHubOptions);
        }
    }
    const policyPassed = result.policyResult !== 'DENY' || config.thresholds?.failOnPolicyDeny === false;
    if (!policyPassed) {
        failureReasons.push('Policy evaluation returned DENY');
    }
    if (!result.success && result.exitCode !== 42 && result.exitCode !== 43) {
        failureReasons.push(`Scanner error (exit code: ${result.exitCode})`);
    }
    const scanPassed = result.success && thresholdsPassed && policyPassed;
    if (config.sendEventBridgeNotification) {
        const eventOptions = (0, eventbridge_1.buildEventFromEnvironment)('code', config.scanPath, scanPassed ? 'PASSED' : 'FAILED', result.policyResult, summary, reportLocations.find((r) => r.type === 'S3')?.path);
        eventOptions.eventBusName = config.eventBusName;
        await (0, eventbridge_1.sendScanCompletionEvent)(eventOptions);
    }
    (0, formatter_1.printFinalStatus)(scanPassed, failureReasons);
    process.exit(scanPassed ? 0 : 1);
}
main().catch((err) => {
    console.error('\nFatal error:', err.message);
    process.exit(1);
});
//# sourceMappingURL=index.js.map