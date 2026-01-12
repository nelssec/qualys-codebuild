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
exports.QScannerRunner = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const zlib = __importStar(require("zlib"));
const crypto = __importStar(require("crypto"));
const child_process_1 = require("child_process");
const https = __importStar(require("https"));
const types_1 = require("../types");
const QSCANNER_BINARY_URL = 'https://github.com/nelssec/qualys-lambda/raw/main/scanner-lambda/qscanner.gz';
const QSCANNER_SHA256 = '1a31b854154ee4594bb94e28aa86460b14a75687085d097f949e91c5fd00413d';
class QScannerRunner {
    config;
    binaryPath = null;
    workDir;
    accessToken = null;
    constructor(config) {
        this.config = config;
        this.workDir = path.join(os.tmpdir(), 'qscanner-codebuild');
        if (!fs.existsSync(this.workDir)) {
            fs.mkdirSync(this.workDir, { recursive: true });
        }
        const podUpper = config.pod.toUpperCase();
        if (!types_1.VALID_PODS.includes(podUpper)) {
            throw new Error(`Invalid pod: ${config.pod}. Valid pods: ${types_1.VALID_PODS.join(', ')}`);
        }
    }
    async setup() {
        const platform = this.getPlatform();
        const arch = this.getArchitecture();
        console.log(`[QScanner] Setting up for ${platform}-${arch}...`);
        if (platform !== 'linux' || arch !== 'amd64') {
            throw new Error(`QScanner binary only supports linux-amd64. Current: ${platform}-${arch}. ` +
                `AWS CodeBuild must use an x86_64 compute type.`);
        }
        const binaryName = 'qscanner';
        this.binaryPath = path.join(this.workDir, binaryName);
        if (fs.existsSync(this.binaryPath)) {
            console.log('[QScanner] Binary already exists, skipping download.');
            await this.authenticate();
            return;
        }
        const gzPath = path.join(this.workDir, 'qscanner.gz');
        console.log('[QScanner] Downloading binary...');
        await this.downloadFile(QSCANNER_BINARY_URL, gzPath);
        console.log('[QScanner] Verifying SHA256 checksum...');
        const actualHash = await this.calculateSha256(gzPath);
        if (actualHash !== QSCANNER_SHA256) {
            fs.unlinkSync(gzPath);
            throw new Error(`SHA256 checksum mismatch. Expected: ${QSCANNER_SHA256}, Got: ${actualHash}`);
        }
        console.log('[QScanner] Checksum verified.');
        console.log('[QScanner] Extracting binary...');
        await this.gunzipFile(gzPath, this.binaryPath);
        fs.unlinkSync(gzPath);
        fs.chmodSync(this.binaryPath, '755');
        console.log(`[QScanner] Binary ready at ${this.binaryPath}`);
        await this.authenticate();
    }
    gunzipFile(srcPath, destPath) {
        return new Promise((resolve, reject) => {
            const src = fs.createReadStream(srcPath);
            const dest = fs.createWriteStream(destPath);
            const gunzip = zlib.createGunzip();
            src.pipe(gunzip).pipe(dest);
            dest.on('finish', () => {
                dest.close();
                resolve();
            });
            dest.on('error', reject);
            src.on('error', reject);
            gunzip.on('error', reject);
        });
    }
    calculateSha256(filePath) {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(filePath);
            stream.on('data', (data) => hash.update(data));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });
    }
    async authenticate() {
        if (!this.config.accessToken) {
            throw new Error('Access token is required');
        }
        this.accessToken = this.config.accessToken;
        console.log('[QScanner] Using provided access token for authentication');
    }
    async scanImage(options) {
        if (!this.binaryPath) {
            throw new Error('QScanner not set up. Call setup() first.');
        }
        const args = this.buildCommonArgs(options);
        args.push('image', options.imageId);
        if (options.storageDriver && options.storageDriver !== 'none') {
            args.push('--storage-driver', options.storageDriver);
        }
        if (options.platform) {
            args.push('--platform', options.platform);
        }
        return this.executeQScanner(args, options.outputDir);
    }
    async scanRepo(options) {
        if (!this.binaryPath) {
            throw new Error('QScanner not set up. Call setup() first.');
        }
        const args = this.buildCommonArgs(options);
        args.push('repo', options.scanPath);
        if (options.excludeDirs && options.excludeDirs.length > 0) {
            args.push('--exclude-dirs', options.excludeDirs.join(','));
        }
        if (options.excludeFiles && options.excludeFiles.length > 0) {
            args.push('--exclude-files', options.excludeFiles.join(','));
        }
        if (options.offlineScan) {
            args.push('--offline-scan=true');
        }
        if (options.showPerfStat) {
            args.push('--show-perf-stat');
        }
        return this.executeQScanner(args, options.outputDir);
    }
    parseSarifReport(reportPath) {
        if (!fs.existsSync(reportPath)) {
            throw new Error(`SARIF report not found at ${reportPath}`);
        }
        const reportContent = fs.readFileSync(reportPath, 'utf-8');
        const report = JSON.parse(reportContent);
        const summary = {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0,
        };
        if (report.runs && report.runs.length > 0) {
            for (const run of report.runs) {
                const ruleSeverityMap = new Map();
                if (run.tool?.driver?.rules) {
                    for (const rule of run.tool.driver.rules) {
                        const ruleSeverity = rule.properties?.severity;
                        if (rule.id && ruleSeverity !== undefined) {
                            ruleSeverityMap.set(rule.id, ruleSeverity);
                        }
                    }
                }
                if (run.results) {
                    for (const result of run.results) {
                        summary.total++;
                        let severity = result.properties?.severity;
                        if (severity === undefined && result.ruleId) {
                            severity = ruleSeverityMap.get(result.ruleId);
                        }
                        if (severity === undefined && result.level) {
                            switch (result.level) {
                                case 'error':
                                    severity = 5;
                                    break;
                                case 'warning':
                                    severity = 3;
                                    break;
                                case 'note':
                                    severity = 2;
                                    break;
                                default:
                                    severity = 1;
                            }
                        }
                        if (severity === 5) {
                            summary.critical++;
                        }
                        else if (severity === 4) {
                            summary.high++;
                        }
                        else if (severity === 3) {
                            summary.medium++;
                        }
                        else if (severity === 2) {
                            summary.low++;
                        }
                        else {
                            summary.informational++;
                        }
                    }
                }
            }
        }
        return { summary, report };
    }
    getBinaryPath() {
        return this.binaryPath;
    }
    getWorkDir() {
        return this.workDir;
    }
    cleanup() {
        if (this.workDir && fs.existsSync(this.workDir)) {
            try {
                const files = fs.readdirSync(this.workDir);
                for (const file of files) {
                    if (file.endsWith('.json') || file.endsWith('.sarif')) {
                        fs.unlinkSync(path.join(this.workDir, file));
                    }
                }
            }
            catch {
            }
        }
    }
    buildCommonArgs(options) {
        const args = [];
        args.push('--pod', this.config.pod);
        args.push('--mode', options.mode);
        if (options.scanTypes && options.scanTypes.length > 0) {
            args.push('--scan-types', options.scanTypes.join(','));
        }
        if (options.format && options.format.length > 0) {
            args.push('--format', options.format.join(','));
        }
        if (options.reportFormat && options.reportFormat.length > 0) {
            args.push('--report-format', options.reportFormat.join(','));
        }
        if (options.outputDir) {
            args.push('--output-dir', options.outputDir);
        }
        if (options.policyTags && options.policyTags.length > 0) {
            args.push('--policy-tags', options.policyTags.join(','));
        }
        if (options.timeout) {
            args.push('--scan-timeout', `${options.timeout}s`);
        }
        if (options.logLevel) {
            args.push('--log-level', options.logLevel);
        }
        if (this.config.proxy) {
            args.push('--proxy', this.config.proxy);
        }
        return args;
    }
    async executeQScanner(args, outputDir) {
        if (!this.binaryPath) {
            throw new Error('QScanner binary path not set');
        }
        if (!this.accessToken) {
            throw new Error('Access token not available. Call setup() first.');
        }
        const resultOutputDir = outputDir || path.join(this.workDir, 'output');
        if (!fs.existsSync(resultOutputDir)) {
            fs.mkdirSync(resultOutputDir, { recursive: true });
        }
        if (!args.includes('--output-dir')) {
            args.push('--output-dir', resultOutputDir);
        }
        console.log(`[QScanner] Executing: ${this.binaryPath} ${args.join(' ')}`);
        return new Promise((resolve, reject) => {
            let stdout = '';
            let stderr = '';
            const proc = (0, child_process_1.spawn)(this.binaryPath, args, {
                env: {
                    ...process.env,
                    QUALYS_ACCESS_TOKEN: this.accessToken,
                },
            });
            proc.stdout?.on('data', (data) => {
                const text = data.toString();
                stdout += text;
                process.stdout.write(text);
            });
            proc.stderr?.on('data', (data) => {
                const text = data.toString();
                stderr += text;
                process.stderr.write(text);
            });
            proc.on('close', (code) => {
                const exitCode = code ?? 1;
                const result = this.buildResult(exitCode, resultOutputDir, stdout, stderr);
                resolve(result);
            });
            proc.on('error', (err) => {
                reject(new Error(`Failed to execute QScanner: ${err.message}`));
            });
        });
    }
    buildResult(exitCode, outputDir, stdout, stderr) {
        let policyResult = 'NONE';
        if (exitCode === types_1.QScannerExitCode.SUCCESS) {
            policyResult = 'ALLOW';
        }
        else if (exitCode === types_1.QScannerExitCode.POLICY_EVALUATION_DENY) {
            policyResult = 'DENY';
        }
        else if (exitCode === types_1.QScannerExitCode.POLICY_EVALUATION_AUDIT) {
            policyResult = 'AUDIT';
        }
        let scanResultFile;
        let reportFile;
        if (fs.existsSync(outputDir)) {
            const files = fs.readdirSync(outputDir);
            for (const file of files) {
                if (file.endsWith('-ScanResult.json')) {
                    scanResultFile = path.join(outputDir, file);
                }
                else if (file.endsWith('-Report.sarif.json')) {
                    reportFile = path.join(outputDir, file);
                }
            }
        }
        return {
            exitCode,
            success: exitCode === types_1.QScannerExitCode.SUCCESS,
            policyResult,
            outputDir,
            scanResultFile,
            reportFile,
            stdout,
            stderr,
        };
    }
    getPlatform() {
        const platform = os.platform();
        switch (platform) {
            case 'linux':
                return 'linux';
            case 'darwin':
                return 'darwin';
            case 'win32':
                return 'windows';
            default:
                throw new Error(`Unsupported platform: ${platform}`);
        }
    }
    getArchitecture() {
        const arch = os.arch();
        switch (arch) {
            case 'x64':
                return 'amd64';
            case 'arm64':
                return 'arm64';
            default:
                throw new Error(`Unsupported architecture: ${arch}`);
        }
    }
    downloadFile(url, destPath) {
        return new Promise((resolve, reject) => {
            if (!url.startsWith('https://')) {
                reject(new Error('Security error: Only HTTPS URLs are allowed for downloads'));
                return;
            }
            const file = fs.createWriteStream(destPath);
            https
                .get(url, (response) => {
                if (response.statusCode === 301 || response.statusCode === 302) {
                    const redirectUrl = response.headers.location;
                    if (redirectUrl) {
                        if (!redirectUrl.startsWith('https://')) {
                            file.close();
                            fs.unlinkSync(destPath);
                            reject(new Error('Security error: Redirect to non-HTTPS URL blocked'));
                            return;
                        }
                        file.close();
                        fs.unlinkSync(destPath);
                        this.downloadFile(redirectUrl, destPath).then(resolve).catch(reject);
                        return;
                    }
                }
                if (response.statusCode !== 200) {
                    reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
                    return;
                }
                response.pipe(file);
                file.on('finish', () => {
                    file.close();
                    resolve();
                });
            })
                .on('error', (err) => {
                fs.unlink(destPath, () => { });
                reject(err);
            });
        });
    }
}
exports.QScannerRunner = QScannerRunner;
exports.default = QScannerRunner;
//# sourceMappingURL=QScannerRunner.js.map