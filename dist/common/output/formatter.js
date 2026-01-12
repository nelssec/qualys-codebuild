"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.printBanner = printBanner;
exports.printSummaryTable = printSummaryTable;
exports.printTopVulnerabilities = printTopVulnerabilities;
exports.printThresholdResult = printThresholdResult;
exports.printPolicyResult = printPolicyResult;
exports.printFinalStatus = printFinalStatus;
exports.printReportLocations = printReportLocations;
const COLORS = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    bgRed: '\x1b[41m',
    bgGreen: '\x1b[42m',
    bgYellow: '\x1b[43m',
};
function colorize(text, color) {
    return `${COLORS[color]}${text}${COLORS.reset}`;
}
function severityColor(severity) {
    switch (severity) {
        case 5:
            return 'red';
        case 4:
            return 'magenta';
        case 3:
            return 'yellow';
        case 2:
            return 'cyan';
        default:
            return 'white';
    }
}
function severityLabel(severity) {
    switch (severity) {
        case 5:
            return 'CRITICAL';
        case 4:
            return 'HIGH';
        case 3:
            return 'MEDIUM';
        case 2:
            return 'LOW';
        default:
            return 'INFO';
    }
}
function printBanner(scanType, target) {
    const width = 70;
    const line = '═'.repeat(width);
    console.log('');
    console.log(colorize(`╔${line}╗`, 'cyan'));
    console.log(colorize(`║${' '.repeat(width)}║`, 'cyan'));
    console.log(colorize(`║`, 'cyan') +
        colorize('  QUALYS QSCANNER FOR AWS CODEBUILD', 'bold').padEnd(width + 9) +
        colorize(`║`, 'cyan'));
    console.log(colorize(`║${' '.repeat(width)}║`, 'cyan'));
    console.log(colorize(`║`, 'cyan') +
        `  Scan Type: ${scanType.toUpperCase()}`.padEnd(width) +
        colorize(`║`, 'cyan'));
    console.log(colorize(`║`, 'cyan') +
        `  Target: ${target.substring(0, 55)}`.padEnd(width) +
        colorize(`║`, 'cyan'));
    console.log(colorize(`║${' '.repeat(width)}║`, 'cyan'));
    console.log(colorize(`╚${line}╝`, 'cyan'));
    console.log('');
}
function printSummaryTable(summary) {
    const width = 50;
    const line = '─'.repeat(width);
    console.log('');
    console.log(colorize(`┌${line}┐`, 'white'));
    console.log(colorize(`│`, 'white') +
        colorize(' VULNERABILITY SUMMARY', 'bold').padEnd(width + 9) +
        colorize(`│`, 'white'));
    console.log(colorize(`├${line}┤`, 'white'));
    const rows = [
        { label: 'Critical', value: summary.critical, color: 'red' },
        { label: 'High', value: summary.high, color: 'magenta' },
        { label: 'Medium', value: summary.medium, color: 'yellow' },
        { label: 'Low', value: summary.low, color: 'cyan' },
        { label: 'Informational', value: summary.informational, color: 'white' },
    ];
    for (const row of rows) {
        const bar = row.value > 0 ? '█'.repeat(Math.min(row.value, 20)) : '';
        const valueStr = row.value.toString().padStart(5);
        const labelStr = row.label.padEnd(15);
        console.log(colorize(`│`, 'white') +
            ` ${labelStr}` +
            colorize(valueStr, row.color) +
            ` ${colorize(bar, row.color)}`.padEnd(width - 21) +
            colorize(`│`, 'white'));
    }
    console.log(colorize(`├${line}┤`, 'white'));
    console.log(colorize(`│`, 'white') +
        ` ${'TOTAL'.padEnd(15)}${colorize(summary.total.toString().padStart(5), 'bold')}`.padEnd(width + 9) +
        colorize(`│`, 'white'));
    console.log(colorize(`└${line}┘`, 'white'));
    console.log('');
}
function printTopVulnerabilities(report, limit = 10) {
    const findings = [];
    for (const run of report.runs || []) {
        const ruleSeverityMap = new Map();
        if (run.tool?.driver?.rules) {
            for (const rule of run.tool.driver.rules) {
                const severity = rule.properties?.severity;
                if (rule.id && severity !== undefined) {
                    ruleSeverityMap.set(rule.id, severity);
                }
            }
        }
        for (const result of run.results || []) {
            let severity = result.properties?.severity;
            if (severity === undefined && result.ruleId) {
                severity = ruleSeverityMap.get(result.ruleId);
            }
            if (severity === undefined) {
                severity = 1;
            }
            findings.push({
                severity,
                title: result.message?.text?.substring(0, 50) || result.ruleId || 'Unknown',
                package: result.properties?.packageName || '-',
                cves: result.properties?.cves || [],
            });
        }
    }
    findings.sort((a, b) => b.severity - a.severity);
    const top = findings.slice(0, limit);
    if (top.length === 0) {
        return;
    }
    console.log(colorize('TOP VULNERABILITIES', 'bold'));
    console.log('─'.repeat(80));
    console.log(`${'SEV'.padEnd(10)}${'PACKAGE'.padEnd(25)}${'CVE'.padEnd(20)}${'TITLE'.padEnd(25)}`);
    console.log('─'.repeat(80));
    for (const finding of top) {
        const sevLabel = colorize(severityLabel(finding.severity).padEnd(10), severityColor(finding.severity));
        const pkg = finding.package.substring(0, 23).padEnd(25);
        const cve = (finding.cves[0] || '-').substring(0, 18).padEnd(20);
        const title = finding.title.substring(0, 23).padEnd(25);
        console.log(`${sevLabel}${pkg}${cve}${title}`);
    }
    console.log('─'.repeat(80));
    console.log('');
}
function printThresholdResult(summary, thresholds) {
    const reasons = [];
    console.log(colorize('THRESHOLD EVALUATION', 'bold'));
    console.log('─'.repeat(50));
    const checks = [
        { name: 'Critical', actual: summary.critical, max: thresholds.maxCritical },
        { name: 'High', actual: summary.high, max: thresholds.maxHigh },
        { name: 'Medium', actual: summary.medium, max: thresholds.maxMedium },
        { name: 'Low', actual: summary.low, max: thresholds.maxLow },
    ];
    for (const check of checks) {
        if (check.max !== undefined) {
            const passed = check.actual <= check.max;
            const status = passed ? colorize('✓ PASS', 'green') : colorize('✗ FAIL', 'red');
            console.log(`  ${check.name.padEnd(12)} ${check.actual}/${check.max} ${status}`);
            if (!passed) {
                reasons.push(`${check.name} (${check.actual}) exceeds threshold (${check.max})`);
            }
        }
    }
    console.log('─'.repeat(50));
    console.log('');
    return { passed: reasons.length === 0, reasons };
}
function printPolicyResult(result) {
    let statusLine;
    switch (result) {
        case 'ALLOW':
            statusLine = colorize('  ✓ POLICY RESULT: ALLOW', 'green');
            break;
        case 'DENY':
            statusLine = colorize('  ✗ POLICY RESULT: DENY', 'red');
            break;
        case 'AUDIT':
            statusLine = colorize('  ⚠ POLICY RESULT: AUDIT', 'yellow');
            break;
        default:
            statusLine = '  - POLICY RESULT: N/A';
    }
    console.log(statusLine);
    console.log('');
}
function printFinalStatus(passed, reasons = []) {
    const width = 50;
    console.log('');
    if (passed) {
        console.log(colorize('╔' + '═'.repeat(width) + '╗', 'green'));
        console.log(colorize('║', 'green') +
            colorize('  ✓ SCAN PASSED', 'bold').padEnd(width + 9) +
            colorize('║', 'green'));
        console.log(colorize('╚' + '═'.repeat(width) + '╝', 'green'));
    }
    else {
        console.log(colorize('╔' + '═'.repeat(width) + '╗', 'red'));
        console.log(colorize('║', 'red') +
            colorize('  ✗ SCAN FAILED', 'bold').padEnd(width + 9) +
            colorize('║', 'red'));
        if (reasons.length > 0) {
            console.log(colorize('╟' + '─'.repeat(width) + '╢', 'red'));
            for (const reason of reasons) {
                console.log(colorize('║', 'red') + `  • ${reason.substring(0, 46)}`.padEnd(width) + colorize('║', 'red'));
            }
        }
        console.log(colorize('╚' + '═'.repeat(width) + '╝', 'red'));
    }
    console.log('');
}
function printReportLocations(locations) {
    if (locations.length === 0)
        return;
    console.log(colorize('REPORT LOCATIONS', 'bold'));
    console.log('─'.repeat(60));
    for (const loc of locations) {
        console.log(`  ${loc.type.padEnd(15)} ${loc.path}`);
    }
    console.log('');
}
//# sourceMappingURL=formatter.js.map