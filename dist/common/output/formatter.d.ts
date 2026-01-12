import { VulnerabilitySummary, SarifReport, ThresholdConfig } from '../types';
export declare function printBanner(scanType: 'container' | 'code', target: string): void;
export declare function printSummaryTable(summary: VulnerabilitySummary): void;
export declare function printTopVulnerabilities(report: SarifReport, limit?: number): void;
export declare function printThresholdResult(summary: VulnerabilitySummary, thresholds: ThresholdConfig): {
    passed: boolean;
    reasons: string[];
};
export declare function printPolicyResult(result: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE'): void;
export declare function printFinalStatus(passed: boolean, reasons?: string[]): void;
export declare function printReportLocations(locations: {
    type: string;
    path: string;
}[]): void;
//# sourceMappingURL=formatter.d.ts.map