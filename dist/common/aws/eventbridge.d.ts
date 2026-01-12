import { VulnerabilitySummary } from '../types';
export interface SendEventOptions {
    projectName: string;
    buildId: string;
    scanType: 'container' | 'code';
    target: string;
    result: 'PASSED' | 'FAILED';
    policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE';
    summary: VulnerabilitySummary;
    reportLocation?: string;
    eventBusName?: string;
}
export declare function sendScanCompletionEvent(options: SendEventOptions): Promise<void>;
export declare function buildEventFromEnvironment(scanType: 'container' | 'code', target: string, result: 'PASSED' | 'FAILED', policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE', summary: VulnerabilitySummary, reportLocation?: string): SendEventOptions;
//# sourceMappingURL=eventbridge.d.ts.map