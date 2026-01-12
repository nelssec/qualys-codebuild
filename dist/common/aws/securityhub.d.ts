import { SarifReport } from '../types';
export interface SecurityHubOptions {
    accountId: string;
    region: string;
    productArn?: string;
    generatorId?: string;
}
export declare function importFindingsToSecurityHub(sarifReport: SarifReport, target: string, scanType: 'container' | 'code', options: SecurityHubOptions): Promise<{
    imported: number;
    failed: number;
}>;
export declare function buildSecurityHubOptionsFromEnv(): SecurityHubOptions | null;
//# sourceMappingURL=securityhub.d.ts.map