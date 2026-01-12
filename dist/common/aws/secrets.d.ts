export interface QualysSecret {
    accessToken: string;
    pod?: string;
}
export declare function getQualysSecret(secretArn: string): Promise<QualysSecret>;
//# sourceMappingURL=secrets.d.ts.map