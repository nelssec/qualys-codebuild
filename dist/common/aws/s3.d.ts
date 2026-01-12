export interface UploadResult {
    bucket: string;
    key: string;
    location: string;
}
export declare function uploadFile(filePath: string, bucket: string, keyPrefix?: string): Promise<UploadResult>;
export declare function uploadDirectory(dirPath: string, bucket: string, keyPrefix?: string): Promise<UploadResult[]>;
export declare function uploadReports(outputDir: string, bucket: string, prefix?: string): Promise<UploadResult[]>;
//# sourceMappingURL=s3.d.ts.map