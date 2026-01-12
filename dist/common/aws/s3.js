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
exports.uploadFile = uploadFile;
exports.uploadDirectory = uploadDirectory;
exports.uploadReports = uploadReports;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const client_s3_1 = require("@aws-sdk/client-s3");
let client = null;
function getClient() {
    if (!client) {
        client = new client_s3_1.S3Client({});
    }
    return client;
}
async function uploadFile(filePath, bucket, keyPrefix = '') {
    const s3Client = getClient();
    const fileName = path.basename(filePath);
    const key = keyPrefix ? `${keyPrefix}/${fileName}` : fileName;
    console.log(`[AWS] Uploading ${fileName} to s3://${bucket}/${key}`);
    const fileContent = fs.readFileSync(filePath);
    const contentType = getContentType(fileName);
    const command = new client_s3_1.PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: fileContent,
        ContentType: contentType,
    });
    await s3Client.send(command);
    const location = `s3://${bucket}/${key}`;
    console.log(`[AWS] Upload complete: ${location}`);
    return {
        bucket,
        key,
        location,
    };
}
async function uploadDirectory(dirPath, bucket, keyPrefix = '') {
    const results = [];
    if (!fs.existsSync(dirPath)) {
        console.log(`[AWS] Directory does not exist: ${dirPath}`);
        return results;
    }
    const files = fs.readdirSync(dirPath);
    for (const file of files) {
        const filePath = path.join(dirPath, file);
        const stat = fs.statSync(filePath);
        if (stat.isFile()) {
            if (file.endsWith('.json') || file.endsWith('.sarif')) {
                const result = await uploadFile(filePath, bucket, keyPrefix);
                results.push(result);
            }
        }
    }
    return results;
}
async function uploadReports(outputDir, bucket, prefix) {
    const buildId = process.env.CODEBUILD_BUILD_ID || 'local';
    const projectName = process.env.CODEBUILD_BUILD_PROJECT || 'unknown';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const keyPrefix = prefix || `${projectName}/${buildId}/${timestamp}`;
    return uploadDirectory(outputDir, bucket, keyPrefix);
}
function getContentType(fileName) {
    if (fileName.endsWith('.json') || fileName.endsWith('.sarif.json')) {
        return 'application/json';
    }
    if (fileName.endsWith('.sarif')) {
        return 'application/sarif+json';
    }
    return 'application/octet-stream';
}
//# sourceMappingURL=s3.js.map