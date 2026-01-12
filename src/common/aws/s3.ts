import * as fs from 'fs';
import * as path from 'path';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

let client: S3Client | null = null;

function getClient(): S3Client {
  if (!client) {
    client = new S3Client({});
  }
  return client;
}

export interface UploadResult {
  bucket: string;
  key: string;
  location: string;
}

export async function uploadFile(
  filePath: string,
  bucket: string,
  keyPrefix: string = ''
): Promise<UploadResult> {
  const s3Client = getClient();
  const fileName = path.basename(filePath);
  const key = keyPrefix ? `${keyPrefix}/${fileName}` : fileName;

  console.log(`[AWS] Uploading ${fileName} to s3://${bucket}/${key}`);

  const fileContent = fs.readFileSync(filePath);
  const contentType = getContentType(fileName);

  const command = new PutObjectCommand({
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

export async function uploadDirectory(
  dirPath: string,
  bucket: string,
  keyPrefix: string = ''
): Promise<UploadResult[]> {
  const results: UploadResult[] = [];

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

export async function uploadReports(
  outputDir: string,
  bucket: string,
  prefix?: string
): Promise<UploadResult[]> {
  const buildId = process.env.CODEBUILD_BUILD_ID || 'local';
  const projectName = process.env.CODEBUILD_BUILD_PROJECT || 'unknown';
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  const keyPrefix = prefix || `${projectName}/${buildId}/${timestamp}`;

  return uploadDirectory(outputDir, bucket, keyPrefix);
}

function getContentType(fileName: string): string {
  if (fileName.endsWith('.json') || fileName.endsWith('.sarif.json')) {
    return 'application/json';
  }
  if (fileName.endsWith('.sarif')) {
    return 'application/sarif+json';
  }
  return 'application/octet-stream';
}
