import {
  EventBridgeClient,
  PutEventsCommand,
  PutEventsRequestEntry,
} from '@aws-sdk/client-eventbridge';
import { VulnerabilitySummary, ScanCompletionEvent } from '../types';

let client: EventBridgeClient | null = null;

function getClient(): EventBridgeClient {
  if (!client) {
    client = new EventBridgeClient({});
  }
  return client;
}

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

export async function sendScanCompletionEvent(options: SendEventOptions): Promise<void> {
  const eventBridgeClient = getClient();
  const eventBusName = options.eventBusName || 'default';

  const event: ScanCompletionEvent = {
    source: 'qualys.codebuild',
    detailType: 'Qualys Scan Completed',
    detail: {
      projectName: options.projectName,
      buildId: options.buildId,
      scanType: options.scanType,
      target: options.target,
      result: options.result,
      policyResult: options.policyResult,
      summary: options.summary,
      reportLocation: options.reportLocation,
      timestamp: new Date().toISOString(),
    },
  };

  console.log(`[AWS] Sending EventBridge event to bus: ${eventBusName}`);
  console.log(`[AWS] Event: ${JSON.stringify(event.detail, null, 2)}`);

  const entry: PutEventsRequestEntry = {
    Source: event.source,
    DetailType: event.detailType,
    Detail: JSON.stringify(event.detail),
    EventBusName: eventBusName,
  };

  const command = new PutEventsCommand({
    Entries: [entry],
  });

  const response = await eventBridgeClient.send(command);

  if (response.FailedEntryCount && response.FailedEntryCount > 0) {
    const failedEntry = response.Entries?.[0];
    throw new Error(
      `Failed to send EventBridge event: ${failedEntry?.ErrorCode} - ${failedEntry?.ErrorMessage}`
    );
  }

  console.log('[AWS] EventBridge event sent successfully');
}

export function buildEventFromEnvironment(
  scanType: 'container' | 'code',
  target: string,
  result: 'PASSED' | 'FAILED',
  policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE',
  summary: VulnerabilitySummary,
  reportLocation?: string
): SendEventOptions {
  return {
    projectName: process.env.CODEBUILD_BUILD_PROJECT || 'unknown',
    buildId: process.env.CODEBUILD_BUILD_ID || 'unknown',
    scanType,
    target,
    result,
    policyResult,
    summary,
    reportLocation,
    eventBusName: process.env.EVENT_BUS_NAME,
  };
}
