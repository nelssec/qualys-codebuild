"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendScanCompletionEvent = sendScanCompletionEvent;
exports.buildEventFromEnvironment = buildEventFromEnvironment;
const client_eventbridge_1 = require("@aws-sdk/client-eventbridge");
let client = null;
function getClient() {
    if (!client) {
        client = new client_eventbridge_1.EventBridgeClient({});
    }
    return client;
}
async function sendScanCompletionEvent(options) {
    const eventBridgeClient = getClient();
    const eventBusName = options.eventBusName || 'default';
    const event = {
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
    const entry = {
        Source: event.source,
        DetailType: event.detailType,
        Detail: JSON.stringify(event.detail),
        EventBusName: eventBusName,
    };
    const command = new client_eventbridge_1.PutEventsCommand({
        Entries: [entry],
    });
    const response = await eventBridgeClient.send(command);
    if (response.FailedEntryCount && response.FailedEntryCount > 0) {
        const failedEntry = response.Entries?.[0];
        throw new Error(`Failed to send EventBridge event: ${failedEntry?.ErrorCode} - ${failedEntry?.ErrorMessage}`);
    }
    console.log('[AWS] EventBridge event sent successfully');
}
function buildEventFromEnvironment(scanType, target, result, policyResult, summary, reportLocation) {
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
//# sourceMappingURL=eventbridge.js.map