"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getQualysSecret = getQualysSecret;
const client_secrets_manager_1 = require("@aws-sdk/client-secrets-manager");
let client = null;
function getClient() {
    if (!client) {
        client = new client_secrets_manager_1.SecretsManagerClient({});
    }
    return client;
}
async function getQualysSecret(secretArn) {
    console.log(`[AWS] Fetching Qualys credentials from Secrets Manager: ${secretArn}`);
    const secretsClient = getClient();
    const command = new client_secrets_manager_1.GetSecretValueCommand({
        SecretId: secretArn,
    });
    const response = await secretsClient.send(command);
    if (!response.SecretString) {
        throw new Error('Secret value is empty');
    }
    try {
        const secret = JSON.parse(response.SecretString);
        if (!secret.accessToken && !secret.QUALYS_ACCESS_TOKEN && !secret.access_token) {
            throw new Error('Secret must contain "accessToken", "QUALYS_ACCESS_TOKEN", or "access_token" field');
        }
        return {
            accessToken: secret.accessToken || secret.QUALYS_ACCESS_TOKEN || secret.access_token,
            pod: secret.pod || secret.QUALYS_POD,
        };
    }
    catch (err) {
        if (err instanceof SyntaxError) {
            return {
                accessToken: response.SecretString,
            };
        }
        throw err;
    }
}
//# sourceMappingURL=secrets.js.map