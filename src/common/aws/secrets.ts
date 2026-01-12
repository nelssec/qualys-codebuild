import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';

let client: SecretsManagerClient | null = null;

function getClient(): SecretsManagerClient {
  if (!client) {
    client = new SecretsManagerClient({});
  }
  return client;
}

export interface QualysSecret {
  accessToken: string;
  pod?: string;
}

export async function getQualysSecret(secretArn: string): Promise<QualysSecret> {
  console.log(`[AWS] Fetching Qualys credentials from Secrets Manager: ${secretArn}`);

  const secretsClient = getClient();

  const command = new GetSecretValueCommand({
    SecretId: secretArn,
  });

  const response = await secretsClient.send(command);

  if (!response.SecretString) {
    throw new Error('Secret value is empty');
  }

  try {
    const secret = JSON.parse(response.SecretString) as Record<string, string>;

    if (!secret.accessToken && !secret.QUALYS_ACCESS_TOKEN && !secret.access_token) {
      throw new Error(
        'Secret must contain "accessToken", "QUALYS_ACCESS_TOKEN", or "access_token" field'
      );
    }

    return {
      accessToken: secret.accessToken || secret.QUALYS_ACCESS_TOKEN || secret.access_token,
      pod: secret.pod || secret.QUALYS_POD,
    };
  } catch (err) {
    if (err instanceof SyntaxError) {
      return {
        accessToken: response.SecretString,
      };
    }
    throw err;
  }
}
