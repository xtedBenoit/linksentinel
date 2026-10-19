import dotenv from 'dotenv';

dotenv.config();

export type LogLevel = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
export type NodeEnv = 'development' | 'production' | 'test';

export interface AppConfig {
  readonly port: number;
  readonly host: string;
  readonly nodeEnv: NodeEnv;
  readonly logLevel: LogLevel;
  readonly rateLimitMax: number;
  readonly rateLimitWindowMs: number;
  readonly maxUrlLength: number;
  readonly providerTimeoutMs: number;
  readonly googleSafeBrowsingApiKey?: string;
  readonly urlhausAuthKey?: string;
}

const VALID_LOG_LEVELS: ReadonlySet<string> = new Set([
  'fatal',
  'error',
  'warn',
  'info',
  'debug',
  'trace',
  'silent',
]);

const VALID_NODE_ENVS: ReadonlySet<string> = new Set(['development', 'production', 'test']);

function parsePositiveInt(
  rawValue: string | undefined,
  defaultValue: number,
  name: string,
  min: number,
  max: number
): number {
  if (rawValue === undefined || rawValue.trim() === '') {
    return defaultValue;
  }
  const parsed = Number.parseInt(rawValue, 10);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(
      `Configuration invalide pour ${name}: "${rawValue}" (attendu: entier entre ${min} et ${max})`
    );
  }
  return parsed;
}

function normalizeOptionalSecret(rawValue: string | undefined): string | undefined {
  if (rawValue === undefined) {
    return undefined;
  }
  const trimmed = rawValue.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Charge et valide la configuration à partir d'un dictionnaire d'environnement.
 * Ne journalise jamais les clés API.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const rawNodeEnv = env.NODE_ENV?.trim() || 'development';
  if (!VALID_NODE_ENVS.has(rawNodeEnv)) {
    throw new Error(`Configuration invalide pour NODE_ENV: "${rawNodeEnv}"`);
  }
  const nodeEnv = rawNodeEnv as NodeEnv;

  const defaultLogLevel: LogLevel = nodeEnv === 'test' ? 'silent' : 'info';
  const rawLogLevel = env.LOG_LEVEL?.trim() || defaultLogLevel;
  if (!VALID_LOG_LEVELS.has(rawLogLevel)) {
    throw new Error(`Configuration invalide pour LOG_LEVEL: "${rawLogLevel}"`);
  }
  const logLevel = rawLogLevel as LogLevel;

  const port = parsePositiveInt(env.PORT, 3000, 'PORT', 1, 65535);
  const host = env.HOST?.trim() || '127.0.0.1';
  const rateLimitMax = parsePositiveInt(env.RATE_LIMIT_MAX, 30, 'RATE_LIMIT_MAX', 1, 10000);
  const rateLimitWindowMs = parsePositiveInt(
    env.RATE_LIMIT_WINDOW_MS,
    60000,
    'RATE_LIMIT_WINDOW_MS',
    1000,
    3600000
  );
  const maxUrlLength = parsePositiveInt(env.MAX_URL_LENGTH, 2048, 'MAX_URL_LENGTH', 64, 4096);
  const providerTimeoutMs = parsePositiveInt(
    env.PROVIDER_TIMEOUT_MS,
    3000,
    'PROVIDER_TIMEOUT_MS',
    500,
    15000
  );

  return Object.freeze({
    port,
    host,
    nodeEnv,
    logLevel,
    rateLimitMax,
    rateLimitWindowMs,
    maxUrlLength,
    providerTimeoutMs,
    googleSafeBrowsingApiKey: normalizeOptionalSecret(env.GOOGLE_SAFE_BROWSING_API_KEY),
    urlhausAuthKey: normalizeOptionalSecret(env.URLHAUS_AUTH_KEY),
  });
}
