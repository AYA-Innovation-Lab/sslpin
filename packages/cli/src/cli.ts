import { Command, InvalidArgumentError } from 'commander';
import chalk from 'chalk';
import clipboardy from 'clipboardy';
import ora from 'ora';
import {
  DEFAULT_TIMEOUT_MS,
  DEFAULT_TLS_PORT,
  MAX_PORT_NUMBER,
  SERIALIZATION_SCHEMA_VERSION,
  UNKNOWN_VALUE,
  getCopyValue,
  inspectTlsHost,
  toLegacyPins,
  toSerializableResult,
  type CopyKind,
} from '@sslpin/core';

const EXIT_CODE_SUCCESS = 0;
const EXIT_CODE_FAILURE = 1;
const EXIT_CODE_WARNING = 2;
const SCHEMA_VERSION = SERIALIZATION_SCHEMA_VERSION;
const COPY_OPTION_VALUES: CopyKind[] = ['spki', 'sha256', 'pem'];
const CLI_HELP_EXAMPLES = [
  '$ sslpin example.com',
  '$ sslpin example.com --json',
  '$ sslpin example.com --leaf-only --copy spki',
  '$ sslpin https://example.com --port 8443 --timeout 10000 --servername example.com',
];

interface CliOptions {
  json?: boolean;
  port?: number;
  timeout?: number;
  servername?: string;
  leafOnly?: boolean;
  copy?: CopyKind;
}

function isCopyKind(value: string): value is CopyKind {
  return COPY_OPTION_VALUES.includes(value as CopyKind);
}

function parsePositiveInteger(value: string, optionLabel: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new InvalidArgumentError(`${optionLabel} must be a positive integer`);
  }

  return parsed;
}

function parsePort(value: string): number {
  const port = parsePositiveInteger(value, '--port');
  if (port > MAX_PORT_NUMBER) {
    throw new InvalidArgumentError(`--port must be less than or equal to ${MAX_PORT_NUMBER}`);
  }

  return port;
}

function parseTimeout(value: string): number {
  return parsePositiveInteger(value, '--timeout');
}

function parseCopyKind(value: string): CopyKind {
  if (isCopyKind(value)) {
    return value;
  }

  throw new InvalidArgumentError(`--copy must be one of: ${COPY_OPTION_VALUES.join(', ')}`);
}

function parseServername(value: string): string {
  const parsed = value.trim();
  if (!parsed) {
    throw new InvalidArgumentError('--servername cannot be empty');
  }

  return parsed;
}

function validateCopyUsage(domains: string[], copy: CopyKind | undefined): string | null {
  if (copy && domains.length !== 1) {
    return '--copy can only be used with exactly one domain';
  }

  return null;
}

function toInspectTlsHostOptions(options: CliOptions) {
  return {
    port: options.port,
    timeoutMs: options.timeout,
    servername: options.servername,
    leafOnly: options.leafOnly,
  };
}

function formatDate(input: string): string {
  const parsed = new Date(input);
  if (Number.isNaN(parsed.getTime())) {
    return input;
  }

  return parsed.toISOString();
}

function formatValidityHint(validTo: string): string {
  const parsed = new Date(validTo);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }

  const deltaMs = parsed.getTime() - Date.now();
  const days = Math.ceil(Math.abs(deltaMs) / (24 * 60 * 60 * 1000));
  if (deltaMs < 0) {
    return `(expired ${days} day${days === 1 ? '' : 's'} ago)`;
  }

  return `(expires in ${days} day${days === 1 ? '' : 's'})`;
}

function toError(value: unknown): Error {
  if (value instanceof Error) {
    return value;
  }

  return new Error(String(value));
}

function displayText(value: string): string {
  return value && value.trim().length > 0 ? value : UNKNOWN_VALUE;
}

function printWarnings(warnings: ReturnType<typeof toSerializableResult>['warnings']): void {
  if (warnings.length === 0) {
    return;
  }

  console.log(chalk.yellow.bold('Warnings:'));
  for (const warning of warnings) {
    console.log(chalk.yellow(`- [${warning.code}] ${warning.message}`));
  }
}

function printResult(result: Awaited<ReturnType<typeof inspectTlsHost>>): void {
  const serializable = toSerializableResult(result);
  const legacy = toLegacyPins(result);

  console.log(
    chalk.bold(
      `PING ${serializable.host} (${serializable.ip}:${serializable.port}) with ${serializable.tlsVersion}:`,
    ),
  );
  console.log(
    chalk.green(
      `${legacy.dataSize} bytes from ${serializable.ip}: Status=${legacy.status} Time=${serializable.durationMs}ms Cipher=${serializable.cipher}`,
    ),
  );
  console.log(chalk.bold(`Certificates for ${serializable.host}:`));

  for (const cert of serializable.certificates) {
    console.log(chalk.bold.white(`Index: ${cert.index}${cert.isLeaf ? ' (leaf)' : ''}`));
    console.log(chalk.cyan(`Subject: ${displayText(cert.subject)}`));
    console.log(chalk.blue(`Issuer: ${displayText(cert.issuer)}`));
    console.log(chalk.green(`Valid From: ${formatDate(cert.validFrom)}`));
    console.log(
      chalk.green(
        `Valid To: ${formatDate(cert.validTo)} ${formatValidityHint(cert.validTo)}`.trim(),
      ),
    );
    console.log(chalk.magenta(`Serial Number: ${displayText(cert.serialNumber)}`));
    console.log(chalk.bold.white(`SHA1 Fingerprint: ${displayText(cert.sha1Fingerprint)}`));
    console.log(chalk.bold.white(`SHA256 Fingerprint: ${displayText(cert.sha256Fingerprint)}`));
    console.log(chalk.bold.yellow(`SHA256 SPKI(base64): ${displayText(cert.spkiSha256)}`));
    console.log(chalk.bold.yellow(`SHA256 SPKI(hex): ${displayText(cert.spkiSha256Hex)}`));
    console.log(chalk.gray('-'.repeat(40)));
  }

  printWarnings(serializable.warnings);
}

function toJsonSuccessPayload(result: Awaited<ReturnType<typeof inspectTlsHost>>) {
  const serializable = toSerializableResult(result);
  const legacy = toLegacyPins(result);

  return {
    schemaVersion: SCHEMA_VERSION,
    ...serializable,
    result,
    ...legacy,
  };
}

function toJsonFailurePayload(target: string, error: Error) {
  return {
    schemaVersion: SCHEMA_VERSION,
    target,
    error: {
      message: error.message,
    },
  };
}

function determineExitCode(hasFailures: boolean, hasWarnings: boolean): number {
  if (hasFailures) {
    return EXIT_CODE_FAILURE;
  }
  if (hasWarnings) {
    return EXIT_CODE_WARNING;
  }

  return EXIT_CODE_SUCCESS;
}

function logError(message: string, json: boolean): void {
  if (json) {
    return;
  }

  console.error(chalk.red(message));
}

function getClipboardGuidance(copyKind: CopyKind): string {
  return `Unable to copy ${copyKind} to clipboard. Ensure clipboard support is available (pbcopy on macOS or xclip/xsel on Linux), or rerun without --copy.`;
}

export function createProgram(): Command {
  const program = new Command();

  program
    .name('sslpin')
    .description('Inspect TLS certificate chains and SSL pinning values for HTTPS hosts')
    .version('0.0.2', '-v, --version')
    .option('--json', 'output as JSON')
    .option('--port <number>', `target port (default: ${DEFAULT_TLS_PORT})`, parsePort)
    .option(
      '--timeout <ms>',
      `connection timeout in milliseconds (default: ${DEFAULT_TIMEOUT_MS})`,
      parseTimeout,
    )
    .option('--servername <name>', 'override TLS SNI / hostname', parseServername)
    .option('--leaf-only', 'include only leaf certificate in output')
    .option('--copy <field>', 'copy one leaf value to clipboard: spki|sha256|pem', parseCopyKind)
    .argument('<domains...>', 'domains or HTTPS URLs to inspect')
    .addHelpText(
      'after',
      `
Examples:
  ${CLI_HELP_EXAMPLES.join('\n  ')}`,
    )
    .action(async (domains: string[], options: CliOptions) => {
      const copyUsageError = validateCopyUsage(domains, options.copy);
      if (copyUsageError) {
        if (options.json) {
          console.log(
            JSON.stringify(
              {
                schemaVersion: SCHEMA_VERSION,
                error: { message: copyUsageError },
              },
              null,
              2,
            ),
          );
        } else {
          logError(copyUsageError, false);
        }

        process.exitCode = EXIT_CODE_FAILURE;
        return;
      }

      const inspectOptions = toInspectTlsHostOptions(options);
      const jsonPayloads: unknown[] = [];
      let hasFailures = false;
      let hasWarnings = false;
      let successfulResult: Awaited<ReturnType<typeof inspectTlsHost>> | null = null;

      for (const domain of domains) {
        const spinner =
          options.json === true ? null : ora(`Fetching certificate data from ${domain}...`).start();

        try {
          const result = await inspectTlsHost({
            input: domain,
            ...inspectOptions,
          });

          successfulResult = result;
          hasWarnings = hasWarnings || result.warnings.length > 0;
          spinner?.succeed(`Fetched certificate data from ${result.target.host}`);

          if (options.json) {
            jsonPayloads.push(toJsonSuccessPayload(result));
          } else {
            printResult(result);
          }
        } catch (error) {
          hasFailures = true;
          spinner?.fail(`Failed to fetch certificate data from ${domain}`);

          const normalizedError = toError(error);
          if (options.json) {
            jsonPayloads.push(toJsonFailurePayload(domain, normalizedError));
          } else {
            logError(`Error fetching pins for ${domain}: ${normalizedError.message}`, false);
          }
        }
      }

      if (options.copy && successfulResult) {
        try {
          const copiedValue = getCopyValue(successfulResult, options.copy);
          await clipboardy.write(copiedValue);
          if (!options.json) {
            console.log(chalk.green(`Copied ${options.copy} value to clipboard.`));
          }
        } catch {
          hasFailures = true;
          const message = getClipboardGuidance(options.copy);
          if (options.json) {
            jsonPayloads.push(
              toJsonFailurePayload(successfulResult.target.input, new Error(message)),
            );
          } else {
            logError(message, false);
          }
        }
      }

      if (options.json) {
        const output = jsonPayloads.length === 1 ? jsonPayloads[0] : jsonPayloads;
        console.log(JSON.stringify(output, null, 2));
      }

      process.exitCode = determineExitCode(hasFailures, hasWarnings);
    });

  program.configureOutput({
    outputError: (str, write) => {
      write(chalk.red(str));
      process.exitCode = EXIT_CODE_FAILURE;
    },
  });

  return program;
}

export async function runCli(argv: string[]): Promise<void> {
  const program = createProgram();
  await program.parseAsync(argv);
}
