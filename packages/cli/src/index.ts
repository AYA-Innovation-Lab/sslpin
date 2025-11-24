import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { format, formatDistanceToNow } from "date-fns";
import { sslPingDomain } from "./utils";

const program = new Command();

// Function to format pins with specified colors
function printPinDetails(pins: any[]) {
  pins.forEach((pin) => {
    console.log(chalk.bold.white(`Index: ${pin.index}`));
    console.log(chalk.cyan(`Subject: ${pin.subject}`));
    console.log(chalk.blue(`Issuer: ${pin.issuer}`));
    const validFrom = new Date(pin.validFrom);
    const validTo = new Date(pin.validTo);
    console.log(chalk.green(`Valid From: ${format(validFrom, 'PPpp zzz')}`));
    console.log(chalk.green(`Valid To: ${format(validTo, 'PPpp zzz')} (expires ${formatDistanceToNow(validTo, { addSuffix: true })})`));
    console.log(chalk.magenta(`Serial Number: ${pin.serialNumber}`));
    console.log(chalk.bold.white(`SHA1 Fingerprint: ${pin.sha1Fingerprint}`));
    console.log(chalk.bold.white(`SHA256 Fingerprint: ${pin.sha256Fingerprint}`));
    console.log(chalk.bold.yellow(`SHA256 SPKI(base64): ${pin.spkiSha256}`));
    console.log(chalk.bold.yellow(`SHA256 SPKI(hex): ${pin.spkiSha256Hex}`));
    console.log(chalk.gray("-".repeat(40)));
  });
}

// Configure CLI
program
  .name("sslpin")
  .description("A lightweight CLI tool to extract SHA1, SHA256, SPKI pins and certificate fingerprints for SSL/TLS pinning from the target domain")
  .version("0.0.1", "-v, --version")
  .option("--json", "output in JSON format")
  .argument("<domains...>", "domains to ping")
  .action(async (domains: string[], options: { json?: boolean }) => {
    for (const domain of domains) {
      const cleanDomain = domain.replace(/^https?:\/\//, ''); // Remove https:// prefix
      const spinner = ora(`Fetching certificate data from ${cleanDomain}...`).start();
      try {
        const result = await sslPingDomain(cleanDomain);
        spinner.succeed(`Fetched certificate data from ${cleanDomain}`);
        if (options.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          const { pins, ip, port, tlsVersion, cipher, time, status, dataSize } = result;
          console.log(chalk.bold(`PING ${cleanDomain} (${ip}:${port}) with ${tlsVersion}:`));
          console.log(chalk.green(`${dataSize} bytes from ${ip}: Status=${status} Time=${time}ms Cipher=${cipher}`));
          console.log(chalk.bold(`Pins for ${cleanDomain}:`));
          printPinDetails(pins);
        }
      } catch (err) {
        spinner.stop();
        if (options.json) {
          console.log(JSON.stringify({ error: (err as Error).message }, null, 2));
        } else {
          console.error(); // Add newline before error
          console.error(chalk.red(`Error fetching pins for ${cleanDomain}: ${(err as Error).message}`));
        }
        process.exit(1);
      }
    }
  });

// Handle uncaught errors
process.on("uncaughtException", (err) => {
  console.error(chalk.red(`Uncaught Exception: ${err.message}`));
  process.exit(1);
});

process.on("unhandledRejection", (err) => {
  console.error(chalk.red(`Unhandled Rejection: ${err}`));
  process.exit(1);
});

program.parse(process.argv);
