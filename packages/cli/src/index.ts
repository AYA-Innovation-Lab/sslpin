import chalk from 'chalk';
import { runCli } from './cli.js';

const EXIT_CODE_FAILURE = 1;

process.on('uncaughtException', (error) => {
  console.error(chalk.red(`Uncaught Exception: ${error.message}`));
  process.exit(EXIT_CODE_FAILURE);
});

process.on('unhandledRejection', (error) => {
  console.error(chalk.red(`Unhandled Rejection: ${String(error)}`));
  process.exit(EXIT_CODE_FAILURE);
});

void runCli(process.argv);
