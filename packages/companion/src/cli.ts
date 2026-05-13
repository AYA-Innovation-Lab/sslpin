#!/usr/bin/env node
import { handleCompanionRequest } from './handler.js';
import { decodeMessageLines, encodeMessageLine } from './protocol.js';
import type { CompanionResponse } from './types.js';

let buffer = '';
let queue = Promise.resolve();

function writeResponse(response: CompanionResponse): void {
  process.stdout.write(encodeMessageLine(response));
}

function enqueue(rawMessage: unknown): void {
  queue = queue
    .then(async () => {
      const response = await handleCompanionRequest(rawMessage);
      writeResponse(response);
    })
    .catch((error) => {
      writeResponse({
        id: 'unknown',
        ok: false,
        error: {
          code: 'INTERNAL',
          message: error instanceof Error ? error.message : String(error),
        },
      });
    });
}

process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;

  try {
    const { messages, remainder } = decodeMessageLines(buffer);
    buffer = remainder;
    for (const message of messages) {
      enqueue(message);
    }
  } catch (error) {
    writeResponse({
      id: 'unknown',
      ok: false,
      error: {
        code: 'BAD_REQUEST',
        message: `Invalid JSON message: ${error instanceof Error ? error.message : String(error)}`,
      },
    });
    buffer = '';
  }
});

process.stdin.resume();
