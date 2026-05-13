export function encodeMessageLine(message: unknown): string {
  return `${JSON.stringify(message)}\n`;
}

export function decodeMessageLines(input: string): {
  messages: unknown[];
  remainder: string;
} {
  const messages: unknown[] = [];
  const lines = input.split(/\r?\n/);
  const remainder = lines.pop() ?? '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    messages.push(JSON.parse(trimmed));
  }

  return {
    messages,
    remainder,
  };
}
