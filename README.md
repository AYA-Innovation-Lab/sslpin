# SSLPin CLI

A lightweight CLI tool that inspects an HTTPS host, reads its TLS certificate chain, and prints fingerprints and SPKI pins locally.

## Features

- SHA1 & SHA256 fingerprints
- SPKI pins (Base64/Hex)
- Certificate validity & expiration
- Issuer, subject, serial number
- TLS connection details

## Installation

```bash
# one-off
npx sslpin google.com

# global install
npm install -g sslpin
```

## Usage

```bash
sslpin google.com
sslpin google.com --json
sslpin https://example.com --leaf-only
sslpin example.com --copy spki
```

## Options

Supports bare domains and HTTPS URLs. Use `--help` for the full list.

- `-v, --version`: Show version
- `--json`: Output in JSON format
- `--leaf-only`: Show only the leaf certificate
- `--copy <field>`: Copy `spki`, `sha256`, or `pem`
- `-h, --help`: Show help

## Development

```bash
yarn build
node packages/cli/bin/sslpin google.com
```

The published CLI is `sslpin` only. `packages/core` stays as an internal workspace package and is bundled into the CLI build.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
