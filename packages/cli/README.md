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
npx sslpin google.com
# or install globally
npm install -g sslpin
```

## Usage

```bash
sslpin google.com
sslpin google.com --json
sslpin example.com --leaf-only
sslpin example.com --copy spki
```

## Options

Supports bare domains and HTTPS URLs. Use `--help` for the full list.

- `-v, --version`: Show version
- `--json`: Output in JSON format
- `--leaf-only`: Show only the leaf certificate
- `--copy <field>`: Copy `spki`, `sha256`, or `pem`
- `-h, --help`: Show help

## Local Development

```bash
yarn workspace @sslpin/core build
yarn workspace sslpin build
node packages/cli/bin/sslpin google.com
```

`sslpin` is published as a single CLI package. The internal core workspace is bundled into the final CLI build, so end users only install `sslpin`.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
