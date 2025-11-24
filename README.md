# SSLPin CLI

A lightweight CLI tool that connects to an HTTPS domain, reads its SSL/TLS certificate, and generates fingerprints and SPKI pins — all locally.

## Features

- SHA1 & SHA256 fingerprints
- SPKI pins (Base64/Hex)
- Certificate validity & expiration
- Issuer, subject, serial number
- TLS connection details

## Installation

```bash
npm install -g sslpin
# or using Yarn Berry
yarn global add sslpin
```

## Usage

```bash
# Using npx (recommended)
npx sslpin www.google.com

# Or if installed globally
sslpin www.google.com
```
### Options

Supports HTTPS URLs (auto-strips `https://`). Use `--help` for all options.

- `-v, --version`: Show version
- `--json`: Output in JSON format
- `-h, --help`: Show help

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
