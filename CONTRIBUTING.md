# Contributing to SSLPin

Thank you for your interest in contributing to SSLPin. We welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/sslpin.git`
3. Install dependencies: `yarn install`
4. Create a new branch for your changes: `git checkout -b feature/feature-name`

## Development Setup

- Requires Node.js 22.11.0+ (use `nvm use` if you have nvm)
- Uses Yarn Berry as package manager
- The repo is split into publishable packages:
  - `packages/core`
  - `packages/cli`
  - `packages/companion`

### Common Commands

```bash
yarn build
yarn build:core
yarn build:cli
yarn build:companion
yarn lint:cli
node packages/cli/bin/sslpin google.com
```

### Publishing

Release packages in this order:

1. `@sslpin/core`
2. `@sslpin/companion` if needed
3. `sslpin`

Before publishing:

```bash
npm_config_cache=/private/tmp/npm-cache npm pack --dry-run ./packages/core
npm_config_cache=/private/tmp/npm-cache npm pack --dry-run ./packages/cli
```

## Code Style

This project uses ESLint and Prettier for code formatting. Please:

- Run `yarn lint` to check code style
- Ensure your code passes all linting checks before submitting
- Follow TypeScript best practices

## Testing

- Add tests for any new functionality
- Run the test suite with `yarn test`
- Ensure all tests pass before submitting a pull request

## Pull Requests

- Describe the changes you made
- Reference any related issues
- Keep PRs focused on a single feature or fix

## Issues

- Use the GitHub issue tracker to report bugs or request features
- Provide detailed information including steps to reproduce for bugs
- Include your Node.js version and OS for bug reports
