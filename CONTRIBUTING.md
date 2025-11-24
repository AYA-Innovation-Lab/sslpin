# Contributing to SSLPing CLI

Thank you for your interest in contributing to SSLPin CLI! We welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/sslpin.git`
3. Install dependencies: `yarn install`
4. Create a new branch for your changes: `git checkout -b feature/feature-name`

## Development Setup

- Requires Node.js 22.11.0+ (use `nvm use` if you have nvm)
- Uses Yarn Berry as package manager
- Uses ESBuild for fast TypeScript compilation and bundling
- Run `yarn build` to build the CLI (generates dist/index.js using esbuild config)
- Run `yarn test` to run tests
- Use `yarn start` to test the CLI locally

### Build Configuration

The project uses ESBuild for building. Configuration is in `packages/cli/esbuild.config.js`:

- Bundles all TypeScript sources into a single ES module
- External dependencies (node modules) are not bundled
- Output: `dist/index.js` as ESM format for Node.js

To modify build settings, edit `esbuild.config.js` which uses the esbuild API.

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
