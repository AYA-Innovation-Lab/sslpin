import { build } from 'esbuild';

await build({
  entryPoints: ['src/index.ts', 'src/cli.ts'],
  outdir: 'dist',
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node18',
  external: ['chalk', 'clipboardy', 'commander', 'ora'],
});
