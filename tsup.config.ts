import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: false,
  minify: false,
  external: [
    /node_modules/,
  ],
  target: 'es2020',
  platform: 'neutral',
  bundle: false,
});
