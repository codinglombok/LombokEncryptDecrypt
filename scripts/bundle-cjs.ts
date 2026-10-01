/**
 * LombokEncryptDecrypt — CommonJS Bundle Builder
 * Converts ESM dist to CJS for Node.js require() compatibility.
 * Usage: tsx scripts/bundle-cjs.ts
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { resolve, relative, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ESM_DIR   = resolve(__dirname, '../dist/esm');
const CJS_DIR   = resolve(__dirname, '../dist/cjs');

mkdirSync(CJS_DIR, { recursive: true });

function convertEsmToCjs(content: string, filePath: string): string {
  // Simple ESM → CJS transform for the barrel exports
  // Production uses esbuild/rollup; this is a minimal fallback
  let cjs = content
    // Convert: export { foo } from './bar.js'
    .replace(/export \{ (.+) \} from '(.+)';\n/g, (_, exports, from) => {
      const names = exports.split(',').map((s: string) => s.trim());
      return names.map((n: string) => {
        const [orig, alias] = n.split(' as ').map((s: string) => s.trim());
        const exportName = alias ?? orig;
        return `Object.defineProperty(exports, '${exportName}', { enumerable: true, get: function() { return require('${from}').${orig}; } });\n`;
      }).join('');
    })
    // Convert: export const foo = ...
    .replace(/export const (\w+)/g, 'exports.$1 = exports.$1 || void 0; const $1')
    // Convert: export function foo
    .replace(/export function (\w+)/g, 'const $1 = exports.$1 = function $1')
    // Convert: export class Foo
    .replace(/export class (\w+)/g, 'const $1 = exports.$1 = class $1')
    // Convert: export type / export interface (strip)
    .replace(/export type .+;\n?/g, '')
    .replace(/export interface .+\{[\s\S]*?\}\n?/g, '')
    // Convert: import { foo } from './bar.js'
    .replace(/import \{ (.+) \} from '(.+)';\n/g, (_, imports, from) => {
      return `const { ${imports} } = require('${from}');\n`;
    })
    // Convert: import foo from './bar.js'
    .replace(/import (\w+) from '(.+)';\n/g, "const $1 = require('$2');\n")
    // Add CJS preamble
    ;
  return `'use strict';\nObject.defineProperty(exports, '__esModule', { value: true });\n${cjs}`;
}

function processDir(dir: string, outDir: string): void {
  mkdirSync(outDir, { recursive: true });
  for (const entry of readdirSync(dir)) {
    const src = resolve(dir, entry);
    const dst = resolve(outDir, entry.replace(/\.js$/, '.cjs'));
    if (statSync(src).isDirectory()) {
      processDir(src, resolve(outDir, entry));
    } else if (entry.endsWith('.js')) {
      const content = readFileSync(src, 'utf8');
      writeFileSync(dst, convertEsmToCjs(content, src));
      console.log(`  CJS: ${relative(CJS_DIR, dst)}`);
    }
  }
}

console.log('\n📦 Building CJS bundle...\n');
processDir(ESM_DIR, CJS_DIR);
console.log('\n✅ CJS bundle complete');
