/**
 * Deno bootstrap — installs jest-style BDD globals (describe/it/expect)
 * so the same test files run on jest, Bun and Deno. Loaded via --preload
 * in the Deno CI job:
 *   deno test --allow-read tests/ --import-map=deno_import_map.json \
 *     --unstable-sloppy-imports --no-check --preload tests/deno-bdd.ts
 *
 * Extends jsr:@std/testing/bdd with jest-compatible table-driven helpers:
 *   - describe.each(table)(name, fn)
 *   - it.each(table)(name, fn, timeout?)   [alias: test.each]
 * Supported table shapes (same as jest):
 *   - array of primitives  -> fn(value)
 *   - array of tuples      -> fn(...tuple)
 *   - array of objects     -> fn(obj)
 * Supported title tokens: %s %d %i %f %j %o %O %p %# %% and $var/$index.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, it } from 'jsr:@std/testing/bdd';
import { expect } from 'jsr:@std/expect';

const globals = globalThis as unknown as Record<string, unknown>;
globals.describe = describe;
globals.it = it;
globals.test = it;
globals.beforeAll = beforeAll;
globals.afterAll = afterAll;
globals.beforeEach = beforeEach;
globals.afterEach = afterEach;
globals.expect = expect;

/** Safely stringify a value for %j / %p-style tokens. */
function pretty(value: unknown): string {
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

/**
 * Jest printf-style title formatting.
 * `%#` yields the 1-based row index (jest uses the test-case index;
 * the exact value is not asserted anywhere in this suite).
 */
function formatTitle(pattern: string, args: unknown[], row: unknown, index: number): string {
  let argIndex = 0;
  let out = pattern.replace(/%[%sdifjoOp#]/g, (token) => {
    if (token === '%%') return '%';
    if (token === '%#') return String(index);
    const value = args[argIndex++];
    switch (token) {
      case '%s':
        return pretty(value);
      case '%d':
      case '%i':
        return String(Math.trunc(Number(value)));
      case '%f':
        return String(Number(value));
      case '%j':
      case '%o':
      case '%O':
      case '%p':
        return pretty(value);
      default:
        return token;
    }
  });
  // jest object-row "$var" / "$0" interpolation (rows of objects or tuples)
  if (/\$[0-9a-zA-Z_]/.test(out)) {
    if (row !== null && typeof row === 'object') {
      out = out.replace(/\$([0-9a-zA-Z_]+)/g, (_m, key: string) => {
        if (/^[0-9]+$/.test(key)) return String((row as unknown[])[Number(key)]);
        const record = row as Record<string, unknown>;
        return key in record ? pretty(record[key]) : `<${key}>`;
      });
    } else if (/^\$0$/.test(out) === false) {
      out = out.replace(/\$0/g, String(index));
    }
  }
  return out;
}

type Row = unknown;
type Table = readonly Row[];
type RunFn = (name: string, fn: (...args: unknown[]) => unknown) => void;
type EachTableFn = (
  table: Table,
) => (name: string, fn: (...args: unknown[]) => unknown, timeout?: number) => void;

/**
 * Build a jest-compatible `.each` for a given runner (`it` or `describe`).
 * Primitives are passed as a single argument; tuples are spread; objects
 * are passed as-is (callbacks destructure them).
 */
function makeEach(run: RunFn): EachTableFn {
  return (table: Table) => {
    if (!Array.isArray(table)) {
      throw new TypeError('.each() expects an array or tagged template literal');
    }
    return (_name: string, fn: (...args: unknown[]) => unknown, _timeout?: number) => {
      // `timeout` is accepted for jest signature parity; Deno enforces no
      // per-test timeout through this shim, so it is intentionally ignored.
      table.forEach((row, index) => {
        const args = Array.isArray(row) ? [...(row as unknown[])] : [row];
        const name = formatTitle(_name, args, row, index);
        run(name, () => fn(...args));
      });
    };
  };
}

(globals.it as { each: EachTableFn }).each = makeEach((name, fn) => it(name, fn));
(globals.test as { each: EachTableFn }).each = makeEach((name, fn) => it(name, fn));
(globals.describe as { each: EachTableFn }).each = makeEach((name, fn) => describe(name, fn));
