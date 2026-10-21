/**
 * Deno bootstrap — installs jest-style BDD globals (describe/it/expect)
 * so the same test files run on jest, Bun and Deno. Loaded via --preload
 * in the Deno CI job:
 *   deno test --allow-read tests/ --import-map=deno_import_map.json \
 *     --unstable-sloppy-imports --no-check --preload tests/deno-bdd.ts
 */

import { afterEach, beforeEach, describe, it } from 'jsr:@std/testing/bdd';
import { expect } from 'jsr:@std/expect';

const globals = globalThis as unknown as Record<string, unknown>;
globals.describe = describe;
globals.it = it;
globals.beforeEach = beforeEach;
globals.afterEach = afterEach;
globals.expect = expect;
