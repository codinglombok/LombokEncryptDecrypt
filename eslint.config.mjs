import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'ports/**',
      'src-rust/**',
      'coverage/**',
      // Deno-only preload shim: imports jsr: specifiers that TS/ESLint cannot
      // resolve and is excluded from tsconfig.json for the same reason.
      'tests/deno-bdd.ts',
    ],
  },
  {
    files: ['src/**/*.ts', 'tests/**/*.ts', 'benches/**/*.ts', 'scripts/**/*.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: here,
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    plugins: { '@typescript-eslint': tseslint },
    rules: {
      // typescript-eslint v8 canonical config names (the old
      // 'recommended-requiring-type-checking' alias is deprecated).
      ...tseslint.configs['recommended'].rules,
      ...tseslint.configs['recommended-type-checked'].rules,

      // Crypto library specific rules
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/strict-boolean-expressions': 'error',
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/prefer-readonly': 'error',
      // The documented API is async (await aesGcm.encrypt(...)) even where the
      // pure-TS implementation is synchronous, so callers can swap in
      // WebCrypto/platform backends without breaking await sites.
      'require-await': 'off',
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/return-await': ['error', 'in-try-catch'],
      '@typescript-eslint/no-floating-promises': 'error',

      // Enforce explicit types in crypto APIs
      '@typescript-eslint/explicit-function-return-type': [
        'error',
        {
          allowExpressions: true,
          allowTypedFunctionExpressions: true,
        },
      ],
      '@typescript-eslint/explicit-module-boundary-types': 'error',

      // No console in library code (benches override this below)
      'no-console': 'error',

      // Prevent accidental use of Math.random() in crypto code.
      // no-restricted-globals cannot target a member expression, so the
      // correct rule for "never call Math.random()" is no-restricted-properties.
      // Math itself stays allowed (Math.imul / Math.floor are required by the
      // 32-bit arithmetic used throughout the pure-TS primitives).
      'no-restricted-properties': [
        'error',
        {
          object: 'Math',
          property: 'random',
          message:
            'Use the platform-aware CSPRNG from utils/random.js — Math.random() is not cryptographically secure.',
        },
      ],

      // Enforce parameter naming for clarity in crypto APIs
      '@typescript-eslint/naming-convention': [
        'error',
        // The documented public API spells SHA-3 family as sha3_256 / shake128
        // (docs/API.md), so snake_case is allowed only for sha3_-prefixed names.
        { selector: 'variable', format: ['camelCase', 'UPPER_CASE', 'PascalCase'] },
        { selector: 'variable', format: [], filter: { regex: '^sha3_', match: true } },
        { selector: 'function', format: ['camelCase'] },
        { selector: 'function', format: [], filter: { regex: '^sha3_', match: true } },
        { selector: 'typeLike', format: ['PascalCase'] },
      ],
    },
  },
  {
    // Benchmarks and the vector generator are CLI tools — printing results is
    // their whole purpose.
    files: ['benches/**/*.ts', 'scripts/**/*.ts'],
    rules: {
      'no-console': 'off',
    },
  },
];
