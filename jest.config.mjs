/** @type {import('jest').Config} */
const config = {
  // ts-jest in CommonJS mode: stable on every OS in the CI matrix (no
  // --experimental-vm-modules requirement). Type checking is done by
  // `npm run typecheck` (tsc --noEmit) in the lint job, so the transform
  // runs in transpile-only mode for speed.
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'json', 'node'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        transpileOnly: true,
        tsconfig: {
          module: 'commonjs',
          esModuleInterop: true,
          target: 'ES2022',
        },
      },
    ],
  },
  testMatch: [
    '<rootDir>/tests/unit/**/*.test.ts',
    '<rootDir>/tests/integration/**/*.test.ts',
    '<rootDir>/tests/vectors/**/*.test.ts',
  ],
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*.d.ts', '!src/**/index.ts'],
  coverageThreshold: {
    global: {
      lines: 95,
      branches: 90,
      functions: 95,
      statements: 95,
    },
  },
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  verbose: true,
  testTimeout: 60000,
};

export default config;
