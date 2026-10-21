// Node 18+ exposes the Web Streams globals; the bundled @types/node version
// used for type-checking does not declare them, so bridge the gap here.
declare global {
  var ReadableStream: typeof import('node:stream/web').ReadableStream;
}

export {};
