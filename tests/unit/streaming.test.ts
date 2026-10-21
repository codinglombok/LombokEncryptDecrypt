import {
  createEncryptStream,
  createDecryptStream,
  encryptStreamGen,
} from '../../src/stream/encrypt_stream.js';
import { concatBytes } from '../../src/utils/encoding.js';
import { randomKey256 } from '../../src/utils/random.js';
import { ErrorCode } from '../../src/errors.js';

const KEY = randomKey256();

async function encryptAll(
  data: Uint8Array,
  chunkSize: number,
  updateSize = 8192,
): Promise<Uint8Array> {
  const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize });
  const parts: Uint8Array[] = [];
  for (let off = 0; off < data.length; off += updateSize) {
    parts.push(...(await enc.update(data.subarray(off, Math.min(off + updateSize, data.length)))));
  }
  parts.push(await enc.final());
  return concatBytes(...parts);
}

async function decryptAll(
  data: Uint8Array,
  chunkSize: number,
  updateSize = 4096,
): Promise<Uint8Array> {
  const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize });
  const parts: Uint8Array[] = [];
  for (let off = 0; off < data.length; off += updateSize) {
    parts.push(...(await dec.update(data.subarray(off, Math.min(off + updateSize, data.length)))));
  }
  parts.push(await dec.final());
  return concatBytes(...parts);
}

describe('streaming AEAD', () => {
  it('round-trips across chunk boundaries, including empty input', async () => {
    for (const size of [0, 1, 100, 65535, 65536, 65537, 200000]) {
      for (const chunkSize of [1024, 65536]) {
        const data = new Uint8Array(size);
        for (let i = 0; i < size; i++) data[i] = (i * 31 + 7) & 0xff;
        const encBytes = await encryptAll(data, chunkSize);
        const back = await decryptAll(encBytes, chunkSize);
        expect(back).toEqual(data);
      }
    }
  });

  it('binds the chunk index: reordering is rejected with INTEGRITY_CHECK_FAILED', async () => {
    const data = new Uint8Array(3000);
    const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1024 });
    const chunk1 = (await enc.update(data.subarray(0, 1024)))[0];
    const chunk2 = (await enc.update(data.subarray(1024, 2048)))[0];
    const sentinel = await enc.final();
    const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1024 });
    await expect(dec.update(concatBytes(chunk2, chunk1))).rejects.toThrow(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
    void sentinel;
  });

  it('detects truncation (missing sentinel)', async () => {
    const data = new Uint8Array(3000);
    const encBytes = await encryptAll(data, 1024);
    const truncated = encBytes.subarray(0, encBytes.length - 4);
    await expect(decryptAll(truncated, 1024)).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
  });

  it('detects tampering in any chunk', async () => {
    const data = new Uint8Array(3000);
    const encBytes = await encryptAll(data, 1024);
    const tampered = new Uint8Array(encBytes);
    tampered[20] ^= 1;
    await expect(decryptAll(tampered, 1024)).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
  });

  it('rejects trailing garbage after the sentinel', async () => {
    const data = new Uint8Array(100);
    const encBytes = await encryptAll(data, 1024);
    const trailing = concatBytes(encBytes, new Uint8Array([1, 2, 3]));
    await expect(decryptAll(trailing, 1024)).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
  });

  it('throws STREAM_FINALISED when reusing finalised streams', async () => {
    const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY });
    await enc.update(new Uint8Array(10));
    await enc.final();
    await expect(enc.update(new Uint8Array(10))).rejects.toThrow(ErrorCode.STREAM_FINALISED);
    await expect(enc.final()).rejects.toThrow(ErrorCode.STREAM_FINALISED);
    // an empty decrypt stream is truncated (no sentinel) — that is its own error
    const emptyDec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY });
    await expect(emptyDec.final()).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
    // a completed stream refuses a second final()
    const enc2 = createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY });
    const frame = concatBytes(...(await enc2.update(new Uint8Array(10))), await enc2.final());
    const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY });
    await dec.update(frame);
    await dec.final();
    await expect(dec.final()).rejects.toThrow(ErrorCode.STREAM_FINALISED);
  });

  it('validates options', async () => {
    expect(() => createEncryptStream({ algorithm: 'NOT-A-CIPHER' as never, key: KEY })).toThrow();
    expect(() => createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 0 })).toThrow(
      ErrorCode.INVALID_IV_SIZE,
    );
    expect(() =>
      createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 2_000_000 }),
    ).toThrow(ErrorCode.INVALID_IV_SIZE);
    await expect(decryptAll(new Uint8Array(3), 1024)).rejects.toThrow(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
  });

  it('works with the async generator API over a ReadableStream', async () => {
    const data = new Uint8Array(5000);
    for (let i = 0; i < 5000; i++) data[i] = i & 0xff;
    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(data.subarray(0, 2000));
        controller.enqueue(data.subarray(2000));
        controller.close();
      },
    });
    const parts: Uint8Array[] = [];
    for await (const chunk of encryptStreamGen(source, {
      algorithm: 'AES-256-GCM',
      key: KEY,
      chunkSize: 1024,
    })) {
      parts.push(chunk);
    }
    const encBytes = concatBytes(...parts);
    expect(encBytes.length).toBeGreaterThan(data.length);
    // decrypt with the manual stream
    const back = await decryptAll(encBytes, 1024);
    expect(back).toEqual(data);
  });

  it('decrypts the documented bench-style usage pattern', async () => {
    const payload = new Uint8Array(70000);
    const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 65536 });
    const parts: Uint8Array[] = [];
    parts.push(...(await enc.update(payload)));
    parts.push(await enc.final());
    const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 65536 });
    const decParts: Uint8Array[] = [];
    decParts.push(...(await dec.update(concatBytes(...parts))));
    decParts.push(await dec.final());
    expect(concatBytes(...decParts)).toEqual(payload);
  });
});
