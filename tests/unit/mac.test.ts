import { hmacSha256, hmacSha384, hmacSha512 } from '../../src/mac/hmac.js';
import { ErrorCode } from '../../src/errors.js';
import { cmac } from '../../src/mac/cmac.js';

const enc = new TextEncoder();

describe('HMAC (RFC 2104 / FIPS 198-1)', () => {
  it('matches RFC 4231 test case 1 for all three hashes', async () => {
    const key = new Uint8Array(20).fill(0x0b);
    const msg = enc.encode('Hi There');
    expect(Buffer.from(await hmacSha256.compute(key, msg)).toString('hex')).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    );
    expect(Buffer.from(await hmacSha384.compute(key, msg)).toString('hex')).toBe(
      'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
    );
    expect(Buffer.from(await hmacSha512.compute(key, msg)).toString('hex')).toBe(
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    );
  });

  it('handles keys longer and shorter than the block size', async () => {
    const msg = enc.encode('x');
    for (const keyLen of [0, 1, 63, 64, 65, 128, 200]) {
      const key = new Uint8Array(keyLen).fill(0xaa);
      const mac = await hmacSha256.compute(key, msg);
      const again = await hmacSha256.compute(key, msg);
      expect(mac.length).toBe(32);
      expect(mac).toEqual(again);
      expect(await hmacSha256.verify(key, msg, mac)).toBe(true);
    }
  });

  it('verify never throws and is false on any mismatch', async () => {
    const key = enc.encode('key');
    const msg = enc.encode('message');
    const mac = await hmacSha256.compute(key, msg);
    expect(await hmacSha256.verify(key, msg, mac)).toBe(true);
    expect(await hmacSha256.verify(key, msg, mac.subarray(0, 31))).toBe(false);
    const bad = Uint8Array.from(mac);
    bad[0] ^= 1;
    expect(await hmacSha256.verify(key, msg, bad)).toBe(false);
    expect(await hmacSha256.verify(enc.encode('other'), msg, mac)).toBe(false);
  });

  it('sign is an alias of compute', async () => {
    const key = enc.encode('k');
    const msg = enc.encode('m');
    expect(await hmacSha256.sign(key, msg)).toEqual(await hmacSha256.compute(key, msg));
  });
});

describe('CMAC (SP 800-38B)', () => {
  const key = new Uint8Array(Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'));

  it('matches the published examples', () => {
    expect(Buffer.from(cmac.compute(key, new Uint8Array(0))).toString('hex')).toBe(
      'bb1d6929e95937287fa37d129b756746',
    );
    expect(
      Buffer.from(
        cmac.compute(
          key,
          new Uint8Array(Buffer.from('6bc1bee22e409f96e93d7e117393172aae2d8a57', 'hex')),
        ),
      ).toString('hex'),
    ).toBe('7d85449ea6ea19c823a7bf78837dfade');
    expect(
      Buffer.from(
        cmac.compute(key, new Uint8Array(Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex'))),
      ).toString('hex'),
    ).toBe('070a16b46b4d4144f79bdd9dd04a287c');
    expect(
      Buffer.from(
        cmac.compute(
          key,
          new Uint8Array(
            Buffer.from(
              '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411',
              'hex',
            ),
          ),
        ),
      ).toString('hex'),
    ).toBe('dfa66747de9ae63030ca32611497c827');
  });

  it('works with 256-bit keys and verifies constant-time', () => {
    const key256 = new Uint8Array(32).fill(0x42);
    const msg = enc.encode('cmac with aes-256');
    const tag = cmac.compute(key256, msg);
    expect(tag.length).toBe(16);
    expect(cmac.verify(key256, msg, tag)).toBe(true);
    const bad = Uint8Array.from(tag);
    bad[7] ^= 1;
    expect(cmac.verify(key256, msg, bad)).toBe(false);
    expect(cmac.verify(key256, msg, tag.subarray(0, 15))).toBe(false);
  });

  it('rejects invalid key sizes', () => {
    expect(() => cmac.compute(new Uint8Array(15), new Uint8Array(4))).toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
  });
});
