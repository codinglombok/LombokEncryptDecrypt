#!/usr/bin/env python3
"""Generate tests/vectors/blake3-vectors.json with the reference `blake3` package (pip install blake3)."""
import json, pathlib, blake3
def data(n): return bytes(i % 251 for i in range(n))
sizes = [0,1,2,63,64,65,127,128,129,1023,1024,1025,2048,2049,3072,3073,4096,4097,5120,7168,8192,8193,31744,102400]
key = bytes(range(32))
doc = {"hash": [], "keyed": [], "derive": []}
for n in sizes:
    d = data(n)
    for outLen in (32, 131):
        doc["hash"].append({"input": d.hex(), "outLen": outLen, "output": blake3.blake3(d).digest(length=outLen).hex()})
    doc["keyed"].append({"key": key.hex(), "input": d.hex(), "outLen": 32, "output": blake3.blake3(d, key=key).digest(length=32).hex()})
    doc["derive"].append({"context": "LombokEncryptDecrypt 2026 test context", "input": d.hex(), "outLen": 48,
        "output": blake3.blake3(d, derive_key_context="LombokEncryptDecrypt 2026 test context").digest(length=48).hex()})
out = pathlib.Path(__file__).resolve().parent.parent / "tests/vectors/blake3-vectors.json"
out.write_text(json.dumps(doc) + "\n")
print("wrote", out)
