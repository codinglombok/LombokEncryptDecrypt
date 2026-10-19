package lombokencryptdecrypt_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	led "github.com/codinglombok/lombokencryptdecrypt-go"
)

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// ── AES-GCM Tests ─────────────────────────────────────────────────────────

type aesVec struct {
	Key        string `json:"key"`
	IV         string `json:"iv"`
	AAD        string `json:"aad"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

func TestAesGcmNistVectors(t *testing.T) {
	vectors := []aesVec{
		{
			Key: "00000000000000000000000000000000",
			IV:  "000000000000000000000000",
			AAD: "", Plaintext: "", Ciphertext: "",
			Tag: "58e2fccefa7e3061367f1d57a4e7455a",
		},
		{
			Key:        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			IV:         "cafebabefacedbaddecaf888",
			AAD:        "",
			Plaintext:  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			Ciphertext: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
			Tag:        "b094dac5d93471bdec1a502270e3cc6c",
		},
	}

	for i, v := range vectors {
		t.Run(t.Name()+string(rune('0'+i)), func(t *testing.T) {
			key := fromHex(t, v.Key)
			iv  := fromHex(t, v.IV)
			pt  := fromHex(t, v.Plaintext)

			var aad []byte
			if v.AAD != "" {
				aad = fromHex(t, v.AAD)
			}

			result, err := led.AesGcmEncrypt(pt, key, iv, aad)
			if err != nil {
				t.Fatalf("AesGcmEncrypt: %v", err)
			}

			if got := hex.EncodeToString(result.Ciphertext); got != v.Ciphertext {
				t.Errorf("ciphertext mismatch:\n  got  %s\n  want %s", got, v.Ciphertext)
			}
			if got := hex.EncodeToString(result.Tag); got != v.Tag {
				t.Errorf("tag mismatch:\n  got  %s\n  want %s", got, v.Tag)
			}

			// Decrypt
			ptGot, err := led.AesGcmDecrypt(result.Ciphertext, key, iv, result.Tag, aad)
			if err != nil {
				t.Fatalf("AesGcmDecrypt: %v", err)
			}
			if !bytes.Equal(ptGot, pt) {
				t.Errorf("decrypt mismatch: got %x want %x", ptGot, pt)
			}
		})
	}
}

func TestAesGcmRoundtrip(t *testing.T) {
	key, err := led.GenerateAesKey(256)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("Hello from Go LombokEncryptDecrypt!")
	result, err := led.AesGcmEncrypt(plaintext, key, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := led.AesGcmDecrypt(result.Ciphertext, key, result.IV, result.Tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("roundtrip failed: got %q want %q", got, plaintext)
	}
}

func TestAesGcmRejectsTamperedTag(t *testing.T) {
	key, _ := led.GenerateAesKey(256)
	result, _ := led.AesGcmEncrypt([]byte("secret"), key, nil, nil)
	badTag := make([]byte, len(result.Tag))
	copy(badTag, result.Tag)
	badTag[0] ^= 0xFF

	_, err := led.AesGcmDecrypt(result.Ciphertext, key, result.IV, badTag, nil)
	if err == nil {
		t.Fatal("expected error on tampered tag, got nil")
	}
}

// ── HMAC Tests ────────────────────────────────────────────────────────────

func TestHmacSha256Rfc4231(t *testing.T) {
	tests := []struct{ key, msg, want string }{
		{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
		{"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
	}
	for _, tc := range tests {
		key := fromHex(t, tc.key)
		msg := fromHex(t, tc.msg)
		got := led.HmacSha256(key, msg)
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("HMAC-SHA256: got %x want %s", got, tc.want)
		}
	}
}

// ── Hash Tests ────────────────────────────────────────────────────────────

func TestSha256(t *testing.T) {
	tests := []struct{ input, want string }{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, tc := range tests {
		data := fromHex(t, tc.input)
		got  := hex.EncodeToString(led.Sha256(data))
		if got != tc.want {
			t.Errorf("SHA256(%q): got %s want %s", tc.input, got, tc.want)
		}
	}
}

// ── Ed25519 Tests ─────────────────────────────────────────────────────────

func TestEd25519Roundtrip(t *testing.T) {
	kp, err := led.Ed25519GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.PrivateKey) != 32 {
		t.Errorf("private key seed: got %d bytes want 32", len(kp.PrivateKey))
	}
	if len(kp.PublicKey) != 32 {
		t.Errorf("public key: got %d bytes want 32", len(kp.PublicKey))
	}

	msg := []byte("Go LombokEncryptDecrypt Ed25519")
	sig, err := led.Ed25519Sign(msg, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Errorf("signature: got %d bytes want 64", len(sig))
	}
	if !led.Ed25519Verify(msg, sig, kp.PublicKey) {
		t.Error("signature verification failed")
	}
}

// ── Cross-Language Vectors ────────────────────────────────────────────────

func TestCrossLanguageVectors(t *testing.T) {
	vectorPath := filepath.Join("..", "..", "tests", "vectors", "lombokencryptdecrypt-vectors-v1.json")
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Skipf("Vector file not found: %v — run: node scripts/generate-vectors.mjs", err)
	}

	var vectors struct {
		AesGcm []struct {
			ID         string `json:"id"`
			Key        string `json:"key"`
			IV         string `json:"iv"`
			AAD        string `json:"aad"`
			Plaintext  string `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
			Tag        string `json:"tag"`
		} `json:"aes_gcm"`
		HmacSha256 []struct {
			ID      string `json:"id"`
			Key     string `json:"key"`
			Message string `json:"message"`
			Output  string `json:"output"`
		} `json:"hmac_sha256"`
	}

	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	t.Run("AES-GCM", func(t *testing.T) {
		for _, v := range vectors.AesGcm {
			t.Run(v.ID, func(t *testing.T) {
				key := fromHex(t, v.Key)
				iv  := fromHex(t, v.IV)
				pt  := fromHex(t, v.Plaintext)
				var aad []byte
				if v.AAD != "" {
					aad = fromHex(t, v.AAD)
				}
				result, err := led.AesGcmEncrypt(pt, key, iv, aad)
				if err != nil {
					t.Fatalf("%s: %v", v.ID, err)
				}
				if got := hex.EncodeToString(result.Ciphertext); got != v.Ciphertext {
					t.Errorf("%s: ciphertext mismatch", v.ID)
				}
				if got := hex.EncodeToString(result.Tag); got != v.Tag {
					t.Errorf("%s: tag mismatch", v.ID)
				}
			})
		}
	})

	t.Run("HMAC-SHA256", func(t *testing.T) {
		for _, v := range vectors.HmacSha256 {
			t.Run(v.ID, func(t *testing.T) {
				key := fromHex(t, v.Key)
				msg := fromHex(t, v.Message)
				got := led.HmacSha256(key, msg)
				if hex.EncodeToString(got) != v.Output {
					t.Errorf("%s: HMAC mismatch", v.ID)
				}
			})
		}
	})
}
