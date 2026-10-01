// LombokEncryptDecrypt — Swift Port (iOS 16+, macOS 13+)
// Universal encrypt/decrypt library
// License: Apache-2.0 | Author: codinglombok | Version: 0.1.0

import Foundation
import CryptoKit

// ── Errors ────────────────────────────────────────────────────────────────

public enum CryptoError: LocalizedError, Equatable {
    case invalidKeySize(expected: String, got: Int)
    case invalidIVSize(expected: Int, got: Int)
    case authenticationFailed(algorithm: String)
    case invalidInput(String)
    case unsupportedAlgorithm(String)
    case keyNotFound(String)
    case internalError(String)

    public var errorCode: String {
        switch self {
        case .invalidKeySize:         return "INVALID_KEY_SIZE"
        case .invalidIVSize:          return "INVALID_IV_SIZE"
        case .authenticationFailed:   return "AUTHENTICATION_FAILED"
        case .invalidInput:           return "INVALID_INPUT"
        case .unsupportedAlgorithm:   return "UNSUPPORTED_ALGORITHM"
        case .keyNotFound:            return "KEY_NOT_FOUND"
        case .internalError:          return "INTERNAL"
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidKeySize(let exp, let got):
            return "[\(errorCode)] Key must be \(exp) bytes; got \(got)"
        case .invalidIVSize(let exp, let got):
            return "[\(errorCode)] IV must be \(exp) bytes; got \(got)"
        case .authenticationFailed(let alg):
            return "[\(errorCode)] \(alg) authentication tag verification failed"
        case .invalidInput(let msg):
            return "[\(errorCode)] \(msg)"
        case .unsupportedAlgorithm(let alg):
            return "[\(errorCode)] Unsupported algorithm: \(alg)"
        case .keyNotFound(let id):
            return "[\(errorCode)] Key not found: \(id)"
        case .internalError(let msg):
            return "[\(errorCode)] \(msg)"
        }
    }
}

// ── AES-GCM ──────────────────────────────────────────────────────────────

/// AES-GCM encrypted result.
public struct AesGcmResult {
    public let ciphertext: Data
    public let tag: Data
    public let iv: Data

    /// Convenience: packed format (IV ++ ciphertext ++ tag)
    public var packed: Data { iv + ciphertext + tag }

    /// Unpack from packed format produced by packed
    public static func unpack(_ packed: Data, ivLen: Int = 12, tagLen: Int = 16) throws -> AesGcmResult {
        guard packed.count >= ivLen + tagLen else {
            throw CryptoError.invalidInput("Packed AES-GCM data too short")
        }
        let iv         = packed[..<ivLen]
        let ciphertext = packed[ivLen ..< packed.count - tagLen]
        let tag        = packed[(packed.count - tagLen)...]
        return AesGcmResult(ciphertext: Data(ciphertext), tag: Data(tag), iv: Data(iv))
    }
}

/// AES-GCM authenticated encryption using CryptoKit (hardware-accelerated on Apple Silicon).
public enum AesGcm {

    /// Encrypt with AES-GCM (NIST SP 800-38D).
    /// Uses CryptoKit's AES.GCM which dispatches to Secure Enclave or AES-NI.
    public static func encrypt(
        _ plaintext: Data,
        key: Data,
        iv: Data? = nil,
        aad: Data? = nil
    ) throws -> AesGcmResult {
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw CryptoError.invalidKeySize(expected: "16/24/32", got: key.count)
        }

        let nonce: AES.GCM.Nonce
        if let iv = iv {
            guard iv.count == 12 else {
                throw CryptoError.invalidIVSize(expected: 12, got: iv.count)
            }
            nonce = try AES.GCM.Nonce(data: iv)
        } else {
            nonce = AES.GCM.Nonce()
        }

        let symKey = SymmetricKey(data: key)
        let box: AES.GCM.SealedBox

        if let aad = aad, !aad.isEmpty {
            box = try AES.GCM.seal(plaintext, using: symKey, nonce: nonce, authenticating: aad)
        } else {
            box = try AES.GCM.seal(plaintext, using: symKey, nonce: nonce)
        }

        return AesGcmResult(
            ciphertext: box.ciphertext,
            tag:        box.tag,
            iv:         Data(nonce)
        )
    }

    /// Decrypt and verify AES-GCM ciphertext.
    public static func decrypt(
        _ ciphertext: Data,
        key: Data,
        iv: Data,
        tag: Data,
        aad: Data? = nil
    ) throws -> Data {
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw CryptoError.invalidKeySize(expected: "16/24/32", got: key.count)
        }
        guard iv.count == 12 else {
            throw CryptoError.invalidIVSize(expected: 12, got: iv.count)
        }

        let symKey = SymmetricKey(data: key)
        let nonce  = try AES.GCM.Nonce(data: iv)
        let box    = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)

        do {
            if let aad = aad, !aad.isEmpty {
                return try AES.GCM.open(box, using: symKey, authenticating: aad)
            } else {
                return try AES.GCM.open(box, using: symKey)
            }
        } catch {
            throw CryptoError.authenticationFailed(algorithm: "AES-GCM")
        }
    }

    public static func generateKey(bits: Int = 256) -> Data {
        var key = Data(count: bits / 8)
        _ = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, bits / 8, $0.baseAddress!) }
        return key
    }

    public static func generateIV() -> Data {
        Data(AES.GCM.Nonce())
    }
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────

public enum ChaCha20Poly1305 {

    public struct EncryptResult {
        public let ciphertext: Data
        public let tag: Data
        public let nonce: Data
    }

    public static func encrypt(
        _ plaintext: Data,
        key: Data,
        nonce: Data? = nil,
        aad: Data? = nil
    ) throws -> EncryptResult {
        guard key.count == 32 else {
            throw CryptoError.invalidKeySize(expected: "32", got: key.count)
        }
        let symKey = SymmetricKey(data: key)
        let actualNonce: ChaChaPoly.Nonce
        if let n = nonce {
            guard n.count == 12 else { throw CryptoError.invalidIVSize(expected: 12, got: n.count) }
            actualNonce = try ChaChaPoly.Nonce(data: n)
        } else {
            actualNonce = ChaChaPoly.Nonce()
        }
        let box: ChaChaPoly.SealedBox
        if let aad = aad, !aad.isEmpty {
            box = try ChaChaPoly.seal(plaintext, using: symKey, nonce: actualNonce, authenticating: aad)
        } else {
            box = try ChaChaPoly.seal(plaintext, using: symKey, nonce: actualNonce)
        }
        return EncryptResult(ciphertext: box.ciphertext, tag: box.tag, nonce: Data(actualNonce))
    }

    public static func decrypt(
        _ ciphertext: Data,
        key: Data,
        nonce: Data,
        tag: Data,
        aad: Data? = nil
    ) throws -> Data {
        guard key.count == 32 else { throw CryptoError.invalidKeySize(expected: "32", got: key.count) }
        let symKey = SymmetricKey(data: key)
        let n      = try ChaChaPoly.Nonce(data: nonce)
        let box    = try ChaChaPoly.SealedBox(nonce: n, ciphertext: ciphertext, tag: tag)
        do {
            if let aad = aad, !aad.isEmpty {
                return try ChaChaPoly.open(box, using: symKey, authenticating: aad)
            }
            return try ChaChaPoly.open(box, using: symKey)
        } catch {
            throw CryptoError.authenticationFailed(algorithm: "ChaCha20-Poly1305")
        }
    }

    public static func generateKey() -> Data { SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }
}

// ── HMAC ──────────────────────────────────────────────────────────────────

public enum HMAC {
    public static func sha256(key: Data, message: Data) -> Data {
        let mac = CryptoKit.HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(mac)
    }
    public static func sha512(key: Data, message: Data) -> Data {
        let mac = CryptoKit.HMAC<SHA512>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(mac)
    }
    /// Constant-time HMAC-SHA256 verification.
    public static func verifySha256(key: Data, message: Data, expected: Data) -> Bool {
        CryptoKit.HMAC<SHA256>.isValidAuthenticationCode(expected, authenticating: message, using: SymmetricKey(data: key))
    }
}

// ── Hash ──────────────────────────────────────────────────────────────────

public enum Hash {
    public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
    public static func sha512(_ data: Data) -> Data { Data(SHA512.hash(data: data)) }
    public static func sha384(_ data: Data) -> Data { Data(SHA384.hash(data: data)) }
}

// ── HKDF ──────────────────────────────────────────────────────────────────

public enum HKDF {
    /// HKDF-SHA256 (RFC 5869).
    public static func sha256(
        ikm: Data,
        outputByteCount: Int,
        salt: Data? = nil,
        info: Data = Data()
    ) -> Data {
        let symKey = SymmetricKey(data: ikm)
        let result = CryptoKit.HKDF<SHA256>.deriveKey(
            inputKeyMaterial: symKey,
            salt: salt ?? Data(count: SHA256.byteCount),
            info: info,
            outputByteCount: outputByteCount
        )
        return result.withUnsafeBytes { Data($0) }
    }

    /// HKDF-SHA512 (RFC 5869).
    public static func sha512(
        ikm: Data,
        outputByteCount: Int,
        salt: Data? = nil,
        info: Data = Data()
    ) -> Data {
        let symKey = SymmetricKey(data: ikm)
        let result = CryptoKit.HKDF<SHA512>.deriveKey(
            inputKeyMaterial: symKey,
            salt: salt ?? Data(count: SHA512.byteCount),
            info: info,
            outputByteCount: outputByteCount
        )
        return result.withUnsafeBytes { Data($0) }
    }
}

// ── Ed25519 ───────────────────────────────────────────────────────────────

public enum Ed25519 {
    public struct KeyPair {
        public let privateKey: Curve25519.Signing.PrivateKey
        public var publicKey: Curve25519.Signing.PublicKey { privateKey.publicKey }
        public var privateKeyRaw: Data { privateKey.rawRepresentation }
        public var publicKeyRaw:  Data { privateKey.publicKey.rawRepresentation }
    }

    public static func generateKeyPair() -> KeyPair {
        KeyPair(privateKey: .init())
    }

    public static func fromSeed(_ seed: Data) throws -> KeyPair {
        let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return KeyPair(privateKey: priv)
    }

    public static func sign(_ message: Data, privateKey: Data) throws -> Data {
        let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        return try priv.signature(for: message)
    }

    public static func verify(_ message: Data, signature: Data, publicKey: Data) -> Bool {
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pub.isValidSignature(signature, for: message)
    }
}

// ── Random ────────────────────────────────────────────────────────────────

public func randomBytes(_ count: Int) -> Data {
    var data = Data(count: count)
    _ = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    return data
}
