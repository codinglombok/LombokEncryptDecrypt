// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "LombokEncryptDecrypt",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(
            name: "LombokEncryptDecrypt",
            targets: ["LombokEncryptDecrypt"]
        ),
        .library(
            name: "LombokEncryptDecryptSymmetric",
            targets: ["LombokEncryptDecryptSymmetric"]
        ),
        .library(
            name: "LombokEncryptDecryptPQC",
            targets: ["LombokEncryptDecryptPQC"]
        ),
    ],
    dependencies: [
        // Zero external dependencies — uses CryptoKit + CommonCrypto (Apple stdlib)
    ],
    targets: [
        .target(
            name: "LombokEncryptDecrypt",
            dependencies: [
                "LombokEncryptDecryptSymmetric",
                "LombokEncryptDecryptPQC",
            ],
            path: "ports/swift/Sources/LombokEncryptDecrypt",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .unsafeFlags(["-O", "-whole-module-optimization"], .when(configuration: .release)),
            ]
        ),
        .target(
            name: "LombokEncryptDecryptSymmetric",
            path: "ports/swift/Sources/LombokEncryptDecryptSymmetric",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),
        .target(
            name: "LombokEncryptDecryptPQC",
            path: "ports/swift/Sources/LombokEncryptDecryptPQC",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "LombokEncryptDecryptTests",
            dependencies: ["LombokEncryptDecrypt"],
            path: "ports/swift/Tests",
            resources: [
                .copy("../../tests/vectors/lombokencryptdecrypt-vectors-v1.json"),
            ]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
