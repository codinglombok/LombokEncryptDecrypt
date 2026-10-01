// LombokEncryptDecrypt — Rust Build Script
// Detects CPU features and configures NAPI-RS bindings.

fn main() {
    // NAPI-RS build
    #[cfg(feature = "napi")]
    napi_build::setup();

    // Detect AES-NI / SHA-NI / AVX2 availability at compile time
    // These are also checked at runtime via cpuid, but compile-time detection
    // allows the linker to include the right object files.

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os   = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env  = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    // Emit build metadata for docs.rs
    println!("cargo:rustc-env=LED_TARGET_ARCH={}", target_arch);
    println!("cargo:rustc-env=LED_TARGET_OS={}", target_os);
    println!("cargo:rustc-env=LED_BUILD_DATE={}", build_date());

    // AES-NI: available on x86/x86_64 with the `aes` CPU feature
    if target_arch == "x86_64" || target_arch == "x86" {
        println!("cargo:rustc-cfg=led_has_x86");
        // Note: we check at runtime via is_x86_feature_detected!()
        // but emit this cfg for conditional compilation of module declarations
        println!("cargo:rustc-cfg=led_x86_available");
    }

    // ARM NEON / AES: available on aarch64
    if target_arch == "aarch64" {
        println!("cargo:rustc-cfg=led_has_aarch64");
    }

    // WASM SIMD
    if target_arch == "wasm32" {
        println!("cargo:rustc-cfg=led_has_wasm32");
    }

    // Embedded targets (thumbv7em, riscv, etc.)
    if target_arch.starts_with("thumb") || target_arch.starts_with("riscv") {
        println!("cargo:rustc-cfg=led_embedded");
    }

    // macOS / iOS → can use Secure Enclave via FFI (Swift interop)
    if target_os == "macos" || target_os == "ios" {
        println!("cargo:rustc-cfg=led_apple");
        // Link Security.framework for Secure Enclave
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }

    // Android → can use Android Keystore via JNI
    if target_os == "android" {
        println!("cargo:rustc-cfg=led_android");
    }

    // Windows → can use BCryptGenRandom, CNG
    if target_os == "windows" {
        println!("cargo:rustc-cfg=led_windows");
        println!("cargo:rustc-link-lib=bcrypt");
    }

    // Rerun if build script itself changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=LED_FIPS_MODE");
    println!("cargo:rerun-if-env-changed=LED_LEGACY_ENABLE");

    // FIPS mode env var
    if std::env::var("LED_FIPS_MODE").is_ok() {
        println!("cargo:rustc-cfg=led_fips");
        println!("cargo:warning=LombokEncryptDecrypt: FIPS mode enabled via LED_FIPS_MODE env var");
    }
}

fn build_date() -> String {
    // Simple YYYY-MM-DD via environment (set in CI) or compile-time approximation
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|epoch| {
            let secs: u64 = epoch.parse().ok()?;
            // Very simple date from epoch (days only)
            let days = secs / 86400;
            let year = 1970 + days / 365;
            Some(format!("{}-00-00", year))
        })
        .unwrap_or_else(|| "2026-09-18".to_string())
}
