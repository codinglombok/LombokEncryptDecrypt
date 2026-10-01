cmake_minimum_required(VERSION 3.25)
project(LombokEncryptDecrypt VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Options ──────────────────────────────────────────────────────────────
option(LED_BUILD_SHARED    "Build shared library"       OFF)
option(LED_BUILD_TESTS     "Build tests"                ON)
option(LED_ENABLE_AESNI    "Enable AES-NI intrinsics"   ON)
option(LED_ENABLE_SHA_NI   "Enable SHA-NI intrinsics"   ON)
option(LED_ENABLE_PQC      "Enable Post-Quantum module"  ON)
option(LED_ENABLE_FIPS     "Enforce FIPS algorithm set"  OFF)
option(LED_ENABLE_LEGACY   "Enable legacy algorithms"    OFF)
option(LED_ENABLE_TEE      "Enable HSM/TPM/SGX stubs"    OFF)
option(LED_INSTALL         "Install targets"             ON)

# ── Source files ─────────────────────────────────────────────────────────
set(LED_SOURCES
    ports/cpp/src/aes.cpp
    ports/cpp/src/chacha20.cpp
    ports/cpp/src/sha256.cpp
    ports/cpp/src/sha512.cpp
    ports/cpp/src/sha3.cpp
    ports/cpp/src/blake2.cpp
    ports/cpp/src/blake3.cpp
    ports/cpp/src/sm2.cpp
    ports/cpp/src/sm3.cpp
    ports/cpp/src/sm4.cpp
    ports/cpp/src/gcm.cpp
    ports/cpp/src/ccm.cpp
    ports/cpp/src/eax.cpp
    ports/cpp/src/xts.cpp
    ports/cpp/src/fpe_ff1.cpp
    ports/cpp/src/hmac.cpp
    ports/cpp/src/cmac.cpp
    ports/cpp/src/poly1305.cpp
    ports/cpp/src/pbkdf2.cpp
    ports/cpp/src/scrypt.cpp
    ports/cpp/src/argon2.cpp
    ports/cpp/src/hkdf.cpp
    ports/cpp/src/rsa.cpp
    ports/cpp/src/ecdh.cpp
    ports/cpp/src/ecdsa.cpp
    ports/cpp/src/ed25519.cpp
    ports/cpp/src/ecies.cpp
    ports/cpp/src/hpke.cpp
    ports/cpp/src/envelope.cpp
    ports/cpp/src/keystore.cpp
    ports/cpp/src/x509.cpp
    ports/cpp/src/audit.cpp
    ports/cpp/src/stream.cpp
)

if(LED_ENABLE_PQC)
    list(APPEND LED_SOURCES
        ports/cpp/src/pq/kyber512.cpp
        ports/cpp/src/pq/kyber768.cpp
        ports/cpp/src/pq/kyber1024.cpp
        ports/cpp/src/pq/dilithium2.cpp
        ports/cpp/src/pq/dilithium3.cpp
        ports/cpp/src/pq/dilithium5.cpp
        ports/cpp/src/pq/sphincsplus.cpp
        ports/cpp/src/pq/falcon512.cpp
        ports/cpp/src/pq/falcon1024.cpp
    )
endif()

# ── Library target ────────────────────────────────────────────────────────
if(LED_BUILD_SHARED)
    add_library(lombokencryptdecrypt SHARED ${LED_SOURCES})
else()
    add_library(lombokencryptdecrypt STATIC ${LED_SOURCES})
endif()

add_library(LombokEncryptDecrypt::lombokencryptdecrypt ALIAS lombokencryptdecrypt)

target_include_directories(lombokencryptdecrypt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ports/cpp/include>
    $<INSTALL_INTERFACE:include>
)

# ── Compile flags ─────────────────────────────────────────────────────────
if(LED_ENABLE_AESNI AND (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i686"))
    target_compile_options(lombokencryptdecrypt PRIVATE -maes -mpclmul)
    target_compile_definitions(lombokencryptdecrypt PRIVATE LED_HAVE_AESNI=1)
endif()

if(LED_ENABLE_SHA_NI AND (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64"))
    target_compile_options(lombokencryptdecrypt PRIVATE -msha)
    target_compile_definitions(lombokencryptdecrypt PRIVATE LED_HAVE_SHA_NI=1)
endif()

if(LED_ENABLE_PQC)
    target_compile_definitions(lombokencryptdecrypt PRIVATE LED_ENABLE_PQC=1)
endif()

if(LED_ENABLE_FIPS)
    target_compile_definitions(lombokencryptdecrypt PRIVATE LED_FIPS_MODE=1)
endif()

target_compile_options(lombokencryptdecrypt PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Werror -O2>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Werror -O2>
    $<$<C_COMPILER_ID:MSVC>:/W4 /WX /O2>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX /O2>
)

set_target_properties(lombokencryptdecrypt PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    PUBLIC_HEADER ports/cpp/include/lombokencryptdecrypt/lombokencryptdecrypt.h
)

# ── Tests ─────────────────────────────────────────────────────────────────
if(LED_BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)
    if(GTest_FOUND)
        add_subdirectory(ports/cpp/tests)
    endif()
endif()

# ── Install ───────────────────────────────────────────────────────────────
if(LED_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    install(TARGETS lombokencryptdecrypt
        EXPORT LombokEncryptDecryptTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lombokencryptdecrypt
    )
    install(DIRECTORY ports/cpp/include/lombokencryptdecrypt/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lombokencryptdecrypt
    )
    install(EXPORT LombokEncryptDecryptTargets
        FILE LombokEncryptDecryptTargets.cmake
        NAMESPACE LombokEncryptDecrypt::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LombokEncryptDecrypt
    )

    write_basic_package_version_file(
        LombokEncryptDecryptConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/cpp/cmake/LombokEncryptDecryptConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/LombokEncryptDecryptConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LombokEncryptDecrypt
    )
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/LombokEncryptDecryptConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/LombokEncryptDecryptConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LombokEncryptDecrypt
    )
endif()
