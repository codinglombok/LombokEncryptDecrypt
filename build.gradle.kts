plugins {
    kotlin("multiplatform") version "2.0.0"
    kotlin("plugin.serialization") version "2.0.0"
    id("com.android.library") version "8.5.0" apply false
    id("org.jetbrains.dokka") version "2.2.0"
    id("maven-publish")
    id("signing")
    id("io.gitlab.arturbosch.detekt") version "1.23.6"
}

group = "com.codinglombok"
version = "0.1.0"

kotlin {
    jvm {
        jvmToolchain(17)
        withJava()
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }
    androidTarget {
        publishLibraryVariants("release", "debug")
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                // Zero external crypto deps — Kotlin stdlib only
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.1")
            }
        }
        val jvmMain by getting
        val jvmTest by getting
    }
}

android {
    namespace = "com.codinglombok.lombokencryptdecrypt"
    compileSdk = 34
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

publishing {
    publications.withType<MavenPublication> {
        artifactId = when (name) {
            "kotlinMultiplatform" -> "lombokencryptdecrypt"
            "jvm" -> "lombokencryptdecrypt-jvm"
            "androidRelease" -> "lombokencryptdecrypt-android"
            else -> artifactId
        }

        pom {
            name.set("LombokEncryptDecrypt")
            description.set("Universal encrypt/decrypt library — AES/ChaCha20/Kyber/Dilithium/SPHINCS+/SM2/SM3/SM4/ZUC/SNOW3G — post-quantum ready, Apache 2.0")
            url.set("https://github.com/codinglombok/LombokEncryptDecrypt")
            inceptionYear.set("2026")

            licenses {
                license {
                    name.set("Apache License, Version 2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    distribution.set("repo")
                }
            }
            developers {
                developer {
                    id.set("codinglombok")
                    name.set("codinglombok")
                    email.set("codinglombok@gmail.com")
                    url.set("https://github.com/codinglombok")
                }
            }
            scm {
                connection.set("scm:git:git://github.com/codinglombok/LombokEncryptDecrypt.git")
                developerConnection.set("scm:git:ssh://github.com/codinglombok/LombokEncryptDecrypt.git")
                url.set("https://github.com/codinglombok/LombokEncryptDecrypt")
                tag.set("HEAD")
            }
            issueManagement {
                system.set("GitHub")
                url.set("https://github.com/codinglombok/LombokEncryptDecrypt/issues")
            }
        }
    }

    repositories {
        maven {
            name = "MavenCentral"
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("MAVEN_USERNAME")
                password = System.getenv("MAVEN_PASSWORD")
            }
        }
    }
}

signing {
    useInMemoryPgpKeys(
        System.getenv("GPG_KEY_ID"),
        System.getenv("GPG_PRIVATE_KEY"),
        System.getenv("GPG_PASSPHRASE")
    )
    sign(publishing.publications)
}
