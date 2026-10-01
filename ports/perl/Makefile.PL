use 5.020;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'LombokEncryptDecrypt',
    AUTHOR           => 'codinglombok <codinglombok@gmail.com>',
    VERSION_FROM     => 'lib/LombokEncryptDecrypt.pm',
    ABSTRACT_FROM    => 'lib/LombokEncryptDecrypt.pm',
    LICENSE          => 'apache_2_0',
    MIN_PERL_VERSION => '5.020',

    PREREQ_PM => {
        'Crypt::OpenSSL::AES'    => '0',
        'Crypt::OpenSSL::RSA'    => '0',
        'Crypt::OpenSSL::EC'     => '0',
        'Crypt::OpenSSL::PKCS10' => '0',
        'Digest::SHA'            => '0',
        'MIME::Base64'           => '0',
        'Storable'               => '0',
    },

    TEST_REQUIRES => {
        'Test::More'       => '0',
        'Test::Exception'  => '0',
        'JSON::PP'         => '0',
    },

    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources => {
            repository => {
                type => 'git',
                url  => 'https://github.com/codinglombok/LombokEncryptDecrypt.git',
                web  => 'https://github.com/codinglombok/LombokEncryptDecrypt',
            },
            bugtracker => {
                web => 'https://github.com/codinglombok/LombokEncryptDecrypt/issues',
            },
            homepage => 'https://github.com/codinglombok/LombokEncryptDecrypt',
        },
        keywords => [
            qw(encrypt decrypt cryptography aes chacha20 sha256 sha3
               post-quantum kyber dilithium sphincs ecdh ecdsa ed25519
               rsa hkdf argon2 sm2 sm3 sm4 lombok)
        ],
        x_authority => 'cpan:CODINGLOMBOK',
    },

    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz' },
    clean => { FILES => 'LombokEncryptDecrypt-*' },
);
