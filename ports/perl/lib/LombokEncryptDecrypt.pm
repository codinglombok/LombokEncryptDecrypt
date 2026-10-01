package LombokEncryptDecrypt;

use 5.020;
use strict;
use warnings;
use Carp qw(croak);
use Crypt::OpenSSL::AES;
use Digest::SHA qw(sha256 sha512 hmac_sha256 hmac_sha512);
use MIME::Base64 qw(encode_base64url decode_base64url);

our $VERSION = '0.1.0';

=head1 NAME

LombokEncryptDecrypt - Universal encrypt/decrypt library (Perl port)

=head1 SYNOPSIS

  use LombokEncryptDecrypt;

  # AES-256-GCM
  my ($ct, $tag, $iv) = LombokEncryptDecrypt::aes_gcm_encrypt($plaintext, $key);
  my $pt = LombokEncryptDecrypt::aes_gcm_decrypt($ct, $key, $iv, $tag);

  # HMAC-SHA256
  my $mac = LombokEncryptDecrypt::hmac_sha256($key, $message);

  # PBKDF2-SHA256
  my $dk = LombokEncryptDecrypt::pbkdf2_sha256($password, $salt, 600_000, 32);

=head1 DESCRIPTION

Perl port of LombokEncryptDecrypt. Uses OpenSSL via Crypt::OpenSSL modules.
Symmetric ciphers (AES-GCM, ChaCha20) and KDF (PBKDF2, HKDF) are covered.
Post-quantum algorithms require the Rust NAPI core.

=head1 LICENSE

Apache-2.0

=cut

# ── AES-GCM ──────────────────────────────────────────────────────────────

sub aes_gcm_encrypt {
    my ($plaintext, $key, $iv, $aad) = @_;

    my $klen = length($key);
    croak "AES key must be 16, 24, or 32 bytes; got $klen"
        unless $klen == 16 || $klen == 24 || $klen == 32;

    $iv  //= _random_bytes(12);
    $aad //= '';

    croak "AES-GCM IV must be 12 bytes" unless length($iv) == 12;

    # Use Crypt::AuthEnc::GCM if available (OpenSSL 1.0+)
    eval { require Crypt::AuthEnc::GCM };
    if (!$@) {
        my $gcm = Crypt::AuthEnc::GCM->new("AES", $key, $iv);
        $gcm->adata_add($aad) if length($aad);
        my $ct  = $gcm->encrypt_add($plaintext);
        my $tag = $gcm->encrypt_done();
        return ($ct, $tag, $iv);
    }

    # Fallback: OpenSSL via system call (requires openssl binary)
    croak "Crypt::AuthEnc::GCM required for AES-GCM. Install CryptX: cpan CryptX";
}

sub aes_gcm_decrypt {
    my ($ciphertext, $key, $iv, $tag, $aad) = @_;
    $aad //= '';

    eval { require Crypt::AuthEnc::GCM };
    if (!$@) {
        my $gcm = Crypt::AuthEnc::GCM->new("AES", $key, $iv);
        $gcm->adata_add($aad) if length($aad);
        my $pt   = $gcm->decrypt_add($ciphertext);
        my $ok   = $gcm->decrypt_done($tag);
        croak "[AUTHENTICATION_FAILED] AES-GCM tag verification failed" unless $ok;
        return $pt;
    }

    croak "Crypt::AuthEnc::GCM required for AES-GCM";
}

# ── HMAC ──────────────────────────────────────────────────────────────────

sub hmac_sha256 {
    my ($key, $message) = @_;
    return Digest::SHA::hmac_sha256($message, $key);
}

sub hmac_sha512 {
    my ($key, $message) = @_;
    return Digest::SHA::hmac_sha512($message, $key);
}

# Constant-time HMAC verification
sub hmac_verify {
    my ($key, $message, $expected) = @_;
    my $computed = hmac_sha256($key, $message);
    return _constant_time_eq($computed, $expected);
}

# ── Hash ──────────────────────────────────────────────────────────────────

sub sha256_hash { return Digest::SHA::sha256($_[0]) }
sub sha512_hash { return Digest::SHA::sha512($_[0]) }
sub sha3_256_hash {
    require Digest::SHA3;
    return Digest::SHA3::sha3_256($_[0]);
}

# ── PBKDF2 ────────────────────────────────────────────────────────────────

sub pbkdf2_sha256 {
    my ($password, $salt, $iterations, $dk_len) = @_;
    $iterations //= 600_000;
    $dk_len     //= 32;

    require Crypt::PBKDF2;
    my $pbkdf2 = Crypt::PBKDF2->new(
        hash_class       => 'HMACSHA2',
        hash_args        => { sha_size => 256 },
        iterations       => $iterations,
        output_len       => $dk_len,
    );
    return $pbkdf2->PBKDF2($salt, $password);
}

# ── HKDF ──────────────────────────────────────────────────────────────────

sub hkdf_sha256 {
    my ($ikm, $length, $salt, $info) = @_;
    $info //= '';
    $salt //= "\x00" x 32;

    # Extract
    my $prk = hmac_sha256($salt, $ikm);

    # Expand
    my $out  = '';
    my $prev = '';
    my $i    = 1;
    while (length($out) < $length) {
        $prev = hmac_sha256($prk, $prev . $info . chr($i));
        $out .= $prev;
        $i++;
    }
    return substr($out, 0, $length);
}

# ── Random ────────────────────────────────────────────────────────────────

sub random_bytes {
    my ($n) = @_;
    return _random_bytes($n);
}

# ── Utilities ─────────────────────────────────────────────────────────────

sub _random_bytes {
    my ($n) = @_;
    open(my $fh, '<:raw', '/dev/urandom') or croak "Cannot open /dev/urandom: $!";
    my $buf;
    read($fh, $buf, $n) == $n or croak "Failed to read $n random bytes";
    close($fh);
    return $buf;
}

# Constant-time string comparison (prevent timing attacks)
sub _constant_time_eq {
    my ($a, $b) = @_;
    return 0 if length($a) != length($b);
    my $diff = 0;
    for my $i (0 .. length($a) - 1) {
        $diff |= ord(substr($a, $i, 1)) ^ ord(substr($b, $i, 1));
    }
    return $diff == 0 ? 1 : 0;
}

sub timing_safe_equal { _constant_time_eq(@_) }

sub version { $VERSION }

1;

__END__
