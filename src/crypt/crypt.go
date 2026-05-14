package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// SaltSize is the recommended salt size (NIST SP 800-132)
	SaltSize = 16

	// legacySaltSize is the old 8-byte salt for backward compatibility
	legacySaltSize = 8

	// KeyRotationInterval is the number of encrypt/decrypt operations
	// after which a new key should be derived to limit nonce reuse risk
	KeyRotationInterval = 1_000_000
)

// New generates a new 32-byte key using Argon2id KDF with a 16-byte salt.
// This is the default and recommended KDF.
func New(passphrase []byte, usersalt []byte) (key []byte, salt []byte, err error) {
	if len(passphrase) < 1 {
		err = fmt.Errorf("need more than that for passphrase")
		return
	}
	if usersalt == nil {
		salt = make([]byte, SaltSize)
		if _, err = rand.Read(salt); err != nil {
			log.Fatalf("can't get random salt: %v", err)
		}
	} else {
		salt = usersalt
	}
	// Argon2id: time=3, memory=64MB, threads=4, output=32 bytes
	key = argon2.IDKey(passphrase, salt, 3, 64*1024, 4, 32)
	return
}

// NewLegacy generates a key using the old PBKDF2 method for backward compatibility.
// NOT recommended for new transfers — PBKDF2 with 100 iterations is trivially brute-forceable.
func NewLegacy(passphrase []byte, usersalt []byte) (key []byte, salt []byte, err error) {
	if len(passphrase) < 1 {
		err = fmt.Errorf("need more than that for passphrase")
		return
	}
	if usersalt == nil {
		salt = make([]byte, legacySaltSize)
		if _, err := rand.Read(salt); err != nil {
			log.Fatalf("can't get random salt: %v", err)
		}
	} else {
		salt = usersalt
	}
	key = pbkdf2.Key(passphrase, salt, 100, 32, sha256.New)
	return
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305 with a random 24-byte nonce.
// The 32-byte key is used directly to construct the XChaCha20-Poly1305 AEAD.
func Encrypt(plaintext []byte, key []byte) (encrypted []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305.NewX: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("can't generate nonce: %w", err)
	}
	encrypted = aead.Seal(nonce, nonce, plaintext, nil)
	return
}

// Decrypt decrypts ciphertext using XChaCha20-Poly1305.
func Decrypt(encrypted []byte, key []byte) (plaintext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305.NewX: %w", err)
	}
	if len(encrypted) < aead.NonceSize() {
		err = fmt.Errorf("ciphertext too short")
		return
	}
	nonce, ciphertext := encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():]
	plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
	return
}

// EncryptAES encrypts plaintext using AES-256-GCM (legacy cipher).
func EncryptAES(plaintext []byte, key []byte) (encrypted []byte, err error) {
	ivBytes := make([]byte, 12)
	if _, err = rand.Read(ivBytes); err != nil {
		log.Fatalf("can't initialize crypto: %v", err)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	encrypted = aesgcm.Seal(nil, ivBytes, plaintext, nil)
	encrypted = append(ivBytes, encrypted...)
	return
}

// DecryptAES decrypts ciphertext using AES-256-GCM (legacy cipher).
func DecryptAES(encrypted []byte, key []byte) (plaintext []byte, err error) {
	if len(encrypted) < 13 {
		err = fmt.Errorf("incorrect passphrase")
		return
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	plaintext, err = aesgcm.Open(nil, encrypted[:12], encrypted[12:], nil)
	return
}

// NewArgon2 generates a new key based on a passphrase and salt using Argon2id,
// returning a pre-built XChaCha20-Poly1305 AEAD.
func NewArgon2(passphrase []byte, usersalt []byte) (aead cipher.AEAD, salt []byte, err error) {
	if len(passphrase) < 1 {
		err = fmt.Errorf("need more than that for passphrase")
		return
	}
	if usersalt == nil {
		salt = make([]byte, SaltSize)
		if _, err = rand.Read(salt); err != nil {
			log.Fatalf("can't get random salt: %v", err)
		}
	} else {
		salt = usersalt
	}
	aead, err = chacha20poly1305.NewX(argon2.IDKey(passphrase, salt, 3, 64*1024, 4, 32))
	return
}

// EncryptChaCha encrypts using a pre-built XChaCha20-Poly1305 AEAD.
func EncryptChaCha(plaintext []byte, aead cipher.AEAD) (encrypted []byte, err error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("can't generate nonce: %w", err)
	}
	encrypted = aead.Seal(nonce, nonce, plaintext, nil)
	return
}

// DecryptChaCha decrypts using a pre-built XChaCha20-Poly1305 AEAD.
func DecryptChaCha(encryptedMsg []byte, aead cipher.AEAD) (plaintext []byte, err error) {
	if len(encryptedMsg) < aead.NonceSize() {
		err = fmt.Errorf("ciphertext too short")
		return
	}
	nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]
	plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
	return
}

// DeriveRotatedKey derives a new key from the current key and a rotation counter
// using HKDF-SHA256. Use this for key rotation in long-lived sessions.
func DeriveRotatedKey(currentKey []byte, counter uint64) (newKey []byte, err error) {
	info := make([]byte, 8)
	binary.LittleEndian.PutUint64(info, counter)

	hkdfReader := hkdf.New(sha256.New, currentKey, nil, info)
	newKey = make([]byte, 32)
	if _, err = hkdfReader.Read(newKey); err != nil {
		return nil, fmt.Errorf("HKDF key rotation failed: %w", err)
	}
	return
}
