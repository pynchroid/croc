package crypt

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func BenchmarkEncrypt(b *testing.B) {
	bob, _, _ := New([]byte("password"), nil)
	for i := 0; i < b.N; i++ {
		Encrypt([]byte("hello, world"), bob)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, _, _ := New([]byte("password"), nil)
	msg := []byte("hello, world")
	enc, _ := Encrypt(msg, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(enc, key)
	}
}

func BenchmarkNewArgon2(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New([]byte("password"), nil)
	}
}

func BenchmarkNewLegacy(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewLegacy([]byte("password"), nil)
	}
}

func BenchmarkEncryptAES(b *testing.B) {
	bob, _, _ := NewLegacy([]byte("password"), nil)
	for i := 0; i < b.N; i++ {
		EncryptAES([]byte("hello, world"), bob)
	}
}

func BenchmarkDecryptAES(b *testing.B) {
	key, _, _ := NewLegacy([]byte("password"), nil)
	msg := []byte("hello, world")
	enc, _ := EncryptAES(msg, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptAES(enc, key)
	}
}

func BenchmarkEncryptChaCha(b *testing.B) {
	bob, _, _ := NewArgon2([]byte("password"), nil)
	for i := 0; i < b.N; i++ {
		EncryptChaCha([]byte("hello, world"), bob)
	}
}

func BenchmarkDecryptChaCha(b *testing.B) {
	key, _, _ := NewArgon2([]byte("password"), nil)
	msg := []byte("hello, world")
	enc, _ := EncryptChaCha(msg, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptChaCha(enc, key)
	}
}

func TestEncryption(t *testing.T) {
	key, salt, err := New([]byte("password"), nil)
	assert.Nil(t, err)
	assert.Len(t, salt, SaltSize)
	msg := []byte("hello, world")
	enc, err := Encrypt(msg, key)
	assert.Nil(t, err)
	dec, err := Decrypt(enc, key)
	assert.Nil(t, err)
	assert.Equal(t, msg, dec)

	// check reusing the salt
	key2, _, _ := New([]byte("password"), salt)
	dec, err = Decrypt(enc, key2)
	assert.Nil(t, err)
	assert.Equal(t, msg, dec)

	// check wrong password
	key2, _, _ = New([]byte("wrong password"), salt)
	dec, err = Decrypt(enc, key2)
	assert.NotNil(t, err)
	assert.NotEqual(t, msg, dec)

	// error with empty ciphertext
	_, err = Decrypt([]byte(""), key)
	assert.NotNil(t, err)

	// error with small password
	_, _, err = New([]byte(""), nil)
	assert.NotNil(t, err)
}

func TestEncryptionAES(t *testing.T) {
	key, salt, err := NewLegacy([]byte("password"), nil)
	assert.Nil(t, err)
	msg := []byte("hello, world")
	enc, err := EncryptAES(msg, key)
	assert.Nil(t, err)
	dec, err := DecryptAES(enc, key)
	assert.Nil(t, err)
	assert.Equal(t, msg, dec)

	// check reusing the salt
	key2, _, _ := NewLegacy([]byte("password"), salt)
	dec, err = DecryptAES(enc, key2)
	assert.Nil(t, err)
	assert.Equal(t, msg, dec)

	// wrong password
	key2, _, _ = NewLegacy([]byte("wrong password"), salt)
	dec, err = DecryptAES(enc, key2)
	assert.NotNil(t, err)
	assert.NotEqual(t, msg, dec)

	// error with short ciphertext
	_, err = DecryptAES([]byte(""), key)
	assert.NotNil(t, err)

	// error with empty passphrase
	_, _, err = NewLegacy([]byte(""), nil)
	assert.NotNil(t, err)
}

func TestEncryptionChaCha(t *testing.T) {
	key, salt, err := NewArgon2([]byte("password"), nil)
	fmt.Printf("key: %x\n", key)
	assert.Nil(t, err)
	msg := []byte("hello, world")
	enc, err := EncryptChaCha(msg, key)
	assert.Nil(t, err)
	dec, err := DecryptChaCha(enc, key)
	assert.Nil(t, err)
	assert.Equal(t, msg, dec)

	// check reusing the salt
	key2, _, _ := NewArgon2([]byte("password"), salt)
	dec, err = DecryptChaCha(enc, key2)
	assert.Nil(t, err)
	assert.Equal(t, msg, dec)

	// wrong password
	key2, _, _ = NewArgon2([]byte("wrong password"), salt)
	dec, err = DecryptChaCha(enc, key2)
	assert.NotNil(t, err)
	assert.NotEqual(t, msg, dec)

	// error with short ciphertext
	_, err = DecryptChaCha([]byte(""), key)
	assert.NotNil(t, err)

	// error with empty passphrase
	_, _, err = NewArgon2([]byte(""), nil)
	assert.NotNil(t, err)
}

func TestKeyRotation(t *testing.T) {
	key, _, err := New([]byte("password"), nil)
	assert.Nil(t, err)

	// rotate key
	rotated1, err := DeriveRotatedKey(key, 1)
	assert.Nil(t, err)
	assert.Len(t, rotated1, 32)
	assert.NotEqual(t, key, rotated1)

	// same counter produces same key
	rotated1b, err := DeriveRotatedKey(key, 1)
	assert.Nil(t, err)
	assert.Equal(t, rotated1, rotated1b)

	// different counter produces different key
	rotated2, err := DeriveRotatedKey(key, 2)
	assert.Nil(t, err)
	assert.NotEqual(t, rotated1, rotated2)

	// rotated key works for encrypt/decrypt
	msg := []byte("hello after rotation")
	enc, err := Encrypt(msg, rotated1)
	assert.Nil(t, err)
	dec, err := Decrypt(enc, rotated1)
	assert.Nil(t, err)
	assert.Equal(t, msg, dec)

	// original key cannot decrypt rotated-key ciphertext
	_, err = Decrypt(enc, key)
	assert.NotNil(t, err)
}
