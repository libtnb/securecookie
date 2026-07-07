// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Register []any so that GobEncoder can handle nested values inside
// map[string]any cookies without requiring callers to do it themselves.
func init() {
	gob.Register([]any{})
}

var (
	ErrKeyLength        = fmt.Errorf("the key must be %d bytes", chacha20poly1305.KeySize)
	ErrDecryptionFailed = fmt.Errorf("the value could not be decrypted")
	ErrNoCodecs         = fmt.Errorf("no codecs provided")
	ErrValueNotByte     = fmt.Errorf("the value is not a []byte")
	ErrValueNotBytePtr  = fmt.Errorf("the value is not a *[]byte")
	ErrValueTooLong     = fmt.Errorf("the value is too long")
	ErrTimestampInvalid = fmt.Errorf("the timestamp is invalid")
	ErrTimestampTooNew  = fmt.Errorf("the timestamp is too new")
	ErrTimestampExpired = fmt.Errorf("the timestamp is expired")
)

// defaultTimeFunc returns the current Unix timestamp, in seconds.
func defaultTimeFunc() int64 {
	return time.Now().UTC().Unix()
}

var DefaultOptions = &Options{
	MinAge:     0,
	MaxAge:     86400 * 30,
	MaxLength:  4096,
	Serializer: JSONEncoder{},
	TimeFunc:   defaultTimeFunc,
}

// Codec defines an interface to encode and decode cookie values.
type Codec interface {
	Encode(name string, value any) (string, error)
	Decode(name, value string, dst any) (int64, error)
}

// New returns a new SecureCookie.
//
// Key is required and must be 32 bytes, used to authenticate and encrypt
// cookie values. The same length requirement applies to every key in
// options.RotatedKeys.
//
// If options is nil, DefaultOptions is used. The provided Options value is
// only read, never modified.
//
// Note that keys created using GenerateRandomKey() are not automatically
// persisted. New keys will be created when the application is restarted, and
// previously issued cookies will not be able to be decoded.
func New(key []byte, options *Options) (*SecureCookie, error) {
	if options == nil {
		options = DefaultOptions
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrKeyLength
	}
	rotated := make([]cipher.AEAD, len(options.RotatedKeys))
	for i, k := range options.RotatedKeys {
		if rotated[i], err = chacha20poly1305.NewX(k); err != nil {
			return nil, ErrKeyLength
		}
	}
	s := &SecureCookie{
		aead:         aead,
		rotatedAEADs: rotated,
		minAge:       options.MinAge,
		maxAge:       options.MaxAge,
		maxLength:    options.MaxLength,
		sz:           options.Serializer,
		timeFunc:     options.TimeFunc,
	}
	// Defaults are filled in on the SecureCookie itself so the caller's
	// Options value is left untouched.
	if s.sz == nil {
		s.sz = DefaultOptions.Serializer
	}
	if s.timeFunc == nil {
		s.timeFunc = defaultTimeFunc
	}
	return s, nil
}

type Options struct {
	// RotatedKeys holds previous keys, tried in order when decoding so that
	// cookies issued before a key rotation remain valid. They are never used
	// for encoding. Each key must be 32 bytes.
	RotatedKeys [][]byte
	// MinAge is the minimum age of a cookie, in seconds. Cookies encoded
	// less than MinAge seconds ago are rejected. 0 disables the check.
	MinAge int64
	// MaxAge is the maximum age of a cookie, in seconds. Cookies encoded
	// more than MaxAge seconds ago are rejected. 0 disables the check.
	MaxAge int64
	// MaxLength is the maximum length of an encoded cookie value, in bytes.
	// 0 disables the check. Note that browsers commonly limit the whole
	// cookie (name, value and attributes) to 4096 bytes.
	MaxLength int
	// Serializer converts values to and from bytes. Defaults to JSONEncoder.
	Serializer Serializer
	// TimeFunc returns the current Unix timestamp, in seconds. It exists so
	// tests can supply a fake clock. Defaults to time.Now().UTC().Unix().
	TimeFunc func() int64
}

// SecureCookie encodes and decodes authenticated and encrypted cookie
// values. It is safe for concurrent use by multiple goroutines, as long as
// the configured Serializer and TimeFunc are (the defaults are).
type SecureCookie struct {
	aead         cipher.AEAD
	rotatedAEADs []cipher.AEAD
	maxLength    int
	maxAge       int64
	minAge       int64
	sz           Serializer
	// timeFunc returns the current timestamp; injectable for testing.
	timeFunc func() int64
}

// Encode encodes a cookie value.
//
// It serializes the value, encrypts and authenticates it together with a
// timestamp using the primary key, and finally encodes the result with
// base64. Rotated keys are never used for encoding.
//
// The name argument is the cookie name. It is bound to the ciphertext as
// additional authenticated data, so a value issued for one cookie name
// cannot be replayed under another.
func (s *SecureCookie) Encode(name string, value any) (string, error) {
	// 1. Serialize.
	b, err := s.sz.Serialize(value)
	if err != nil {
		return "", err
	}
	// 2. Encrypt.
	if b, err = s.encrypt([]byte(name), b); err != nil {
		return "", err
	}
	b = encode(b)
	// 3. Check length.
	if s.maxLength != 0 && len(b) > s.maxLength {
		return "", ErrValueTooLong
	}
	// Done.
	return string(b), nil
}

// Decode decodes a cookie value.
//
// It decodes the base64 value, decrypts and verifies the ciphertext, checks
// the embedded timestamp against MinAge/MaxAge, and finally deserializes
// the value into dst, which must be a pointer.
//
// The name argument is the cookie name. It must be the same name used when
// it was encoded.
//
// It returns the timestamp at which the cookie was encoded whenever it is
// known, even if a timestamp or deserialization error is returned alongside.
func (s *SecureCookie) Decode(name, value string, dst any) (int64, error) {
	// 1. Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return 0, ErrValueTooLong
	}
	// 2. Decode from base64.
	b, err := decode([]byte(value))
	if err != nil {
		return 0, err
	}
	// 3. Decrypt, trying the primary key first and then any rotated keys so
	// that cookies issued before a key rotation remain valid.
	ad := []byte(name)
	dec, err := decrypt(s.aead, ad, b)
	for i := 0; err != nil && i < len(s.rotatedAEADs); i++ {
		dec, err = decrypt(s.rotatedAEADs[i], ad, b)
	}
	if err != nil {
		return 0, err
	}
	// 4. Validate the timestamp.
	tsPart, payload, found := bytes.Cut(dec, []byte("|"))
	if !found {
		return 0, ErrDecryptionFailed
	}
	ts, err := strconv.ParseInt(string(tsPart), 10, 64)
	if err != nil {
		return 0, ErrTimestampInvalid
	}
	now := s.timestamp()
	if s.minAge != 0 && ts > now-s.minAge {
		return ts, ErrTimestampTooNew
	}
	if s.maxAge != 0 && ts < now-s.maxAge {
		return ts, ErrTimestampExpired
	}
	// 5. Deserialize.
	if err = s.sz.Deserialize(payload, dst); err != nil {
		return ts, err
	}
	// Done.
	return ts, nil
}

// timestamp returns the current timestamp, in seconds.
func (s *SecureCookie) timestamp() int64 {
	return s.timeFunc()
}

// encrypt seals "timestamp|value" using the primary key, so that the
// timestamp can be verified after decrypting but before deserializing. A
// random nonce is generated and prepended to the ciphertext, and ad (the
// cookie name) is bound as additional authenticated data.
func (s *SecureCookie) encrypt(ad, value []byte) ([]byte, error) {
	plaintext := make([]byte, 0, 20+1+len(value))
	plaintext = strconv.AppendInt(plaintext, s.timestamp(), 10)
	plaintext = append(plaintext, '|')
	plaintext = append(plaintext, value...)
	// The buffer holds the nonce and reserves capacity for Seal to append
	// the ciphertext in place, without another allocation.
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plaintext)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, ad), nil
}

// decrypt opens a value sealed by encrypt, with the nonce extracted from
// the head of the value. Any failure is reported as ErrDecryptionFailed.
func decrypt(aead cipher.AEAD, ad, value []byte) ([]byte, error) {
	if len(value) < aead.NonceSize() {
		return nil, ErrDecryptionFailed
	}
	nonce, ciphertext := value[:aead.NonceSize()], value[aead.NonceSize():]
	dec, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	return dec, nil
}

// Encoding -------------------------------------------------------------------

// encode encodes a value using base64.
func encode(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return encoded
}

// decode decodes a cookie using base64.
func decode(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, err
	}
	return decoded[:b], nil
}

// Helpers --------------------------------------------------------------------

// GenerateRandomKey creates a random key with the given length in bytes.
// It panics if the system's secure random number source fails, in which
// case the process should not continue.
//
// Note that keys created using `GenerateRandomKey()` are not automatically
// persisted. New keys will be created when the application is restarted, and
// previously issued cookies will not be able to be decoded.
func GenerateRandomKey(length int) []byte {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("securecookie: error generating random key: %v", err))
	}
	return b
}

// EncodeMulti encodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
//
// On error, may return a MultiError.
func EncodeMulti(name string, value any, codecs ...Codec) (string, error) {
	if len(codecs) == 0 {
		return "", ErrNoCodecs
	}

	var errors MultiError
	for _, codec := range codecs {
		encoded, err := codec.Encode(name, value)
		if err == nil {
			return encoded, nil
		}
		errors = append(errors, err)
	}
	return "", errors
}

// DecodeMulti decodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
//
// On error, may return a MultiError.
func DecodeMulti(name string, value string, dst any, codecs ...Codec) error {
	if len(codecs) == 0 {
		return ErrNoCodecs
	}

	var errors MultiError
	for _, codec := range codecs {
		_, err := codec.Decode(name, value, dst)
		if err == nil {
			return nil
		}
		errors = append(errors, err)
	}
	return errors
}

// MultiError groups multiple errors.
type MultiError []error

func (m MultiError) Error() string {
	s, n := "", 0
	for _, e := range m {
		if e != nil {
			if n == 0 {
				s = e.Error()
			}
			n++
		}
	}
	switch n {
	case 0:
		return "(0 errors)"
	case 1:
		return s
	case 2:
		return s + " (and 1 other error)"
	}
	return fmt.Sprintf("%s (and %d other errors)", s, n-1)
}

// Unwrap returns the grouped errors, allowing errors.Is and errors.As to
// examine each of them.
func (m MultiError) Unwrap() []error {
	return m
}
