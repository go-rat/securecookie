// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

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

var DefaultOptions = &Options{
	MinAge:     0,
	MaxAge:     86400 * 30,
	MaxLength:  4096,
	Serializer: JSONEncoder{},
	TimeFunc: func() int64 {
		return time.Now().UTC().Unix()
	},
}

// Codec defines an interface to encode and decode cookie values.
type Codec interface {
	Encode(name string, value any) (string, error)
	Decode(name, value string, dst any) error
}

// New returns a new SecureCookie.
//
// Key is required and must be 32 bytes, used to authenticate and
// encrypt cookie values.
//
// Note that keys created using GenerateRandomKey() are not automatically
// persisted. New keys will be created when the application is restarted, and
// previously issued cookies will not be able to be decoded.
func New(key []byte, options *Options) (*SecureCookie, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrKeyLength
	}
	if options == nil {
		options = DefaultOptions
	}
	if options.Serializer == nil {
		options.Serializer = DefaultOptions.Serializer
	}
	if options.TimeFunc == nil {
		options.TimeFunc = func() int64 {
			return time.Now().UTC().Unix()
		}
	}
	s := &SecureCookie{
		key:         key,
		rotatedKeys: options.RotatedKeys,
		minAge:      options.MinAge,
		maxAge:      options.MaxAge,
		maxLength:   options.MaxLength,
		sz:          options.Serializer,
		timeFunc:    options.TimeFunc,
	}
	return s, nil
}

type Options struct {
	RotatedKeys [][]byte
	MinAge      int64
	MaxAge      int64
	MaxLength   int
	Serializer  Serializer
	TimeFunc    func() int64
}

// SecureCookie encodes and decodes authenticated and optionally encrypted
// cookie values.
type SecureCookie struct {
	key         []byte
	rotatedKeys [][]byte
	maxLength   int
	maxAge      int64
	minAge      int64
	sz          Serializer
	// For testing purposes, the function that returns the current timestamp.
	// If not set, it will use time.Now().UTC().Unix().
	timeFunc func() int64
}

// Encode encodes a cookie value.
//
// It serializes, optionally encrypts, signs with a message authentication code,
// and finally encodes the value.
//
// The name argument is the cookie name. It is used to authenticate the cookie.
// The value argument is the value to be encoded. It can be any value that can
// be encoded using the currently selected serializer.
//
// It is the client's responsibility to ensure that value, when encoded using
// the current serialization/encryption settings on s and then base64-encoded,
// is shorter than the maximum permissible length.
func (s *SecureCookie) Encode(name string, value any) (string, error) {
	var err error
	var errors MultiError
	var b []byte
	// 1. Serialize.
	if b, err = s.sz.Serialize(value); err != nil {
		return "", err
	}
	// 2. Encrypt.
	key := s.key
	index := -1
walk:
	// We can't directly use 'b' here because if the encryption fails, we need
	// to retry with a different key.
	enc, err := s.encrypt([]byte(name), key, b)
	if err != nil {
		errors = append(errors, err)
		if index++; index < len(s.rotatedKeys) {
			key = s.rotatedKeys[index]
			goto walk
		} else {
			return "", errors
		}
	}
	b = encode(enc)
	// 3. Check length.
	if s.maxLength != 0 && len(b) > s.maxLength {
		return "", ErrValueTooLong
	}
	// Done.
	return string(b), nil
}

// Decode decodes a cookie value.
//
// It decodes, verifies a message authentication code, optionally decrypts and
// finally deserializes the value.
//
// The name argument is the cookie name. It must be the same name used when
// it was encoded. The value argument is the encoded cookie value. The dst
// argument is where the cookie will be decoded. It must be a pointer.
func (s *SecureCookie) Decode(name, value string, dst any) error {
	var err error
	var errors MultiError
	// 1. Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return ErrValueTooLong
	}
	// 2. Decode from base64.
	b, err := decode([]byte(value))
	if err != nil {
		return err
	}
	// 3. Decrypt.
	key := s.key
	index := -1
walk:
	// We can't directly use 'b' here because if the decryption fails, we need
	// to retry with a different key.
	dec, err := s.decrypt([]byte(name), key, b)
	if err != nil {
		errors = append(errors, err)
		if index++; index < len(s.rotatedKeys) {
			key = s.rotatedKeys[index]
			goto walk
		} else {
			return errors
		}
	}
	parts := bytes.SplitN(dec, []byte("|"), 2)
	if len(parts) != 2 {
		return ErrDecryptionFailed
	}
	ts, err := strconv.ParseInt(string(parts[0]), 10, 64)
	if err != nil {
		return ErrTimestampInvalid
	}
	now := s.timestamp()
	if s.minAge != 0 && ts > now-s.minAge {
		return ErrTimestampTooNew
	}
	if s.maxAge != 0 && ts < now-s.maxAge {
		return ErrTimestampExpired
	}
	// 4. Deserialize.
	if err = s.sz.Deserialize(parts[1], dst); err != nil {
		return err
	}
	// Done.
	return nil
}

// timestamp returns the current timestamp, in seconds.
//
// For testing purposes, the function that generates the timestamp can be
// overridden. If not set, it will return time.Now().UTC().Unix().
func (s *SecureCookie) timestamp() int64 {
	return s.timeFunc()
}

// encrypt encrypts a value using the given key, nonce will be generated
// and prepended to the ciphertext.
func (s *SecureCookie) encrypt(name, key, value []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := GenerateRandomKey(aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	// We create a buffer of "timestamp|ciphertext" so that we can verify
	// the validity of the timestamp after decrypting, but before deserializing.
	buf := new(bytes.Buffer)
	buf.WriteString(strconv.FormatInt(s.timestamp(), 10) + "|")
	buf.Write(value)
	value = aead.Seal(nonce, nonce, buf.Bytes(), name)
	return value, nil
}

// decrypt decrypts a value using the given key, nonce will be extracted from
// the ciphertext.
func (s *SecureCookie) decrypt(name, key, value []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(value) < aead.NonceSize() {
		return nil, ErrDecryptionFailed
	}
	nonce, ciphertext := value[:aead.NonceSize()], value[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, name)
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
// On failure, returns nil.
//
// Note that keys created using `GenerateRandomKey()` are not automatically
// persisted. New keys will be created when the application is restarted, and
// previously issued cookies will not be able to be decoded.
//
// Callers should explicitly check for the possibility of a nil return, treat
// it as a failure of the system random number generator, and not continue.
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
		err := codec.Decode(name, value, dst)
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
