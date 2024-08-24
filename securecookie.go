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
)

// Codec defines an interface to encode and decode cookie values.
type Codec interface {
	Encode(name string, value any) (string, error)
	Decode(name, value string, dst any) error
}

// New returns a new SecureCookie.
//
// hashKey is required, used to authenticate values using HMAC. Create it using
// GenerateRandomKey(). It is recommended to use a key with 32 or 64 bytes.
//
// blockKey is optional, used to encrypt values. Create it using
// GenerateRandomKey(). The key length must correspond to the key size
// of the encryption algorithm. For AES, used by default, valid lengths are
// 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The default encoder used for cookie serialization is encoding/gob.
//
// Note that keys created using GenerateRandomKey() are not automatically
// persisted. New keys will be created when the application is restarted, and
// previously issued cookies will not be able to be decoded.
func New(key []byte) (*SecureCookie, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrKeyLength
	}
	s := &SecureCookie{
		key:       key,
		maxAge:    86400 * 30,
		maxLength: 4096,
		sz:        JSONEncoder{},
		timeFunc:  func() int64 { return time.Now().UTC().Unix() },
	}
	return s, nil
}

// SecureCookie encodes and decodes authenticated and optionally encrypted
// cookie values.
type SecureCookie struct {
	key       []byte
	maxLength int
	maxAge    int64
	minAge    int64
	sz        Serializer
	// For testing purposes, the function that returns the current timestamp.
	// If not set, it will use time.Now().UTC().Unix().
	timeFunc func() int64
}

// MaxLength restricts the maximum length, in bytes, for the cookie value.
//
// Default is 4096, which is the maximum value accepted by Internet Explorer.
func (s *SecureCookie) MaxLength(value int) *SecureCookie {
	s.maxLength = value
	return s
}

// MaxAge restricts the maximum age, in seconds, for the cookie value.
//
// Default is 86400 * 30. Set it to 0 for no restriction.
func (s *SecureCookie) MaxAge(value int) *SecureCookie {
	s.maxAge = int64(value)
	return s
}

// MinAge restricts the minimum age, in seconds, for the cookie value.
//
// Default is 0 (no restriction).
func (s *SecureCookie) MinAge(value int) *SecureCookie {
	s.minAge = int64(value)
	return s
}

// SetSerializer sets the encoding/serialization method for cookies.
//
// Default is encoding/gob.  To encode special structures using encoding/gob,
// they must be registered first using gob.Register().
func (s *SecureCookie) SetSerializer(sz Serializer) *SecureCookie {
	s.sz = sz
	return s
}

// SetTimeFunc sets the function that returns the current timestamp.
//
// For testing purposes, the function that generates the timestamp can be
// overridden. If not set, it will return time.Now().UTC().Unix().
func (s *SecureCookie) SetTimeFunc(f func() int64) *SecureCookie {
	s.timeFunc = f
	return s
}

// Encode encodes a cookie value.
//
// It serializes, optionally encrypts, signs with a message authentication code,
// and finally encodes the value.
//
// The name argument is the cookie name. It is stored with the encoded value.
// The value argument is the value to be encoded. It can be any value that can
// be encoded using the currently selected serializer; see SetSerializer().
//
// It is the client's responsibility to ensure that value, when encoded using
// the current serialization/encryption settings on s and then base64-encoded,
// is shorter than the maximum permissible length.
func (s *SecureCookie) Encode(name string, value any) (string, error) {
	var err error
	var b []byte
	// 1. Serialize.
	if b, err = s.sz.Serialize(value); err != nil {
		return "", err
	}
	// 2. Encrypt.
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(b)+aead.Overhead())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	// We create a buffer of "name|timestamp|ciphertext" so that we can verify
	// the validity of the timestamp after decrypting, but before deserializing.
	buf := new(bytes.Buffer)
	buf.WriteString(name + "|")
	buf.WriteString(strconv.FormatInt(s.timestamp(), 10) + "|")
	buf.Write(b)
	b = aead.Seal(nonce, nonce, buf.Bytes(), nil)
	b = encode(b)
	// 3. Check length.
	if s.maxLength != 0 && len(b) > s.maxLength {
		return "", fmt.Errorf("the value is too long: %d", len(b))
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
// it was stored. The value argument is the encoded cookie value. The dst
// argument is where the cookie will be decoded. It must be a pointer.
func (s *SecureCookie) Decode(name, value string, dst any) error {
	// 1. Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return fmt.Errorf("the value is too long: %d", len(value))
	}
	// 2. Decode from base64.
	b, err := decode([]byte(value))
	if err != nil {
		return err
	}
	// 3. Decrypt
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return err
	}
	if len(b) < aead.NonceSize() {
		return ErrDecryptionFailed
	}
	nonce, ciphertext := b[:aead.NonceSize()], b[aead.NonceSize():]
	b, err = aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	parts := bytes.SplitN(b, []byte("|"), 3)
	if len(parts) != 3 {
		return ErrDecryptionFailed
	}
	if string(parts[0]) != name {
		return fmt.Errorf("the name is not valid: %s", name)
	}
	ts, err := strconv.ParseInt(string(parts[1]), 10, 64)
	if err != nil {
		return fmt.Errorf("the timestamp is not valid: %s", parts[1])
	}
	now := s.timestamp()
	if s.minAge != 0 && ts > now-s.minAge {
		return fmt.Errorf("timestamp is too new: %d", ts)
	}
	if s.maxAge != 0 && ts < now-s.maxAge {
		return fmt.Errorf("expired timestamp: %d", ts)
	}
	// 4. Deserialize.
	if err = s.sz.Deserialize(parts[2], dst); err != nil {
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

// CodecsFromPairs returns a slice of SecureCookie instances.
//
// It is a convenience function to create a list of codecs for key rotation. Note
// that the generated Codecs will have the default options applied: callers
// should iterate over each Codec and type-assert the underlying *SecureCookie to
// change these.
//
// Example:
//
//	codecs, _ := securecookie.CodecsFromPairs(
//	     []byte("new-key"),
//	     []byte("old-key"),
//	 )
//
//	// Modify each instance.
//	for _, s := range codecs {
//	       if cookie, ok := s.(*securecookie.SecureCookie); ok {
//	           cookie.MaxAge(86400 * 7)
//	           cookie.SetSerializer(securecookie.JSONEncoder{})
//	       }
//	   }
func CodecsFromPairs(keys ...[]byte) ([]Codec, error) {
	var codecs []Codec
	for _, v := range keys {
		codec, err := New(v)
		if err != nil {
			return nil, err
		}
		codecs = append(codecs, codec)
	}
	return codecs, nil
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
