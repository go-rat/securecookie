// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	fuzz "github.com/google/gofuzz"
)

var testCookies = []any{
	map[string]string{"foo": "bar"},
	map[string]string{"baz": "ding"},
}

var testStrings = []string{"foo", "bar", "baz"}

func TestSecureCookie(t *testing.T) {
	s1, err1 := New([]byte("12345678901234567890123456789012"), DefaultOptions)
	s2, err2 := New([]byte("abcdefghijklmnopqrstuvwxyz123456"), DefaultOptions)
	if err1 != nil {
		t.Fatal(err1)
	}
	if err2 != nil {
		t.Fatal(err2)
	}
	value := map[string]any{
		"foo": "bar",
		"baz": float64(128),
	}

	for i := 0; i < 50; i++ {
		// Running this multiple times to check if any special character
		// breaks encoding/decoding.
		encoded, err := s1.Encode("sid", value)
		if err != nil {
			t.Error(err)
			continue
		}
		dst := make(map[string]any)
		if _, err = s1.Decode("sid", encoded, &dst); err != nil {
			t.Fatalf("%#v: %#v", err, encoded)
		}
		if !reflect.DeepEqual(dst, value) {
			t.Fatalf("Expected %#v, got %#v.", value, dst)
		}
		dst2 := make(map[string]any)
		if _, err = s2.Decode("sid", encoded, &dst2); err == nil {
			t.Fatalf("Expected failure decoding.")
		}
	}
}

func TestSecureCookieNilKey(t *testing.T) {
	s1, err := New(nil, DefaultOptions)
	if s1 != nil {
		t.Fatalf("Expected nil, got %#v", s1)
	}
	if !errors.Is(err, ErrKeyLength) {
		t.Fatalf("Expected ErrKeyLength, got %#v", err)
	}
}

func TestDecodeInvalid(t *testing.T) {
	// List of invalid cookies, which must not be accepted, base64-decoded
	// (they will be encoded before passing to Decode).
	invalidCookies := []string{
		"",
		" ",
		"\n",
		"||",
		"|||",
		"cookie",
	}
	s, err := New([]byte("12345678901234567890123456789012"), DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	var dst string
	for i, v := range invalidCookies {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding,
			base64.URLEncoding,
		} {
			_, err = s.Decode("name", enc.EncodeToString([]byte(v)), &dst)
			if err == nil {
				t.Fatalf("%d: expected failure decoding", i)
			}
		}
	}
}

func TestGobSerialization(t *testing.T) {
	var (
		sz           GobEncoder
		serialized   []byte
		deserialized map[string]string
		err          error
	)
	for _, value := range testCookies {
		if serialized, err = sz.Serialize(value); err != nil {
			t.Error(err)
		} else {
			deserialized = make(map[string]string)
			if err = sz.Deserialize(serialized, &deserialized); err != nil {
				t.Error(err)
			}
			if fmt.Sprintf("%#v", deserialized) != fmt.Sprintf("%#v", value) {
				t.Errorf("Expected %#v, got %#v.", value, deserialized)
			}
		}
	}
}

func TestJSONSerialization(t *testing.T) {
	var (
		sz           JSONEncoder
		serialized   []byte
		deserialized map[string]string
		err          error
	)
	for _, value := range testCookies {
		if serialized, err = sz.Serialize(value); err != nil {
			t.Error(err)
		} else {
			deserialized = make(map[string]string)
			if err = sz.Deserialize(serialized, &deserialized); err != nil {
				t.Error(err)
			}
			if fmt.Sprintf("%#v", deserialized) != fmt.Sprintf("%#v", value) {
				t.Errorf("Expected %#v, got %#v.", value, deserialized)
			}
		}
	}
}

func TestNopSerialization(t *testing.T) {
	cookieData := "fooobar123"
	sz := NopEncoder{}

	if _, err := sz.Serialize(cookieData); !errors.Is(err, ErrValueNotByte) {
		t.Fatal("Expected error unless you pass a []byte")
	}
	dat, err := sz.Serialize([]byte(cookieData))
	if err != nil {
		t.Fatal(err)
	}
	if (string(dat)) != cookieData {
		t.Fatal("Expected serialized data to be same as source")
	}

	var dst []byte
	if err = sz.Deserialize(dat, dst); !errors.Is(err, ErrValueNotBytePtr) {
		t.Fatal("Expect error unless you pass a *[]byte")
	}
	if err = sz.Deserialize(dat, &dst); err != nil {
		t.Fatal(err)
	}
	if (string(dst)) != cookieData {
		t.Fatal("Expected deserialized data to be same as source")
	}
}

func TestEncoding(t *testing.T) {
	for _, value := range testStrings {
		encoded := encode([]byte(value))
		decoded, err := decode(encoded)
		if err != nil {
			t.Error(err)
		} else if string(decoded) != value {
			t.Errorf("Expected %#v, got %s.", value, string(decoded))
		}
	}
}

func TestMultiError(t *testing.T) {
	s1, err1 := New([]byte("12345678901234567890123456789012"), DefaultOptions)
	s2, err2 := New([]byte("abcdefghijklmnopqrstuvwxyz123456"), DefaultOptions)
	if err1 != nil {
		t.Fatal(err1)
	}
	if err2 != nil {
		t.Fatal(err2)
	}
	_, err := EncodeMulti("sid", New, s1, s2)
	if err == nil {
		t.Fatal("Expected failure encoding.")
	}
	if len(err.(MultiError)) != 2 {
		t.Errorf("Expected 2 errors, got %s.", err)
	} else {
		if !strings.Contains(err.Error(), "unsupported type") {
			t.Errorf("Expected unsupported type error, got %s.", err.Error())
		}
	}
}

func TestMultiNoCodecs(t *testing.T) {
	_, err := EncodeMulti("foo", "bar")
	if !errors.Is(err, ErrNoCodecs) {
		t.Errorf("EncodeMulti: bad value for error, got: %#v", err)
	}

	var dst []byte
	err = DecodeMulti("foo", "bar", &dst)
	if !errors.Is(err, ErrNoCodecs) {
		t.Errorf("DecodeMulti: bad value for error, got: %#v", err)
	}
}

func TestMissingKey(t *testing.T) {
	emptyKeys := [][]byte{
		nil,
		[]byte(""),
	}

	for _, key := range emptyKeys {
		s1, err := New(key, DefaultOptions)
		if s1 != nil {
			t.Fatalf("Expected nil, got %#v", s1)
		}
		if !errors.Is(err, ErrKeyLength) {
			t.Fatalf("Expected ErrKeyLength, got %#v", err)
		}
	}
}

// ----------------------------------------------------------------------------

type FooBar struct {
	Foo int
	Bar string
}

func TestCustomType(t *testing.T) {
	s1, err := New([]byte("12345678901234567890123456789012"), DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	// Type is not registered in gob. (!!!)
	src := &FooBar{42, "bar"}
	encoded, _ := s1.Encode("sid", src)

	dst := &FooBar{}
	_, _ = s1.Decode("sid", encoded, dst)
	if dst.Foo != 42 || dst.Bar != "bar" {
		t.Fatalf("Expected %#v, got %#v", src, dst)
	}
}

type Cookie struct {
	B bool
	I int
	S string
}

func FuzzEncodeDecode(f *testing.F) {
	fuzzer := fuzz.New()
	s1, err := New([]byte("12345678901234567890123456789012"), DefaultOptions)
	if err != nil {
		f.Fatal(err)
	}
	s1.maxLength = 0

	for i := 0; i < 100000; i++ {
		var c Cookie
		fuzzer.Fuzz(&c)
		f.Add(c.B, c.I, c.S)
	}

	f.Fuzz(func(t *testing.T, b bool, i int, s string) {
		c := Cookie{b, i, s}
		encoded, err := s1.Encode("sid", c)
		if err != nil {
			t.Errorf("Encode failed: %#v", err)
		}
		dc := Cookie{}
		_, err = s1.Decode("sid", encoded, &dc)
		if err != nil {
			t.Errorf("Decode failed: %#v", err)
		}
		if dc != c {
			t.Fatalf("Expected %#v, got %#v.", s, dc)
		}
	})
}

func TestEncodeDecodeWithRotatedKeys(t *testing.T) {
	key1 := []byte("abcdefghijklmnopqrstuvwxyz123456")
	key2 := []byte("12345678901234567890123456789012")
	s1, err := New(key1, &Options{RotatedKeys: [][]byte{key2}})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := New(key2, &Options{RotatedKeys: [][]byte{key1}})
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"foo": "bar"}
	encoded1, err := s1.Encode("sid", value)
	if err != nil {
		t.Fatal(err)
	}
	encoded2, err := s2.Encode("sid", value)
	if err != nil {
		t.Fatal(err)
	}
	dst1 := make(map[string]any)
	if _, err = s2.Decode("sid", encoded1, &dst1); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dst1, value) {
		t.Fatalf("Expected %#v, got %#v.", value, dst1)
	}
	dst2 := make(map[string]any)
	if _, err = s1.Decode("sid", encoded2, &dst2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dst2, value) {
		t.Fatalf("Expected %#v, got %#v.", value, dst2)
	}
}

func TestEncodeDecodeWithExpiredTimestamp(t *testing.T) {
	s1, err := New([]byte("12345678901234567890123456789012"), &Options{MaxAge: 1})
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"foo": "bar"}
	encoded, err := s1.Encode("sid", value)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	dst := make(map[string]any)
	if _, err = s1.Decode("sid", encoded, &dst); err == nil {
		t.Fatal("Expected failure due to expired timestamp.")
	}
	if !errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("Expected ErrTimestampExpired, got %#v", err)
	}
}

func TestEncodeDecodeWithFutureTimestamp(t *testing.T) {
	s1, err := New([]byte("12345678901234567890123456789012"), &Options{MinAge: 1})
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"foo": "bar"}
	encoded, err := s1.Encode("sid", value)
	if err != nil {
		t.Fatal(err)
	}
	dst := make(map[string]any)
	if _, err = s1.Decode("sid", encoded, &dst); err == nil {
		t.Fatal("Expected failure due to future timestamp.")
	}
	if !errors.Is(err, ErrTimestampTooNew) {
		t.Fatalf("Expected ErrTimestampTooNew, got %#v", err)
	}
}

func TestEncodeDecodeWithInvalidKeyLength(t *testing.T) {
	_, err := New([]byte("shortkey"), DefaultOptions)
	if !errors.Is(err, ErrKeyLength) {
		t.Fatalf("Expected ErrKeyLength, got %#v", err)
	}
}

func TestEncodeDecodeWithMaxLengthExceeded(t *testing.T) {
	s1, err := New([]byte("12345678901234567890123456789012"), &Options{MaxLength: 10})
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"foo": "bar"}
	_, err = s1.Encode("sid", value)
	if err == nil {
		t.Fatal("Expected failure due to max length exceeded.")
	}
	if !errors.Is(err, ErrValueTooLong) {
		t.Fatalf("Expected ErrValueTooLong, got %#v", err)
	}
}
