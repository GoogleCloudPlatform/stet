// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gf8_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field/gf8"
	"github.com/google/go-cmp/cmp"
)

func getRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatalf("Failed to read random bytes: %v", err)
	}
	return b
}

func TestAddition(t *testing.T) {
	f := gf8.New()
	for range 10 {
		elems := getRandomBytes(t, 2)

		e1, err := f.CreateElement(int(elems[0]))
		if err != nil {
			t.Fatal(err)
		}
		e2, err := f.CreateElement(int(elems[1]))
		if err != nil {
			t.Fatal(err)
		}

		got := e1.Add(e2).Bytes()[0]

		if got != elems[0]^elems[1] {
			t.Fatalf("a(%d) + b(%b), got = %d, want = %d", elems[0], elems[1], got, elems[0]^elems[1])
		}
	}
}

func TestSubtraction(t *testing.T) {
	f := gf8.New()
	for range 10 {
		elems := getRandomBytes(t, 2)

		e1, err := f.CreateElement(int(elems[0]))
		if err != nil {
			t.Fatal(err)
		}
		e2, err := f.CreateElement(int(elems[1]))
		if err != nil {
			t.Fatal(err)
		}

		got := e1.Subtract(e2).Bytes()[0]

		if got != elems[0]^elems[1] {
			t.Errorf("a(%d) - b(%b), got = %d, want = %d", elems[0], elems[1], got, elems[0]^elems[1])
		}
	}
}

func TestMultiplication(t *testing.T) {
	f := gf8.New()
	for _, tc := range []struct {
		a    byte
		b    byte
		want byte
	}{
		// The following test cases are taken from various online examples of AES finite field
		// arithmetic, which uses GF(2^8) over the same irreducible polynomial:
		// - https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
		// - https://uomustansiriyah.edu.iq/media/lectures/5/5_2020_12_28!10_55_23_AM.pdf
		{
			a:    0x53,
			b:    0xCA,
			want: 0x01,
		},
		{
			a:    0x02,
			b:    0x87,
			want: 0x15,
		},
		{
			a:    0x03,
			b:    0x6E,
			want: 0xB2,
		},
		// The following test cases where generated manually:
		// http://www.ee.unb.ca/cgi-bin/tervo/calc2.pl
		{
			a:    161,
			b:    56,
			want: 102,
		},
		{
			a:    51,
			b:    82,
			want: 15,
		},
		{
			a:    15,
			b:    30,
			want: 170,
		},
		{
			a:    105,
			b:    27,
			want: 20,
		},
		{
			a:    178,
			b:    160,
			want: 67,
		},
		{
			a:    244,
			b:    118,
			want: 55,
		},
		{
			a:    250,
			b:    221,
			want: 160,
		},
		{
			a:    244,
			b:    34,
			want: 90,
		},
	} {
		t.Run(fmt.Sprintf("%d * %d", tc.a, tc.b), func(t *testing.T) {
			a, err := f.CreateElement(int(tc.a))
			if err != nil {
				t.Fatal(err)
			}
			b, err := f.CreateElement(int(tc.b))
			if err != nil {
				t.Fatal(err)
			}
			got := uint8(a.Multiply(b).Bytes()[0])
			if got != tc.want {
				t.Errorf("a(%d) * b(%d), got = %d, want = %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestInverse(t *testing.T) {
	f := gf8.New()
	for _, tc := range []struct {
		a    byte
		want byte
	}{
		// Test case was taken from AES FF arithmetic example: https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
		{
			a: 0x53, want: 0xCA,
		},
		// The following test cases where generated manually:
		// http://www.ee.unb.ca/cgi-bin/tervo/calc2.pl
		{
			a: 29, want: 64,
		},
		{
			a: 180, want: 17,
		},
		{
			a: 249, want: 156,
		},
		{
			a: 186, want: 118,
		},
		{
			a: 209, want: 7,
		},
		{
			a: 233, want: 78,
		},
		{
			a: 242, want: 56,
		},
		{
			a: 249, want: 156,
		},
	} {
		t.Run(fmt.Sprintf("inverse(%d)", tc.a), func(t *testing.T) {
			a, err := f.ReadElement([]byte{tc.a}, 0)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := a.Inverse()
			if err != nil {
				t.Fatal(err)
			}
			got := uint8(inv.Bytes()[0])
			if got != tc.want {
				t.Errorf("inverse(%d), got = %d, want = %d", tc.a, got, tc.want)
			}
		})
	}
}

func TestIdentityInverseFails(t *testing.T) {
	e, err := gf8.New().CreateElement(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Inverse(); err == nil {
		t.Fatalf("Inverse() err = nil, want non-nil error")
	}
}

func TestGreaterThan(t *testing.T) {
	f := gf8.New()
	for _, tc := range []struct {
		a    byte
		b    byte
		want bool
	}{
		{
			a:    0,
			b:    1,
			want: false,
		},
		{
			a:    1,
			b:    0,
			want: true,
		},
		{
			a:    1,
			b:    1,
			want: false,
		},
		{
			a:    0,
			b:    0,
			want: false,
		},
		{
			a:    255,
			b:    254,
			want: true,
		},
	} {
		t.Run(fmt.Sprintf("%d > %d", tc.a, tc.b), func(t *testing.T) {
			a, err := f.CreateElement(int(tc.a))
			if err != nil {
				t.Fatal(err)
			}
			b, err := f.CreateElement(int(tc.b))
			if err != nil {
				t.Fatal(err)
			}
			if got := a.GT(b); got != tc.want {
				t.Errorf("GT(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestCreateElementLargerThanFieldFails(t *testing.T) {
	f := gf8.New()
	if _, err := f.CreateElement(256); err == nil {
		t.Fatalf("CreateElement(256) err = nil, want non-nil error")
	}
}

func TestBytes(t *testing.T) {
	f := gf8.New()
	for range 10 {
		a := getRandomBytes(t, 1)
		e, err := f.CreateElement(int(a[0]))
		if err != nil {
			t.Fatal(err)
		}
		got := e.Bytes()
		if !cmp.Equal(got, a) {
			t.Errorf("Bytes() got = %d, want = %d", got, a)
		}
	}
}

func TestFlip(t *testing.T) {
	f := gf8.New()
	a := getRandomBytes(t, 1)
	e, err := f.CreateElement(int(a[0]))
	if err != nil {
		t.Fatal(err)
	}
	got := e.Flip().Bytes()
	if !cmp.Equal(got, a) {
		t.Errorf("Flip() got = %d, want = %d", got, a)
	}
}

func TestDecodeElements(t *testing.T) {
	f := gf8.New()
	r := getRandomBytes(t, 30)
	elements := f.DecodeElements(r)
	for i, e := range elements {
		if e.Bytes()[0] != r[i] {
			t.Errorf("DecodeElements()[%d] got = %d, want = %d", i, e.Bytes()[0], r[i])
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	f := gf8.New()
	n := 10
	elems := make([]field.Element, n)
	for i := range n {
		var err error
		if elems[i], err = f.NewRandomNonZero(); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := f.EncodeElements(elems, n)
	if err != nil {
		t.Fatal(err)
	}

	decoded := f.DecodeElements(encoded)
	if !cmp.Equal(elems, decoded) {
		t.Fatalf("EncodeElements(DecodeElements()) got = %q, want = %q", decoded, elems)
	}
}

func TestFieldElementSize(t *testing.T) {
	got := gf8.New().ElementSize()
	if got != 1 {
		t.Fatalf("gf8.New().ElementSize() got = %d, want %d", got, 1)
	}
}

func TestFieldID(t *testing.T) {
	got := gf8.New().FieldID()
	if got != finitefield.GF8 {
		t.Fatalf("gf8.New().FieldID() got = %q, want %q", got, finitefield.GF8)
	}
}
