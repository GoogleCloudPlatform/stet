// Copyright 2022 Google LLC
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

package gf32_test

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field/gf32"
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

func TestEncodeDecode(t *testing.T) {
	type testCase struct {
		tag string
		b   []byte
	}
	for _, tc := range []testCase{
		{
			tag: "small value no carry over",
			b:   []byte{0x01, 0x02, 0x03},
		},
		{
			tag: "small value no carry over",
			b:   []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			tag: "5 bytes pushes on bit causing carry",
			b:   []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			tag: "8 bytes pushes on bit causing carry",
			b:   []byte{0xFF, 0x02, 0x03, 0x04, 0xFF, 0x06, 0x07, 0x08, 0xFF},
		},
		{
			tag: "32 bytes pushes on bit causing carry",
			b:   getRandomBytes(t, 32),
		},
		{
			tag: "large random value",
			b:   getRandomBytes(t, 300),
		},
	} {
		gf := gf32.New()
		t.Run(tc.tag, func(t *testing.T) {
			e := gf.DecodeElements(tc.b)
			got, err := gf.EncodeElements(e, len(tc.b))
			if err != nil {
				t.Fatalf("EncodeElements() err = %v, want nil", err)
			}
			if !cmp.Equal(got, tc.b) {
				t.Errorf("ConvertGF32 got %v, want %v, intermediate: %v", got, tc.b, e)
			}
		})
	}
}

const fieldPrimeOrder = 2147483659

func TestFieldArithmetic(t *testing.T) {
	type testCase struct {
		tag  string
		a    int
		b    int
		sum  uint32
		mult uint32
		sub  uint32
	}
	gf := gf32.New()
	for _, tc := range []testCase{
		{
			tag:  "small values",
			a:    2,
			b:    5,
			sum:  7,
			mult: 10,
			sub:  2147483656,
		},
		{
			tag:  "field order",
			a:    fieldPrimeOrder - 1,
			b:    1,
			sum:  0,
			mult: fieldPrimeOrder - 1,
			sub:  fieldPrimeOrder - 2,
		},
		{
			tag:  "field order + 1",
			a:    fieldPrimeOrder - 1,
			b:    2,
			sum:  1,
			mult: fieldPrimeOrder - 2,
			sub:  fieldPrimeOrder - 3,
		},
		{
			tag:  "max integer values",
			a:    (1 << 32),
			b:    (1 << 32),
			sum:  2147483615,
			mult: 484,
			sub:  0,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			ea, err := gf.CreateElement(tc.a)
			if err != nil {
				t.Fatalf("CreateElement(%d) err = %v, want nil", tc.a, err)
			}
			eb, err := gf.CreateElement(tc.b)
			if err != nil {
				t.Fatalf("CreateElement(%d) err = %v, want nil", tc.b, err)
			}
			rsum := binary.BigEndian.Uint32(ea.Add(eb).Bytes())
			rsub := binary.BigEndian.Uint32(ea.Subtract(eb).Bytes())
			rmult := binary.BigEndian.Uint32(ea.Multiply(eb).Bytes())
			if rsum != tc.sum {
				t.Errorf("%d + %d got = %d, want %d", tc.a, tc.b, rsum, tc.sum)
			}
			if rmult != tc.mult {
				t.Errorf("%d * %d got = %d, want %d", tc.a, tc.b, rmult, tc.mult)
			}
			if rsub != tc.sub {
				t.Errorf("%d - %d got = %d, want %d", tc.a, tc.b, rsub, tc.sub)
			}
		})
	}
}

func TestModularInverse(t *testing.T) {
	type testCase struct {
		tag string
		e   int
		inv uint32
	}
	gf := gf32.New()
	for _, tc := range []testCase{
		{
			tag: "identity",
			e:   1,
			inv: 1,
		},
		{
			tag: "order - 1",
			e:   fieldPrimeOrder - 1,
			inv: fieldPrimeOrder - 1,
		},
		{
			tag: "larger than order",
			e:   21474836580,
			inv: 1932735293,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			e, err := gf.CreateElement(tc.e)
			if err != nil {
				t.Fatalf("CreateElement(%d) err = %v, want nil", tc.e, err)
			}
			i, err := e.Inverse()
			if err != nil {
				t.Fatalf("e.Inverse() err = %v, want nil", err)
			}
			rinv := binary.BigEndian.Uint32(i.Bytes())
			if rinv != tc.inv {
				t.Errorf("%d ^-1 = %d, want %d", tc.e, rinv, tc.inv)
			}
		})
	}
}

func TestIdentityInverseFails(t *testing.T) {
	e, err := gf32.New().CreateElement(0)
	if err != nil {
		t.Fatalf("CreateElement(0) err = %v, want nil", err)
	}
	if _, err = e.Inverse(); err == nil {
		t.Fatalf("Inverse() err = nil, want non-nil error")
	}
}
