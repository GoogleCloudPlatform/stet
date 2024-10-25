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

// Package gf32 implements a finite field of characteristic 2^5.
package gf32

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field"
)

const (
	primeGF32   = 2147483659
	factor      = 8589934548                    // (1 << bitlen(primeGF32) * 2) // primeGF32
	barretLimit = (2147483659 * 2147483659) - 1 // primeGF32 ^ 2 - 1

	bitPerSubsecret  = 31
	elementSizeBytes = 4
)

var (
	maxGF32 = newElement(primeGF32 - 1)
)

// Element is an element in the GF32
type Element struct {
	Value uint32
}

var _ field.Element = (*Element)(nil)

func newElement(v uint32) field.Element {
	return &Element{Value: v}
}

// Add element by 'x' modulo the field order.
func (e *Element) Add(x field.Element) field.Element {
	return newElement(mod(uint64(e.Value) + uint64(x.(*Element).Value)))
}

// Subtract element by 'x' modulo the field order.
func (e *Element) Subtract(x field.Element) field.Element {
	return newElement(mod(uint64(e.Value) + primeGF32 - uint64(x.(*Element).Value)))
}

// Multiply element by 'x' modulo the field order.
func (e *Element) Multiply(x field.Element) field.Element {
	return newElement(multiplyMod(e.Value, x.(*Element).Value))
}

// Inverse returns the multiplicative inverse for an element in the field.
func (e *Element) Inverse() (field.Element, error) {
	ne, err := modInverse(e.Value)
	if err != nil {
		return nil, err
	}
	return newElement(ne), nil
}

// Flip flips a value
func (e *Element) Flip() field.Element {
	return e.Multiply(maxGF32)
}

// GT returns true if the element is greater than 'b'.
func (e *Element) GT(b field.Element) bool {
	return e.Value > b.(*Element).Value
}

// Bytes returns a big endian representation of the element value as a byte slice.
func (e *Element) Bytes() []byte {
	o := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(o, e.Value)
	return o
}

// barretReduce performs barret reduction which calculates `a mod n`
// replacing divisions by multiplications. This is advantageous because
// DIV instructions are not commonly constant time, while multiplication
// tend to be.
// For a more detailed explanation see "Handbook of Applied Cryptography",
// Chapter 14.3.3 - https://cacr.uwaterloo.ca/hac/about/chap14.pdf
//
// In a standard `a mod n` calculation barret reduction approximates 1/n
// with a value m/(2^k), division by 2^k is just a right shift.
// m/(2^k) = 1/n <-> m = (2^k) / n
func barretReduce(x uint64) uint32 {
	// This barret reduction only works for values between 0 and `n^2``, however field elements should
	// be in this range. Secrets are read in 31-bit chunks so they can't be greater than `n`. Field
	// elements get the `%` operator applied when created, but not during arithmetic operations. Hence
	// every element should be in the field and the maximum value can be (n-1)^2.
	if x > barretLimit {
		panic(fmt.Sprintf("value out of range: %d", x))
	}
	// This is equivalent to multiplication by (m/(2^k))
	// Mul64 multiplies `x` by `factor` and returns the result in two unsigned 64-bit values,
	// representing a 128-bit unsigned value. we skip multuplying by 1/(2^k), since
	// k in this case is always 64, we'll be shifting 64 bytes, which means we can just
	// ignore the lower limb.
	hi, _ := bits.Mul64(uint64(x), uint64(factor))
	t := x - (uint64(hi) * primeGF32)
	if t < primeGF32 {
		return uint32(t)
	}
	return uint32(t - primeGF32)
}

func mod(a uint64) uint32 {
	return barretReduce(a)
}

func multiplyMod(a, b uint32) uint32 {
	return mod(uint64(a) * uint64(b))
}

func modInverse(a uint32) (uint32, error) {
	if a == 0 {
		return 0, fmt.Errorf("modular inverse isn't defined for identity element")
	}
	var inverse uint32 = 1
	for exponent := primeGF32 - 2; exponent > 0; exponent >>= 1 {
		if exponent&1 == 1 {
			inverse = multiplyMod(inverse, a)
		}
		a = multiplyMod(a, a)
	}
	return inverse, nil
}

// Field is a finite field with characteristic 2^5 (GF32).
type Field struct{}

// New creates a new GF32.
func New() field.GaloisField { return &Field{} }

var _ field.GaloisField = (*Field)(nil)

func divideRoundUp(a, b int) int {
	return (a + b - 1) / b
}

// FieldID returns an ID for the specific field implemented.
func (e *Field) FieldID() finitefield.ID {
	return finitefield.GF32
}

// ElementSize returns the size in bytes of elements in the field.
func (e *Field) ElementSize() int {
	return elementSizeBytes
}

// CreateElement creates an element in the field by performing a modulo
// operation over the field order. This function isn't guaranteed to execute
// in constant time.
func (e *Field) CreateElement(o int) (field.Element, error) {
	return newElement(uint32(o % primeGF32)), nil
}

// NewRandomNonZero returns a random non-zero element in the field.
func (e *Field) NewRandomNonZero() (field.Element, error) {
	b := make([]byte, 4)
	for {
		clear(b)
		if _, err := rand.Read(b); err != nil {
			return newElement(0), fmt.Errorf("rand.Read failed: %v", err)
		}
		r := binary.BigEndian.Uint32(b)
		if r < primeGF32 && r != 0 {
			return newElement(r), nil
		}
	}
}

// ReadElement reads a field element from a byte slice, in GF32 each element
// is a uint32. The function builds an integer by taking the next 4 bytes at
// the offset and interprets them as a big endian encoded unsigned integer.
func (e *Field) ReadElement(b []byte, i int) (field.Element, error) {
	if len(b) < ((i * elementSizeBytes) + elementSizeBytes) {
		return nil, fmt.Errorf("b (len = %d), is smaller than offset %d", len(b), i)
	}
	subshare := uint32(0)
	for k := 0; k < elementSizeBytes; k++ {
		j := elementSizeBytes*i + k
		if j >= len(b) {
			break
		}
		subshare <<= 8
		subshare += uint32(b[j])
	}
	return newElement(subshare), nil
}

// EncodeElements encode field elements into a byte slice.
func (e *Field) EncodeElements(parts []field.Element, secLen int) ([]byte, error) {
	secret := make([]byte, secLen, secLen)
	bitsDone := 0
	j := len(parts) - 1

	secretParts := make([]uint32, len(parts), len(parts))
	for i, p := range parts {
		secretParts[i] = p.(*Element).Value
	}

	for i := len(secret) - 1; i >= 0 && j >= 0; i-- {
		if bitPerSubsecret-bitsDone > 8 {
			secret[i] = uint8((secretParts[j] >> bitsDone) & 0xFF)
			bitsDone += 8
		} else {
			nextLowBits := uint8(secretParts[j] >> bitsDone)
			j--
			if j >= 0 {
				secret[i] = uint8(
					secretParts[j] & (0xFF >> (bitPerSubsecret - bitsDone)))
			}
			bitsDone = (bitsDone + 8) % bitPerSubsecret
			secret[i] <<= 8 - bitsDone
			secret[i] |= nextLowBits
		}
	}
	return secret, nil
}

// DecodeElements translates the byte slice into a set of elements in
// GF32. The slice is divided into 31-bit chunks, this allows the use of unsigned
// 64-bit integer multiplication without worrying about overflowing.
func (e *Field) DecodeElements(s []byte) []field.Element {
	var bitsDone = 0
	var bitsPerSub = 31

	n := divideRoundUp(len(s)*8, bitsPerSub)
	parts := make([]uint32, n, n)

	currSub := len(parts) - 1

	for i := len(s) - 1; i >= 0; i-- {
		currByte := uint8(s[i])
		if bitsPerSub-bitsDone > 8 {
			parts[currSub] |= uint32(currByte) << bitsDone
			bitsDone += 8
			continue
		}

		currByteRight := currByte & (0xFF >> (8 - (bitsPerSub - bitsDone)))
		parts[currSub] |= uint32(currByteRight) << bitsDone

		if !(i == 0 && bitsDone+8 == bitsPerSub) {
			bitsDone = (bitsDone + 8) % bitsPerSub
			currSub--
			parts[currSub] |= uint32(currByte) >> (8 - bitsDone)
		}
	}
	out := []field.Element{}
	for _, p := range parts {
		out = append(out, newElement(p))
	}
	return out
}
