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

// Package gf8 implements with a field with characteristic 2^8 (GF(2^8)).
package gf8

import (
	"crypto/rand"
	"fmt"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field"
)

type element byte

// Add element `a` and returns a new element in GF(2^8).
func (e element) Add(a field.Element) field.Element {
	return e ^ a.(element)
}

// Subtract element `a` and returns a new element in GF(2^8).
func (e element) Subtract(a field.Element) field.Element {
	return e.Add(a)
}

// irreducible polynomial (x^8 + x^4 + x^3 + x + 1)
// (x^8 + x^4 + x^3 + x + 1) = {0x01 0x1B}
// we deal with uint8 so we only need 0x1B
const irreduciblePolynomial = 0x1B

// Multiply by element `a` and returns a new element.
func (e element) Multiply(a field.Element) field.Element {
	// This function tries to defend against side-channel attacks
	// (timing, cache), hence avoiding pre-computed tables and branches.
	x := byte(e)
	y := byte(a.(element))

	var product uint8 = 0

	// Similar steps to:
	// https://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication
	// This code avoids branching by negating values (ex:`-foo`)
	// negating values produces a mask of either all zeros or ones
	// which allows AND operations without branching.
	//
	for i := 7; i >= 0; i-- {

		// if MSB in current product is set, mod is irreduciblePolynomial, else 0
		mod := (-(product >> 7)) & irreduciblePolynomial

		// multiply coefficient x[i] with every coefficient in y
		xiTimesY := -((x >> i) & 1) & y

		// reduce the multiplication by irreduciblePolynomial if MSB in product was
		// set and left shift product
		product = xiTimesY ^ mod ^ (product << 1)
	}
	return element(product)
}

// Inverse returns an element that's the multiplicative inverse.
// If element has no inverse, an error is returned.
func (e element) Inverse() (field.Element, error) {
	if e == 0 {
		return nil, fmt.Errorf("inverse of zero is not defined")
	}
	// we calculate the multiplicative inverse (e^-1) by computing:
	//  e^254, which in GF(2^8) is (e^-1)
	// multiplication chain reference: https://crypto.stackexchange.com/a/40140

	b := e.Multiply(e) // e^2
	c := e.Multiply(b) // e^3

	b = c.Multiply(c)         // e^6   = (e^3)^2
	b = b.Multiply(b)         // e^12  = (e^6)^2
	c = b.Multiply(c)         // e^15  = (e^12) * (e^3)
	b = b.Multiply(b)         // e^30  = (e^15)^2
	b = b.Multiply(b)         // e^60  = (e^30)^2
	b = b.Multiply(c)         // e^63  = (e^60) * (e^3)
	b = b.Multiply(b)         // e^126 = (e^63)^2
	b = e.Multiply(b)         // e^127 = (e^126) * e
	return b.Multiply(b), nil // e^254 = (e^127)^2
}

// GT returns true if element is greater than 'b'.
func (e element) GT(b field.Element) bool {
	return e > b.(element)
}

// Bytes returns a big endian representation of the element value as a byte array.
func (e element) Bytes() []byte {
	return []byte{byte(e)}
}

// Flip is needed in circumstances where substraction is done over two elements based on which is
// larger, and then a flip is get the equivalent value. In other fields, this requires multiplication
// by the field order. In GF(2^8), addition and substraction are the same operation (xor), hence this isn't necessary.
func (e element) Flip() field.Element {
	return e
}

type gf8Field struct{}

// New creates a new GF8.
func New() field.GaloisField { return &gf8Field{} }

var _ field.GaloisField = (*gf8Field)(nil)

// CreateElement creates a new field element from an integer.
// Returns an error when i is larger than the largest uint8 (255).
func (e *gf8Field) CreateElement(i int) (field.Element, error) {
	if i > 255 {
		return nil, fmt.Errorf("field element can't be larger than %d bytes", e.ElementSize())
	}
	return element(i), nil
}

// NewRandomNonZero generates a random element inside the field.
// The random element is assumed to be good enough for cryptographic purposes.
func (e *gf8Field) NewRandomNonZero() (field.Element, error) {
	b := make([]byte, 1)
	for {
		clear(b)
		if _, err := rand.Read(b); err != nil {
			return element(0), fmt.Errorf("rand.Read failed: %v", err)
		}
		if b[0] != 0 {
			return element(b[0]), nil
		}
	}
}

// ReadElement reads an element from a big endian encoded byte array `b` at an offset `i`.
func (e *gf8Field) ReadElement(b []byte, i int) (field.Element, error) {
	if len(b) < i {
		return element(0), fmt.Errorf("b (len = %d), is smaller than offset %d", len(b), i)
	}
	return element(b[i]), nil
}

// EncodeElements encodes a set of field elements into a byte array of size `secLen` .
func (e *gf8Field) EncodeElements(parts []field.Element, secLen int) ([]byte, error) {
	if secLen != len(parts) {
		return nil, fmt.Errorf("can't encode elements (len = %d) into secret len (%d)", len(parts), secLen)
	}
	elems := make([]byte, secLen, secLen)
	for i, e := range parts {
		elems[i] = byte(e.(element))
	}
	return elems, nil
}

// DecodeElements decodes a byte array into a set of elements in GF(2^8).
func (e *gf8Field) DecodeElements(in []byte) []field.Element {
	elems := make([]field.Element, len(in))
	for i, b := range in {
		elems[i] = element(b)
	}
	return elems
}

func (e *gf8Field) ElementSize() int {
	return 1
}

func (e *gf8Field) FieldID() finitefield.ID {
	return finitefield.GF8
}
