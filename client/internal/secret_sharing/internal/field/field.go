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

// Package field defines a generic definition of a finite field.
package field

import "github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"

// Element is an element in a Finite Field
type Element interface {
	// Add element `a` and returns a new element.
	Add(a Element) Element
	// Subtract element `a` and returns a new element.
	Subtract(a Element) Element
	// Multiply by element `a` and returns a new element.
	Multiply(a Element) Element
	// Inverse returns an element that's the multiplicative inverse.
	// If element has no inverse, an error is returned.
	Inverse() (Element, error)
	// GT returns true if the element `b` is greater than.
	GT(b Element) bool
	// Bytes returns the element in a big endian encoded byte representation.
	Bytes() []byte
	// Flip flips an element by multiplying the element by the group order,
	// Flip is only required if the order of elements in substraction affects the result, hence some
	// fields might return the same element.
	Flip() Element
}

// GaloisField represents a Finite Field.
type GaloisField interface {
	// CreateElement creates a new field element from i. The value of i should be within the range
	// of unsigned integers that can be stored in a byte array of length ElementSize().
	CreateElement(i int) (Element, error)
	// NewRandomNonZero generates a random element inside the field.
	// The random element is assumed to be good enough for cryptographic purposes.
	NewRandomNonZero() (Element, error)
	// ReadElement reads an element from a big endian encoded byte slice b at an offset i.
	ReadElement(b []byte, i int) (Element, error)
	// EncodeElements encodes a set of field elements into a byte slice of size secLen.
	// The output of this function can be passed to DecodeElements() to recreate the elements.
	EncodeElements(parts []Element, secLen int) ([]byte, error)
	// DecodeElements creates a set of field elements from a byte slice.
	// Expects the output of EncodeElements().
	DecodeElements([]byte) []Element
	// ElementSize returns the size of each element in bytes.
	ElementSize() int
	// FieldID returns a unique identifier for the field.
	FieldID() finitefield.ID
}
