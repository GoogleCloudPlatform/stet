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

// Package finitefield represents the finite fields supported by the secret sharing library.
package finitefield

import "fmt"

// ID represents a finite field supported by the secret sharing library.
type ID int

const (
	// GF32 is a Galois Field with characteristic 2^5.
	GF32 ID = 1 + iota
	// GF8 is a Galois Field with characteristic 2^8.
	GF8
)

func (id ID) String() string {
	switch id {
	case GF8:
		return "GF8"
	case GF32:
		return "GF32"
	default:
		return fmt.Sprintf("unknown finite field ID: %d", id)
	}
}
