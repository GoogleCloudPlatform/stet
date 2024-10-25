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

// Package shamirgeneric implements shamir secret sharing with a generic group structure.
package shamirgeneric

import (
	"fmt"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/secrets"
)

// SplitSecret splits a secret into n shares where t or more shares can be combined to reconstruct
// the original secret using shamir secret sharing.
func SplitSecret(metadata secrets.Metadata, secret []byte, gf field.GaloisField) (secrets.Split, error) {
	if err := validateSplitInput(metadata, secret, gf); err != nil {
		return secrets.Split{}, err
	}
	threshold := metadata.Threshold
	numShares := metadata.NumShares
	// The `secret` can be an arbitrary length byte array, but each element in a field is of
	// a finite size, hence the `secret` is split into a set of elements in the field.
	subsecrets := gf.DecodeElements(secret)
	shares := make([]secrets.Share, numShares)

	// For each subsecret we build a polynomial of degree N, where N is `threshold`.
	// Each subsecret is the constant coefficient in the polynomial and every other coefficient
	// is selected as a random field element:
	// subsecret + R_1 * x^1 + R_2 * X^2 + ... + R_N * X^N
	for _, subsecret := range subsecrets {
		coefficients := make([]field.Element, threshold, threshold)
		coefficients[0] = subsecret
		for i := 1; i < threshold; i++ {
			var err error
			if coefficients[i], err = gf.NewRandomNonZero(); err != nil {
				return secrets.Split{}, err
			}
		}
		for i := 0; i < numShares; i++ {
			// We create each sub-share by evaluating each polynomial for a subsecret
			// at a specific value `X`, this gives us the point (X, Y).
			xi, err := gf.CreateElement(i + 1)
			if err != nil {
				return secrets.Split{}, err
			}
			subshare, err := evaluatePolynomial(coefficients, xi, gf)
			if err != nil {
				return secrets.Split{}, err
			}
			// shares is a set of encoded field elements. Each field element is the evaluation of a
			// different polynomial where the constant term of each polynomial represents a subsecrets.
			// shares[0] = 			[ F1(1), F2(1), ..., FN(1) ]
			// shares[1] = 			[ F1(2), F2(2), ..., FN(2) ]
			// shares[N - 1] = 	[ F1(N), F2(N), ..., FN(N) ]
			shares[i].Value = append(shares[i].Value, subshare.Bytes()...)
			shares[i].X = i + 1
		}
	}
	return secrets.Split{
		Shares:    shares,
		Metadata:  metadata,
		SecretLen: len(secret),
	}, nil
}

// evaluates a polynomial at `x` where `coefficients` take the form:
// f(x) = c[n-1] * x^(n-1) + c[n-2] * x^(n-2) + ... + c[1] * x^1 + c[0]
// Evaluation assumes no coefficient is zero and performs all arithmetic
// over a finite field.
func evaluatePolynomial(coefficients []field.Element, x field.Element, gf field.GaloisField) (field.Element, error) {
	sum, err := gf.CreateElement(0)
	if err != nil {
		return nil, err
	}
	for i := len(coefficients) - 1; i > 0; i-- {
		sum = sum.Add(coefficients[i]).Multiply(x)
	}
	return sum.Add(coefficients[0]), nil
}

// Reconstruct reconstructs a secret with at least t out of n shares using shamir secret sharing.
func Reconstruct(splitSecret secrets.Split, gf field.GaloisField) ([]byte, error) {
	if err := validateReconstructInput(splitSecret); err != nil {
		return nil, err
	}
	// We only need `threshold` shares to reconstruct the secrets.
	shares := splitSecret.Shares[:splitSecret.Metadata.Threshold]
	xVals := []field.Element{}
	for _, s := range shares {
		xi, err := gf.CreateElement(s.X)
		if err != nil {
			return nil, err
		}
		xVals = append(xVals, xi)
	}
	// Precompute the Lagrange coefficients before performing polynomial interpolation.
	// The output to this step could be kept in memory, but it would require making
	// this implementation thread safe.
	coefficients, err := lagrangeCoefficients(xVals, gf)
	if err != nil {
		return nil, err
	}
	// Calculate the number of field elements per secret share based on the share size.
	var numSubSecrets = len(shares[0].Value) / gf.ElementSize()
	subsecrets := make([]field.Element, numSubSecrets, numSubSecrets)
	for i := 0; i < numSubSecrets; i++ {
		yVals := make([]field.Element, len(xVals))

		for j, s := range shares {
			yVals[j], err = gf.ReadElement(s.Value, i)
			if err != nil {
				return nil, err
			}
		}
		// interpolatePolynomial recovers the C[0] coefficient, the geometric interpretation
		// of the intersection with the Y axis.
		subsecrets[i], err = interpolatePolynomial(coefficients, yVals, gf)
		if err != nil {
			return nil, err
		}
	}
	// combine the subsecret field elements into the original secrets.
	return gf.EncodeElements(subsecrets, splitSecret.SecretLen)
}

// performs lagrange polynomial interpolation to recover a polynomial from a set of points.
// receives a set of points on a finite field:
// ∑i={1,n} y[i] * ( ∏j={1,n,j≠i} ( (x[j]) / ( x[j] - x[i]) ) )
// lagrange coefficients (∏j={1,n,j≠i} ( (x[j]) / ( x[j] - x[i] ) )) are precalculated
// and the y coordinates are used to compute the sum. This function assumes, no coefficient is zero.
func interpolatePolynomial(lagCoeff []field.Element, yVals []field.Element, gf field.GaloisField) (field.Element, error) {
	if len(lagCoeff) != len(yVals) {
		return nil, fmt.Errorf("invalid lagrange coefficients")
	}
	sum, err := gf.CreateElement(0)
	if err != nil {
		return nil, err
	}
	// ∑i={1,n} y[i] * lagrange_coefficient[i]
	for i, y := range yVals {
		sum = sum.Add(y.Multiply(lagCoeff[i]))
	}
	return sum, nil
}

// recovers the coefficients to perform lagrange polynomial interpolation using the x coordinates.
// ∏j={1,n,j≠i} ( (x[j]) / ( x[j] - x[i] ) )
func lagrangeCoefficients(x []field.Element, gf field.GaloisField) ([]field.Element, error) {
	if len(x) < 2 {
		return nil, fmt.Errorf("must have at least 2 values")
	}
	out := []field.Element{}
	for i := 0; i < len(x); i++ {
		one, err := gf.CreateElement(1)
		if err != nil {
			return nil, err
		}
		out = append(out, one)
		for j := 0; j < len(x); j++ {
			if i == j {
				continue
			}
			if x[i] == x[j] {
				return nil, fmt.Errorf("all shares should be unique point")
			}
			out[i] = out[i].Multiply(x[j])
			// Perform ( x[j] * ( x[j] - x[i] )^-1 )
			// if x[j] > x[i]: (x[j] - x[i])^-1 * out[i]
			// if x[j] < x[i]  ((x[i] - x[j])^-1 * out[i]) - 1 mod FieldOrder
			x1, x2 := x[j], x[i]
			if !x[j].GT(x[i]) {
				x1, x2 = x[i], x[j]
				out[i] = out[i].Flip()
			}
			diff, err := x1.Subtract(x2).Inverse()
			if err != nil {
				return nil, err
			}
			out[i] = out[i].Multiply(diff)
		}
	}
	return out, nil
}

func validateSplitInput(metadata secrets.Metadata, secret []byte, gf field.GaloisField) error {
	if len(secret) == 0 {
		return fmt.Errorf("secret must not be nil")
	}
	if metadata.NumShares < 2 {
		return fmt.Errorf("numShares must be larger than 1")
	}
	if metadata.Threshold < 2 {
		return fmt.Errorf("threshold must be larger than 1")
	}
	if metadata.Threshold > metadata.NumShares {
		return fmt.Errorf("threshold should be smaller than or equal to numShares")
	}
	if metadata.Field != gf.FieldID() {
		return fmt.Errorf("field ID mismatch")
	}
	return nil
}

func validateReconstructInput(splitSecret secrets.Split) error {
	if splitSecret.Metadata.Threshold < 2 {
		return fmt.Errorf("threshold should be at least 2")
	}
	if splitSecret.Metadata.NumShares < splitSecret.Metadata.Threshold {
		return fmt.Errorf("threshold larger than number of shares")
	}
	if len(splitSecret.Shares) < splitSecret.Metadata.Threshold {
		return fmt.Errorf("not enough shares to reconstruct the secret, need at least %d, got: %d", len(splitSecret.Shares), splitSecret.Metadata.Threshold)
	}
	for _, s := range splitSecret.Shares {
		if s.X == 0 {
			return fmt.Errorf("invalid X value")
		}
		if len(s.Value) == 0 {
			return fmt.Errorf("empty secret value")
		}
	}
	return nil
}
