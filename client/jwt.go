// Copyright 2021 Google LLC
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

// Utility functions for generating JWTs from a service account.

package client

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/iam/credentials/apiv1"
	"golang.org/x/oauth2/google"

	iamcredspb "google.golang.org/genproto/googleapis/iam/credentials/v1"
)

const (
	googleCredsEnvVar    string = "GOOGLE_APPLICATION_CREDENTIALS"
	instanceIdentityURL  string = "instance/service-accounts/default/identity?audience=%v&format=full"
	serviceAccountPrefix string = "projects/-/serviceAccounts/"
)

// instanceIdentityToken returns the instance identity token obtained by
// querying the metadata server on a GCE VM. See:
// https://cloud.google.com/compute/docs/instances/verifying-instance-identity
func instanceIdentityToken(audience string) (string, error) {
	// The metadata package doesn't have a convenient getter method to grab
	// the instance identity token, so format the URL manually and use .Get().
	return metadata.Get(fmt.Sprintf(instanceIdentityURL, audience))
}

// Generates an JWT with the FQDN of the given address as its audience.
func generateTokenFromEKMAddress(ctx context.Context, address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("could not parse EKM address: %v", err)
	}

	audience := fmt.Sprintf("%v://%v", u.Scheme, u.Hostname())

	var authToken string
	if authToken, err = GenerateJWT(ctx, audience); err != nil {
		return "", fmt.Errorf("failed to generate JWT: %v", err)
	}

	return authToken, nil
}

// GenerateJWT returns a signed JWT derived from a Google service account.
// By default, it will generate it based on the service account key defined
// in the GOOGLE_APPLICATION_CREDENTIALS environment variable. If not, it
// will assume we are running in a GCE VM, and attempt to use the default
// service account credentials to generate the JWT instead.
func GenerateJWT(ctx context.Context, audience string) (string, error) {
	// First, check to see if the GOOGLE_APPLICATION_CREDENTIALS environment
	// variable has been set. If so, we can assume we are running on either
	// an on-prem environment (ie. not in GCE), or alternatively, we *are*
	// running in a GCE VM, but the user has chosen to override the default
	// service account with explicit credentials from another account. In
	// either case, we want to use this private key file to generate our JWT.
	if saKeyFile := os.Getenv(googleCredsEnvVar); saKeyFile != "" {
		// Read the service account file manually, as we need the email.
		sa, err := os.ReadFile(saKeyFile)
		if err != nil {
			return "", fmt.Errorf("failed to read service account file: %v", err)
		}

		conf, err := google.JWTConfigFromJSON(sa)
		if err != nil {
			return "", fmt.Errorf("could not parse service account JSON: %v", err)
		}

		// Request an OIDC token from IAM. Creating a new IAM credentials client
		// implicitly will look for the private key file specified in the
		// GOOGLE_APPLICATION_CREDENTIALS env var, so we don't need to pass
		// option.WithCredentials(saKeyFile) as an argument here.
		c, err := credentials.NewIamCredentialsClient(ctx)
		if err != nil {
			return "", fmt.Errorf("could not create a new IAM credentials client: %v", err)
		}
		defer c.Close()

		resp, err := c.GenerateIdToken(ctx, &iamcredspb.GenerateIdTokenRequest{
			Name:         serviceAccountPrefix + conf.Email,
			Audience:     audience,
			IncludeEmail: true,
		})

		if err != nil {
			return "", fmt.Errorf("error generating ID token: %v", err)
		}

		return resp.GetToken(), nil
	}

	// Otherwise, if we're not running in a GCE VM, we can't generate a signed
	// JWT from a service account, so return an error.
	if !metadata.OnGCE() {
		return "", fmt.Errorf("could not find GOOGLE_APPLICATION_CREDENTIALS and not running on GCE")
	}

	return instanceIdentityToken(audience)
}
