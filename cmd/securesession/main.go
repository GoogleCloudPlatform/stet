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

// Binary to demonstrate establishing a secure session with an EKM.
package main

import (
	"bytes"
	"context"
	"fmt"
	"net/url"

	"flag"
	"github.com/GoogleCloudPlatform/stet/client"
	"github.com/GoogleCloudPlatform/stet/constants"
	glog "github.com/golang/glog"
)

var (
	addr         = flag.String("addr", fmt.Sprintf("localhost:%d", constants.GrpcPort), "Service address of server")
	audience     = flag.String("audience", "", "Audience for the JWT generation")
	authToken    = flag.String("auth_token", "", "Bearer JWT for RPC requests")
	keyPath      = flag.String("key_path", "testPath", "The key path for wrapping/unwrapping")
	plaintext    = flag.String("plaintext", "foobar", "The test plaintext to wrap and unwrap")
	resourceName = flag.String("resource", "foo", "The relative resource name of the key to wrap/unwrap")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	// Generate new JWT from service account credentials if not passed via flag.
	if *authToken == "" {
		// Use host of service address as the audience for the JWT if not passed
		// in as a flag (needed when the connection is done via an IP address).
		if *audience == "" {
			u, err := url.Parse(*addr)
			if err != nil {
				glog.Exitf("Failed to parse host from address: %v", err)
			}
			*audience = u.Host
		}

		var err error
		if *authToken, err = client.GenerateJWT(ctx, *audience); err != nil {
			glog.Exitf("Failed to generate new JWT: %v", err)
		}
		glog.Infof("Generated new JWT: %v", *authToken)
	}

	glog.Infof("Attempting to connect to secure session server at %v.", *addr)
	client, err := client.EstablishSecureSession(ctx, *addr, *authToken)
	if err != nil {
		glog.Exit(fmt.Sprintf("Error establishing secure session: %v", err.Error()))
	}
	glog.Info("Established secure session")

	wrappedBlob, err := client.ConfidentialWrap(ctx, *keyPath, *resourceName, []byte(*plaintext))
	if err != nil {
		glog.Exit(fmt.Sprintf("Error calling ConfidentialWrap: %v", err.Error()))
	}

	unwrapped, err := client.ConfidentialUnwrap(ctx, *keyPath, *resourceName, wrappedBlob)
	if err != nil {
		glog.Exit(fmt.Sprintf("Error calling ConfidentialUnwrap: %v", err.Error()))
	}

	if !bytes.Equal([]byte(*plaintext), unwrapped) {
		glog.Exitf("Wrap result mismatch: expected %v, was %v", []byte(*plaintext), unwrapped)
	}

	glog.Info("Wrapped and unwrapped test plaintext")

	// Try ending the session explicitly, which confirms that the session
	// was indeed established successfully from the server's perspective.
	if err := client.EndSession(ctx); err != nil {
		glog.Exit(fmt.Sprintf("Error ending session: %v", err.Error()))
	}

	glog.Info("Ended secure session")
}
