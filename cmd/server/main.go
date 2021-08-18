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

// Reference server binary.
package main

import (
	"fmt"
	"net"

	"flag"
	"github.com/GoogleCloudPlatform/stet/constants"
	cwgrpc "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	ssgrpc "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"github.com/GoogleCloudPlatform/stet/server"
	glog "github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	port = flag.Int("port", constants.SrvPort, "service port")
)

func main() {
	flag.Parse()

	// Listen for connections on *port.
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
		return
	}

	grpcServer := grpc.NewServer()

	reflection.Register(grpcServer)

	// Register a new SecureSessionService instance to handle RPCs.
	serv, _ := server.NewSecureSessionService()
	ssgrpc.RegisterConfidentialEkmSessionEstablishmentServiceServer(grpcServer, serv)
	cwgrpc.RegisterConfidentialWrapUnwrapServiceServer(grpcServer, serv)
	glog.Infof("Starting SecureSession server on port %v.", *port)
	grpcServer.Serve(lis)
}
