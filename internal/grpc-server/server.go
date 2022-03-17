/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package grpcserver

import (
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"k8s.io/klog/v2/klogr"
)

type Service interface {
	// RegisterService exposes the service over the grpc server
	RegisterService(server *grpc.Server)
}

// GrpcSErver is a wait group with a grpc server
type GrpcServer struct {
	sync.WaitGroup
	server   *grpc.Server
	listener net.Listener
}

func NewSever(socketPath string, services ...Service) (*GrpcServer, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("empty socket path")
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove existing socket file: %v", err)
	}

	oldMask := unix.Umask(0077)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen at address '%s': %v", socketPath, err)
	}
	unix.Umask(oldMask)
	server := &GrpcServer{
		listener: l,
		server:   grpc.NewServer(),
	}

	for _, svc := range services {
		svc.RegisterService(server.server)
	}

	return server, nil
}

func (s *GrpcServer) Start() {
	s.Add(1)
	go func() {
		defer s.Done()
		if err := s.server.Serve(s.listener); err != nil {
			klogr.New().WithName("blocking-server").V(2).Error(err, "failed to start")
		}
	}()
}

func (s *GrpcServer) Stop() {
	s.Done()
	s.server.GracefulStop()
}
