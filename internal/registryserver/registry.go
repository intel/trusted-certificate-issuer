/*
Copyright 2022.

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

package registryserver

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	pluginapi "github.com/intel/trusted-certificate-issuer/api/plugin/v1alpha1"
	grpcserver "github.com/intel/trusted-certificate-issuer/internal/grpc-server"
	"google.golang.org/grpc"
	"k8s.io/klog/v2/klogr"
)

type PluginRegistry struct {
	*grpcserver.GrpcServer
	log     logr.Logger
	plugins map[string]*plugin
	lock    sync.Mutex
}

func NewPluginRegistry(socketPath string) (*PluginRegistry, error) {
	registry := &PluginRegistry{
		log:     klogr.New().WithName("plugin-registry"),
		plugins: map[string]*plugin{},
	}
	registry.log.Info("Starting server...", "socketPath", socketPath)
	s, err := grpcserver.NewSever(socketPath, registry)
	if err != nil {
		return nil, err
	}
	registry.GrpcServer = s

	return registry, nil
}

func (registry *PluginRegistry) RegisterService(s *grpc.Server) {
	pluginapi.RegisterRegistryServer(s, registry)
}

func (registry *PluginRegistry) RegisterPlugin(ctx context.Context, req *pluginapi.RegisterPluginRequest) (*pluginapi.RegisterKeyServerReply, error) {
	registry.lock.Lock()
	defer registry.lock.Unlock()

	l := registry.log.WithValues("req", req)

	p, ok := registry.plugins[req.Name]
	if ok {
		if p.socketPath == req.Address {
			// Nothing new, just ignore the call
			return &pluginapi.RegisterKeyServerReply{}, nil
		}
		if p.cc != nil {
			// close existing connection
			p.cc.Close()
		}
		delete(registry.plugins, req.Name)
	}

	l.Info("Registering...")

	cc, err := grpc.DialContext(ctx, "unix://"+req.Address, grpc.WithInsecure())
	if err != nil {
		l.V(2).Info("failed to dial plugin", "err", err)
		return nil, err
	}

	registry.plugins[req.Name] = &plugin{
		name:       req.Name,
		socketPath: req.Address,
		cc:         cc,
	}
	l.Info("Registered!")
	return &pluginapi.RegisterKeyServerReply{}, nil
}

func (registry *PluginRegistry) GetPlugin(name string) pluginapi.Plugin {
	registry.lock.Lock()
	defer registry.lock.Unlock()
	plugin, ok := registry.plugins[name]
	if !ok {
		return nil
	}
	return plugin
}

func (registry *PluginRegistry) GetPluginNames() []string {
	registry.lock.Lock()
	defer registry.lock.Unlock()
	names := []string{}
	for _, info := range registry.plugins {
		names = append(names, info.Name())
	}
	return names
}

type plugin struct {
	name       string
	socketPath string
	cc         *grpc.ClientConn
}

var _ pluginapi.Plugin = &plugin{}

func (ks *plugin) Name() string {
	if ks == nil {
		return ""
	}
	return ks.name
}

func (ks *plugin) Endpoint() string {
	if ks == nil {
		return ""
	}
	return ks.socketPath
}

func (ks *plugin) IsReady() bool {
	return ks != nil && ks.cc != nil
}

func (ks *plugin) GetCASecret(ctx context.Context, signerName string, quote []byte, publicKey []byte) ([]byte, []byte, error) {
	if !ks.IsReady() {
		return nil, nil, fmt.Errorf("%s: server is not ready", ks.name)
	}

	client := pluginapi.NewPluginClient(ks.cc)
	res, err := client.GetCASecret(ctx, &pluginapi.GetCASecretRequest{
		SignerName: signerName,
		Quote:      quote,
		PublicKey:  publicKey,
	})
	if err != nil {
		return nil, nil, err
	}

	return res.WrappedKey, res.Certificate, nil
}
