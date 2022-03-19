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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	pluginapi "github.com/intel/trusted-certificate-issuer/api/plugin/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/plugins/kmra/client"
	"github.com/intel/trusted-certificate-issuer/plugins/kmra/plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"k8s.io/klog/v2/klogr"
)

func main() {
	var socketPath string
	var pluginName string
	//	var registrationPath string
	var controllerEndpoint string
	flag.StringVar(&pluginName, "plugin-name", "kmra", "Name of the plugin.")
	flag.StringVar(&socketPath, "plugin-endpoint", "/kmra.sock", "The address the key server endpoint binds to.")
	flag.StringVar(&controllerEndpoint, "registry-endpoint", "/registration/registry.sock", "Plugin registration server socket path.")
	flag.Parse()

	l := klogr.New().WithName("setup")

	keyServerAddr := os.Getenv("KEY_SERVER")
	if keyServerAddr == "" {
		l.Error(fmt.Errorf("no key server configured"), "set via KEY_SERVER environment.")
		os.Exit(1)
	}

	plugin, err := plugin.NewPlugin(pluginName, socketPath, &client.Config{
		KMHost:     keyServerAddr,
		CaCert:     "/certs/ca.crt",
		ClientCert: "/certs/client.crt",
		ClientKey:  "/certs/client.key",
	})
	if err != nil {
		l.Error(err, "Failed to initialize plugin", "serverAddress", keyServerAddr)
		os.Exit(-1)
	}
	plugin.Start()

	ctx, cancelRegistration := context.WithCancel(context.TODO())
	go registerPlugin(ctx, l, pluginName, socketPath, controllerEndpoint)

	plugin.Wait()
	plugin.Stop()

	cancelRegistration()
}

func registerPlugin(ctx context.Context, l logr.Logger, pluginName, socketPath, controllerSocketPath string) {
	success := false
	retryTimeout := time.Minute
	var conn *grpc.ClientConn
	for {
		var err error
		if conn != nil && conn.GetState() == connectivity.Ready {
			break
		}
		l.Info("Connecting to registry server...", "at", controllerSocketPath)
		conn, err = grpc.DialContext(ctx, "unix://"+controllerSocketPath, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			l.V(4).Error(err, "failed to connect controller socket, will retry", "after", retryTimeout)
			time.Sleep(retryTimeout)
			continue
		}
	}
	defer conn.Close()

	client := pluginapi.NewRegistryClient(conn)
	for {
		if success {
			return
		}
		l.Info("Registering the plugin...", "name", pluginName, "socket", socketPath)
		_, err := client.RegisterPlugin(ctx, &pluginapi.RegisterPluginRequest{
			Name:    pluginName,
			Address: socketPath,
		})
		if err != nil {
			l.V(3).Error(err, "Failed to register plugin socket, will retry", "after", retryTimeout)
			time.Sleep(retryTimeout)
			continue
		}
		l.Info("Registration success!!!")
		success = true
	}
}
