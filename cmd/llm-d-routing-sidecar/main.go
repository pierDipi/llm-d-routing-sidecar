/*
Copyright 2025 IBM.

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
	"net/url"

	"k8s.io/klog/v2"

	"github.com/llm-d/llm-d-routing-sidecar/internal/proxy"
	"github.com/llm-d/llm-d-routing-sidecar/internal/signals"
)

func main() {
	var (
		port              string
		vLLMPort          string
		connector         string
		serverTLSEnabled  bool
		serverTLSCertFile string
		serverTLSKeyFile  string
		clientTLSEnabled  bool
		clientTLSInsecure bool
		clientTLSCACert   string
		clientTLSCert     string
		clientTLSKey      string
		// Legacy flag for backward compatibility
		prefillerUseTLS bool
	)

	flag.StringVar(&port, "port", "8000", "the port the sidecar is listening on")
	flag.StringVar(&vLLMPort, "vllm-port", "8001", "the port vLLM is listening on")
	flag.StringVar(&connector, "connector", "nixl", "the P/D connector being used. Either nixl, nixlv2 or lmcache")
	flag.BoolVar(&serverTLSEnabled, "server-tls", false, "enable TLS/HTTPS serving")
	flag.StringVar(&serverTLSCertFile, "server-tls-cert", "", "path to server TLS certificate file (optional, will generate self-signed if not provided)")
	flag.StringVar(&serverTLSKeyFile, "server-tls-key", "", "path to server TLS private key file (optional, will generate self-signed if not provided)")
	flag.BoolVar(&clientTLSEnabled, "client-tls", false, "enable TLS for outbound connections to prefiller and decoder services")
	flag.BoolVar(&clientTLSInsecure, "client-tls-insecure", false, "skip TLS certificate verification for outbound connections (dev/testing only)")
	flag.StringVar(&clientTLSCACert, "client-tls-ca-cert", "", "path to CA certificate for verifying outbound TLS connections")
	flag.StringVar(&clientTLSCert, "client-tls-cert", "", "path to client certificate for mutual TLS authentication")
	flag.StringVar(&clientTLSKey, "client-tls-key", "", "path to client private key for mutual TLS authentication")
	// Legacy flag for backward compatibility
	flag.BoolVar(&prefillerUseTLS, "prefiller-use-tls", false, "whether to use TLS when sending requests to prefillers (legacy, use --client-tls instead)")
	klog.InitFlags(nil)
	flag.Parse()

	// make sure to flush logs before exiting
	defer klog.Flush()

	ctx := signals.SetupSignalHandler(context.Background())
	logger := klog.FromContext(ctx)

	if connector != proxy.ConnectorNIXLV1 && connector != proxy.ConnectorNIXLV2 && connector != proxy.ConnectorLMCache {
		logger.Info("Error: --connector must either be 'nixl', 'nixlv2' or 'lmcache'")
		return
	}
	logger.Info("p/d connector validated", "connector", connector)

	// Handle legacy flag
	if prefillerUseTLS {
		clientTLSEnabled = true
		clientTLSInsecure = true // Assume insecure for legacy compatibility
		logger.Info("Legacy --prefiller-use-tls flag detected, enabling client TLS with insecure mode")
	}

	// Validate server TLS configuration
	if serverTLSEnabled {
		if (serverTLSCertFile == "" && serverTLSKeyFile != "") || (serverTLSCertFile != "" && serverTLSKeyFile == "") {
			logger.Info("Error: both --server-tls-cert and --server-tls-key must be provided together, or neither (for self-signed)")
			return
		}
		logger.Info("Server TLS enabled", "certFile", serverTLSCertFile, "keyFile", serverTLSKeyFile)
	}

	// Validate client TLS configuration
	if clientTLSEnabled {
		if (clientTLSCert == "" && clientTLSKey != "") || (clientTLSCert != "" && clientTLSKey == "") {
			logger.Info("Error: both --client-tls-cert and --client-tls-key must be provided together for mutual TLS")
			return
		}
		logger.Info("Client TLS enabled", "insecure", clientTLSInsecure, "clientCert", clientTLSCert, "clientKey", clientTLSKey, "caCert", clientTLSCACert)
	}

	// Configure TLS
	var tlsConfig *proxy.TLSConfig
	if serverTLSEnabled || clientTLSEnabled {
		tlsConfig = &proxy.TLSConfig{
			// Server-side TLS
			Enabled:  serverTLSEnabled,
			CertFile: serverTLSCertFile,
			KeyFile:  serverTLSKeyFile,
			// Client-side TLS
			ClientTLSEnabled: clientTLSEnabled,
			ClientInsecure:   clientTLSInsecure,
			ClientCACert:     clientTLSCACert,
			ClientCert:       clientTLSCert,
			ClientKey:        clientTLSKey,
		}
	}

	// start reverse proxy HTTP server
	targetURL, err := url.Parse("http://localhost:" + vLLMPort)
	if err != nil {
		logger.Error(err, "Failed to create targetURL")
		return
	}

	proxy := proxy.NewProxy(port, targetURL, connector, tlsConfig)
	if err := proxy.Start(ctx); err != nil {
		logger.Error(err, "Failed to start proxy server")
	}
}
