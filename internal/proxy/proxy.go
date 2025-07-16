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

package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	lru "github.com/hashicorp/golang-lru/v2"
	"k8s.io/klog/v2"
)

const (
	requestHeaderPrefillURL      = "x-prefiller-url"
	requestHeaderPrefillHostPort = "x-prefiller-host-port"
	requestHeaderRequestID       = "x-request-id"

	requestFieldKVTransferParams = "kv_transfer_params"
	requestFieldMaxTokens        = "max_tokens"
	requestFieldDoRemotePrefill  = "do_remote_prefill"
	requestFieldDoRemoteDecode   = "do_remote_decode"
	requestFieldRemoteBlockIDs   = "remote_block_ids"
	requestFieldRemoteEngineID   = "remote_engine_id"
	requestFieldRemoteHost       = "remote_host"
	requestFieldRemotePort       = "remote_port"
	requestFieldStream           = "stream"
	requestFieldStreamOptions    = "stream_options"

	// ConnectorNIXLV1 enables the (now deprecated) P/D NIXL v1 protocol
	ConnectorNIXLV1 = "nixl"

	// ConnectorNIXLV2 enables the P/D NIXL v2 protocol
	ConnectorNIXLV2 = "nixlv2"

	// ConnectorLMCache enables (now deprecated) P/D LMCache protocol
	ConnectorLMCache = "lmcache"
)

type protocolRunner func(http.ResponseWriter, *http.Request, string)

// TLSConfig holds TLS configuration options
type TLSConfig struct {
	// Server-side TLS configuration
	Enabled  bool
	CertFile string
	KeyFile  string
	CertPEM  []byte
	KeyPEM   []byte

	// Client-side TLS configuration
	ClientTLSEnabled bool
	ClientInsecure   bool   // Skip TLS verification for client connections
	ClientCACert     string // Path to CA certificate for client connections
	ClientCert       string // Path to client certificate
	ClientKey        string // Path to client private key
}

// Server is the reverse proxy server
type Server struct {
	logger               logr.Logger
	addr                 net.Addr       // the proxy TCP address
	port                 string         // the proxy TCP port
	decoderURL           *url.URL       // the local decoder URL
	decoderProxy         http.Handler   // decoder proxy handler
	runConnectorProtocol protocolRunner // the handler for running the protocol
	prefillerURLPrefix   string
	prefillerProxies     *lru.Cache[string, http.Handler] // cached prefiller proxy handlers
	tlsConfig            *TLSConfig                       // TLS configuration
}

// NewProxy creates a new routing reverse proxy
func NewProxy(port string, decodeURL *url.URL, connector string, tlsConfig ...*TLSConfig) *Server {
	cache, _ := lru.New[string, http.Handler](16) // nolint:all

	var tls *TLSConfig
	if len(tlsConfig) > 0 {
		tls = tlsConfig[0]
	}

	server := &Server{
		port:               port,
		decoderURL:         decodeURL,
		prefillerProxies:   cache,
		prefillerURLPrefix: "http://",
		tlsConfig:          tls,
	}
	switch connector {
	case ConnectorLMCache:
		server.runConnectorProtocol = server.runLMCacheProtocol
	case ConnectorNIXLV1:
		server.runConnectorProtocol = server.runNIXLProtocolV1
	case ConnectorNIXLV2:
		fallthrough
	default:
		server.runConnectorProtocol = server.runNIXLProtocolV2
	}

	if tls != nil && tls.ClientTLSEnabled {
		server.prefillerURLPrefix = "https://"
	}

	return server
}

// CreateSelfSignedTLSCertificate creates a self-signed cert the server can use to serve TLS.
func CreateSelfSignedTLSCertificate(logger logr.Logger) (tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creating serial number: %v", err)
	}
	now := time.Now()
	notBefore := now.UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Inference Ext"},
		},
		NotBefore:             notBefore,
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10).UTC(), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generating key: %v", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creating certificate: %v", err)
	}

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error marshalling private key: %v", err)
	}
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certBytes, keyBytes)
}

// Start the HTTP reverse proxy.
func (s *Server) Start(ctx context.Context) error {
	logger := klog.FromContext(ctx).WithName("proxy server")
	s.logger = logger

	ln, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		logger.Error(err, "Failed to start")
		return err
	}
	s.addr = ln.Addr()

	// Configure handlers
	mux := s.createRoutes()

	server := &http.Server{Handler: mux}

	// Configure TLS if enabled
	if s.tlsConfig != nil && s.tlsConfig.Enabled {
		var cert tls.Certificate

		if s.tlsConfig.CertPEM != nil && s.tlsConfig.KeyPEM != nil {
			// Use provided certificate and key
			cert, err = tls.X509KeyPair(s.tlsConfig.CertPEM, s.tlsConfig.KeyPEM)
			if err != nil {
				logger.Error(err, "Failed to load TLS certificate from PEM data")
				return err
			}
			logger.Info("using provided TLS certificate")
		} else if s.tlsConfig.CertFile != "" && s.tlsConfig.KeyFile != "" {
			// Load certificate and key from files
			cert, err = tls.LoadX509KeyPair(s.tlsConfig.CertFile, s.tlsConfig.KeyFile)
			if err != nil {
				logger.Error(err, "Failed to load TLS certificate from files")
				return err
			}
			logger.Info("using TLS certificate from files", "certFile", s.tlsConfig.CertFile, "keyFile", s.tlsConfig.KeyFile)
		} else {
			// Generate self-signed certificate
			cert, err = CreateSelfSignedTLSCertificate(logger)
			if err != nil {
				logger.Error(err, "Failed to generate self-signed certificate")
				return err
			}
			logger.Info("using generated self-signed certificate")
		}

		// Configure TLS
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
	}

	// Setup graceful termination (not strictly needed for sidecars)
	go func() {
		<-ctx.Done()
		logger.Info("shutting down")

		ctx, cancelFn := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancelFn()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error(err, "Failed to gracefully shutdown")
		}
	}()

	// Start server with or without TLS
	if s.tlsConfig != nil && s.tlsConfig.Enabled {
		logger.Info("starting with TLS", "addr", s.addr.String())
		if err := server.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			logger.Error(err, "Failed to start TLS server")
			return err
		}
	} else {
		logger.Info("starting without TLS", "addr", s.addr.String())
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error(err, "Failed to start server")
			return err
		}
	}

	return nil
}

func (s *Server) createRoutes() *http.ServeMux {
	// Configure handlers
	mux := http.NewServeMux()

	// Intercept chat requests
	mux.HandleFunc("POST "+ChatCompletionsPath, s.chatCompletionsHandler) // /v1/chat/completions (openai)
	mux.HandleFunc("POST "+CompletionsPath, s.chatCompletionsHandler)     // /v1/completions (legacy)

	// Passthrough decoder handler
	decoderProxy := s.createReverseProxy(s.decoderURL)
	decoderProxy.ErrorHandler = func(res http.ResponseWriter, _ *http.Request, err error) {

		// Log errors from the decoder proxy
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			s.logger.Error(err, "waiting for vLLM to be ready")
		default:
			s.logger.Error(err, "http: proxy error")
		}
		res.WriteHeader(http.StatusBadGateway)
	}
	s.decoderProxy = decoderProxy
	mux.Handle("/", s.decoderProxy)

	return mux
}

func (s *Server) prefillerProxyHandler(hostPort string) (http.Handler, error) {
	proxy, exists := s.prefillerProxies.Get(hostPort)
	if exists {
		return proxy, nil
	}

	// Backward compatible behavior: trim `http:` prefix
	hostPort, _ = strings.CutPrefix(hostPort, "http://")

	u, err := url.Parse(s.prefillerURLPrefix + hostPort)
	if err != nil {
		s.logger.Error(err, "failed to parse URL", "hostPort", hostPort)
		return nil, err
	}
	proxy = s.createReverseProxy(u)
	s.prefillerProxies.Add(hostPort, proxy)

	return proxy, nil
}

// createHTTPTransport creates an HTTP transport with optional TLS configuration
func (s *Server) createHTTPTransport() *http.Transport {
	transport := &http.Transport{}

	if s.tlsConfig != nil && s.tlsConfig.ClientTLSEnabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: s.tlsConfig.ClientInsecure,
		}

		// Load client certificates if provided
		if s.tlsConfig.ClientCert != "" && s.tlsConfig.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(s.tlsConfig.ClientCert, s.tlsConfig.ClientKey)
			if err != nil {
				s.logger.Error(err, "Failed to load client certificate", "certFile", s.tlsConfig.ClientCert, "keyFile", s.tlsConfig.ClientKey)
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
				s.logger.Info("loaded client certificate for outbound TLS", "certFile", s.tlsConfig.ClientCert)
			}
		}

		// Load CA certificate if provided
		if s.tlsConfig.ClientCACert != "" {
			caCert, err := os.ReadFile(s.tlsConfig.ClientCACert)
			if err != nil {
				s.logger.Error(err, "Failed to read CA certificate file", "caFile", s.tlsConfig.ClientCACert)
			} else {
				caCertPool, err := x509.SystemCertPool()
				if err != nil {
					s.logger.Error(err, "Failed to load system certificate pool")
					caCertPool = x509.NewCertPool()
				}
				if caCertPool.AppendCertsFromPEM(caCert) {
					tlsConfig.RootCAs = caCertPool
					s.logger.Info("loaded custom CA certificate for outbound TLS verification", "caFile", s.tlsConfig.ClientCACert)
				} else {
					s.logger.Error(fmt.Errorf("failed to parse CA certificate"), "Failed to parse CA certificate", "caFile", s.tlsConfig.ClientCACert)
				}
			}
		}

		transport.TLSClientConfig = tlsConfig
		s.logger.Info("configured TLS for outbound connections", "insecure", s.tlsConfig.ClientInsecure)
	}

	return transport
}

// createReverseProxy creates a reverse proxy with custom HTTP transport
func (s *Server) createReverseProxy(targetURL *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Configure custom transport for TLS support
	proxy.Transport = s.createHTTPTransport()

	return proxy
}
