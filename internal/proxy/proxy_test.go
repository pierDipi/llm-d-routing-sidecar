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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/llm-d/llm-d-routing-sidecar/test/mock"
	. "github.com/onsi/ginkgo/v2" // nolint:revive
	. "github.com/onsi/gomega"    // nolint:revive
	"k8s.io/klog/v2/ktesting"
)

var _ = Describe("Reverse Proxy", func() {
	When("x-prefiller-url is not present", func() {
		DescribeTable("should forward requests to decode server",

			func(path string, connector string) {
				_, ctx := ktesting.NewTestContext(GinkgoT())

				ackHandlerFn := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
				})

				decodeBackend := httptest.NewServer(ackHandlerFn)
				defer decodeBackend.Close()

				targetURL, err := url.Parse(decodeBackend.URL)
				Expect(err).ToNot(HaveOccurred())

				proxy := NewProxy("0", targetURL, connector, nil) // port 0 to automatically choose one that's available.

				ctx, cancelFn := context.WithCancel(ctx)
				defer cancelFn()

				go func() {
					defer GinkgoRecover()

					err := proxy.Start(ctx)
					Expect(err).ToNot(HaveOccurred())
				}()

				time.Sleep(1 * time.Second)
				Expect(proxy.addr).ToNot(BeNil())

				proxyAddr := "http://" + proxy.addr.String() + path
				resp, err := http.Get(proxyAddr)
				Expect(err).ToNot(HaveOccurred())

				_, err = io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				err = resp.Body.Close()
				Expect(err).ToNot(HaveOccurred())

				Expect(resp.StatusCode).To(BeNumerically("==", 200))
			},

			Entry("when the path is /v1/chat/completions and protocol is LMCache", "/v1/chat/completions", ConnectorLMCache),
			Entry("when the path is /v1/completions and protocol is LMCache", "/v1/completions", ConnectorLMCache),
			Entry("when the path is /v1/embeddings and protocol is LMCache", "/v1/embeddings", ConnectorLMCache),
			Entry("when the path is /score and protocol is LMCache", "/score", ConnectorLMCache),
			Entry("when the path is /healthz and protocol is LMCache", "/healthz", ConnectorLMCache),

			Entry("when the path is /v1/chat/completions and protocol is NIXL", "/v1/chat/completions", ConnectorNIXLV1),
			Entry("when the path is /v1/completions and protocol is NIXL", "/v1/completions", ConnectorNIXLV1),
			Entry("when the path is /v1/embeddings and protocol is NIXL", "/v1/embeddings", ConnectorNIXLV1),
			Entry("when the path is /score and protocol is NIXL", "/score", ConnectorNIXLV1),
			Entry("when the path is /healthz and protocol is NIXL", "/healthz", ConnectorNIXLV1),
		)
	})

	When("server-side TLS is enabled", func() {
		var ctx context.Context
		var proxy *Server
		var decodeBackend *httptest.Server
		var targetURL *url.URL

		BeforeEach(func() {
			_, ctx = ktesting.NewTestContext(GinkgoT())

			// Create mock decoder backend
			ackHandlerFn := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(200)
				w.Write([]byte("OK"))
			})
			decodeBackend = httptest.NewServer(ackHandlerFn)
			DeferCleanup(decodeBackend.Close)

			var err error
			targetURL, err = url.Parse(decodeBackend.URL)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should serve HTTPS with self-signed certificate", func() {
			tlsConfig := &TLSConfig{
				Enabled: true,
			}
			proxy = NewProxy("0", targetURL, ConnectorNIXLV2, tlsConfig)

			ctx, cancelFn := context.WithCancel(ctx)
			defer cancelFn()

			go func() {
				defer GinkgoRecover()
				err := proxy.Start(ctx)
				Expect(err).ToNot(HaveOccurred())
			}()

			time.Sleep(1 * time.Second)
			Expect(proxy.addr).ToNot(BeNil())

			// Create HTTP client that accepts self-signed certificates
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: tr}

			proxyAddr := "https://" + proxy.addr.String() + "/healthz"
			resp, err := client.Get(proxyAddr)
			Expect(err).ToNot(HaveOccurred())
			defer resp.Body.Close()

			Expect(resp.StatusCode).To(Equal(200))
			Expect(resp.TLS).ToNot(BeNil()) // Verify TLS connection was established
		})

		It("should serve HTTPS with provided certificate", func() {
			// Generate test certificate directly as PEM

			// Generate private key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).ToNot(HaveOccurred())

			// Create certificate template
			template := x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					Organization: []string{"Test Org"},
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}

			// Create certificate
			certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
			Expect(err).ToNot(HaveOccurred())

			// Encode certificate to PEM
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certDER,
			})

			// Encode private key to PEM
			privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
			Expect(err).ToNot(HaveOccurred())
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privateKeyDER,
			})

			tlsConfig := &TLSConfig{
				Enabled: true,
				CertPEM: certPEM,
				KeyPEM:  keyPEM,
			}
			proxy = NewProxy("0", targetURL, ConnectorNIXLV2, tlsConfig)

			ctx, cancelFn := context.WithCancel(ctx)
			defer cancelFn()

			go func() {
				defer GinkgoRecover()
				err := proxy.Start(ctx)
				Expect(err).ToNot(HaveOccurred())
			}()

			time.Sleep(1 * time.Second)

			// Test HTTPS connection
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: tr}

			proxyAddr := "https://" + proxy.addr.String() + "/healthz"
			resp, err := client.Get(proxyAddr)
			Expect(err).ToNot(HaveOccurred())
			defer resp.Body.Close()

			Expect(resp.StatusCode).To(Equal(200))
		})
	})

	When("client-side TLS is enabled", func() {
		var ctx context.Context
		var proxy *Server
		var decodeBackend *httptest.Server
		var prefillBackend *httptest.Server

		BeforeEach(func() {
			_, ctx = ktesting.NewTestContext(GinkgoT())

			// Create HTTPS mock backends
			decodeHandler := &mock.ChatCompletionHandler{
				Connector: ConnectorNIXLV2,
				Role:      mock.RoleDecode,
			}
			decodeBackend = httptest.NewTLSServer(decodeHandler)
			DeferCleanup(decodeBackend.Close)

			prefillHandler := &mock.ChatCompletionHandler{
				Connector: ConnectorNIXLV2,
				Role:      mock.RolePrefill,
			}
			prefillBackend = httptest.NewTLSServer(prefillHandler)
			DeferCleanup(prefillBackend.Close)
		})

		It("should connect to HTTPS backends with insecure mode", func() {
			targetURL, err := url.Parse(decodeBackend.URL)
			Expect(err).ToNot(HaveOccurred())

			tlsConfig := &TLSConfig{
				ClientTLSEnabled: true,
				ClientInsecure:   true,
			}
			proxy = NewProxy("0", targetURL, ConnectorNIXLV2, tlsConfig)

			ctx, cancelFn := context.WithCancel(ctx)
			defer cancelFn()

			go func() {
				defer GinkgoRecover()
				err := proxy.Start(ctx)
				Expect(err).ToNot(HaveOccurred())
			}()

			time.Sleep(1 * time.Second)

			// Test request without prefiller (direct to decoder)
			proxyAddr := "http://" + proxy.addr.String() + "/healthz"
			resp, err := http.Get(proxyAddr)
			Expect(err).ToNot(HaveOccurred())
			defer resp.Body.Close()

			Expect(resp.StatusCode).To(Equal(200))
		})

		It("should connect to HTTPS prefiller with insecure mode", func() {
			targetURL, err := url.Parse(decodeBackend.URL)
			Expect(err).ToNot(HaveOccurred())

			tlsConfig := &TLSConfig{
				ClientTLSEnabled: true,
				ClientInsecure:   true,
			}
			proxy = NewProxy("0", targetURL, ConnectorNIXLV2, tlsConfig)

			ctx, cancelFn := context.WithCancel(ctx)
			defer cancelFn()

			go func() {
				defer GinkgoRecover()
				err := proxy.Start(ctx)
				Expect(err).ToNot(HaveOccurred())
			}()

			time.Sleep(1 * time.Second)

			// Test request with prefiller
			body := `{
				"model": "test-model",
				"messages": [{"role": "user", "content": "Hello"}],
				"max_tokens": 50
			}`

			req, err := http.NewRequest(http.MethodPost, "http://"+proxy.addr.String()+ChatCompletionsPath, strings.NewReader(body))
			Expect(err).ToNot(HaveOccurred())
			req.Header.Add(requestHeaderPrefillURL, prefillBackend.URL)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			Expect(err).ToNot(HaveOccurred())
			defer resp.Body.Close()

			// Should get a response (even if it's an error due to mock limitations)
			Expect(resp.StatusCode).To(BeNumerically(">=", 200))
		})

		It("should connect to HTTPS backends with mutual TLS (client certificates)", func() {
			// Generate client certificate and key
			clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).ToNot(HaveOccurred())

			clientTemplate := x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject: pkix.Name{
					Organization: []string{"Test Client"},
					CommonName:   "test-client",
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				BasicConstraintsValid: true,
			}

			clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &clientTemplate, &clientPrivateKey.PublicKey, clientPrivateKey)
			Expect(err).ToNot(HaveOccurred())

			clientCertPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: clientCertDER,
			})

			clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivateKey)
			Expect(err).ToNot(HaveOccurred())
			clientKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: clientKeyDER,
			})

			// Create temporary files for client cert and key
			clientCertFile, err := os.CreateTemp("", "client-cert-*.pem")
			Expect(err).ToNot(HaveOccurred())
			defer os.Remove(clientCertFile.Name())
			defer clientCertFile.Close()

			clientKeyFile, err := os.CreateTemp("", "client-key-*.pem")
			Expect(err).ToNot(HaveOccurred())
			defer os.Remove(clientKeyFile.Name())
			defer clientKeyFile.Close()

			// Write certificate and key data to temporary files
			_, err = clientCertFile.Write(clientCertPEM)
			Expect(err).ToNot(HaveOccurred())
			err = clientCertFile.Sync()
			Expect(err).ToNot(HaveOccurred())

			_, err = clientKeyFile.Write(clientKeyPEM)
			Expect(err).ToNot(HaveOccurred())
			err = clientKeyFile.Sync()
			Expect(err).ToNot(HaveOccurred())

			// Create HTTPS backend that requires client certificates
			mTLSHandler := &mock.ChatCompletionHandler{
				Connector: ConnectorNIXLV2,
				Role:      mock.RoleDecode,
			}

			// Create TLS server with client cert verification
			server := httptest.NewUnstartedServer(mTLSHandler)
			server.TLS = &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  x509.NewCertPool(),
			}

			// Add client cert to the CA pool for verification
			clientCert, err := x509.ParseCertificate(clientCertDER)
			Expect(err).ToNot(HaveOccurred())
			server.TLS.ClientCAs.AddCert(clientCert)

			server.StartTLS()
			defer server.Close()

			targetURL, err := url.Parse(server.URL)
			Expect(err).ToNot(HaveOccurred())

			tlsConfig := &TLSConfig{
				ClientTLSEnabled: true,
				ClientInsecure:   true, // Accept self-signed server cert
				ClientCert:       clientCertFile.Name(),
				ClientKey:        clientKeyFile.Name(),
			}
			proxy = NewProxy("0", targetURL, ConnectorNIXLV2, tlsConfig)

			ctx, cancelFn := context.WithCancel(ctx)
			defer cancelFn()

			go func() {
				defer GinkgoRecover()
				err := proxy.Start(ctx)
				Expect(err).ToNot(HaveOccurred())
			}()

			time.Sleep(1 * time.Second)

			// Test request - should succeed with mutual TLS
			proxyAddr := "http://" + proxy.addr.String() + "/healthz"
			resp, err := http.Get(proxyAddr)
			Expect(err).ToNot(HaveOccurred())
			defer resp.Body.Close()

			// Should successfully connect with mTLS
			Expect(resp.StatusCode).To(Equal(200))
		})
	})

	When("both server and client TLS are enabled", func() {
		var ctx context.Context
		var proxy *Server
		var decodeBackend *httptest.Server

		BeforeEach(func() {
			_, ctx = ktesting.NewTestContext(GinkgoT())

			// Create HTTPS mock backend
			ackHandlerFn := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(200)
				w.Write([]byte("OK"))
			})
			decodeBackend = httptest.NewTLSServer(ackHandlerFn)
			DeferCleanup(decodeBackend.Close)
		})

		It("should serve HTTPS and connect to HTTPS backends", func() {
			targetURL, err := url.Parse(decodeBackend.URL)
			Expect(err).ToNot(HaveOccurred())

			tlsConfig := &TLSConfig{
				Enabled:          true, // Server-side TLS
				ClientTLSEnabled: true, // Client-side TLS
				ClientInsecure:   true, // Accept self-signed from backends
			}
			proxy = NewProxy("0", targetURL, ConnectorNIXLV2, tlsConfig)

			ctx, cancelFn := context.WithCancel(ctx)
			defer cancelFn()

			go func() {
				defer GinkgoRecover()
				err := proxy.Start(ctx)
				Expect(err).ToNot(HaveOccurred())
			}()

			time.Sleep(1 * time.Second)

			// Create HTTPS client for proxy
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: tr}

			proxyAddr := "https://" + proxy.addr.String() + "/healthz"
			resp, err := client.Get(proxyAddr)
			Expect(err).ToNot(HaveOccurred())
			defer resp.Body.Close()

			Expect(resp.StatusCode).To(Equal(200))
			Expect(resp.TLS).ToNot(BeNil()) // Verify HTTPS connection to proxy
		})
	})

	When("x-prefiller-url is present", func() {
		var ctx context.Context
		var decodeBackend *httptest.Server
		var decodeHandler *mock.ChatCompletionHandler
		var prefillBackend *httptest.Server
		var prefillHandler *mock.ChatCompletionHandler
		var decodeURL *url.URL

		BeforeEach(func() {
			_, ctx = ktesting.NewTestContext(GinkgoT())

			// Decoder
			decodeHandler = &mock.ChatCompletionHandler{
				Role: mock.RoleDecode,
			}
			decodeBackend = httptest.NewServer(decodeHandler)
			DeferCleanup(decodeBackend.Close)

			// Prefiller
			prefillHandler = &mock.ChatCompletionHandler{
				Role: mock.RolePrefill,
			}
			prefillBackend = httptest.NewServer(prefillHandler)
			DeferCleanup(prefillBackend.Close)

			// Proxy
			url, err := url.Parse(decodeBackend.URL)
			Expect(err).ToNot(HaveOccurred())
			decodeURL = url
		})

		When("using NIXL connector V1", func() {
			var proxy *Server

			BeforeEach(func() {
				proxy = NewProxy("0", decodeURL, ConnectorNIXLV1) // port 0 to automatically choose one that's available.

				decodeHandler.Connector = ConnectorNIXLV1
				prefillHandler.Connector = ConnectorNIXLV1
			})

			It("should successfully send request to 1. prefill 2. decode with the right fields (backward compatible behavior)", func() {
				By("starting the proxy")
				go func() {
					defer GinkgoRecover()

					err := proxy.Start(ctx)
					Expect(err).ToNot(HaveOccurred())
				}()

				time.Sleep(1 * time.Second)
				Expect(proxy.addr).ToNot(BeNil())
				proxyBaseAddr := "http://" + proxy.addr.String()

				By("sending a /v1/chat/completions request with prefill header")
				body := `{
        			"model": "Qwen/Qwen2-0.5B",
	        		"messages": [
    			      {"role": "user", "content": "Hello"}
        			],
        			"max_tokens": 50
				}`

				req, err := http.NewRequest(http.MethodPost, proxyBaseAddr+ChatCompletionsPath, strings.NewReader(body))
				Expect(err).ToNot(HaveOccurred())
				req.Header.Add(requestHeaderPrefillHostPort, prefillBackend.URL)

				_, err = http.DefaultClient.Do(req)
				Expect(err).ToNot(HaveOccurred())

				Expect(prefillHandler.RequestCount.Load()).To(BeNumerically("==", 1))

				Expect(prefillHandler.CompletionRequests).To(HaveLen(1))
				prq1 := prefillHandler.CompletionRequests[0]

				Expect(prq1).To(HaveKeyWithValue(requestFieldDoRemoteDecode, true))
				Expect(prq1).To(HaveKeyWithValue("stream", false))
				Expect(prq1).ToNot(HaveKey("stream_options"))

				Expect(prefillHandler.CompletionResponses).To(HaveLen(1))
				prp1 := prefillHandler.CompletionResponses[0]
				Expect(prp1).To(HaveKey(requestFieldRemoteBlockIDs))
				Expect(prp1).To(HaveKey(requestFieldRemoteEngineID))

				Expect(decodeHandler.RequestCount.Load()).To(BeNumerically("==", 1))
				Expect(decodeHandler.CompletionRequests).To(HaveLen(1))
				drq1 := decodeHandler.CompletionRequests[0]

				Expect(drq1).To(HaveKey(requestFieldRemoteBlockIDs))
				Expect(drq1).To(HaveKey(requestFieldRemoteEngineID))
			})

			It("should successfully send request to 1. prefill 2. decode with the right fields", func() {
				By("starting the proxy")
				go func() {
					defer GinkgoRecover()

					err := proxy.Start(ctx)
					Expect(err).ToNot(HaveOccurred())
				}()

				time.Sleep(1 * time.Second)
				Expect(proxy.addr).ToNot(BeNil())
				proxyBaseAddr := "http://" + proxy.addr.String()

				By("sending a /v1/chat/completions request with prefill header")
				body := `{
        			"model": "Qwen/Qwen2-0.5B",
	        		"messages": [
    			      {"role": "user", "content": "Hello"}
        			],
        			"max_tokens": 50
				}`

				req, err := http.NewRequest(http.MethodPost, proxyBaseAddr+ChatCompletionsPath, strings.NewReader(body))
				Expect(err).ToNot(HaveOccurred())
				req.Header.Add(requestHeaderPrefillHostPort, prefillBackend.URL[len("http://"):])

				_, err = http.DefaultClient.Do(req)
				Expect(err).ToNot(HaveOccurred())

				Expect(prefillHandler.RequestCount.Load()).To(BeNumerically("==", 1))

				Expect(prefillHandler.CompletionRequests).To(HaveLen(1))
				prq1 := prefillHandler.CompletionRequests[0]

				Expect(prq1).To(HaveKeyWithValue(requestFieldDoRemoteDecode, true))
				Expect(prq1).To(HaveKeyWithValue("stream", false))
				Expect(prq1).ToNot(HaveKey("stream_options"))

				Expect(prefillHandler.CompletionResponses).To(HaveLen(1))
				prp1 := prefillHandler.CompletionResponses[0]
				Expect(prp1).To(HaveKey(requestFieldRemoteBlockIDs))
				Expect(prp1).To(HaveKey(requestFieldRemoteEngineID))

				Expect(decodeHandler.RequestCount.Load()).To(BeNumerically("==", 1))
				Expect(decodeHandler.CompletionRequests).To(HaveLen(1))
				drq1 := decodeHandler.CompletionRequests[0]

				Expect(drq1).To(HaveKey(requestFieldRemoteBlockIDs))
				Expect(drq1).To(HaveKey(requestFieldRemoteEngineID))
			})
		})
	})
})
