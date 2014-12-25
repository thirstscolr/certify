package certify

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
)

func NewConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("certs/examples/server.pem", "certs/examples/server.key")
	if err != nil {
		return nil, err
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}

	ca, err := ioutil.ReadFile("certs/cert.pem")
	if err != nil {
		return nil, err
	}
	config.ClientCAs = x509.NewCertPool()
	if !config.ClientCAs.AppendCertsFromPEM(ca) {
		return nil, errors.New("Failed to add client CAs.")
	}

	return &config, nil
}

func Authenticate(r *http.Request) bool {
	if r.TLS == nil {
		return false
	}

	for _, chain := range r.TLS.VerifiedChains {
		cn := chain[0].Subject.CommonName
		r.Header.Del("X-Certify-User")
		r.Header.Add("X-Certify-User", cn)
		return true
	}

	return false
}
