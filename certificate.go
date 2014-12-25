package certify

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
)

type Certificate struct {
	Cert *x509.Certificate `json:"cert"`
	Pkey *ecdsa.PrivateKey `json:"fkey"`
}

func (c *Certificate) Json() ([]byte, error) {
	encodedCert, err := json.Marshal(map[string][]byte{
		"cert": c.pemEncoded(),
		"pkey": c.pemEncodedPrivateKey()})
	if err != nil {
		return nil, err
	}

	return encodedCert, nil
}

func (c *Certificate) pemEncoded() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

func (c *Certificate) pemEncodedPrivateKey() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: c.getPrivateKeyBytes()})
}

func (c *Certificate) getPrivateKeyBytes() []byte {
	privKeyBytes, err := x509.MarshalECPrivateKey(c.Pkey)
	if err != nil {
		log.Fatalf("Failed to marshal EC private key: %s\n", err)
	}
	return privKeyBytes
}

func CertificateFromRawBytes(rawCert []byte) (*Certificate, error) {
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, err
	}
	return &Certificate{Cert: cert, Pkey: nil}, nil
}
