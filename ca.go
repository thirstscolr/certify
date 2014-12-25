package certify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"time"
)

var (
	template = x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Certify Certificate Authority",
			Organization: []string{"Certify"},
			Locality:     []string{"San Francisco"},
			Province:     []string{"CA"},
			Country:      []string{"US"},
		},
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
		CRLDistributionPoints: []string{"certify.com/crl"},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
)

type CertificateAuthority struct {
	SigningCert *x509.Certificate `signing_cert`
	pkey        *ecdsa.PrivateKey `pkey`
}

func NewCertificateAuthority() (*CertificateAuthority, error) {
	ca := &CertificateAuthority{}
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %s", err)
		return nil, err
	}

	template.NotBefore = time.Now().UTC()
	template.NotAfter = template.NotBefore.AddDate(5, 0, 0).UTC()
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %s", err)
		return nil, err
	}

	template.SerialNumber = serialNumber
	asn1cert, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&caPrivateKey.PublicKey,
		caPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %s", err)
		return nil, err
	}
	ca.pkey = caPrivateKey

	cert, err := x509.ParseCertificate(asn1cert)
	if err != nil {
		log.Fatalf("Failed to parse CA certificate: %s", err)
		return nil, err
	}

	ca.SigningCert = cert
	return ca, nil
}

func (ca *CertificateAuthority) SignCertificateRequest(request *CertificateRequest) (*Certificate, error) {
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		request.Request,
		ca.SigningCert,
		&request.Pkey.PublicKey,
		ca.pkey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %s", err)
		return nil, err
	}

	return &Certificate{Cert: cert, Pkey: request.Pkey}, nil

}
