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

type CertificateRequest struct {
	Request *x509.Certificate `request`
	Pkey    *ecdsa.PrivateKey `pkey`
}

func NewCertificateRequest(commonName string, orgUnitName string) *CertificateRequest {
	cert := CertificateRequest{}
	cert.setRequestTemplate(commonName, orgUnitName)
	return &cert
}

func (cr *CertificateRequest) setRequestTemplate(commonName string, orgUnitName string) {
	ecdsa521Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	cr.Pkey = ecdsa521Priv
	cr.Request = cr.createRequestTemplate(commonName, orgUnitName)
}

func (cr *CertificateRequest) createRequestTemplate(commonName string, orgUnitName string) *x509.Certificate {
	now := time.Now()
	cert := x509.Certificate{
		Subject:            cr.newPkixName(commonName, orgUnitName),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		NotBefore:          now.UTC(),
		// TODO(tdaniels): configure expiry
		NotAfter: now.AddDate(2, 0, 0).UTC(),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		CRLDistributionPoints: []string{"https://certify.com/crl"},
		BasicConstraintsValid: false,
	}

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %s", err)
		return nil
	}
	cert.SerialNumber = serialNumber

	return &cert
}

func (cr *CertificateRequest) newPkixName(commonName string, orgUnitName string) pkix.Name {
	return pkix.Name{
		CommonName:         commonName,
		OrganizationalUnit: []string{orgUnitName},
		Organization:       []string{"Certify"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"CA"},
		Country:            []string{"US"},
	}
}
