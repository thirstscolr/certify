package certify

import (
	"net/http"
	"net/url"
	"testing"
)

func TestSignCertificateRequest(t *testing.T) {
	cn := "test.foobar.com"
	certifyUrl := &url.URL{
		Scheme: "https",
		Host:   "certify.com",
		Path:   "/certs/new"}

	values := url.Values{}
	values.Add("fqdn", cn)

	request := &http.Request{
		Method:   "POST",
		URL:      certifyUrl,
		Host:     "certify.com",
		PostForm: values}

	c, err := NewCertifier()
	if err != nil {
		t.Errorf("Failed to create certificate handler: %s", err)
	}

	cert, err := c.RA.IssueCertificate(request, cn)
	if err != nil {
		t.Errorf("Failed to sign CSR: %s", err)
	}

	if cert.Cert.Subject.CommonName != cn {
		t.Errorf("Invalid CN: %s", cert.Cert.Subject.CommonName)
	}
	if cert.Cert.Subject.OrganizationalUnit[0] != "certify" {
		t.Errorf("Invalid OU: %s", cert.Cert.Subject.CommonName)
	}
}
