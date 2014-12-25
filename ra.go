package certify

import (
	"errors"
	"log"
	"net/http"
	"strings"
)

type RegistrationAuthority struct {
	CA *CertificateAuthority `ca`
}

func NewRegistrationAuthority() (*RegistrationAuthority, error) {
	ca, err := NewCertificateAuthority()
	if err != nil {
		return nil, err
	}
	return &RegistrationAuthority{CA: ca}, nil
}

func (RA *RegistrationAuthority) IssueCertificate(r *http.Request, cn string) (*Certificate, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	fqdn := r.PostForm.Get("fqdn")
	authorizedDomains, err := RA.getAuthorizedDomains(cn)
	if err != nil {
		return nil, err
	}

	for _, domain := range authorizedDomains {
		if strings.HasSuffix(fqdn, domain) {
			log.Printf("Issuing certificate for CN: %s", fqdn)
			csr := NewCertificateRequest(fqdn, "certify")
			cert, err := RA.CA.SignCertificateRequest(csr)
			if err != nil {
				log.Fatalf("Failed to sign CSR: %s\n", err)
				return nil, err
			}

			return cert, nil
		}
	}
	return nil, errors.New("Not authorized for domain.")
}

func (RA *RegistrationAuthority) getAuthorizedDomains(cn string) ([]string, error) {
	// TODO(tdaniels): fetch list of authorized domains
	return []string{"foobar.com"}, nil
}
