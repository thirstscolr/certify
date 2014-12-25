package certify

import (
	"net/http"
	"strings"
)

type Certifier struct {
	RA *RegistrationAuthority
}

func NewCertifier() (*Certifier, error) {
	// TODO(tdaniels): use existing RA
	ra, err := NewRegistrationAuthority()
	if err != nil {
		return nil, err
	}
	return &Certifier{RA: ra}, nil
}

func (c *Certifier) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// TODO(tdaniels): user model
	cn := r.Header.Get("X-Certify-User")

	uriElems := strings.Split(r.RequestURI, "/")
	action := uriElems[len(uriElems)-1]

	switch action {
	case "new":
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		response, err := c.HandleNewCertificateRequest(cn, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(response)
		return
	default:
		http.NotFound(w, r)
	}
}

func (c *Certifier) HandleNewCertificateRequest(cn string, r *http.Request) ([]byte, error) {
	cert, err := c.RA.IssueCertificate(r, cn)
	if err != nil {
		return nil, err
	}
	response, err := cert.Json()
	if err != nil {
		return nil, err
	}
	return response, nil
}
