package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"certify"
)

func main() {
	certifier, err := certify.NewCertifier()
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/certs/", func(w http.ResponseWriter, r *http.Request) {
		// Enforce authentication
		if certify.Authenticate(r) {
			certifier.HandleRequest(w, r)
		} else {
			http.Error(w, "Invalid client certificate", http.StatusUnauthorized)
		}
	})

	config, err := certify.NewConfig()
	if err != nil {
		log.Fatal(err)
	}

	listener, tlsErr := tls.Listen("tcp", ":3000", config)
	if tlsErr != nil {
		log.Fatal(tlsErr)
	}

	log.Println("Listening...")
	http.Serve(listener, nil)
}
