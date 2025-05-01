package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"keypair/keypair"
)

type CSRArgs struct {
	PrivateKey   crypto.PrivateKey
	Curve        keypair.Curve
	CN           string
	SAN          []string
	Email        string
	Country      string
	State        string
	Locality     string
	Organization string
	OU           string
}

func GenerateCSR(opts CSRArgs) (*x509.CertificateRequest, error) {
	subject := pkix.Name{
		CommonName:         opts.CN,
		Country:            []string{opts.Country},
		Province:           []string{opts.State},
		Locality:           []string{opts.Locality},
		Organization:       []string{opts.Organization},
		OrganizationalUnit: []string{opts.OU},
	}

	sigAlg, err := curveToAlg(opts.Curve)
	if err != nil {
		return nil, err
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: sigAlg,
		EmailAddresses:     []string{opts.Email},
		DNSNames:           opts.SAN,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, opts.PrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(csrBytes)
}

func EncodeToPEM(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})
}

func curveToAlg(curve keypair.Curve) (x509.SignatureAlgorithm, error) {
	switch curve {
	case keypair.P256:
		return x509.ECDSAWithSHA256, nil
	case keypair.P384:
		return x509.ECDSAWithSHA384, nil
	case keypair.P521:
		return x509.ECDSAWithSHA512, nil
	case keypair.ED25519:
		return x509.PureEd25519, nil
	default:
		return -1, fmt.Errorf("unknown curve: %s", curve)
	}
}
