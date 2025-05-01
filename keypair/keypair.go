package keypair

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type ECOpts struct {
	Curve Curve
}

type Curve string

const (
	P256    Curve = "P-256"
	P384    Curve = "P-384"
	P521    Curve = "P-521"
	ED25519 Curve = "ED25519"
)

func (c Curve) String() string {
	return string(c)
}

func GenerateECKeyPair(opts ECOpts) (publicKey crypto.PublicKey, privateKey crypto.PrivateKey, err error) {
	if opts.Curve == ED25519 {
		return ed25519.GenerateKey(rand.Reader)
	} else {
		return generateNistCurveKeypair(opts)
	}
}

func generateNistCurveKeypair(opts ECOpts) (publicKey crypto.PublicKey, privateKey crypto.PrivateKey, err error) {
	var curve elliptic.Curve
	switch opts.Curve {
	case P256:
		curve = elliptic.P256()
	case P384:
		curve = elliptic.P384()
	case P521:
		curve = elliptic.P521()
	default:
		return nil, nil, errors.New("unsupported curve")
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey = key.Public()

	return publicKey, key, nil
}

func EncodeToPEM(publicKey crypto.PublicKey, privateKey crypto.PrivateKey) (pubKeyPem []byte, privKeyPem []byte, err error) {
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	privKeyPem = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	pubKeyPem = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPem, privKeyPem, nil
}
