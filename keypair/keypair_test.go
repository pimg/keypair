package keypair_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"keypair/keypair"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateECKeyPair(t *testing.T) {
	t.Parallel()
	tests := []string{"P-256", "P-384", "P-521", "ED25519", "Unsupported"}
	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			t.Parallel()
			publicKey, privateKey, err := keypair.GenerateECKeyPair(keypair.ECOpts{Curve: keypair.Curve(test)})

			switch test {
			case "ED25519":
				assert.NotNil(t, publicKey)
				assert.NotNil(t, privateKey)
				assert.NoError(t, err)
				assert.IsType(t, ed25519.PublicKey{}, publicKey)
				assert.IsType(t, ed25519.PrivateKey{}, privateKey)
			case "Unsupported":
				assert.ErrorContains(t, err, "unsupported curve")
			default:
				assert.NotNil(t, publicKey)
				assert.NotNil(t, privateKey)
				assert.NoError(t, err)
				assert.IsType(t, &ecdsa.PublicKey{}, publicKey)
				assert.IsType(t, &ecdsa.PrivateKey{}, privateKey)
			}
		})
	}
}
