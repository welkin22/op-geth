//go:build cgo
// +build cgo

package vm

import (
	"io"

	"github.com/prysmaticlabs/prysm/v4/crypto/bls"
)

func SignatureFromBytes(sig []byte) (Signature, error) {
	return bls.SignatureFromBytes(sig)
}

func PublicKeyFromBytes(pubKey []byte) (PublicKey, error) {
	return bls.PublicKeyFromBytes(pubKey)
}

// PublicKey represents a BLS public key.
type PublicKey = bls.PublicKey

type SecretKey = bls.SecretKey

// Signature represents a BLS signature.
type Signature = bls.Signature

// RandKey creates a new private key using a random method provided as an io.Reader.
func RandKey(r io.Reader) (SecretKey, error) {
	return bls.RandKey()
}

// AggregateSignatures converts a list of signatures into a single, aggregated sig.
func AggregateSignatures(sigs []Signature) Signature {
	return bls.AggregateSignatures(sigs)
}
