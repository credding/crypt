package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/credding/crypt/pkg/encoding"
	"github.com/spf13/cobra"
	"os"
	"reflect"
)

var publicCommand = &cobra.Command{
	Use:   "public",
	Short: "Output the public key given a private key or certificate on stdin",
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := encoding.DecodePEM(os.Stdin)
		if err != nil {
			return err
		}

		chain, err := getPublicPEMChain(key)
		if err != nil {
			return err
		}
		return encoding.EncodePEM(os.Stdout, chain)
	},
}

func init() {
	rootCommand.AddCommand(publicCommand)
}

func getPublicPEMChain(chain encoding.PEMChain) (encoding.PEMChain, error) {
	publicChain := make(encoding.PEMChain, len(chain))
	for i, key := range chain {
		publicKey, err := getPublicKey(key)
		if err != nil {
			return nil, err
		}
		publicChain[i] = publicKey
	}
	return publicChain, nil
}

func getPublicKey(key interface{}) (interface{}, error) {
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return key, nil
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return key.(crypto.Signer).Public(), nil
	case *x509.Certificate:
		return key.(*x509.Certificate).PublicKey, nil
	case *x509.CertificateRequest:
		return key.(*x509.CertificateRequest).PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %v", reflect.TypeOf(key))
	}
}
