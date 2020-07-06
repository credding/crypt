package jcrypt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"github.com/credding/crypt/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"
	"os"
)

var (
	signKey = flags.FileRead()
	signAlg string
	signKid string
)

var signCommand = &cobra.Command{
	Use:   "sign [key]",
	Short: "Generate a JWS given a payload on stdin",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		payload, err := decodePlainPayload(os.Stdin)
		if err != nil {
			return err
		}
		key, err := getKey(signKey.File(), args, signKid)

		signer, err := getSigner(signAlg, key)
		if err != nil {
			return err
		}
		jws, err := signer.Sign(payload)
		if err != nil {
			return err
		}
		compact, err := jws.CompactSerialize()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, compact)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	signCommand.Flags().SortFlags = false
	signCommand.Flags().VarP(signKey, "key", "k", "Key file")
	signCommand.Flags().StringVarP(&signAlg, "alg", "a", "", "Signature algorithm (default auto)")
	signCommand.Flags().StringVar(&signKid, "kid", "", "Key ID")
}

func getSigner(algArg string, key *jose.JSONWebKey) (jose.Signer, error) {
	signingKey := jose.SigningKey{
		Key: key,
		Algorithm: getSignatureAlgorithm(algArg, key),
	}
	return jose.NewSigner(signingKey, nil)
}

func getSignatureAlgorithm(alg string, key *jose.JSONWebKey) jose.SignatureAlgorithm {
	if alg != "" {
		return jose.SignatureAlgorithm(alg)
	}
	if key.Algorithm != "" {
		return jose.SignatureAlgorithm(key.Algorithm)
	}
	return defaultSignatureAlgorithm(key.Key)
}

func defaultSignatureAlgorithm(key interface{}) jose.SignatureAlgorithm {
	switch key.(type) {
	case *rsa.PrivateKey:
		return jose.RS256
	case *ecdsa.PrivateKey:
		switch key.(*ecdsa.PrivateKey).Curve.Params().Name {
		case "P-256":
			return jose.ES256
		case "P-384":
			return jose.ES384
		case "P-521":
			return jose.ES512
		}
	case []byte:
		return jose.HS256
	}
	return ""
}
