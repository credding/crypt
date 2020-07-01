package jcrypt

import (
	"encoding/json"
	"github.com/credding/crypt/pkg/encoding"
	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"
	"os"
)

var jwkEncodings = encoding.Encodings{
	encoding.PEM,
	encoding.JWKs,
	encoding.JWK,
}

var publicCommand = &cobra.Command{
	Use:   "public",
	Short: "Output the public key given a private key on stdin",
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := jwkEncodings.Decode(os.Stdin)
		if err != nil {
			return err
		}

		switch key.(type) {
		case encoding.PEMChain:
			jwk, err := pemChainToJWK(key.(encoding.PEMChain))
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(jwk.Public())
		case *jose.JSONWebKeySet:
			jwks := getPublicJWKs(key.(*jose.JSONWebKeySet))
			return json.NewEncoder(os.Stdout).Encode(jwks)
		case *jose.JSONWebKey:
			jwk := key.(*jose.JSONWebKey).Public()
			return json.NewEncoder(os.Stdout).Encode(jwk)
		}
		return nil
	},
}

func init() {
	rootCommand.AddCommand(publicCommand)
}

func getPublicJWKs(jwks *jose.JSONWebKeySet) *jose.JSONWebKeySet {
	publicJWKs := make([]jose.JSONWebKey, len(jwks.Keys))
	for i, jwk := range jwks.Keys {
		publicJWKs[i] = jwk.Public()
	}
	return &jose.JSONWebKeySet{Keys: publicJWKs}
}
