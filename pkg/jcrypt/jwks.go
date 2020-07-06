package jcrypt

import (
	"encoding/json"
	"github.com/credding/crypt/pkg/encoding"
	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"
	"os"
)

var jwksCommand = &cobra.Command{
	Use:   "jwks",
	Short: "Generate a JWK set given a public, or private key on stdin",
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := keyEncodings.Decode(os.Stdin)
		if err != nil {
			return err
		}

		keys := make([]jose.JSONWebKey, 0, 1)

		switch key.(type) {
		case encoding.PEMChain:
			key, err := pemChainToJWK(key.(encoding.PEMChain))
			if err != nil {
				return err
			}
			keys = append(keys, *key)
		case *jose.JSONWebKeySet:
			for _, key := range key.(*jose.JSONWebKeySet).Keys {
				keys = append(keys, key)
			}
		case *jose.JSONWebKey:
			keys = append(keys, *key.(*jose.JSONWebKey))
		case []byte:
			keys = append(keys, jose.JSONWebKey{Key: key})
		}

		return json.NewEncoder(os.Stdout).Encode(&jose.JSONWebKeySet{Keys: keys})
	},
}
