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
	encryptKey = flags.FileRead()
	encryptAlg string
	encryptEnc string
	encryptKid string
)

var encryptCommand = &cobra.Command{
	Use:   "encrypt [key]",
	Short: "Generate a JWE given a payload on stdin",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		payload, err := decodePlainPayload(os.Stdin)
		if err != nil {
			return err
		}
		key, err := getEncryptingKey(encryptKey.File(), args, encryptKid)
		if err != nil {
			return err
		}

		encrypter, err := getEncrypter(encryptAlg, encryptEnc, key)
		if err != nil {
			return err
		}
		jwe, err := encrypter.Encrypt(payload)
		if err != nil {
			return err
		}
		compact, err := jwe.CompactSerialize()
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
	encryptCommand.Flags().SortFlags = false
	encryptCommand.Flags().VarP(encryptKey, "key", "k", "Key file")
	encryptCommand.Flags().StringVarP(&encryptAlg, "alg", "a", "", "Key algorithm (default auto)")
	encryptCommand.Flags().StringVarP(&encryptEnc, "enc", "e", defaultContentEncryption, "Encryption algorithm")
	encryptCommand.Flags().StringVar(&encryptKid, "kid", "", "Key ID")
}

func getEncryptingKey(keyFile *os.File, args []string, kid string) (*jose.JSONWebKey, error) {
	key, err := getKey(keyFile, args, kid)
	if err != nil {
		return nil, err
	}
	k := key.Public()
	return &k, nil
}

func getEncrypter(alg string, enc string, key *jose.JSONWebKey) (jose.Encrypter, error) {
	encryption := jose.ContentEncryption(enc)
	recipient := jose.Recipient{
		Algorithm: getKeyAlgorithm(alg, key),
		Key: key,
	}
	return jose.NewEncrypter(encryption, recipient, nil)
}

func getKeyAlgorithm(alg string, key *jose.JSONWebKey) jose.KeyAlgorithm {
	if alg != "" {
		return jose.KeyAlgorithm(alg)
	}
	if key.Algorithm != "" {
		return jose.KeyAlgorithm(key.Algorithm)
	}
	return defaultKeyAlgorithm(key)
}

func defaultKeyAlgorithm(key *jose.JSONWebKey) jose.KeyAlgorithm {
	switch key.Key.(type) {
	case *rsa.PublicKey:
		return jose.RSA_OAEP
	case *ecdsa.PublicKey:
		return jose.ECDH_ES
	case []byte:
		return jose.DIRECT
	}
	return ""
}

const defaultContentEncryption = string(jose.A128CBC_HS256)
