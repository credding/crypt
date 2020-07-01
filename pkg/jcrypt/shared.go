package jcrypt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/credding/crypt/pkg/encoding"
	"github.com/square/go-jose/v3"
	"io"
	"io/ioutil"
	"os"
	"reflect"
)

var keyEncodings = encoding.Encodings{
	encoding.PEM,
	encoding.JWKs,
	encoding.JWK,
	encoding.Base64,
	encoding.Base64URL,
}

func decodePlainPayload(reader io.Reader) ([]byte, error) {
	payload, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func getKey(keyFile *os.File, args []string, kid string) (*jose.JSONWebKey, error) {
	key, err := decodeKey(keyFile, args)
	if err != nil {
		return nil, err
	}
	return selectKey(key, kid)
}

func decodeKey(keyFile *os.File, args []string) (interface{}, error) {
	if keyFile != nil {
		defer keyFile.Close()
		return keyEncodings.Decode(keyFile)
	}
	if len(args) == 0 {
		return nil, errors.New("key not provided")
	}
	return keyEncodings.Unmarshal([]byte(args[0]))
}

func selectKey(key interface{}, kid string) (*jose.JSONWebKey, error) {
	switch key.(type) {
	case encoding.PEMChain:
		return selectPEMKey(key.(encoding.PEMChain), kid)
	case *jose.JSONWebKeySet:
		return selectJWKsKey(key.(*jose.JSONWebKeySet), kid)
	case []byte:
		return &jose.JSONWebKey{Key: kid, KeyID: kid}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", reflect.TypeOf(key))
	}
}

func selectPEMKey(chain encoding.PEMChain, kid string) (*jose.JSONWebKey, error) {
	key := chain[0]
	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey, *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return &jose.JSONWebKey{Key: key, KeyID: kid}, nil
	case *x509.Certificate:
		return &jose.JSONWebKey{Key: key.(*x509.Certificate), KeyID: kid}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", reflect.TypeOf(key))
	}
}

func selectJWKsKey(jwks *jose.JSONWebKeySet, kid string) (*jose.JSONWebKey, error) {
	if kid != "" {
		keys := jwks.Key(kid)
		if len(keys) != 1 {
			return nil, fmt.Errorf("could not match single key with id: %s", kid)
		}
		return &jwks.Key(kid)[0], nil
	} else {
		return &jwks.Keys[0], nil
	}
}

func pemChainToJWK(chain encoding.PEMChain) (*jose.JSONWebKey, error) {
	first := chain[0]
	switch first.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey, *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return &jose.JSONWebKey{Key: first}, nil
	case *x509.Certificate:
		jwk := &jose.JSONWebKey{Key: first.(*x509.Certificate).PublicKey}
		for _, key := range chain[1:] {
			if cert, ok := key.(*x509.Certificate); ok {
				jwk.Certificates = append(jwk.Certificates, cert)
			}
		}
		return jwk, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", reflect.TypeOf(first))
	}
}
