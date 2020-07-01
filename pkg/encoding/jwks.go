package encoding

import (
	"encoding/json"
	"github.com/square/go-jose/v3"
	json2 "github.com/square/go-jose/v3/json"
	"strings"
)

var JWKs = &jwksFormat{}
var JWK = &jwkFormat{}

type jwksFormat struct{}

func (*jwksFormat) Type() string {
	return "jwks"
}

func (*jwksFormat) TryUnmarshal(data []byte) (interface{}, error) {
	jwks := &jose.JSONWebKeySet{}
	err := json.Unmarshal(data, jwks)
	if err != nil {
		return nil, handleTryUnmarshalError(err)
	}
	return jwks, nil
}

type jwkFormat struct{}

func (*jwkFormat) Type() string {
	return "jwk"
}

func (*jwkFormat) TryUnmarshal(data []byte) (interface{}, error) {
	jwks := &jose.JSONWebKey{}
	err := json.Unmarshal(data, jwks)
	if err != nil {
		return nil, handleTryUnmarshalError(err)
	}
	return jwks, nil
}

func handleTryUnmarshalError(err error) error {
	switch err.(type) {
	case *json.UnmarshalTypeError, *json2.UnmarshalTypeError:
		return err
	}
	if strings.HasPrefix(err.Error(), "square/go-jose: ") {
		return err
	}
	return UnsupportedEncoding
}
