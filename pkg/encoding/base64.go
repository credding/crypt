package encoding

import (
	"encoding/base64"
)

var Base64 = &base64Format{}
var Base64URL = &base64URLFormat{}

type base64Format struct{}

func (*base64Format) Type() string {
	return "base64"
}

func (*base64Format) TryUnmarshal(data []byte) (interface{}, error) {
	return tryDecodeBase64(base64.StdEncoding, data)
}

type base64URLFormat struct{}

func (*base64URLFormat) Type() string {
	return "base64url"
}

func (*base64URLFormat) TryUnmarshal(data []byte) (interface{}, error) {
	return tryDecodeBase64(base64.RawURLEncoding, data)
}

func tryDecodeBase64(encoding *base64.Encoding, data []byte) ([]byte, error) {
	decoded, err := encoding.DecodeString(string(data))
	if err != nil {
		return nil, UnsupportedEncoding
	}
	return decoded, nil
}
