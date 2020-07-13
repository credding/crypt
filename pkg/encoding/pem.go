package encoding

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
)

var PEM = &pemFormat{}

type PEMChain []interface{}

type pemFormat struct{}

func (*pemFormat) Type() string {
	return "pem"
}

func (p *pemFormat) TryUnmarshal(data []byte) (interface{}, error) {
	return UnmarshalPEM(data)
}

func DecodePEM(in io.Reader) (PEMChain, error) {
	data, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return UnmarshalPEM(data)
}

func UnmarshalPEM(data []byte) (PEMChain, error) {
	blocks := make(PEMChain, 0)
	block, data := pem.Decode(data)
	for block != nil {
		result, err := parsePEMBlock(block)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, result)
		block, data = pem.Decode(data)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("expected pem: %w", UnsupportedEncoding)
	}
	return blocks, nil
}

func EncodePEM(out io.Writer, data interface{}) error {
	switch data.(type) {
	case PEMChain:
		for _, data := range data.(PEMChain) {
			err := EncodePEM(out, data)
			if err != nil {
				return err
			}
		}
		return nil
	case *rsa.PublicKey, *ecdsa.PublicKey:
		encoded, err := x509.MarshalPKIXPublicKey(data)
		if err != nil {
			return err
		}
		return pem.Encode(out, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: encoded,
		})
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		encoded, err := x509.MarshalPKCS8PrivateKey(data)
		if err != nil {
			return err
		}
		return pem.Encode(out, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: encoded,
		})
	case *x509.Certificate:
		return pem.Encode(out, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: data.(*x509.Certificate).Raw,
		})
	case *x509.CertificateRequest:
		return pem.Encode(out, &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: data.(*x509.CertificateRequest).Raw,
		})
	default:
		return fmt.Errorf("unsupported pem data type: %v", reflect.TypeOf(data))
	}
}

func parsePEMBlock(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "CERTIFICATE":
		return x509.ParseCertificate(block.Bytes)
	case "CERTIFICATE REQUEST":
		return x509.ParseCertificateRequest(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported pem block type: %s", block.Type)
	}
}
