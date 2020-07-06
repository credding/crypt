package crypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/credding/crypt/pkg/encoding"
	"github.com/credding/crypt/pkg/flags"
	"github.com/spf13/cobra"
	"os"
	"reflect"
)

var (
	csrSigningKey = flags.FileRead()
	csrCommonName string
	csrDnsNames   []string
)

var csrCommand = &cobra.Command{
	Use: "csr",
	Short: "Generate a certificate signing request (CSR)",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyPem, err := encoding.DecodePEM(csrSigningKey.File())
		if err != nil {
			return err
		}
		key := keyPem[0]
		template, err := certificateRequestTemplate(key)
		if err != nil {
			return err
		}
		csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, key)
		if err != nil {
			return err
		}
		csr, err := x509.ParseCertificateRequest(csrRaw)
		if err != nil {
			return err
		}
		return encoding.EncodePEM(os.Stdout, csr)
	},
}

func init() {
	options := csrCommand.Flags()
	options.SortFlags = false
	options.VarP(csrSigningKey, "key", "k", "Certificate request signing key")
	options.StringVarP(&csrCommonName, "common-name", "n", "localhost", "Subject common name")
	options.StringSliceVarP(&csrDnsNames, "dns-name", "d", nil, "SAN DNS name")

	_ = csrCommand.MarkFlagRequired("key")
}

func certificateRequestTemplate(key interface{}) (*x509.CertificateRequest, error) {
	signatureAlgorithm, err := determineSignatureAlgorithm(key)
	if err != nil {
		return nil, err
	}

	return &x509.CertificateRequest{
		SignatureAlgorithm: signatureAlgorithm,
		Subject: pkix.Name{
			CommonName: csrCommonName,
		},
		DNSNames: csrDnsNames,
	}, nil
}

func determineSignatureAlgorithm(key interface{}) (x509.SignatureAlgorithm, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return x509.SHA256WithRSA, nil
	case *ecdsa.PrivateKey:
		return x509.ECDSAWithSHA256, nil
	default:
		return 0, fmt.Errorf("unsupported private key type: %v", reflect.TypeOf(key))
	}
}
