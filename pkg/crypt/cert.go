package crypt

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/credding/crypt/pkg/encoding"
	"github.com/credding/crypt/pkg/flags"
	"github.com/spf13/cobra"
	"math"
	"math/big"
	"os"
	"reflect"
	"time"
)

var (
	certParent     = flags.FileRead()
	certSigningKey = flags.FileRead()
	certExpiry     flags.Time
	certIsCA       bool
)

var certCommand = &cobra.Command{
	Use:   "cert",
	Short: "Generate a certificate given a CSR on stdin",
	RunE: func(cmd *cobra.Command, args []string) error {
		csrPem, err := encoding.DecodePEM(os.Stdin)
		if err != nil {
			return err
		}
		csr, ok := csrPem[0].(*x509.CertificateRequest)
		if !ok {
			return fmt.Errorf("expected a CSR, got %v", reflect.TypeOf(csrPem[0]))
		}
		template, err := certificateTemplate(csr)
		if err != nil {
			return nil
		}
		parent, err := certificateParent(template)
		if err != nil {
			return err
		}
		keyPem, err := encoding.DecodePEM(certSigningKey.File())
		if err != nil {
			return err
		}
		certRaw, err := x509.CreateCertificate(rand.Reader, parent, template, csr.PublicKey, keyPem[0])
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			return err
		}
		return encoding.EncodePEM(os.Stdout, cert)
	},
}

func init() {
	options := certCommand.Flags()
	options.SortFlags = false
	options.VarP(certParent, "parent", "p", "Parent certificate (default self-signed)")
	options.VarP(certSigningKey, "key", "k", "Certificate signing key")
	options.VarP(&certExpiry, "expires", "e", "Certificate expiry (default \"8760h\")")
	options.BoolVar(&certIsCA, "ca", false, "Generate a CA certificate")

	_ = certCommand.MarkFlagRequired("key")
}

func certificateTemplate(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	serialNumber, err := certificateSerialNumber()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SignatureAlgorithm: csr.SignatureAlgorithm,
		SerialNumber:       serialNumber,
		Subject:            csr.Subject,
		NotBefore:          time.Now(),
		NotAfter:           certificateExpiry(),
		IsCA:               certIsCA,
		ExtraExtensions:    csr.Extensions,
	}, nil
}

func certificateParent(template *x509.Certificate) (*x509.Certificate, error) {
	if certParent.File() == nil {
		return template, nil
	}
	parentPem, err := encoding.DecodePEM(certParent.File())
	if err != nil {
		return nil, err
	}
	parent, ok := parentPem[0].(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("expected parent to be a certificate, got %v", reflect.TypeOf(parentPem[0]))
	}
	return parent, nil
}

func certificateExpiry() time.Time {
	if certExpiry > 0 {
		return time.Unix(int64(certExpiry), 0)
	} else {
		return time.Now().Add(365 * 24 * time.Hour)
	}
}

func certificateSerialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
}
