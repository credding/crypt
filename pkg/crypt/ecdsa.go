package crypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/credding/crypt/pkg/encoding"
	"github.com/spf13/cobra"
	"os"
	"regexp"
)

var (
	ecdsaCurve string
)

var ecdsaCommand = &cobra.Command{
	Use:   "ecdsa",
	Short: "Generate an ECDSA key",
	RunE: func(cmd *cobra.Command, args []string) error {
		curve, err := parseCurveName(ecdsaCurve)
		if err != nil {
			return err
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}

		return encoding.EncodePEM(os.Stdout, key)
	},
}

func init() {
	ecdsaCommand.Flags().StringVarP(&ecdsaCurve, "curve", "c", "P-256", "Curve")
}

var curvePattern = regexp.MustCompile("(?i)p-?(\\d+)")

func parseCurveName(name string) (elliptic.Curve, error) {
	nameMatch := curvePattern.FindStringSubmatch(name)
	if nameMatch == nil {
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
	switch nameMatch[1] {
	case "256":
		return elliptic.P256(), nil
	case "384":
		return elliptic.P384(), nil
	case "521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}
