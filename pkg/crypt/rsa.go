package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/credding/crypt/pkg/encoding"
	"github.com/spf13/cobra"
	"os"
)

var (
	rsaBits int
)

var rsaCommand = &cobra.Command{
	Use:   "rsa",
	Short: "Generate a RSA key",
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return err
		}

		return encoding.EncodePEM(os.Stdout, key)
	},
}

func init() {
	rsaCommand.Flags().IntVarP(&rsaBits, "bits", "b", 4096, "RSA bits")

	rootCommand.AddCommand(rsaCommand)
}
