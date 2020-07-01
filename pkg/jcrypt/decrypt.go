package jcrypt

import (
	"fmt"
	"github.com/credding/crypt/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"
	"io/ioutil"
	"os"
)

var (
	decryptKey = flags.FileRead()
	decryptKid string
)

var decryptCommand = &cobra.Command{
	Use:   "decrypt [key]",
	Short: "Generate a JWE given a payload on stdin",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		compact, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		jwe, err := jose.ParseEncrypted(string(compact))
		if err != nil {
			return err
		}

		if decryptKid == "" {
			decryptKid = jwe.Header.KeyID
		}
		key, err := getKey(decryptKey.File(), args, decryptKid)
		if err != nil {
			return err
		}

		payload, err := jwe.Decrypt(key)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, payload)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	decryptCommand.Flags().VarP(decryptKey, "key", "k", "Key file")
	decryptCommand.Flags().StringVar(&decryptKid, "kid", "", "Key ID")

	rootCommand.AddCommand(decryptCommand)
}
