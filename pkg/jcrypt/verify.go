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
	verifyKey = flags.FileRead()
	verifyKid string
)

var verifyCommand = &cobra.Command{
	Use:   "verify [key]",
	Short: "Verity a JWS given on stdin",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		compact, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		jws, err := jose.ParseSigned(string(compact))
		if err != nil {
			return err
		}

		if verifyKid == "" {
			verifyKid = jws.Signatures[0].Protected.KeyID
		}
		key, err := getKey(decryptKey.File(), args, verifyKid)
		if err != nil {
			return err
		}

		payload, err := jws.Verify(key)
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
	verifyCommand.Flags().SortFlags = false
	verifyCommand.Flags().VarP(verifyKey, "key", "k", "Key file")
	verifyCommand.Flags().StringVar(&verifyKid, "kid", "", "Key ID")
}
