package jcrypt

import (
	"encoding/base64"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
)

var base64Command = &cobra.Command{
	Use: "base64 [string]",
	Short: "Encode to base64url without padding given a string, or data on stdin",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := parseBase64Args(args)
		if err != nil {
			return err
		}

		_, err = base64.NewEncoder(base64.RawURLEncoding, os.Stdout).Write(data)
		if err != nil {
			return err
		}

		return nil
	},
}

func parseBase64Args(args []string) ([]byte, error) {
	if len(args) == 0 {
		return ioutil.ReadAll(os.Stdin)
	}
	return []byte(args[0]), nil
}
