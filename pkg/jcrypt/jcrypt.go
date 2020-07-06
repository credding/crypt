package jcrypt

import (
	"github.com/spf13/cobra"
	"os"
)

var rootCommand = &cobra.Command{
	Use:   "jcrypt",
	Short: "Simple JWE cryptography toolset",
}

func init() {
	cobra.EnableCommandSorting = false
	rootCommand.AddCommand(
		jwksCommand,
		publicCommand,
		claimsCommand,
		signCommand,
		verifyCommand,
		encryptCommand,
		decryptCommand,
		base64Command,
	)
}

func Execute() {
	err := rootCommand.Execute()
	if err != nil {
		os.Exit(1)
	}
}
