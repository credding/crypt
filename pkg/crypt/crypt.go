package crypt

import (
	"github.com/spf13/cobra"
)

var rootCommand = &cobra.Command{
	Use:   "crypt",
	Short: "Simple cryptography toolset",
}

func Execute() {
	_ = rootCommand.Execute()
}

func init() {
	cobra.EnableCommandSorting = false
	rootCommand.AddCommand(
		rsaCommand,
		ecdsaCommand,
		csrCommand,
		certCommand,
		publicCommand,
		randCommand,
	)
}
