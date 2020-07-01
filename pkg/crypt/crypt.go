package crypt

import (
	"github.com/spf13/cobra"
	"os"
)

var rootCommand = &cobra.Command{
	Use: "crypt",
	Short: "Simple cryptography toolset",
}

func Execute() {
	err := rootCommand.Execute()
	if err != nil {
		os.Exit(1)
	}
}
