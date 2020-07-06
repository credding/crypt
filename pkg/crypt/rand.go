package crypt

import (
	"encoding/base64"
	"github.com/spf13/cobra"
	"math/rand"
	"os"
	"strconv"
)

var randCommand = &cobra.Command{
	Use: "rand [bytes]",
	Short: "Generate random bytes, default 32",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bytes, err := parseRandArgs(args)
		if err != nil {
			return err
		}

		data := make([]byte, bytes)
		_, err = rand.Read(data)
		if err != nil {
			return err
		}

		_, err = base64.NewEncoder(base64.StdEncoding, os.Stdout).Write(data)
		if err != nil {
			return err
		}

		return nil
	},
}

func parseRandArgs(args []string) (int, error) {
	if len(args) == 0 {
		return 32, nil
	}
	bytes, err := strconv.Atoi(args[0])
	if err != nil {
			return 0, err
		}
	return bytes, nil
}
