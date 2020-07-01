package jcrypt

import (
	"encoding/json"
	"github.com/credding/crypt/pkg/flags"
	"github.com/spf13/cobra"
	"os"
)

var (
	claimsIss   string
	claimsSub   string
	claimsAud   []string
	claimsExp   flags.Time
	claimsNbf   flags.Time
	claimsIat   flags.Time
	claimsJti   string
	claimsExtra map[string]string
)

var claimsCommand = &cobra.Command{
	Use:   "claims",
	Short: "Generate a JWT claims payload",
	RunE: func(cmd *cobra.Command, args []string) error {
		claims := map[string]interface{}{}

		if claimsIss != "" {
			claims["iss"] = claimsIss
		}
		if claimsSub != "" {
			claims["sub"] = claimsSub
		}
		switch len(claimsAud) {
		case 0:
		case 1:
			claims["aud"] = claimsAud[0]
		default:
			claims["aud"] = claimsAud
		}
		if claimsExp > 0 {
			claims["exp"] = claimsExp
		}
		if claimsNbf > 0 {
			claims["nbf"] = claimsNbf
		}
		if claimsIat > 0 {
			claims["iat"] = claimsIat
		}
		if claimsJti != "" {
			claims["jti"] = claimsJti
		}

		for key, value := range claimsExtra {
			claims[key] = value
		}

		return json.NewEncoder(os.Stdout).Encode(claims)
	},
}

func init() {
	options := claimsCommand.Flags()
	options.StringVarP(&claimsIss, "iss", "i", "", "Issuer")
	options.StringVarP(&claimsSub, "sub", "s", "", "Subject")
	options.StringSliceVarP(&claimsAud, "aud", "a", nil, "Audience")
	options.VarP(&claimsExp, "exp", "e", "Expiration Time")
	options.Var(&claimsNbf, "nbf", "Not Before")
	options.Var(&claimsIat, "iat", "Issued At")
	options.StringVar(&claimsJti, "jti", "", "JWT ID")
	options.StringToStringVarP(&claimsExtra, "claim", "c", nil, "Additional claims")

	claimsCommand.Flag("exp").NoOptDefVal = "24h"
	claimsCommand.Flag("nbf").NoOptDefVal = "0"
	claimsCommand.Flag("iat").NoOptDefVal = "0"

	rootCommand.AddCommand(claimsCommand)
}
