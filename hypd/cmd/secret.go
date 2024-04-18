/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/
package cmd

import (
	"fmt"

	"deadbeef.codes/steven/hyp/otphyp"
	"github.com/spf13/cobra"
)

// secretCmd represents the secret command
var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Generates a secret key for hyp",
	Long: `Generates a secret for hyp which should be distributed to both the
server and to clients.  

Example:

hypd generate secret > hyp.secret`,
	Run: func(cmd *cobra.Command, args []string) {
		sharedSecret, err := otphyp.GenerateSecret()
		if err != nil {
			panic(fmt.Errorf("failed to generate shared secret: %w", err))
		}
		fmt.Println(sharedSecret)
	},
}

func init() {
	generateCmd.AddCommand(secretCmd)
}
