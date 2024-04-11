/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "hypd",
	Short: "Hide Your Ports Daemon",
	Long: `Hide Your Ports (hyp) is a combination of Port Knocking and One Time Passwords:

hyp uses a pre-shared key distributed between the server and client, as well as the time
to calculate a unique authentic knock sequence which is only valid for 90 seconds.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {

}
