/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/
package cmd

import (
	"fmt"
	"os/user"

	"deadbeef.codes/steven/hyp/hypd/configuration"
	"deadbeef.codes/steven/hyp/hypd/server"
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server <configFilePath>",
	Args:  cobra.ExactArgs(1),
	Short: "Runs hyp in server mode",
	Long: `Runs the hyp server and begins watching for authentic knock sequences.

Before running this command, you must first have a configuration file.  You can
generate a configuration file with:  hypd generate defaultconfig > hypdconfig.json

You should then edit the config file to meet your needs.  

In addition to a config file you will need to generate pre-shared keys: 
mkdir -p ./secrets
hypd generate secret > secrets/mykey.secret

Example Usage:

	# Use config file in local directory
	hypd server hypdconfig.json

	# Use config file in /etc/hyp/
	hypd server /etc/hyp/hypdconfig.json
	`,
	Run: func(cmd *cobra.Command, args []string) {
		currentUser, err := user.Current()
		if err != nil {
			panic(fmt.Errorf("could not determine current user: %w", err))
		}
		if currentUser.Username != "root" {
			fmt.Println("WARNING: It's recommended you run this as root, but will proceed anyways...")
		}

		hypdConfiguration, err := configuration.LoadConfiguration(args[0])
		if err != nil {
			panic(fmt.Errorf("failed to load configuration file '%s': %w", args[0], err))
		}

		secrets, err := configuration.LoadSecrets(hypdConfiguration.PreSharedKeyDirectory)
		if err != nil {
			panic(fmt.Errorf("failed to load secrets from directory '%s': %w", hypdConfiguration.PreSharedKeyDirectory, err))
		}

		err = server.PacketServer(hypdConfiguration, secrets)
		if err != nil {
			panic(fmt.Errorf("failed to start packet server: %w", err))
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
