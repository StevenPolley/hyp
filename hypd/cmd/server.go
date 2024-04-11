/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/
package cmd

import (
	"fmt"

	"deadbeef.codes/steven/hyp/hypd/server"
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server <NIC>",
	Args:  cobra.ExactArgs(1),
	Short: "Runs hyp in server mode",
	Long: `Runs the hyp server and begins capture on the NIC specified

Example Usage:

	# Linux - capture enp0s0
	hyp server enp0s0

	# Linux - capture eth0
	hyp server eth0

	# Windows - get-netadapter | where {$_.Name -eq “Ethernet”} | Select-Object -Property DeviceName
	hyp.exe server "\\Device\\NPF_{A6F067DE-C2DC-4B4E-9C74-BE649C4C0F03}"

	`,
	Run: func(cmd *cobra.Command, args []string) {
		err := server.PacketServer(args[0])
		if err != nil {
			panic(fmt.Errorf("failed to start packet server: %w", err))
		}

	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	/*
		viper.SetConfigName("hypconfig")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/hyp/")
		viper.AddConfigPath("$HOME/.hyp")
		viper.AddConfigPath(".")
		viper.SetDefault("RefreshInterval", 7200)

		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				// Config file not found
				// TBD: Implement
			} else {
				// Config file was found, but another error was produced
				panic(fmt.Errorf("failed reading existing config file: %w", err))
			}
		}*/

}
