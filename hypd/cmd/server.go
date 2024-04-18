/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/
package cmd

import (
	"fmt"

	"deadbeef.codes/steven/hyp/hypd/configuration"
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
		configFile, err := cmd.Flags().GetString("configfile")
		if err != nil {
			panic(fmt.Errorf("failed to get configfile flag: %w", err))
		}
		hypdConfiguration, err := configuration.LoadConfiguration(configFile)
		if err != nil {
			panic(fmt.Errorf("failed to start packet server: %w", err))
		}

		err = server.PacketServer(args[0], hypdConfiguration)
		if err != nil {
			panic(fmt.Errorf("failed to start packet server: %w", err))
		}

	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.PersistentFlags().String("configfile", "", "Path to the file containing the hypd configuration.")

}
