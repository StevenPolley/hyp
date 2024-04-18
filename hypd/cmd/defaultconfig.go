/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/
package cmd

import (
	"encoding/json"
	"fmt"

	"deadbeef.codes/steven/hyp/hypd/configuration"
	"github.com/spf13/cobra"
)

// defaultconfigCmd represents the defaultconfig command
var defaultconfigCmd = &cobra.Command{
	Use:   "defaultconfig",
	Short: "Prints the default configuration to stdout",
	Long: `The default configuration is used if one is not set.  The default configuration
	can be used as a reference to build your own.  `,
	Run: func(cmd *cobra.Command, args []string) {
		config := configuration.DefaultConfig()
		b, err := json.MarshalIndent(config, "", "    ")
		if err != nil {
			panic(fmt.Errorf("failed to marshal default configuration to json (this should never happen): %v", err))
		}
		fmt.Println(string(b))
	},
}

func init() {
	generateCmd.AddCommand(defaultconfigCmd)

}
