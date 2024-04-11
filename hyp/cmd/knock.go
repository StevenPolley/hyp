/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/
package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"deadbeef.codes/steven/hyp/otphyp"
	"github.com/spf13/cobra"
)

// knockCmd represents the knock command
var knockCmd = &cobra.Command{
	Use:   "knock <hypServer>",
	Short: "Sends an authenticated knock sequence to the server specified",
	Long: `Runs the hyp client and performs an authentic knock sequence
against the server provided.  
	
Example usage:

	hyp knock <hypServer>

	hyp knock hyp.deadbeef.codes
	
	hyp knock 10.69.4.20
	`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		// load secret and generate ports using secret and current time
		secretFilePath, err := cmd.Flags().GetString("secret")
		if err != nil {
			panic(fmt.Errorf("failed to parse command flag 'secret': %w", err))
		}

		secretBytes, err := os.ReadFile(secretFilePath)
		if err != nil {
			log.Fatalf("failed to read file 'hyp.secret': %v", err)
		}
		sharedSecret := string(secretBytes)

		ports, err := otphyp.GeneratePorts(sharedSecret, time.Now())
		if err != nil {
			log.Fatalf("failed to generate ports from shared secret: %v", err)
		}

		// Transmit
		fmt.Println("Transmitting knock sequence:", ports)
		for _, port := range ports {
			conn, _ := net.Dial("udp", fmt.Sprintf("%s:%d", args[0], port))
			conn.Write([]byte{0})
			conn.Close()
			time.Sleep(time.Millisecond * 200) // TBD: Make this configurable with flag (maxJitter)
		}
	},
}

func init() {
	rootCmd.AddCommand(knockCmd)

	knockCmd.PersistentFlags().String("secret", "hyp.secret", "Path to the file containing the hyp secret.")
}
