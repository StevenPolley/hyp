/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/
package cmd

import (
	"encoding/base32"
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

		maxJitter, err := cmd.Flags().GetInt("maxjitter")
		if err != nil {
			panic(fmt.Errorf("failed to parse command flag 'maxjitter': %w", err))
		}
		if maxJitter < 1 || maxJitter > 1500 {
			panic(fmt.Errorf("maxjitter must be value between 1 and 1500"))
		}

		secretBytes, err := os.ReadFile(secretFilePath)
		if err != nil {
			log.Fatalf("failed to read file 'hyp.secret': %v", err)
		}

		decodedSecret, err := base32.StdEncoding.DecodeString(string(secretBytes))
		if err != nil {
			log.Fatalf("failed to base32 decode secret '%s': %w", secretFilePath, err)
		}

		ports, err := otphyp.GeneratePorts(decodedSecret, time.Now())
		if err != nil {
			log.Fatalf("failed to generate ports from shared secret: %v", err)
		}

		// Transmit
		for _, port := range ports {
			fmt.Printf("knock | %s:%d\n", args[0], port)
			conn, _ := net.Dial("udp", fmt.Sprintf("%s:%d", args[0], port))
			conn.Write([]byte{0})
			conn.Close()
			time.Sleep(time.Millisecond * time.Duration(maxJitter)) // TBD: Make this configurable with flag (maxJitter)
		}
	},
}

func init() {
	rootCmd.AddCommand(knockCmd)

	knockCmd.PersistentFlags().String("secret", "hyp.secret", "Path to the file containing the hyp secret.")
	knockCmd.PersistentFlags().Int("maxjitter", 200, "Specifies the time in milliseconds between knock sequence transmissions.")
}
