package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"deadbeef.codes/steven/hyp/otphyp"
)

func main() {

	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "generatesecret":
		sharedSecret, err := otphyp.GenerateSecret()
		if err != nil {
			log.Fatalf("failed to generate shared secret: %v", err)
		}
		f, err := os.Create("hyp.secret")
		if err != nil {
			log.Fatalf("failed to create file 'hyp.secret': %v", err)
		}
		_, err = f.WriteString(sharedSecret)
		if err != nil {
			log.Fatalf("failed to write to file 'hyp.secret': %v", err)
		}
		f.Close()
		fmt.Println("Created file hyp.secret")
	case "server":
		secretBytes, err := os.ReadFile("hyp.secret")
		if err != nil {
			log.Fatalf("failed to read file 'hyp.secret': %v", err)
		}
		sharedSecret = string(secretBytes)
		if len(os.Args) < 3 {
			usage()
		}
		packetServer(os.Args[2])
	default:
		usage()
	}

}

func usage() {
	fmt.Print(`hypd <command>
	
	Commands:
		generatesecret - creates a pre shared key file named hyp.secret which can be distributed to a trusted client
		server <device> - runs the hypd server watching for an authentic knock sequence

	Example Usage:

		# Generate a secret, to be shared with a trusted client
		hypd generatesecret

		# Linux - ip link
		hypd server eth0

		# Windows - get-netadapter | where {$_.Name -eq “Ethernet”} | Select-Object -Property DeviceName
		hypd server "\\Device\\NPF_{A066F7DE-CC2D-4E4B-97C4-BF0EC4C03649}"

`)
	os.Exit(1)
}

// TBD: Implement - this is a temporary routine to demonstrate an application
func handleSuccess(srcip string) {
	fmt.Println("Success for ", srcip)

	cmd := exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "-s", srcip, "--dport", "22", "-j", "ACCEPT")
	err := cmd.Run()
	if err != nil {
		log.Printf("failed to execute iptables command for '%s': %v", srcip, err)
	}
}
