package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"deadbeef.codes/steven/hyp/otphyp"
)

// MaxNetworkLatency specifies the number of milliseconds
// A packet-switched network... more like "race condition factory"
const MaxNetworkLatency = 500

func main() {

	// validate number of input arguments
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// load secret and generate ports using secret and current time
	secretBytes, err := os.ReadFile("hyp.secret")
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
		conn, _ := net.Dial("udp", fmt.Sprintf("%s:%d", os.Args[1], port))
		conn.Write([]byte{0})
		conn.Close()
		time.Sleep(time.Millisecond * MaxNetworkLatency)
	}
}

func usage() {
	fmt.Println(os.Args[0], "usage")
	fmt.Println("Supply an ordered list of ports to knock")
	fmt.Println(os.Args[0], "server")
}
