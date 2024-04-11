/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/

package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"deadbeef.codes/steven/hyp/otphyp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Client is used to keep track of a client attempting to perform an authentic knock sequence
type Client struct {
	Progress    int       // index of current progress in sequence.   Value of 1 means first port has been matched
	Sequence    [4]uint16 // stores the knock sequence the current client is attempting.  It's set and tracked here to prevent race conditions during a knock sequence being received and key rotations
	LastUpdated time.Time // The last time the client sent a correct packet in the sequence
}

// KnockSequence is used keep track of an ordered knock sequence and whether it's been marked for use (to prevent replay attacks)
type KnockSequence struct {
	Used         bool      // If true, that means this knock sequence has already been used once.  It may still be within the valid time window, but it can't be used again
	PortSequence [4]uint16 // Each knock sequence is four ports long
}

var (
	clients        map[string]*Client // Contains a map of clients
	knockSequences []KnockSequence    // We have 3 valid knock sequences at any time to account for clock skew
	sharedSecret   string             // base32 encoded shared secret used for totp
)

// PacketServer is the main function when operating in server mode
// it sets up the pcap on the capture device and starts a goroutine
// to rotate the knock sequence
func PacketServer(captureDevice string) error {
	secretBytes, err := os.ReadFile("hyp.secret")
	if err != nil {
		log.Fatalf("failed to read file 'hyp.secret': %v", err)
	}
	sharedSecret = string(secretBytes)

	clients = make(map[string]*Client, 0)
	knockSequences = []KnockSequence{}

	// Open pcap handle on device
	handle, err := pcap.OpenLive(captureDevice, 126, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap on capture device: %w", err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Setup a goroutine to periodically rotate the authentic knock sequence
	go rotateSequence(handle)

	// Read from the pcap handle until we exit
	for packet := range packetSource.Packets() {
		handlePacket(packet) // Do something with a packet here.
	}
	return nil
}

// packets that match the BPF filter get passed to handlePacket
func handlePacket(packet gopacket.Packet) {
	port := binary.BigEndian.Uint16(packet.TransportLayer().TransportFlow().Dst().Raw())
	srcip := packet.NetworkLayer().NetworkFlow().Src().String()

	client, ok := clients[srcip]
	if !ok { // client doesn't exist yet
		for i, knockSequence := range knockSequences { // identify which of the 3 authentic knock sequences is matched
			if knockSequence.Used { // skip over sequences that are already used to prevent replay attack
				continue
			}
			if port == knockSequence.PortSequence[0] {
				// Create the client and mark the knock sequence as used
				clients[srcip] = &Client{Progress: 1, Sequence: knockSequence.PortSequence}
				knockSequences[i].Used = true
			}
		}
		return
	}

	// if it's wrong, reset progress
	// TBD: vulnerable to sweep attack - this won't be triggered if a wrong packet doesn't match BPF filter
	// TBD: make the sweep attack fix on by default, but configurable to be off to allow for limited BPF filter for extremely low overhead as compromise.
	if port != client.Sequence[client.Progress] {
		delete(clients, srcip)
		fmt.Printf("port '%d' is in sequence, but came at unexpected order - resetting progress", port)
		return
	}

	// Client increases progress through sequence and checks if sequence is completed
	client.Progress++
	if client.Progress >= len(client.Sequence) {
		delete(clients, srcip)
		handleSuccess(srcip) // The magic function, the knock is completed
		return
	}
}

// Used to rotate the authentic port knock sequence
func rotateSequence(handle *pcap.Handle) {
	for {

		// Generate new knock sequences with time skew support
		t := time.Now().Add(time.Second * -30)
		for i := len(knockSequences); i < 3; i++ {
			portSequence, err := otphyp.GeneratePorts(sharedSecret, t.Add((time.Second * 30 * time.Duration(i))))
			if err != nil {
				log.Fatalf("failed to generate port knock sequence: %v", err)
			}
			knockSequence := KnockSequence{PortSequence: portSequence}
			knockSequences = append(knockSequences, knockSequence)
		}
		fmt.Println("New sequences:", knockSequences)

		// Set BPF filter
		err := setPacketFilter(handle)
		if err != nil {
			log.Printf("failed to change packet filter: %v", err)
		}

		// Sleep until next 30 second offset
		time.Sleep(time.Until(time.Now().Truncate(time.Second * 30).Add(time.Second * 30)))

		// pop first value, next iteration pushes new value
		knockSequences = knockSequences[1:]
	}
}

// Given a pcap handle and list of authentic port knock sequences, configures a BPF filter
func setPacketFilter(handle *pcap.Handle) error {
	filter := "udp && ("
	for i, knockSequence := range knockSequences {
		for j, port := range knockSequence.PortSequence {
			if i == 0 && j == 0 {
				filter += fmt.Sprint("port ", port)
			} else {
				filter += fmt.Sprint(" || port ", port)
			}
		}
	}
	filter += ")"
	err := handle.SetBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("failed to set BPF filter '%s': %v", filter, err)
	}
	return nil
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
