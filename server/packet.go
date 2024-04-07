package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"deadbeef.codes/steven/hyp/otphyp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Client is used to keep track of a client attempting to perform an authentic knock sequence
type Client struct {
	Progress int       // index of current progress in sequence.   Value of 1 means first port has been matched
	Sequence [4]uint16 // stores the knock sequence the current client is attempting.  It's set and tracked here to prevent race conditions during a knock sequence being received and key rotations
}

// KnockSequence is used keep track of an ordered knock sequence and whether it's been marked for use (to prevent replay attacks)
type KnockSequence struct {
	Used         bool
	PortSequence [4]uint16
}

var (
	clients        map[string]*Client // Contains a map of clients
	knockSequences []KnockSequence
	sharedSecret   string // base32 encoded shared secret used for totp
)

// packetServer is the main function when operating in server mode
// it sets up the pcap on the capture deivce and starts a goroutine
// to rotate the knock sequence
func packetServer(captureDevice string) {
	clients = make(map[string]*Client, 0) // key is flow, value is the current progress through the sequence. i.e. value of 1 means that the first port in the sequence was successful
	knockSequences = []KnockSequence{}    // Slice of accepted port sequences, there have to be several to account for clock skew between client and server

	handle, err := pcap.OpenLive(captureDevice, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("failed to open adapter")
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go rotateSequence(handle)
	for packet := range packetSource.Packets() {
		handlePacket(packet) // Do something with a packet here.
	}
}

// packets that match the BPF filter get passed to handlePacket
func handlePacket(packet gopacket.Packet) {
	port := binary.BigEndian.Uint16(packet.TransportLayer().TransportFlow().Dst().Raw())
	srcip := packet.NetworkLayer().NetworkFlow().Src().String()
	client, ok := clients[srcip]
	if !ok { // create the client, identify which authentic knock sequence is matched
		for i, knockSequence := range knockSequences {
			if knockSequence.Used { // skip over sequences that are already used to prevent replay attack
				continue
			}

			if port == knockSequence.PortSequence[0] {
				clients[srcip] = &Client{Progress: 1, Sequence: knockSequence.PortSequence}
				knockSequences[i].Used = true
			}
		}
		return
	}

	// if it's wrong, reset progress
	// TBD: vulnerable to sweep attack - this won't be triggered if a wrong packet doesn't match BPF filter
	if port != client.Sequence[client.Progress] {
		delete(clients, srcip)
		fmt.Printf("port '%d' is in sequence, but came at unexpected order - resetting progress", port)
		return
	}

	// Client increases progress through sequence and checks if sequence is completed
	client.Progress++
	if client.Progress >= len(client.Sequence) {
		delete(clients, srcip)
		handleSuccess(srcip)
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
