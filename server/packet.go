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

// type client is used to keept track of a client attempting to perform an authentic knock sequence
type Client struct {
	Progress int       // index of current progress in sequence.   Value of 1 means first port has been matched
	Sequence [4]uint16 // stores the knock sequence the current client is attempting.  It's set and tracked here to prevent race conditions during a knock sequence being received and key rotations
}

var (
	clients       map[string]*Client // Contains a map of clients
	portSequences [][4]uint16
	sharedSecret  string // base32 encoded shared secret used for totp
)

func packetServer(captureDevice string) {
	clients = make(map[string]*Client, 0) // key is flow, value is the current progress through the sequence. i.e. value of 1 means that the first port in the sequence was successful
	portSequences = [][4]uint16{}         // Slice of accepted port sequences, there have to be several to account for clock skew between client and server

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
		for _, sequence := range portSequences {
			if port == sequence[0] {
				clients[srcip] = &Client{Progress: 1, Sequence: sequence}
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

		if len(portSequences) < 3 {
			t := time.Now().Add(time.Second * -30)
			for i := 0; i < 3; i++ {
				portSequence, err := otphyp.GeneratePorts(sharedSecret, t.Add((time.Second * 30 * time.Duration(i))))
				if err != nil {
					log.Fatalf("failed to generate port knock sequence: %v", err)
				}
				portSequences = append(portSequences, portSequence)
			}
		}

		fmt.Println("New sequences:", portSequences)
		err := setPacketFilter(handle)
		if err != nil {
			log.Printf("failed to change packet filter: %v", err)
		}

		// Sleep until next 30 second offset
		time.Sleep(time.Until(time.Now().Truncate(time.Second * 30).Add(time.Second * 30)))

		// TBD: pop first value and only generate latest (time.Now().Add(time.Second*30)) value instead of re-initializing completely
		portSequences = [][4]uint16{}
	}
}

// Given a pcap handle and list of authentic port knock sequences, configures a BPF filter
func setPacketFilter(handle *pcap.Handle) error {
	filter := "udp && ("
	for i, portSequence := range portSequences {
		for j, port := range portSequence {
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
