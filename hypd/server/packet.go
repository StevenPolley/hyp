/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/

package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"deadbeef.codes/steven/hyp/otphyp"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --type knock_data hyp_bpf hyp_bpf.c

// Client is used to keep track of a client attempting to perform an authentic knock sequence
type Client struct {
	Progress int       // index of current progress in sequence.   Value of 1 means first port has been matched
	Sequence [4]uint16 // stores the knock sequence the current client is attempting.  It's set and tracked here to prevent race conditions during a knock sequence being received and key rotations
}

// KnockSequence is used keep track of an ordered knock sequence and whether it's been marked for use (to prevent replay attacks)
type KnockSequence struct {
	Used         bool      // If true, that means this knock sequence has already been used once.  It may still be within the valid time window, but it can't be used again
	PortSequence [4]uint16 // Each knock sequence is four ports long
}

const (
	KnockSequenceTimeout = 3 // TBD: Make this a configurable value
)

var (
	clients        map[uint32]*Client // Contains a map of clients, key is IPv4 address
	knockSequences []KnockSequence    // We have 3 valid knock sequences at any time to account for clock skew
	sharedSecret   string             // base32 encoded shared secret used for totp
)

// PacketServer is the main function when operating in server mode
// it sets up the pcap on the capture device and starts a goroutine
// to rotate the knock sequence
func PacketServer(captureDevice string) error {

	iface, err := net.InterfaceByName(captureDevice)
	if err != nil {
		log.Fatalf("lookup network iface %q: %v", captureDevice, err)
	}

	secretBytes, err := os.ReadFile("hyp.secret")
	if err != nil {
		log.Fatalf("failed to read file 'hyp.secret': %v", err)
	}
	sharedSecret = string(secretBytes)

	clients = make(map[uint32]*Client, 0)
	knockSequences = []KnockSequence{}

	// Setup a goroutine to periodically rotate the authentic knock sequence
	go rotateSequence()

	////////////////////////////////////

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs into the kernel.
	objs := hyp_bpfObjects{}
	if err := loadHyp_bpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %v", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("could not open ring buffer reader: %v", err)
	}
	defer rd.Close()

	var event hyp_bpfKnockData
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("eBPF ring buffer closed, exiting...")
				return nil
			}
			log.Printf("error reading from ring buffer reader: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing ringbuf event: %v", err)
			continue
		}
		handleKnock(event)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

// packets that match the BPF filter get passed to handlePacket
func handleKnock(knockEvent hyp_bpfKnockData) {

	client, ok := clients[knockEvent.Srcip]
	if !ok { // client doesn't exist yet
		for i, knockSequence := range knockSequences { // identify which of the 3 authentic knock sequences is matched
			if knockSequence.Used { // skip over sequences that are already used to prevent replay attack
				continue
			}
			if knockEvent.Dstport == knockSequence.PortSequence[0] {
				// Create the client and mark the knock sequence as used
				clients[knockEvent.Srcip] = &Client{Progress: 1, Sequence: knockSequence.PortSequence}
				knockSequences[i].Used = true
				go timeoutKnockSequence(knockEvent.Srcip)
			}
		}
		return
	}

	// if it's wrong, reset progress
	// TBD: vulnerable to sweep attack - this won't be triggered if a wrong packet doesn't match BPF filter
	// TBD: make the sweep attack fix on by default, but configurable to be off to allow for limited BPF filter for extremely low overhead as compromise.
	if knockEvent.Dstport != client.Sequence[client.Progress] {
		delete(clients, knockEvent.Srcip)
		fmt.Printf("port '%d' is in sequence, but came at unexpected order - resetting progress", knockEvent.Dstport)
		return
	}

	// Client increases progress through sequence and checks if sequence is completed
	client.Progress++
	if client.Progress >= len(client.Sequence) {
		delete(clients, knockEvent.Srcip)
		handleSuccess(intToIP(knockEvent.Srcip)) // The magic function, the knock is completed
		return
	}
}

// Remove the client after the timeout value has elapsed.  This prevents a client from
// being indefinitely stuck part way through an old knock sequence.  It's also helpful
// in preventing sweep attacks as the authentic knock sequence must be correctly entered
// within the timeout value from start to finish.
func timeoutKnockSequence(srcip uint32) {
	time.Sleep(time.Second * KnockSequenceTimeout)
	_, ok := clients[srcip]
	if ok {
		delete(clients, srcip)
	}
}

// Used to rotate the authentic port knock sequence
func rotateSequence() {
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

		// Sleep until next 30 second offset
		time.Sleep(time.Until(time.Now().Truncate(time.Second * 30).Add(time.Second * 30)))

		// pop first value, next iteration pushes new value
		knockSequences = knockSequences[1:]
	}
}

// TBD: Implement - this is a temporary routine to demonstrate an application
func handleSuccess(srcip net.IP) {
	fmt.Println("Success for ", srcip)
	cmd := exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "-s", fmt.Sprint(srcip), "--dport", "22", "-j", "ACCEPT")
	err := cmd.Run()
	if err != nil {
		log.Printf("failed to execute iptables command for '%s': %v", srcip, err)
	}
}
