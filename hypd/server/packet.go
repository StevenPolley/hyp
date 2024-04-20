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
	"os/exec"
	"time"

	"deadbeef.codes/steven/hyp/hypd/configuration"
	"deadbeef.codes/steven/hyp/otphyp"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --type knock_data hyp_bpf hyp_bpf.c

// Client is used to keep track of a client attempting to perform an authentic knock sequence
type Client struct {
	Progress    int       // index of current progress in sequence.   Value of 1 means first port has been matched
	Sequence    [4]uint16 // stores the knock sequence the current client is attempting.  It's set and tracked here to prevent race conditions during a knock sequence being received and key rotations
	LastSuccess time.Time
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
	serverConfig   *configuration.HypdConfiguration
	sharedSecrets  [][]byte // A slice of byte slices, each being a secret key
)

// PacketServer is the main function when operating in server mode
// it sets up the pcap on the capture device and starts a goroutine
// to rotate the knock sequence
func PacketServer(config *configuration.HypdConfiguration, secrets [][]byte) error {
	serverConfig = config
	sharedSecrets = secrets
	iface, err := net.InterfaceByName(serverConfig.NetworkInterface)
	if err != nil {
		log.Fatalf("lookup network iface %q: %v", serverConfig.NetworkInterface, err)
	}

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
		go handleKnock(event)
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
		client = &Client{}
		clients[knockEvent.Srcip] = client
	}

	if client.Progress == 0 {
		for i, knockSequence := range knockSequences { // identify which of the authentic knock sequences is matched
			if knockSequence.Used { // skip over sequences that are already used to prevent replay attack
				continue
			}
			if knockEvent.Dstport == knockSequence.PortSequence[0] {
				knockSequences[i].Used = true // TBD: This is vulnerable to a DoS just by doing a full UDP port scan
				client.Progress = 1
				client.Sequence = knockSequence.PortSequence
				go timeoutKnockSequence(knockEvent.Srcip)
			}
		}
		return
	}

	// if it's wrong, reset progress
	if knockEvent.Dstport != client.Sequence[client.Progress] {
		delete(clients, knockEvent.Srcip)
		fmt.Printf("port '%d' is in sequence, but came at unexpected order - resetting progress", knockEvent.Dstport)
		return
	}

	// Client increases progress through sequence and checks if sequence is completed
	client.Progress++
	if client.Progress >= len(client.Sequence) {
		client.Progress = 0
		client.LastSuccess = time.Now()
		handleSuccess(knockEvent.Srcip) // The magic function, the knock is completed
		return
	}
}

// Remove the client after the timeout value has elapsed.  This prevents a client from
// being indefinitely stuck part way through an old knock sequence.  It's also helpful
// in preventing sweep attacks as the authentic knock sequence must be correctly entered
// within the timeout value from start to finish.
// Note: This is not related to handling the timeout / clsoe ports action after a client
// has successfully completed an authentic knock sequence
func timeoutKnockSequence(srcip uint32) {
	time.Sleep(time.Second * KnockSequenceTimeout)
	client, ok := clients[srcip]
	if ok {
		if client.LastSuccess.IsZero() { // If they've never succeeded, just drop them from the map
			delete(clients, srcip)
		} else { // If they have succeeded, just reset their progress to 0 but keep them in map.  They will be cleaned in handleSuccess
			client.Progress = 0
		}

	}
}

// Used to rotate the authentic port knock sequence
func rotateSequence() {
	for {
		// Generate new knock sequences with time skew support
		t := time.Now().Add(time.Second * -30)
		for i := len(knockSequences) / len(sharedSecrets); i < 3; i++ {
			for _, secret := range sharedSecrets {
				portSequence, err := otphyp.GeneratePorts(secret, t.Add((time.Second * 30 * time.Duration(i))))
				if err != nil {
					log.Fatalf("failed to generate port knock sequence: %v", err)
				}
				knockSequence := KnockSequence{PortSequence: portSequence}
				knockSequences = append(knockSequences, knockSequence)
			}
		}

		// Sleep until next 30 second offset
		time.Sleep(time.Until(time.Now().Truncate(time.Second * 30).Add(time.Second * 30)))

		// pop first value, next iteration pushes new value
		knockSequences = knockSequences[len(sharedSecrets):]
	}
}

// handleSuccess is ran when a source IP successfully enters the authentic knock sequence
// the configured success action is ran
func handleSuccess(srcip uint32) {
	srcipf := intToIP(srcip) // formatted as net.IP
	log.Printf("Successful knock from: %s", srcipf)

	client, ok := clients[srcip]
	if !ok {
		log.Printf("failed to lookup %s in clients", srcipf)
		return
	}

	// Don't care about command injection, the configuration file providing the command literally NEEDS to be trusted
	// TBD: Use template / substitution instead of string formatting directive - allows for srcip token to be used multiple times
	cmd := exec.Command("sh", "-c", fmt.Sprintf(serverConfig.SuccessAction, srcipf))
	err := cmd.Run()
	if err != nil {
		log.Printf("failed to execute success action command for '%s': %v", srcipf, err)
	}

	// Handle timeout action
	if serverConfig.TimeoutSeconds < 1 { // Timeout action is disabled
		delete(clients, srcip)
		return
	}

	// Handle checks for client timeout
	// TBD: Persistence / journaling state to disk?  How to handle case if knock daemon is restarted - ports would remain open
	lastSuccess := client.LastSuccess
	time.Sleep(time.Until(client.LastSuccess.Add(time.Duration(serverConfig.TimeoutSeconds * int(time.Second)))))
	if client.LastSuccess.After(lastSuccess) { // The client has refreshed
		return
	}

	// Don't care about command injection, the configuration file providing the command literally NEEDS to be trusted
	// TBD: Use template / substitution instead of string formatting directive - allows for srcip token to be used multiple times
	log.Printf("Performing timeout action on: %s", srcipf)
	cmd = exec.Command("sh", "-c", fmt.Sprintf(serverConfig.TimeoutAction, srcipf))
	err = cmd.Run()
	if err != nil {
		log.Printf("failed to execute timeout action command for '%s': %v", srcipf, err)
	}

	delete(clients, srcip)
}
