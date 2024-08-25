package capture

import (
	"net"

	"github.com/google/gopacket/layers"
)

type Basic struct {
	// size is the total size of the packets
	size int
	// time at which the packet was captured
	timestamp string
}

// Ethernet frame infromation
type EthFrameInfo struct {
	// Mac address of device that sent the packet
	SourceMacAddr net.HardwareAddr
	// Mac address of device that recieves the packet
	DestMacAddr net.HardwareAddr
	// Ethernet type indicated which protocol is
	// encapsulated in the payload of the frame
	EthType layers.EthernetType
}
type ArpLayerInfo struct {
	SourceHwAddress   []byte
	SourceProtAddress []byte
	DstHwAddress      []byte
	DstProtAddress    []byte
}
type IPProtocol uint8

// Also called the Network Layer information
type IPLayer struct {
	// The IP address of the sender
	SourceIPAddr net.IP
	// The IP address of the reciever
	DestIPAddr net.IP
	// IP version
	IPv uint8
	// This indicates how many hops the packet is allowed to make before being discarded
	TTL uint8
	// Protocol used at transport layer
	Proto IPProtocol
	// Tells the Transport Layer type
	NextHeader IPProtocol
}
type TransLayerFlags struct {
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
}

// Trasport Layer Information
type TransLayerInfo struct {
	// Port number of the sender
	SourcePort uint16
	// Port number of the recipient
	DestPort uint16
	// Sequence number
	SeqNum uint32
	// Acknowledgement number
	AckNum uint32
	// Flags various control bits like SYN, ACK, FIN etc.
	Flags    TransLayerFlags
	Checksum uint16
	Id       uint16
	Seq      uint16
	Payload  []byte
}

type PayloadData struct {
	//
}

type AppLayerInfo struct {
	Content      []byte
	Payload      *PayloadData
	ClientIP     net.IP
	YourClientIP net.IP
	NextServerIP net.IP
	RelayAgentIP net.IP
}

// Security Information
type SecInfo struct {
	Flags        int
	EncryptIndic string
}

type ErrorDetectInfo struct {
	Checksum string
	Errors   error
}

type Status struct {
	State   string
	Session string
}
