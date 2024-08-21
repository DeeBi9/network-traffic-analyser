package capture

import (
	"fmt"
	"log"
	"sync"

	"github.com/Deepanshuisjod/network-traffic-analyser/packages/interfaces"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type AvaInterface struct {
	Name        string
	Description string
	Flags       uint32
	Addresses   []pcap.InterfaceAddress
}

var interfaceStructure = make(map[int]AvaInterface)

// Offline Packaet Capture Example
func OffLinePackageCapture() {
	handle, err := pcap.OpenOffline("tcp_anon.pcapng")
	if err != nil {
		log.Printf("Error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Do something with the handle

	fmt.Println("Yes")
}

// Variable
var CapInterfaceNames []string

func Capture(interfaceName string, wg *sync.WaitGroup) {
	defer wg.Done()
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}

// This live packet capture will capture the network packets which are currently running
func LivePacketCapture() {
	// wg waitGroup waits untill the capturing of every Packet finishes
	var wg sync.WaitGroup

	CapInterfaceNames = interfaces.CapInterfaces()

	for Names := range CapInterfaceNames {
		wg.Add(1)
		go Capture(CapInterfaceNames[Names], &wg)
	}

}
