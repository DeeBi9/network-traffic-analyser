package capture

import (
	"fmt"
	"log"
	"sync"

	"github.com/Deepanshuisjod/network-traffic-analyser/packages/interfaces"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketStructure struct {
}

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
	wg.Wait()
}

func PacketCaptureByPreference(name string) error {
	handle, err := pcap.OpenLive(name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open packet capture handle: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Getting the information from EthernetLayer
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		fmt.Println(packet)
		// Exception to handle the empty Information
		if ethernetLayer == nil {
			fmt.Println("Error getting infromation !")
			continue
		}
		ethernet := ethernetLayer.(*layers.Ethernet)

		// Storing the Ethernet infromation in the EthFrameInfo
		ethInfo := EthFrameInfo{
			SourceMacAddr: ethernet.SrcMAC,
			DestMacAddr:   ethernet.DstMAC,
			EthType:       ethernet.EthernetType,
		}

		fmt.Println(ethInfo)

		// EthernetType will tell the IPv (Internet Protocol Version)/ Network Layer version
		NetLayerVersion := ethInfo.EthType.String()
		fmt.Println(NetLayerVersion)

		ipInfo := IPLayer{}
		if NetLayerVersion == "IPv4" {
			// Getting the information from the IP Layer/ Network Layer
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				fmt.Println("Couldn't find IP layer for this packet")
				continue
			}

			ip := ipLayer.(*layers.IPv4)

			// Storing the IP layer information
			ipInfo = IPLayer{
				SourceIPAddr: ip.SrcIP,
				DestIPAddr:   ip.DstIP,
				IPv:          ip.Version,
				TTL:          ip.TTL,
				Proto:        IPProtocol(ip.Protocol),
			}

		} else if NetLayerVersion == "IPv6" {
			// Getting the information from the IP Layer/ Network Layer
			ipLayer := packet.Layer(layers.LayerTypeIPv6)
			if ipLayer == nil {
				fmt.Println("Couldn't find IP layer for this packet")
				continue
			}

			ip := ipLayer.(*layers.IPv6)

			// Storing the IP layer information
			ipInfo = IPLayer{
				SourceIPAddr: ip.SrcIP,
				DestIPAddr:   ip.DstIP,
				IPv:          ip.Version,
				NextHeader:   IPProtocol(ip.NextHeader),
			}
		}

		// Transport Layer Information
		TransLayerProto := ipInfo.NextHeader
		if TransLayerProto == 0 {
			TransLayerProto = ipInfo.Proto
		}
		transinfo := TransLayerInfo{}

		switch TransLayerProto {
		/* For the protocol ICMP*/

		// For the protocol ICMPv4
		case 1:
			TransLayer := packet.Layer(layers.LayerTypeICMPv4)
			if TransLayer != nil {
				Trans := TransLayer.(*layers.ICMPv4)
				transinfo = TransLayerInfo{
					Checksum: Trans.Checksum,
					Id:       Trans.Id,
					Seq:      Trans.Seq,
				}
			}

		// For the protocol ICMPv6
		case 58:
			TransLayer := packet.Layer(layers.LayerTypeICMPv6)
			if TransLayer != nil {
				Trans := TransLayer.(*layers.ICMPv6)
				transinfo = TransLayerInfo{
					Checksum: Trans.Checksum,
				}
			} else {
				fmt.Println("NO ICMP Protocol")
			}

		// For the protocol TCP
		case 6:
			TransLayer := packet.Layer(layers.LayerTypeTCP)
			if TransLayer != nil {
				Trans := TransLayer.(*layers.TCP)
				transinfo = TransLayerInfo{
					SourcePort: uint16(Trans.SrcPort),
					DestPort:   uint16(Trans.DstPort),
					SeqNum:     uint32(Trans.Seq),
					AckNum:     uint32(Trans.Ack),
					Checksum:   uint16(Trans.Checksum),
					Flags: TransLayerFlags{
						FIN: Trans.FIN,
						SYN: Trans.SYN,
						RST: Trans.RST,
						PSH: Trans.PSH,
						ACK: Trans.ACK,
						URG: Trans.URG,
						ECE: Trans.ECE,
						CWR: Trans.CWR,
						NS:  Trans.NS,
					},
				}

			} else {
				fmt.Println("NO TCP PROTOCOL")
			}

		case 17:
			TransLayer := packet.Layer(layers.LayerTypeUDP)
			if TransLayer != nil {
				Trans := TransLayer.(*layers.UDP)
				transinfo = TransLayerInfo{
					SourcePort: uint16(Trans.SrcPort),
					DestPort:   uint16(Trans.DstPort),
					Checksum:   Trans.Checksum,
				}
			}
		}
		// Log extracted information
		fmt.Printf("Ethernet: %+v\n", ethInfo)
		fmt.Printf("IP: %+v\n", ipInfo)
		fmt.Printf("Transport: %+v\n", transinfo)
	}

	return nil
}
