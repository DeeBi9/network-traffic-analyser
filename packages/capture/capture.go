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
		// Ethernet Layer Information
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			fmt.Println("No Ethernet layer found, skipping packet")
			continue
		}
		ethernet := ethernetLayer.(*layers.Ethernet)

		ethInfo := EthFrameInfo{
			SourceMacAddr: ethernet.SrcMAC,
			DestMacAddr:   ethernet.DstMAC,
			EthType:       ethernet.EthernetType,
		}

		fmt.Printf("Ethernet: %+v\n", ethInfo)

		// ARP Layer Infromation
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			fmt.Println("No ARP layer found, skipping packet")
			continue
		}

		arp := arpLayer.(*layers.ARP)

		arpInfo := ArpLayerInfo{
			SourceHwAddress:   arp.SourceHwAddress,
			SourceProtAddress: arp.SourceProtAddress,
			DstHwAddress:      arp.DstHwAddress,
			DstProtAddress:    arp.DstProtAddress,
		}
		fmt.Printf("Ethernet: %+v\n", arpInfo)

		// IP Layer Information
		ipInfo := IPLayer{}
		switch ethInfo.EthType {
		case layers.EthernetTypeIPv4:
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				fmt.Println("No IPv4 layer found, skipping packet")
				continue
			}

			ip := ipLayer.(*layers.IPv4)
			ipInfo = IPLayer{
				SourceIPAddr: ip.SrcIP,
				DestIPAddr:   ip.DstIP,
				IPv:          ip.Version,
				TTL:          ip.TTL,
				Proto:        IPProtocol(ip.Protocol),
			}
		case layers.EthernetTypeIPv6:
			ipLayer := packet.Layer(layers.LayerTypeIPv6)
			if ipLayer == nil {
				fmt.Println("No IPv6 layer found, skipping packet")
				continue
			}

			ip := ipLayer.(*layers.IPv6)
			ipInfo = IPLayer{
				SourceIPAddr: ip.SrcIP,
				DestIPAddr:   ip.DstIP,
				IPv:          ip.Version,
				NextHeader:   IPProtocol(ip.NextHeader),
			}
		default:
			fmt.Println("Unsupported Ethernet type, skipping packet")
			continue
		}

		fmt.Printf("IP: %+v\n", ipInfo)

		// Transport Layer Information
		TransLayerProto := ipInfo.NextHeader
		if TransLayerProto == 0 {
			TransLayerProto = ipInfo.Proto
		}
		transinfo := TransLayerInfo{}

		switch TransLayerProto {
		case 1:
			TransLayer := packet.Layer(layers.LayerTypeICMPv4)
			if TransLayer != nil {
				Trans := TransLayer.(*layers.ICMPv4)
				transinfo = TransLayerInfo{
					Checksum: Trans.Checksum,
					Id:       Trans.Id,
					Seq:      Trans.Seq,
				}
			} else {
				fmt.Println("No ICMPv4 layer found, skipping packet")
			}
		case 58:
			TransLayer := packet.Layer(layers.LayerTypeICMPv6)
			if TransLayer != nil {
				Trans := TransLayer.(*layers.ICMPv6)
				transinfo = TransLayerInfo{
					Checksum: Trans.Checksum,
				}
			} else {
				fmt.Println("No ICMPv6 layer found, skipping packet")
			}
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
					Payload: Trans.Payload,
				}
			} else {
				fmt.Println("No TCP layer found, skipping packet")
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
			} else {
				fmt.Println("No UDP layer found, skipping packet")
			}
		default:
			fmt.Println("Unsupported Transport layer protocol, skipping packet")
			continue
		}

		fmt.Printf("Transport: %+v\n", transinfo)

		// Application Layer Information
		appinfo := AppLayerInfo{}
		switch transinfo.DestPort {
		case 53:
			AppLayer := packet.Layer(layers.LayerTypeDNS)
			if AppLayer != nil {
				app := AppLayer.(*layers.DNS)
				appinfo = AppLayerInfo{
					Content: app.Contents,
				}
			} else {
				fmt.Println("No DNS layer found, skipping packet")
			}
		case 67:
			AppLayer := packet.Layer(layers.LayerTypeDHCPv4)
			if AppLayer != nil {
				app := AppLayer.(*layers.DHCPv4)
				appinfo = AppLayerInfo{
					ClientIP:     app.ClientIP,
					YourClientIP: app.YourClientIP,
					NextServerIP: app.NextServerIP,
					RelayAgentIP: app.RelayAgentIP,
				}
			}
		default:
			appinfo.Content = transinfo.Payload
		}

		fmt.Printf("Application: %+v\n", appinfo)
	}

	return nil
}
