package interfaces

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// Define the NetInterface struct
type NetInterface struct {
	Index        int    // positive integer that starts at one, zero is never used
	MTU          int    // maximum transmission unit
	Name         string // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr string // IEEE MAC-48, EUI-48 and EUI-64 form
	Flags        string // e.g., FlagUp, FlagLoopback, FlagMulticast
}

// Define the InterfaceIp struct
type InterfaceIP struct {
	Name string // Name of the network interface
	IP   string // IP address of network interface
}

// Network Interface that can be captured
type CapInterface struct {
	Name        string
	Description string
	Flags       uint32
	Addresses   []pcap.InterfaceAddress
}

// Map to store interfaces that can be captured
var capinterfaceStructure = make(map[int]CapInterface)

// Map to store interfaces with their index as the key
var interfaceStructure = make(map[int]NetInterface)

// Map to store interface Addresses with their name as the key
var InterfaceAddress = make(map[string]InterfaceIP)

func AvailableInterfaces() {

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	fmt.Println("Network Interfaces:")
	for _, iface := range interfaces {
		interfaceStructure[iface.Index] = NetInterface{
			Index:        iface.Index,
			Name:         iface.Name,
			MTU:          iface.MTU,
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        iface.Flags.String(),
		}
	}

	for _, value := range interfaceStructure {
		fmt.Printf("Index: %d\n", value.Index)
		fmt.Printf("Name: %s\n", value.Name)
		fmt.Printf("MTU: %d\n", value.MTU)
		fmt.Printf("Hardware Address: %s\n", value.HardwareAddr)
		fmt.Printf("Flags: %s\n", value.Flags)
		fmt.Println()
	}

}

// 'running' variable to check if network interface is running or not
var running bool = true

// Address of a particular interface
func AssignedAddress(running bool) {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error retrieving interfaces:", err)
		return
	}

	for _, iface := range interfaces {
		// Skip interfaces based on running status
		if running && (iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("Error retrieving addresses:", err)
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok {
				InterfaceAddress[iface.Name] = InterfaceIP{
					Name: iface.Name,
					IP:   ipnet.IP.String(),
				}
			}
		}
	}

	// Print interface addresses
	for _, value := range InterfaceAddress {
		fmt.Println("Name : ", value.Name)
		fmt.Println("IP Address : ", value.IP)
	}
}

// List of Name interfaces
var NameInterface []string
var ValInterface []int

// Prints the Network interface Description using Name value converted to int then to String
func InterfaceDescription() {
	for _, value := range InterfaceAddress {
		NameInterface = append(NameInterface, value.Name)

		// pcap.DatalinkNameToVal is converting NameInterface to Int value and appending the integer value into a List
		val := pcap.DatalinkNameToVal(value.Name)
		ValInterface = append(ValInterface, val)

		// Converting ValInterface value to a proper Description
		description := pcap.DatalinkValToDescription(val)
		fmt.Println("Name: ", value.Name)
		fmt.Println("Description:", description)
	}

}

// Names
var CapInterfaceNames []string

func CapInterfaces() []string {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	i := 1
	for _, iface := range interfaces {
		capinterfaceStructure[i] = CapInterface{
			Name:        iface.Name,
			Description: iface.Description,
			Flags:       iface.Flags,
			Addresses:   iface.Addresses,
		}
		i++
	}

	// Clear CapInterfaceNames before appending
	CapInterfaceNames = nil

	for _, value := range capinterfaceStructure {
		fmt.Println("Name : ", value.Name)
		fmt.Println("Description : ", value.Description)
		fmt.Println("Flags : ", value.Flags)
		fmt.Println("Addresses : ", value.Addresses)
		CapInterfaceNames = append(CapInterfaceNames, value.Name)
	}

	return CapInterfaceNames
}
