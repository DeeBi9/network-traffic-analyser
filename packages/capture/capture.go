package capture

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func OffLinePackageCapture() {
	handle, err := pcap.OpenOffline("tcp_anon.pcapng")
	if err != nil {
		log.Printf("Error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Do something with the handle

	fmt.Println("Yes")
}
