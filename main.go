package main

import (
	"fmt"

	"github.com/Deepanshuisjod/network-traffic-analyser/packages/capture"
	"github.com/Deepanshuisjod/network-traffic-analyser/packages/interfaces"
)

func main() {
	// Available interfaces
	interfaces.AvailableInterfaces()
	interfaces.AssignedAddress(true)
	interfaces.InterfaceDescription()
	fmt.Println("/................./")
	//capture.LivePacketCapture()
	capture.PacketCaptureByPreference("wlp0s20f3")
}
