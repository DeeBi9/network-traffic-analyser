package main

import (
	"github.com/Deepanshuisjod/network-traffic-analyser/packages/capture"
	"github.com/Deepanshuisjod/network-traffic-analyser/packages/interfaces"
)

func main() {
	// Available interfaces
	interfaces.AvailableInterfaces()
	interfaces.AssignedAddress(true)
	interfaces.InterfaceDescription()
	capture.OffLinePackageCapture()
}
