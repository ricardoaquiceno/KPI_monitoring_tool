//go:build linux

package dpi

import (
	"github.com/google/gopacket"
	"github.com/mushorg/go-dpi"
	"github.com/mushorg/go-dpi/types"
)

var _ = godpi.Initialize()

func DpiPacket(packet gopacket.Packet) string {
	//fmt.Println("Linux")
	flow, _ := godpi.GetPacketFlow(packet)
	result := godpi.ClassifyFlow(flow)
	if result.Protocol != types.Unknown {
		//fmt.Println(result.Source, "detected protocol", result.Protocol)
		return string(result.Source) + "_" + string(result.Protocol)
	} else {
		//fmt.Println("No detection was made")
	}
	return ""
}
