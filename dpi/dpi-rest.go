//go:build !windows && !linux

package dpi

func DpiPacket(packet gopacket.Packet) string {
	//fmt.Println("Other")
	return ""
}
