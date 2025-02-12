package models

import "github.com/google/gopacket/layers"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Old Stuff, might not be needed??

type PortMapping struct {
	Port        int
	Protocol    string
	Application string // like http or ssh
	Comment     string // Optional comment
}

type PortProtocol struct {
	Port     int
	Protocol string
}

type MappingInfo struct {
	Application string
	Comment     string
}

type PacketCounts map[string]int

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// New Stuff

// FlowID is the main identifier for a flow, using a hash that can identify the flow in either direction.
// This is accomplished using the NetFlowHash between the IP Addresses as well as the TransFlowHash between the ports.
type FlowID struct {
	NetFlowHash   uint64
	TransFlowHash uint64
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TCP Stuff

// TCPFlags is a type for the TCP Flags
type TCPFlags uint8

// TCP Flags
const (
	FlagNone TCPFlags = 0
	FlagACK  TCPFlags = 1 << 0
	FlagSYN  TCPFlags = 1 << 1
	FlagFIN  TCPFlags = 1 << 2
	FlagRST  TCPFlags = 1 << 3
	FlagPSH  TCPFlags = 1 << 4
	FlagURG  TCPFlags = 1 << 5
	FlagECE  TCPFlags = 1 << 6
	FlagCWR  TCPFlags = 1 << 7
)

// Packet Types
const (
	PacketTypeOther = iota
	PacketTypeNone
	PacketTypeAck
	PacketTypeAckPiggyback
	PacketTypeSyn
	PacketTypeSynAck
	PacketTypeFin
	PacketTypeRst
	PacketTypePshAck
)

// Supporting Functions: TCP Flags

func GetTcpFlags(tcp *layers.TCP) TCPFlags {
	var flags TCPFlags = 0
	if tcp.SYN == true {
		flags += FlagSYN
	}
	if tcp.ACK == true {
		flags += FlagACK
	}
	if tcp.FIN == true {
		flags += FlagFIN
	}
	if tcp.RST == true {
		flags += FlagRST
	}
	if tcp.PSH == true {
		flags += FlagPSH
	}
	if tcp.URG == true {
		flags += FlagURG
	}
	if tcp.ECE == true {
		flags += FlagECE
	}
	if tcp.CWR == true {
		flags += FlagCWR
	}
	return flags
}

func TcpPacketClassification(tcp *layers.TCP) int {
	// Some help here https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
	flags := GetTcpFlags(tcp)
	if flags == FlagNone {
		return PacketTypeNone
	} else if flags == FlagACK {
		if len(tcp.Payload) == 0 {
			return PacketTypeAck
		}
		return PacketTypeAckPiggyback
	} else if flags == FlagSYN {
		return PacketTypeSyn
	} else if flags == FlagSYN|FlagACK {
		return PacketTypeSynAck
	} else if flags == FlagFIN {
		return PacketTypeFin
	} else if flags == FlagRST {
		return PacketTypeRst
	} else if flags == FlagPSH|FlagACK {
		return PacketTypePshAck
	} else {
		return PacketTypeOther
	}
}
