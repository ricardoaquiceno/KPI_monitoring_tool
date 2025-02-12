package protocols

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"time"
)

type QuicFlow struct {
	sourceID    *[]uint8
	sourceIDLen *uint8
	destID      *[]uint8
	destIDLen   *uint8

	lastSpinState *bool
	lastSpinTime  *time.Time

	// Normally a connection is closed via timeout, often after 2 minutes.
	// Interestingly the max_idle_timeout seems to be a parameter in the quick_transport_parameters of the Handshake.
	// 	This could indeed be used to set the timeout
	lastPacketTime *time.Time
}

func CheckQuic(packet gopacket.Packet, flow *QuicFlow) bool {
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-formats
	// ToDo: correctly use the flow
	packetLayers := packet.Layers()
	var udpLayer *layers.UDP
	for _, l := range packetLayers {
		if l.LayerType() == layers.LayerTypeUDP {
			udpLayer = l.(*layers.UDP)
			break
		}
	}
	if udpLayer != nil {
		srcPort := uint16(udpLayer.SrcPort)
		dstPort := uint16(udpLayer.DstPort)
		possibleQuic := false
		var packetFromServer bool
		if srcPort == 443 {
			possibleQuic = true
			packetFromServer = true
		}
		if dstPort == 443 {
			possibleQuic = true
			packetFromServer = false
		}
		if possibleQuic {
			// possible Quic Packet found
			udpPayload := udpLayer.Payload
			_ = udpPayload
			if len(udpPayload) < 1 {
				return false
			}
			quicHeader := udpPayload[0]
			headerForm := (quicHeader >> 7) & 1
			fixedBit := (quicHeader >> 6) & 1
			if fixedBit == 0 {
				// Fixed Bit needs to be set in QUIC Packet -> this in not a QUIC Packet
				return false
			}
			if headerForm == 1 {
				// Long Header
				longPacketType := (quicHeader & 0b00110000) >> 4
				if len(udpPayload) < 7 {
					// Minimum required for mandatory quic version and dst/src connection length
					// 1B Header, 4B Version, at least 2B dst,src connection length
					return false
				}
				switch longPacketType {
				case 0, 1, 2, 3:
					// 0: Initial Packet, 1: 0-RTT Packet, 2: Handshake Packet, 3: Retry Packet
					if longPacketType < 3 {
						packetNumberLength := quicHeader & 0b00000011
						_ = packetNumberLength
					}
					if longPacketType == 1 {
						//println()
					}
					quicVersion := (uint32(udpPayload[1]) << 24) | (uint32(udpPayload[2]) << 16) | (uint32(udpPayload[3]) << 8) | uint32(udpPayload[4])
					_ = quicVersion

					dstConnIdLength := udpPayload[5]
					dstConnIdEnd := 5 + dstConnIdLength
					if len(udpPayload) < int(dstConnIdEnd+1) || dstConnIdLength < 0 || dstConnIdLength > 255 {
						return false
					}
					if dstConnIdLength > 0 {
						dstConnId := udpPayload[6 : dstConnIdEnd+1]
						_ = dstConnId
					}

					srcConnIdLength := udpPayload[dstConnIdEnd+1]
					srcConnIdStrt := dstConnIdEnd + 2
					srcConnIdEnd := dstConnIdEnd + 1 + srcConnIdLength
					if len(udpPayload) < int(srcConnIdEnd+1) || srcConnIdLength < 0 || srcConnIdLength > 255 {
						return false
					}
					if srcConnIdLength > 0 {
						srcConnId := udpPayload[srcConnIdStrt : srcConnIdEnd+1]
						_ = srcConnId
					}
					return true

				}

			} else {
				// Short Header https://www.rfc-editor.org/rfc/rfc9000.html#name-short-header-packets
				// FixMe: Get dstConnIdLength from flow information struct yet To Be Created
				if flow == nil {
					return false
				}
				if flow.destIDLen == nil {
					return false
				}

				dstConnIdLength := int(*flow.destIDLen)
				spinBit := (quicHeader >> 5) & 1
				keyPhase := (quicHeader >> 2) & 1
				packetNumberLength := quicHeader & 0b00000011
				if !packetFromServer {
					dstConnIdEnd := dstConnIdLength
					if len(udpPayload) < dstConnIdEnd || dstConnIdLength < 0 || dstConnIdLength > 255 {
						return false
					}
					if dstConnIdLength > 0 {
						dstConnId := udpPayload[1 : dstConnIdEnd+1]
						_ = dstConnId
					}
				}
				_ = spinBit
				_ = keyPhase
				_ = packetNumberLength
				return true
			}
		}
	}
	return false
}
