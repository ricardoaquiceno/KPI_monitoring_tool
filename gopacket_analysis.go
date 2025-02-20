package main

import (
	"fmt"
	"gopacket_analysis/config"
	"gopacket_analysis/helpers"
	"gopacket_analysis/models"
	ERM "gopacket_analysis/models/errorRateMap"
	FLOWMAP "gopacket_analysis/models/newFlowMap"
	PLM "gopacket_analysis/models/passiveLatencyMap"
	"gopacket_analysis/mydb/influxv1"
	PROTO "gopacket_analysis/protocols"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Constant Declarations

// End of Constants
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Type Structs

// TCPPacketMetadata represents the metadata of a captured TCP packet.
type TCPPacketMetadata struct {
	SourceIP             net.IP
	DestinationIP        net.IP
	SourcePort           uint16
	DestinationPort      uint16
	SequenceNumber       uint32
	AcknowledgmentNumber uint32
	PayloadSize          int
	Flags                models.TCPFlags
	PacketType           int
	DirectionOut         bool
	Timestamp            time.Time
}

// newTcpPacketMapType tries to just save the last packet metadata per flow in order to more efficiently calculate the
// retransmit rate and rtt latency
type newTcpPacketMapType map[models.FlowID]TCPPacketMetadata

// End of Type Structs
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// pcapInit creates the pcap packet source, either using the local interface or ssh.
// Mostly works ok, just the ssh is not as great, as I always need to type in the password
func pcapInit(bpfFilter string) (*gopacket.PacketSource, error) {
	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Remote SSH Init
	if config.Pcap.UseRemote {
		fmt.Println("Using remote pcap on 192.168.1.1")
		rStdout, wStdout := io.Pipe()
		var sshCommand *exec.Cmd
		// for capturing the whole packet, a snaplen of 1600 would probably suffice
		// as we only need headers 160 bytes should be enough
		// Check for pubkey config

		bpfFilter = strings.ReplaceAll(bpfFilter, "(", "'(")
		bpfFilter = strings.ReplaceAll(bpfFilter, ")", ")'")
		tcpdumpCommand := "echo 'fwclient' | sudo -S tcpdump -i ens21 -n --immediate-mode -s 160 -U -w - -p " + bpfFilter

		if config.Pcap.SSHUsePubkey {
			// sshCommand = exec.Command("ssh", "-i", config.Pcap.SSHPubkeyLocation, "fwclient@10.0.2.110", tcpdumpCommand)
			sshCommand = exec.Command("ssh", "fwclient@10.0.2.110", tcpdumpCommand)
		} else {
			sshCommand = exec.Command("ssh", "fwclient@10.0.2.110", tcpdumpCommand)
		}

		sshCommand.Stdout = wStdout

		if err := sshCommand.Start(); err != nil {
			fmt.Println(err)
			return nil, err
		}
		fmt.Println(sshCommand.String())

		reader, err := pcapgo.NewReader(rStdout)
		if err != nil {
			return nil, err
		}
		println("sali de la config")
		packetSource := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)
		packetSource.Lazy = true
		packetSource.NoCopy = true
		return packetSource, nil
	} else {
		//////////////////////////////////////////////////////////////////////////////////////////////////////
		// Local Init
		fmt.Println("Using local pcap on ", config.Pcap.LocalDevice)
		if handle, err := pcap.OpenLive(config.Pcap.LocalDevice, 160, true, pcap.BlockForever); err != nil {
			return nil, err
		} else if err := handle.SetBPFFilter(bpfFilter); err != nil { // optional
			return nil, err
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			return packetSource, nil
		}
	}
}

// End of Pcap Init
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// pcapRunner is the main runner that handles all packets from the packet source
// Filter Name will be used to identify the data in database
// Protocol Filter can be for example "tcp" or "udp" or "udp or tcp"
// Port Filter can be "port 80" or "port 443" or "portrange 2000-2100" or "port '(80 or 443)'"
// I.e. if you want only quic packets you could use "udp" and "port 443"
// For normal non QUIC Webtraffic you could use "tcp" and "port '(80 or 443)'"
// If no filtering is needed, just use two empty strings
func pcapRunner(filterName string, bpfFilter string, printStats bool) {
	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Initialization of variables

	// Create packet source
	packetSource, psErr := pcapInit(bpfFilter)

	if psErr != nil {
		log.Fatal(psErr)
	}

	// ToDo: Make the Runtime Variables as a struct
	// ToDo: Move analysis into functions that get called (with runtime variable struct and packet as the parameters)
	// ToDo: Add QUIC statistics using spin bit

	// Time variable used for sending data to influx every second
	startTime := time.Now()

	// Debug Variable for profiler
	programStartTime := time.Now()
	_ = programStartTime

	// Set Throughput variables
	var totalBytesIn uint64
	var totalBytesOut uint64

	// Configure MAC Address for detecting traffic direction
	var ownMAC net.HardwareAddr
	if config.Pcap.UseRemote {
		ownMAC, _ = net.ParseMAC(config.Pcap.RemoteMac)
	} else {
		ownMAC, _ = net.ParseMAC(config.Pcap.LocalMac)
	}

	completeFlowMap := FLOWMAP.NewFlowMap(config.Performance.FlowMapSize)
	var debugOtherPacketsSize uint64
	var debugOtherPackets int
	// Outgoing packet map for latency
	outgoingPacketPLM := PLM.NewPassiveLatencyMap(10000)
	rttSumPLM := time.Duration(0)
	rttPacketsPLM := 0

	// flowErrorRateMap for retransmits, dup acks and out of order detection
	flowErrorRateMap := ERM.NewFlowErrorRateMap()
	packetCountERM := 0
	duplicatesERM := 0
	fastRetransmitERM := 0
	slowRetransmitERM := 0
	duplicateAckERM := 0

	// Runtime variables for all kinds of statistics
	tcpPacketsCount := 0
	udpPacketsCount := 0
	incorrectPackets := 0
	_ = incorrectPackets
	packets := 0
	quicPackets := 0

	// End of Initialization of variables
	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Packet handling for each packet

	// First add the timer for once a second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case packet := <-packetSource.Packets():
			////////////////////////////////////////////////////////////////////////////////////////////
			// For profiler only
			/*
				if time.Now().Sub(programStartTime) > 30*time.Second {
					return
				}
			*/
			// End of Profiler
			////////////////////////////////////////////////////////////////////////////////////////////
			// DEBUG

			// Simple Packet Counter
			packets++

			////////////////////////////////////////////////////////////////////////////////////////////
			// Get Ethernet Layer
			Layer0 := packet.LinkLayer()
			if Layer0 == nil {
				fmt.Println("No link layer for\n", packet)
				continue
			}

			var ethernet *layers.Ethernet
			if Layer0.LayerType() == layers.LayerTypeEthernet {
				ethernet = Layer0.(*layers.Ethernet)
			} else {
				fmt.Println("Found unexpected layer type\n", Layer0.LayerType())
				fmt.Println(packet)
				continue
			}
			// End of Ethernet Layer
			////////////////////////////////////////////////////////////////////////////////////////////
			// Try to get IP Layer
			Layer1 := packet.NetworkLayer()
			if Layer1 == nil {
				// To Do: Could try and save these as pcaps to further analyse
				etherType := ethernet.EthernetType
				unknownEthertypes := []int{35041, 35090}
				if helpers.IsInInt(unknownEthertypes, int(etherType)) {
					// don't know what that might be
				}

				//fmt.Println("No network layer for\n", packet)
				continue
			}

			var ipv4 *layers.IPv4
			var ipv6 *layers.IPv6
			var srcIP, dstIP net.IP
			_ = srcIP
			_ = dstIP
			if Layer1.LayerType() == layers.LayerTypeIPv4 {
				ipv4 = Layer1.(*layers.IPv4)
				srcIP = ipv4.SrcIP
				dstIP = ipv4.DstIP
			} else if Layer1.LayerType() == layers.LayerTypeIPv6 {
				ipv6 = Layer1.(*layers.IPv6)
				srcIP = ipv6.SrcIP
				dstIP = ipv6.DstIP
			} else {
				fmt.Println("Found unexpected layer type\n", Layer0.LayerType())
				fmt.Println(packet)
				continue
			}
			// End of IP Layer
			////////////////////////////////////////////////////////////////////////////////////////////
			// Feature Throughput
			size := packet.Metadata().Length
			outgoingTraffic := ethernet.SrcMAC.String() == ownMAC.String()

			if outgoingTraffic {
				totalBytesOut += uint64(size)
			} else {
				totalBytesIn += uint64(size)
			}
			// End of throughput
			////////////////////////////////////////////////////////////////////////////////////////////
			// Try to get Transport Layer
			Layer2 := packet.TransportLayer()
			if Layer2 == nil {
				var nextLayer layers.IPProtocol
				if ipv4 != nil {
					nextLayer = ipv4.Protocol
				} else {
					nextLayer = ipv6.NextHeader
				}
				_ = nextLayer
				//fmt.Println("No transport layer for\n", packet)
				debugOtherPackets++
				debugOtherPacketsSize += uint64(size)
				continue
			}

			var tcp *layers.TCP
			var udp *layers.UDP
			var srcPort, dstPort uint16
			_ = srcPort
			_ = dstPort
			if Layer2.LayerType() == layers.LayerTypeTCP {
				tcp = Layer2.(*layers.TCP)
				srcPort = uint16(tcp.SrcPort)
				dstPort = uint16(tcp.DstPort)
			} else if Layer2.LayerType() == layers.LayerTypeUDP {
				udp = Layer2.(*layers.UDP)
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
			} else {
				fmt.Println("Found unexpected layer type\n", Layer0.LayerType())
				fmt.Println(packet)
				debugOtherPackets++
				debugOtherPacketsSize += uint64(size)
				continue
			}
			// End of Transport Layer
			////////////////////////////////////////////////////////////////////////////////////////////
			// Try a Flow Detection for TCP
			if tcp != nil {
				// TCP Packet Stat
				tcpPacketsCount++

				// Get my flows
				netFlow := packet.NetworkLayer().NetworkFlow()
				// TestMe: Is this always Layer 2? What about VLAN traffic?
				transportFlow := Layer2.TransportFlow()

				// Create the Flow Hash to enable bidirectional detection of the flow
				nfH := netFlow.FastHash()
				pfH := transportFlow.FastHash()

				// Calculate TCP Payload site using the packet size and Payload size
				var tcpPayloadSize int
				if size > 160 {
					tcpPayloadSize = size - (160 - len(tcp.Payload))
				} else {
					tcpPayloadSize = len(tcp.Payload)
				}

				// Get Packet Type
				packetType := models.TcpPacketClassification(tcp)

				// Get Timestamp of Packet
				packetTimestamp := packet.Metadata().Timestamp

				//////////////////////////////////////////////////////////////////////////////
				// Create Objects for maps

				// Flow ID will always be needed
				flowid := models.FlowID{
					NetFlowHash:   nfH,
					TransFlowHash: pfH,
				}

				/*
					// Metadata contains the most important information about the flow. Not needed anymore
					metadata := TCPPacketMetadata{
						SourceIP:             srcIP,
						SourcePort:           srcPort,
						DestinationIP:        dstIP,
						DestinationPort:      dstPort,
						SequenceNumber:       tcp.Seq,
						AcknowledgmentNumber: tcp.Ack,
						PayloadSize:          tcpPayloadSize,
						Flags:                models.GetTcpFlags(tcp),
						PacketType:           packetType,
						DirectionOut:         outgoingTraffic,
						Timestamp:            packetTimestamp,
					}
				*/

				// Create the Error Rate Map ID and Record
				ermID := ERM.ErrorRatePacketID{
					AckID:  tcp.Ack,
					SeqID:  tcp.Seq,
					DirTyp: fmt.Sprintf("%t_%d", outgoingTraffic, packetType),
				}
				ermRec := ERM.NewRecordData(packetTimestamp, outgoingTraffic, tcp.Seq, tcp.Ack, uint32(tcpPayloadSize), packetType)

				//////////////////////////////////////////////////////////////////////////////
				// Add Packet to the Flow
				flowMapError := flowErrorRateMap.Add(flowid, ermID, ermRec)
				packetCountERM++
				if flowMapError != nil {
					if flowMapError.Error() == ERM.AlreadyDeletedErr {

					} else if flowMapError.Error() == ERM.DupErr {
						//helpers.AddToPcap(packet, time.Now().Format("2006-01-02T15-04-05"))
						duplicatesERM++
						// ToDo: Move retransmit type detection to errorRateMap.Add() function and throw upwards as error
						originalPacket, err := flowErrorRateMap.GetPacket(flowid, ermID)
						if err == nil {
							ts := originalPacket.GetTimestamp()
							delay := packetTimestamp.Sub(ts)
							if packetType == models.PacketTypeAck {
								duplicateAckERM++
							} else {
								if delay > 100*time.Millisecond {
									slowRetransmitERM++
								} else {
									fastRetransmitERM++
								}
							}
						}
					} else if flowMapError.Error() == ERM.ConnectionClose {
						fmt.Print(".")
					}
				} else {
					// Actually no Problem, as this Packet was added without errors, so nothing to do
				}

				//////////////////////////////////////////////////////////////////////////////
				// Dedicated PassiveLatencyMap Approach for Latency Measurements
				if outgoingTraffic {
					keyPLM := PLM.PassiveLatencyPacketID{
						ThisFlowId:    flowid,
						ExpectedAckID: tcp.Seq + uint32(tcpPayloadSize),
					}
					if packetType != models.PacketTypeAck && tcpPayloadSize > 0 {
						errPLM := outgoingPacketPLM.Add(keyPLM, packetTimestamp)
						if errPLM != nil {
							// can only be, that the packet was already sent and hence is already in the map
						}
					}
				} else {
					keyPLM := PLM.PassiveLatencyPacketID{
						ThisFlowId:    flowid,
						ExpectedAckID: tcp.Ack,
					}
					if packetType == models.PacketTypeAck {
						rttDelay, errPLM := outgoingPacketPLM.CalculateLatency(keyPLM, packetTimestamp, 1000)
						if errPLM != nil {
							// can only be, that the packet was not found, hence this is a duplicate ack or the ack needed
							// too much time
							// Also will throw away any rtt that is too long (over a second)
						} else {
							// Found the rttDelay, need to add it to our running variables
							rttPacketsPLM++
							rttSumPLM += rttDelay
						}
					}
				}

				//////////////////////////////////////////////////////////////////////////////
				// New Flow Map Approach
				// ToDo: Improve Data
				flowKey := FLOWMAP.FlowMapID{NetFlowHash: nfH}
				appKey := FLOWMAP.ApplicationMapID{
					TransportFlowHash: pfH,
					TransportProtocol: "TCP",
				}
				var networkProtocol string
				if ipv4 != nil {
					networkProtocol = "IPV4"
				} else if ipv6 != nil {
					networkProtocol = "IPV6"
				} else {
					networkProtocol = "UNKNOWN"
				}
				basicFlowMapInfo := FLOWMAP.FlowMapElement{
					NetworkProtocol: networkProtocol,
					SrcIP:           srcIP,
					DstIP:           dstIP,
					LastPacketTime:  packetTimestamp,
				}
				// The measurements are completely off due to stuff like duplicates and retransmits!
				var sizeByteOut, sizeByteIn uint64
				var packetsOut, packetsIn int
				if outgoingTraffic {
					sizeByteOut = uint64(size)
					packetsOut = 1
				} else {
					sizeByteIn = uint64(size)
					packetsIn = 1
				}
				measurement := FLOWMAP.Measurements{
					PacketsOut:      packetsOut,
					PacketsIn:       packetsIn,
					SizeBytesOut:    sizeByteOut,
					SizeBytesIn:     sizeByteIn,
					RttPacketsPLM:   0,
					RttSumPLM:       0,
					ErmPacketsCount: 0,
					ErmDuplicates:   0,
					QuicPackets:     0,
				}

				// ToDo: Detect potential traffic and application types
				basicApplicationElement := FLOWMAP.ApplicationMapElement{
					SrcPort:                  srcPort,
					DstPort:                  dstPort,
					PotentialTrafficType:     nil,
					PotentialApplicationType: nil,
					LastPacketTime:           packetTimestamp,
					Measurements:             measurement,
				}
				optionalApplicationParameters := FLOWMAP.ApplicationMapOptionalParameters{
					PassiveLatencyMapKey:       nil,
					PassiveLatencyMapTimestamp: nil,
					ErrorRateFlowID:            nil,
					ErrorRatePacketID:          nil,
					ErrorRateRecordData:        nil,
				}
				err := completeFlowMap.AddPacket(flowKey, &basicFlowMapInfo, appKey, &basicApplicationElement,
					optionalApplicationParameters)
				if err != nil {
					fmt.Println(err)
				}
			}

			////////////////////////////////////////////////////////////////////////////////////////////
			// Try a something for UDP, Flow Detection Could also work
			if udp != nil {
				// TCP Packet Stat
				udpPacketsCount++

				// Get my flows
				netFlow := packet.NetworkLayer().NetworkFlow()
				transportFlow := Layer2.TransportFlow()

				// Create the Flow Hash to enable bidirectional detection of the flow
				nfH := netFlow.FastHash()
				pfH := transportFlow.FastHash()

				// Calculate TCP Payload site using the packet size and Payload size
				var udpPayloadSize int
				_ = udpPayloadSize
				/*
					if size > 160 {
						udpPayloadSize = size - (160 - len(tcp.Payload))
					} else {
						udpPayloadSize = len(tcp.Payload)
					}
				*/

				// Get Packet Type
				//packetType := models.TcpPacketClassification(tcp)

				// Get Timestamp of Packet
				packetTimestamp := packet.Metadata().Timestamp
				_ = packetTimestamp
				//////////////////////////////////////////////////////////////////////////////
				// Create Objects for maps

				// Flow ID will always be needed
				flowid := models.FlowID{
					NetFlowHash:   nfH,
					TransFlowHash: pfH,
				}
				_ = flowid

				//////////////////////////////////////////////////////////////////////////////
				// New Flow Map Approach
				// ToDo: Improve Data
				flowKey := FLOWMAP.FlowMapID{NetFlowHash: nfH}
				appKey := FLOWMAP.ApplicationMapID{
					TransportFlowHash: pfH,
					TransportProtocol: "UDP",
				}
				var networkProtocol string
				if ipv4 != nil {
					networkProtocol = "IPV4"
				} else if ipv6 != nil {
					networkProtocol = "IPV6"
				} else {
					networkProtocol = "UNKNOWN"
				}
				basicFlowMapInfo := FLOWMAP.FlowMapElement{
					NetworkProtocol: networkProtocol,
					SrcIP:           srcIP,
					DstIP:           dstIP,
					LastPacketTime:  packetTimestamp,
				}

				// QUIC Packet test
				var quic int
				if PROTO.CheckQuic(packet, &PROTO.QuicFlow{}) {
					quicPackets++
					quic = 1
				}

				// The measurements are completely off due to stuff like duplicates and retransmits!
				var sizeByteOut, sizeByteIn uint64
				var packetsOut, packetsIn int
				if outgoingTraffic {
					sizeByteOut = uint64(size)
					packetsOut = 1
				} else {
					sizeByteIn = uint64(size)
					packetsIn = 1
				}
				measurement := FLOWMAP.Measurements{
					PacketsOut:      packetsOut,
					PacketsIn:       packetsIn,
					SizeBytesOut:    sizeByteOut,
					SizeBytesIn:     sizeByteIn,
					RttPacketsPLM:   0,
					RttSumPLM:       0,
					ErmPacketsCount: 0,
					ErmDuplicates:   0,
					QuicPackets:     quic,
				}

				// ToDo: Detect potential traffic and application types
				basicApplicationElement := FLOWMAP.ApplicationMapElement{
					SrcPort:                  srcPort,
					DstPort:                  dstPort,
					PotentialTrafficType:     nil,
					PotentialApplicationType: nil,
					LastPacketTime:           packetTimestamp,
					Measurements:             measurement,
				}
				optionalApplicationParameters := FLOWMAP.ApplicationMapOptionalParameters{
					PassiveLatencyMapKey:       nil,
					PassiveLatencyMapTimestamp: nil,
					ErrorRateFlowID:            nil,
					ErrorRatePacketID:          nil,
					ErrorRateRecordData:        nil,
				}
				err := completeFlowMap.AddPacket(flowKey, &basicFlowMapInfo, appKey, &basicApplicationElement,
					optionalApplicationParameters)
				if err != nil {
					fmt.Println(err)
				}
			}
			if tcp == nil && udp == nil {
				println("No packets sent")
				debugOtherPackets++
				debugOtherPacketsSize += uint64(size)
			}
		case <-ticker.C:
			now := time.Now()
			elapsedTime := now.Sub(startTime)
			//////////////////////////////////////////////////////////////////////////////
			// Calculations
			otherPackets := packets - tcpPacketsCount
			tcpPacketRate := float64(tcpPacketsCount) / float64(packets) * 100
			// Throughput
			bitThroughputOut := float64(totalBytesOut) / elapsedTime.Seconds() * 8
			bitThroughputIn := float64(totalBytesIn) / elapsedTime.Seconds() * 8
			throughputOut := bitThroughputOut / 1024 / 1024
			throughputIn := bitThroughputIn / 1024 / 1024

			// PLM Latency
			var averageRTTPLM float64
			if rttPacketsPLM > 0 {
				averageRTTPLM = float64(rttSumPLM.Milliseconds()) / float64(rttPacketsPLM)
			}

			// ERM Values
			flowCountERM := flowErrorRateMap.GetFlowCount()
			var duplicateRateERM float64
			if duplicatesERM > 0 {
				duplicateRateERM = float64(duplicatesERM) / float64(tcpPacketsCount) * 100
			}

			// FlowMap Beta Test

			flowCount := completeFlowMap.Len()
			var appCount int
			flows := completeFlowMap.Flows
			for _, flow := range flows {
				apps := flow.ApplicationMap.Applications
				appCount += len(apps)
			}
			flowPacketsIn, flowPacketsOut, flowBytesIncoming, flowBytesOutgoing, flowQuicPackets := completeFlowMap.StatisticsAndMaintenance()
			flowBitThroughputIncoming := float64(flowBytesIncoming) / elapsedTime.Seconds() * 8
			flowBitThroughputOutgoing := float64(flowBytesOutgoing) / elapsedTime.Seconds() * 8
			flowThroughputIncoming := flowBitThroughputIncoming / 1024 / 1024
			flowThroughputOutgoing := flowBitThroughputOutgoing / 1024 / 1024

			// End of Calculations
			//////////////////////////////////////////////////////////////////////////////
			// Print Information
			if printStats {
				fmt.Println()
				fmt.Println(strings.Repeat("\u2500", 80))
				fmt.Println(time.Now())
				fmt.Printf("FLOWMAP Flow Count: %d\n", flowCount)
				fmt.Printf("FLOWMAP App Count: %d\n", appCount)
				fmt.Printf("FLOWMAP Packets Out: %d | FLOWMAP Packets In: %d\n", flowPacketsOut, flowPacketsIn)
				fmt.Printf("FLOWMAP Throughput Out: %.3f Mbit/s | FLOWMAP Throughput In: %.3f Mbit/s\n", flowThroughputOutgoing, flowThroughputIncoming)
				fmt.Printf("Throughput Out: %.3f Mbit/s | Throughput In: %.3f Mbit/s\n", throughputOut, throughputIn)
				fmt.Printf("Packet Count Total: %d Packet Count Flow Map: %d Packet Count Non TCP/IP: %d\n", packets, flowPacketsOut+flowPacketsIn, debugOtherPackets)
				fmt.Printf("TCP Packets: %d Other Packets: %d TCP Rate: %1.f%%\n", tcpPacketsCount, otherPackets, tcpPacketRate)
				//fmt.Println("Size of tcpPackets map:", (tcpPacketsCount*69+(16+40)*len(tcpFlowIPs))/1024, "kB")
				//fmt.Println("Incorrect Packages:", incorrectPackets, "Might be completely off")
				fmt.Printf("PLM Size: %d PLM Latency for %d Packets: %.1fms\n", outgoingPacketPLM.Len(), rttPacketsPLM, averageRTTPLM)
				fmt.Printf("ERM Flow Count: %d Rough ERM Packet Size: %d ERM Packets Considered: %d \n", flowCountERM, flowCountERM*100, packetCountERM)
				fmt.Printf("ERM found %d duplicate Packets for a rate of %.1f%%\n", duplicatesERM, duplicateRateERM)
				fmt.Printf("ERM DupAck %d ERM fast Retransmit %d slow Retransmit %d\n", duplicateAckERM, fastRetransmitERM, slowRetransmitERM)
				fmt.Printf("QUIC Packets Old: %d New: %d\n", quicPackets, flowQuicPackets)

			}

			// End of Print
			//////////////////////////////////////////////////////////////////////////////
			// Writing to DB
			remoteText := "remote"
			if !config.Pcap.UseRemote {
				remoteText = "local"
			}
			device := config.InfluxV1.TestDevice + "_" + remoteText

			// tags := map[string]string{"filter": filterName, "device": device}
			tags := map[string]string{
				"filter": filterName,
				"device": device,
				"src_ip": srcIP.String(), // Add Source IP
				"dst_ip": dstIP.String(), // (Optional) Add Destination IP
			}
			fields := map[string]interface{}{
				"packetsOut":        flowPacketsOut,
				"packetsIn":         flowPacketsIn,
				"throughputOut":     flowBitThroughputOutgoing,
				"throughputIn":      flowBitThroughputIncoming,
				"flowMapFlows":      flowCount,
				"flowMapApps":       appCount,
				"packetCountERM":    packetCountERM,
				"flowCountERM":      flowCountERM,
				"duplicatesERM":     duplicatesERM,
				"duplicateRateERM":  duplicateRateERM,
				"duplicateAckERM":   duplicateAckERM,
				"fastRetransmitERM": fastRetransmitERM,
				"slowRetransmitERM": slowRetransmitERM,
			}
			if averageRTTPLM > 0 {
				fields["passiveRTT"] = averageRTTPLM
			}

			influxv1.WriteLine("general_stats", tags, fields)

			// End of Influx
			//////////////////////////////////////////////////////////////////////////////
			// Reset of variables
			totalBytesOut = 0
			totalBytesIn = 0
			packets = 0
			tcpPacketsCount = 0
			udpPacketsCount = 0
			incorrectPackets = 0
			startTime = time.Now()
			rttPacketsPLM = 0
			rttSumPLM = time.Duration(0)
			packetCountERM = 0
			duplicatesERM = 0
			fastRetransmitERM = 0
			slowRetransmitERM = 0
			duplicateAckERM = 0
			quicPackets = 0
			debugOtherPacketsSize = 0
			debugOtherPackets = 0
			// End of Reset
			//////////////////////////////////////////////////////////////////////////////
			// Garbage Control
			deletedERM := flowErrorRateMap.DeleteInactiveFlows(1 * time.Minute)
			if deletedERM > 0 {
				fmt.Println(strings.Repeat("\u2504", 80))
				fmt.Printf("ERM deleted %d inactive flows\n", deletedERM)
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Main

func main() {
	config.ReadJsonConfig()
	if !influxv1.CheckInfluxConnection() {
		fmt.Println("Cannot establish connection to Influxdb.\n" +
			"Please check your configuration or Influxdb!\n" +
			"Running in View Mode only.")
		time.Sleep(5 * time.Second)
	}

	if len(config.FlowFilterSettings) == 0 {
		fmt.Println("No flow filter settings found. Exiting")
		os.Exit(1)
	}

	// FixMe: Make BPF Filter in pcapRunner, see https://github.com/nikilase/gopacket_analysis/issues/3

	// Go through all Flow Filter Settings  and start their pcap Runner
	filter := config.FlowFilterSettings[0]
	pcapRunner(filter.FilterName, filter.BpfFilter, true)

}
