package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/thediveo/netdb"
	"gopacket_analysis/config"
	"gopacket_analysis/dpi"
	"gopacket_analysis/models"
	"gopacket_analysis/mydb"
	"gopacket_analysis/mydb/influxv1"
	"io"
	"log"
	_ "modernc.org/sqlite"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func print_all_packet() {
	interfaces, _ := pcap.FindAllDevs()
	for _, iface := range interfaces {
		println(iface.Name)
		println(iface.Description)
		println(iface.Addresses)
		println(iface.Flags)
	}

	if handle, err := pcap.OpenLive("\\Device\\NPF_{8113A098-92AA-4433-B7B2-FA2F12439EFE}", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
		//} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil { // optional
	} else if err := handle.SetBPFFilter(""); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			appLayer := packet.ApplicationLayer()
			if appLayer == nil {
				continue
			}
			packetLayers := packet.Layers()
			linkLayer := packet.LinkLayer()
			if linkLayer.LayerType() == layers.LayerTypeEthernet {
				fmt.Println(linkLayer.LayerType().String())
			} else {
				fmt.Println(linkLayer.LayerType().String())
			}

			//println(packet.String())
			ipLayer := packet.NetworkLayer()
			if ipLayer != nil {
				Protocol := ipLayer.LayerType().String()
				fmt.Println("Network Layer Type:", Protocol)
				if Protocol == "IPv4" {
					ipPacket, _ := ipLayer.(*layers.IPv4)
					fmt.Println("IP source address:", ipPacket.SrcIP)
					fmt.Println("IP destination address:", ipPacket.DstIP)
				} else if Protocol == "IPv6" {
					ipPacket, _ := ipLayer.(*layers.IPv6)
					fmt.Println("IP source address:", ipPacket.SrcIP)
					fmt.Println("IP destination address:", ipPacket.DstIP)
				}

			} else if packetLayers[1].LayerType().String() == "ARP" {
				fmt.Println("Found ARP packet")
				continue
			} else {
				fmt.Println("Found new Network Layer", packet.String())
			}
			transLayer := packet.TransportLayer()
			if transLayer != nil {
				Protocol := transLayer.LayerType().String()
				fmt.Println("Transport Layer Type:", Protocol)
				if Protocol == "TCP" {
					transPacket, _ := transLayer.(*layers.TCP)
					fmt.Println("TCP Source Port:", transPacket.DstPort)
					fmt.Println("TCP Dest Port:", transPacket.SrcPort)
					fmt.Println("TCP Sequence Number:", transPacket.Seq)
				} else if Protocol == "UDP" {
					transPacket, _ := transLayer.(*layers.UDP)
					fmt.Println("TCP Source Port:", transPacket.DstPort)
					fmt.Println("TCP Dest Port:", transPacket.SrcPort)
				} else {
					fmt.Println("Unknown protocol:", transLayer.LayerType().String())
				}

			} else if packetLayers[2].LayerType().String() == "ICMPv4" {
				transPacket, _ := packetLayers[2].(*layers.ICMPv4)
				fmt.Println("Found ICMPv4", transPacket.Id)

			}

			{
				fmt.Println("Application Layer Type:", appLayer.LayerType().String())
				//fmt.Printf("%s\n", appLayer.Payload())
				if strings.Contains(string(appLayer.Payload()), "HTTP") {
					fmt.Println("HTTP found!\n")
				} else {
					x := string(appLayer.Payload())
					fmt.Println(x)
					fmt.Println("Not found!\n")
				}
			}
		}
	}
}

func link_decode(link gopacket.LinkLayer) {

}

func network_decode(network gopacket.NetworkLayer) {

}

func tcp_decode(portMap map[models.PortProtocol]models.MappingInfo, tcpPacket *layers.TCP) {
	srcPort := int(tcpPacket.SrcPort)
	dstPort := int(tcpPacket.DstPort)
	srcService := netdb.ServiceByPort(srcPort, "tcp")
	dstService := netdb.ServiceByPort(dstPort, "tcp")
	if srcService == nil && dstService == nil {
		// No known service by ports, need to further investigate, maybe by common known headers?
		return
	}
	if srcService != nil {
		name := srcService.Name
		pp := models.PortProtocol{Port: srcPort, Protocol: "tcp"}
		if _, ok := portMap[pp]; !ok {
			if mydb.InsertSql(pp, models.MappingInfo{Application: name}, 5) {
				portMap[pp] = models.MappingInfo{Application: name}
			}
		}
	}
	if dstService != nil {
		name := dstService.Name
		pp := models.PortProtocol{Port: dstPort, Protocol: "tcp"}
		if _, ok := portMap[pp]; !ok {
			if mydb.InsertSql(pp, models.MappingInfo{Application: name}, 5) {
				portMap[pp] = models.MappingInfo{Application: name}
			}
		}
	}

	tcpOptions := tcpPacket.Options
	if len(tcpOptions) > 0 {
		fmt.Println(tcpOptions)
	}
}

func udp_decode(portMap map[models.PortProtocol]models.MappingInfo, udpPacket *layers.UDP) {
	srcPort := int(udpPacket.SrcPort)
	dstPort := int(udpPacket.DstPort)
	srcService := netdb.ServiceByPort(srcPort, "udp")
	dstService := netdb.ServiceByPort(dstPort, "udp")
	if srcService == nil && dstService == nil {
		// No known service by ports, need to further investigate, maybe by common known headers?
		return
	}
	if srcService != nil {
		name := srcService.Name
		pp := models.PortProtocol{Port: srcPort, Protocol: "udp"}
		if _, ok := portMap[pp]; !ok {
			if mydb.InsertSql(pp, models.MappingInfo{Application: name}, 5) {
				portMap[pp] = models.MappingInfo{Application: name}
			}
		}
	}
	if dstService != nil {
		name := dstService.Name
		pp := models.PortProtocol{Port: dstPort, Protocol: "udp"}
		if _, ok := portMap[pp]; !ok {
			if mydb.InsertSql(pp, models.MappingInfo{Application: name}, 5) {
				portMap[pp] = models.MappingInfo{Application: name}
			}
		}
	}
}

func ipDecode(srcIP net.IP, dstIP net.IP, proto string, packet gopacket.Packet) {
	transportLayer := packet.TransportLayer()
	if dstIP.Equal(net.ParseIP("192.168.10.2")) {
		fmt.Print()
	}
	var srcPort, dstPort int
	switch proto {
	case "tcp":
		transPacket, _ := transportLayer.(*layers.TCP)
		nlt := transPacket.NextLayerType().String()
		if (transPacket.SYN || transPacket.ACK || transPacket.FIN || transPacket.RST || true) && len(transPacket.Payload) == 0 {
			packetStat["TCP_Handshake"]++
			addToPcap(packet, "tcp_handshake")
			return
		}
		if nlt == "Payload" {
			srcPort = int(transPacket.SrcPort)
			dstPort = int(transPacket.DstPort)
		} else {
			packetStat[nlt]++
			addToPcap(packet, nlt)
			return
		}

	case "udp":
		transPacket, _ := transportLayer.(*layers.UDP)
		nlt := transPacket.NextLayerType().String()
		if nlt == "Payload" {
			srcPort = int(transPacket.SrcPort)
			dstPort = int(transPacket.DstPort)
		} else {
			packetStat[nlt]++
			addToPcap(packet, nlt)
			return
		}
	default:
		return
	}

	srcService := netdb.ServiceByPort(srcPort, proto)
	dstService := netdb.ServiceByPort(dstPort, proto)
	if srcService != nil && dstService != nil {
		packetStat["Found_"+srcService.Name+"_"+dstService.Name]++
		addToPcap(packet, "Found_"+srcService.Name+"_"+dstService.Name)
	} else if srcService != nil {
		packetStat["Found_"+srcService.Name]++
		addToPcap(packet, "Found_"+srcService.Name)
	} else if dstService != nil {
		packetStat["Found_"+dstService.Name]++
		addToPcap(packet, "Found_"+dstService.Name)
	} else {
		// Hence srcService == nil && dstService == nil
		foundDpi := dpi.DpiPacket(packet)
		if foundDpi != "" {
			packetStat["Found_"+foundDpi]++
			addToPcap(packet, foundDpi)
		} else {
			if dstPort == 1900 {
				packetStat["Found_SSDP"]++
				addToPcap(packet, "SSDP")
				return
			}
			if srcPort == 48000 && dstPort == 48000 && dstIP.Equal(net.ParseIP("239.254.127.63")) {
				packetStat["Found_UbiquityMembershipReport"]++
				addToPcap(packet, "UbiquityMembershipReport")
				return
			}
			if srcPort == 1883 || dstPort == 1883 {
				packetStat["Found_MQTT"]++
				addToPcap(packet, "MQTT")
				return
			}

			packetStat[fmt.Sprintf("Unknown_%s", proto)]++
			addToPcap(packet, "unknown")
			fmt.Printf("Unkwn_%d_%d\n", srcPort, dstPort)

		}
	}

}

var packetStat models.PacketCounts

func pcapInit() (*gopacket.PacketSource, error) {
	if config.Pcap.UseRemote {
		fmt.Println("Using remote pcap on 192.168.1.1")
		rStdout, wStdout := io.Pipe()

		sshCommand := exec.Command("ssh", "nikilase@192.168.1.1", "sudo tcpdump -i eth0 -n --immediate-mode -s 1600 -U -w - ")
		sshCommand.Stdout = wStdout

		if err := sshCommand.Start(); err != nil {
			return nil, err
		}

		reader, err := pcapgo.NewReader(rStdout)
		if err != nil {
			return nil, err
		}

		packetSource := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)
		packetSource.Lazy = true
		packetSource.NoCopy = true
		return packetSource, nil
	} else {
		fmt.Println("Using local pcap on ", config.Pcap.LocalDevice)
		if handle, err := pcap.OpenLive(config.Pcap.LocalDevice, 1600, true, pcap.BlockForever); err != nil {
			return nil, err
		} else if err := handle.SetBPFFilter(""); err != nil { // optional
			return nil, err
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			return packetSource, nil
		}
	}
}

func pcapRunner(portMap map[models.PortProtocol]models.MappingInfo) {
	i := 0
	analyzed := 0
	packetStat = make(models.PacketCounts)
	lastExec := time.Now()
	mydb.LastPacketsReset()
	lastLog := "lastLog"
	err := os.Remove("pcaps/" + lastLog + ".pcap")
	if err != nil {
		fmt.Println(err)
	}
	packetSource, psErr := pcapInit()
	if psErr != nil {
		log.Fatal(psErr)
	}

	// Feature: Throughput
	var totalBytesIn uint64
	var totalBytesOut uint64
	startTime := time.Now()
	ownMAC, _ := net.ParseMAC(config.Pcap.LocalMac)
	var alreadySeen = make(map[uint32]time.Time)
	fastRetransmits := 0
	retransmits := 0
	packets := 0
	dupAck := 0
	for packet := range packetSource.Packets() {
		// Feature: Throughput
		packets++
		Layer0 := packet.LinkLayer()
		if Layer0 == nil {
			packetStat["No Link"]++
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

		if packet.TransportLayer() != nil && packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
			tcpPacket := packet.TransportLayer().(*layers.TCP)
			if _, exists := alreadySeen[tcpPacket.Seq]; exists {
				if tcpPacket.ACK && len(tcpPacket.Payload) == 0 {
					dupAck++
				} else if packet.Metadata().Timestamp.Sub(alreadySeen[tcpPacket.Seq]) > 100*time.Millisecond {
					retransmits++
				} else {
					fastRetransmits++
				}
			}
			alreadySeen[tcpPacket.Seq] = packet.Metadata().Timestamp
		}

		size := packet.Metadata().Length
		outgoingTraffic := ethernet.SrcMAC.String() == ownMAC.String()

		if outgoingTraffic {
			totalBytesOut += uint64(size)
		} else {
			totalBytesIn += uint64(size)
		}

		// Calculate throughput every second
		elapsedTime := time.Since(startTime)
		if elapsedTime >= 1*time.Second {
			bitThroughputOut := float64(totalBytesOut) / elapsedTime.Seconds() * 8
			bitThroughputIn := float64(totalBytesIn) / elapsedTime.Seconds() * 8
			throughputOut := bitThroughputOut / 1024 / 1024
			throughputIn := bitThroughputIn / 1024 / 1024
			fmt.Println(strings.Repeat("\u2500", 80))
			fmt.Printf("Throughput Out: %.3f Mbit/s | Throughput In: %.3f Mbit/s\n", throughputOut, throughputIn)
			fmt.Printf("Retransmits: %d | Fast Retransmits: %d\n", retransmits, fastRetransmits)
			retransRate := float64(retransmits) / float64(packets) * 100
			fastRetransRate := float64(fastRetransmits) / float64(packets) * 100
			fmt.Printf("Packets: %d | Retransmit Rate %.1f%% | Fast Retransmit Rate %.1f%%\n", packets, retransRate, fastRetransRate)
			fmt.Printf("Dup Ack: %d\n", dupAck)
			fmt.Printf("Length of already seen map: %d\n", len(alreadySeen))

			// Writing to DB
			remoteText := "remote"
			if !config.Pcap.UseRemote {
				remoteText = "local"
			}
			device := config.InfluxV1.TestDevice + "_" + remoteText

			tags := map[string]string{"filter": "all", "device": device}
			fields := map[string]interface{}{
				"packets":         packets,
				"throughputOut":   bitThroughputOut,
				"throughputIn":    bitThroughputIn,
				"retransmits":     retransmits,
				"fastRetransmits": fastRetransmits,
				"retransRate":     retransRate,
				"fastRetransRate": fastRetransRate,
				"dupAck":          dupAck,
				"alreadySeen":     len(alreadySeen),
			}
			influxv1.WriteLine("general_stats", tags, fields)

			// Reset of variables
			totalBytesOut = 0
			totalBytesIn = 0
			fastRetransmits = 0
			retransmits = 0
			packets = 0
			dupAck = 0
			startTime = time.Now()
		}
		continue

		// Debug stuff only
		addToPcap(packet, lastLog)
		foundLayers := []string{"None", "None", "None", "None", "None"}
		data := "None"
		for l, layer := range packet.Layers() {
			foundLayers[l] = layer.LayerType().String()
			data = string(packet.Data())
		} /*
			if len(packet.Layers()) >= 4 {
				fmt.Println("\nFound layers ", foundLayers)
				fmt.Println("With Link Layer ", packet.LinkLayer().LayerType())
				fmt.Println("With Network Layer ", packet.NetworkLayer().LayerType())
				fmt.Println("With Transport Layer ", packet.TransportLayer().LayerType())
				fmt.Println("With App Layer ", packet.ApplicationLayer().LayerType())
				fmt.Println("With App Layer Content ", packet.ApplicationLayer().LayerContents())
				fmt.Println("With App Layer Payload ", packet.ApplicationLayer().LayerPayload())
				fmt.Println("With App Payload ", packet.ApplicationLayer().Payload())
			}*/

		mydb.LastPacketsInsert(i, foundLayers[0], foundLayers[1], foundLayers[2], foundLayers[3], foundLayers[4], data, packet.Dump(), 5)
		i++

		/***************************************
		Actual Handling
		 ***************************************/
		// LINK LAYER: ONLY ETHERNET
		if time.Now().Sub(lastExec) > 1*time.Minute {
			fmt.Println(packetStat)
			mydb.InfInsertStat(packetStat)
			clear(packetStat)
			analyzed = 0
			lastExec = time.Now()
		}
		analyzed++
		linkLayer := packet.LinkLayer()
		if linkLayer == nil {
			packetStat["No Link"]++
			addToPcap(packet, "No_Link")
			fmt.Println("No link layer for\n", packet)
			continue
		}

		var ethernetLayer *layers.Ethernet
		var srcMac net.HardwareAddr
		var dstMac net.HardwareAddr
		switch linkLayer.LayerType() {
		case layers.LayerTypeEthernet:
			ethernetLayer = linkLayer.(*layers.Ethernet)
			srcMac = ethernetLayer.SrcMAC
			dstMac = ethernetLayer.DstMAC
		default:
			fmt.Println("Found unexpected layer type\n", linkLayer.LayerType())
			fmt.Println(packet)

			packetStat["ETH_"+linkLayer.LayerType().String()]++
			addToPcap(packet, "ETH_"+linkLayer.LayerType().String())
			continue
		}
		_ = srcMac
		_ = dstMac

		// NETWORK LAYER: ONLY IP (non ICMP)
		netLayer := packet.NetworkLayer()
		if netLayer != nil {
			// Found IP Layers
			switch netLayer.LayerType() {
			case layers.LayerTypeIPv4:
				ipLayer := netLayer.(*layers.IPv4)
				_ = ipLayer.SrcIP
				if ipLayer.NextLayerType() == layers.LayerTypeICMPv4 {
					//fmt.Println("ICMPv4", packet)
				} else if ipLayer.NextLayerType() == layers.LayerTypeIPSecAH || ipLayer.NextLayerType() == layers.LayerTypeIPSecESP {

				} else if ipLayer.NextLayerType() == layers.LayerTypeTCP {
					ipDecode(ipLayer.SrcIP, ipLayer.DstIP, "tcp", packet)
				} else if ipLayer.NextLayerType() == layers.LayerTypeUDP {
					ipDecode(ipLayer.SrcIP, ipLayer.DstIP, "udp", packet)
				} else {
					ipDecode(ipLayer.SrcIP, ipLayer.DstIP, "", packet)
				}
				packetStat["IPv4_"+ipLayer.NextLayerType().String()]++
				addToPcap(packet, "IPv4_"+ipLayer.NextLayerType().String())

			case layers.LayerTypeIPv6:
				ipLayer := netLayer.(*layers.IPv6)
				_ = ipLayer.SrcIP
				if ipLayer.NextLayerType() == layers.LayerTypeICMPv6 {
					//fmt.Println("ICMPv6", packet)
				} else if ipLayer.NextLayerType() == layers.LayerTypeIPSecAH || ipLayer.NextLayerType() == layers.LayerTypeIPSecESP {

				} else if ipLayer.NextLayerType() == layers.LayerTypeTCP {
					ipDecode(ipLayer.SrcIP, ipLayer.DstIP, "tcp", packet)
				} else if ipLayer.NextLayerType() == layers.LayerTypeUDP {
					ipDecode(ipLayer.SrcIP, ipLayer.DstIP, "udp", packet)
				} else {
					ipDecode(ipLayer.SrcIP, ipLayer.DstIP, "", packet)
				}
				packetStat["IPv6_"+ipLayer.NextLayerType().String()]++
				addToPcap(packet, "IPv6_"+ipLayer.NextLayerType().String())

			default:
				fmt.Println("Found unexpected Network layer type\n", netLayer.LayerType())
				packetStat["Net_"+netLayer.LayerType().String()]++
				addToPcap(packet, "Net_"+netLayer.LayerType().String())
			}
		} else {
			nextLayer := packet.Layers()[1]
			_ = nextLayer
			switch ethernetLayer.NextLayerType() {
			case layers.LayerTypeLLC, layers.LayerTypeARP, layers.LayerTypeLinkLayerDiscovery:
				// LLC should only be in Local Network from a mac to the broadcast mac, so not important
				// ARP similarly only broadcasts to the LAN
				// LinkLayerDiscovery
				packetStat["L2_"+ethernetLayer.NextLayerType().String()]++
				addToPcap(packet, "L2_"+ethernetLayer.NextLayerType().String())
				continue
			case layers.LayerTypeDot1Q:
				// Should be done beforehand as this is just a layer for the VLAN Tag
				// Maybe detect this before the switch and change out the netLayer then?

			default:
				x := ethernetLayer.EthernetType
				if x == 35085 {
					// Some Ubiquity WiFi management stuff: https://community.ui.com/questions/Multicast-announcements/d539e024-c8a2-42b7-8918-dbf408edfab7
					packetStat["L2_UbiquityRRI"]++
					addToPcap(packet, "L2_UbiquityRRI")
					continue
				} else {
					fmt.Println("No network layer for\n", packet)
					packetStat["L2_"+ethernetLayer.NextLayerType().String()]++
					addToPcap(packet, "L2_"+ethernetLayer.NextLayerType().String())
				}
				continue
			}

		}

		continue
		transLayer := packet.TransportLayer()
		if transLayer != nil {
			Protocol := transLayer.LayerType().String()

			switch Protocol {
			case "TCP":
				tcpPacket, _ := transLayer.(*layers.TCP)
				tcp_decode(portMap, tcpPacket)
			case "UDP":
				udp, _ := transLayer.(*layers.UDP)
				udp_decode(portMap, udp)
			default:
				fmt.Println("Unknown protocol:", transLayer.LayerType().String())
			}
		}
	}
}

func get_ports(portMap map[models.PortProtocol]models.MappingInfo) {
	/*interfaces, _ := pcap.FindAllDevs()
	for _, iface := range interfaces {
		println(iface.Name)
		println(iface.Description)
		println(iface.Addresses)
		println(iface.Flags)
	}
	*/

	if handle, err := pcap.OpenLive("\\Device\\NPF_{8113A098-92AA-4433-B7B2-FA2F12439EFE}", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
		//} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil { // optional
	} else if err := handle.SetBPFFilter(""); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		if runtime.GOOS == "linux " {

			//godpi.Initialize()
			//defer godpi.Destroy()
		} else {

		}

		for packet := range packetSource.Packets() {
			if runtime.GOOS == "linux " {
				/*flow, _ := godpi.GetPacketFlow(packet)
				result := godpi.ClassifyFlow(flow)
				if result.Protocol != types.Unknown {
					fmt.Println(result.Source, "detected protocol", result.Protocol)
				} else {
					fmt.Println("No detection was made")
				}*/
				_ = packet
			}

			continue
			/*
				transLayer := packet.TransportLayer()

				if transLayer != nil {
					Protocol := transLayer.LayerType().String()
					//fmt.Println("Transport Layer Type:", Protocol)

					switch Protocol {
					case "TCP":
						transPacket, _ = transLayer.(*layers.TCP)
					case "UDP":
						transPacket, _ = transLayer.(*layers.UDP)
					default:
						fmt.Println("Unknown protocol:", transLayer.LayerType().String())
					}
					if Protocol == "TCP" {
						transPacket, _ := transLayer.(*layers.TCP)

						dns := netdb.ServiceByPort(int(transPacket.DstPort), "tcp")
						pp := portProtocol{int(transPacket.DstPort), "tcp"}
						var name string
						if dns != nil {
							name = dns.Name
						} else {
							continue
						}
						if _, ok := portMap[pp]; !ok {
							if insert_sql(pp, mappingInfo{name, ""}, 5) {
								portMap[pp] = mappingInfo{name, ""}
							}
						}

						dns = netdb.ServiceByPort(int(transPacket.SrcPort), "tcp")
						pp = portProtocol{int(transPacket.SrcPort), "tcp"}
						if dns != nil {
							name = dns.Name
						} else {
							continue
						}

						if _, ok := portMap[pp]; !ok {
							if insert_sql(pp, mappingInfo{name, ""}, 5) {
								portMap[pp] = mappingInfo{name, ""}
							}
						}

						//fmt.Println("TCP Source Port:", transPacket.DstPort)
						//fmt.Println("TCP Dest Port:", transPacket.SrcPort)
						//fmt.Println("TCP Sequence Number:", transPacket.Seq)
					} else if Protocol == "UDP" {
						transPacket, _ := transLayer.(*layers.UDP)
						_ = transPacket
						dns := netdb.ServiceByPort(int(transPacket.DstPort), "udp")
						pp := portProtocol{int(transPacket.DstPort), "udp"}
						if dns != nil {
							if _, ok := portMap[pp]; !ok {
								if insert_sql(pp, mappingInfo{dns.Name, ""}, 5) {
									portMap[pp] = mappingInfo{dns.Name, ""}
								}
							}
						}
						dns = netdb.ServiceByPort(int(transPacket.SrcPort), "udp")
						pp = portProtocol{int(transPacket.SrcPort), "udp"}
						if dns != nil {
							if _, ok := portMap[pp]; !ok {
								if insert_sql(pp, mappingInfo{dns.Name, ""}, 5) {
									portMap[pp] = mappingInfo{dns.Name, ""}
								}
							}
						}

						//fmt.Println("TCP Source Port:", transPacket.DstPort)
						//fmt.Println("TCP Dest Port:", transPacket.SrcPort)
					} else {
						//fmt.Println("Unknown protocol:", transLayer.LayerType().String())
					}

				}
			*/
		}
	}
}

func addToPcap(packet gopacket.Packet, packetType string) {
	newFile := false
	_ = newFile
	f, err := os.OpenFile("pcaps/"+packetType+".pcap", os.O_APPEND|os.O_WRONLY, 0700)
	if err != nil {
		fmt.Println(err)
		f, err = os.Create("pcaps/" + packetType + ".pcap")
		if err != nil {
			fmt.Println(err)
			return
		}
		newFile = true
	}
	defer func(f *os.File) {
		cErr := f.Close()
		if cErr != nil {
			fmt.Println(cErr)
		}
	}(f)

	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		fmt.Println(err)
	}
	defer func(w *pcapgo.NgWriter) {
		err := w.Flush()
		if err != nil {
			fmt.Println(err)
		}
	}(w)
	err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	mydb.ReadDummy()
	config.ReadJsonConfig()
	fmt.Println("Using Remote:", config.Pcap.UseRemote, " Using Local Device:", config.Pcap.LocalDevice)
	dns := netdb.ServiceByPort(5060, "udp")
	fmt.Println(dns.Name)

	mydb.InitSql()
	portMap := mydb.RetrieveSql()
	for key, value := range portMap {
		if value.Application != "unknown" {
			fmt.Println("Port:", key.Port, "Protocol:", key.Protocol, "Application:", value.Application, "Comment:", value.Comment)
		}

	}
	mydb.InsertSql(models.PortProtocol{Port: 5060, Protocol: "udp"}, models.MappingInfo{Application: "sip", Comment: "followed by different port negotiated in initial request"}, 0)
	mydb.InsertSql(models.PortProtocol{Port: 5061, Protocol: "tcp"}, models.MappingInfo{Application: "sip", Comment: "sip secured by tls, need to find data stream manually"}, 0)
	fmt.Println()
	//get_ports(portMap)
	//dpiPacket()
	pcapRunner(portMap)

	/*
		var snapshotLen int32 = 102400
		var timeout time.Duration = 1 * time.Second
		var handle *pcap.Handle

		handle, _ = pcap.OpenLive("eth0", snapshotLen, true, timeout)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			println(packet)
		}
		/*
			// Decode a packet
			packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				fmt.Println("This is a TCP packet!")
				// Get actual TCP data from this layer
				tcp, _ := tcpLayer.(*layers.TCP)
				fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
			}
			// Iterate over all layers, printing out each layer type
			for _, layer := range packet.Layers() {
				fmt.Println("PACKET LAYER:", layer.LayerType())
			}*/
}
