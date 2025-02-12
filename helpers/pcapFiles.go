package helpers

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"os"
)

func AddToPcap(packet gopacket.Packet, fileName string) {
	f, err := os.OpenFile("pcaps/"+fileName+".pcap", os.O_APPEND|os.O_WRONLY, 0700)
	if err != nil {
		fmt.Println("Pcap File Open Error:", err)
		f, err = os.Create("pcaps/" + fileName + ".pcap")
		if err != nil {
			fmt.Println("Pcap File Creation Error:", err)
			return
		}
	}
	defer func(f *os.File) {
		cErr := f.Close()
		if cErr != nil {
			fmt.Println("Pcap File Close Error:", cErr)
		}
	}(f)

	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		fmt.Println("Pcap NewNgWriter Error:", err)
	}
	defer func(w *pcapgo.NgWriter) {
		err := w.Flush()
		if err != nil {
			fmt.Println("Pcap Flush NgWriter Error:", err)
		}
	}(w)
	err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	if err != nil {
		fmt.Println("Pcap Write Packet Error:", err)
	}
}
