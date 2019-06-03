package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var handle *pcap.Handle
	var err error

	microPtr := flag.Bool("micro", false, "microseconds, without it all times are nanoseconds")
	var div int64 = 1
	if *microPtr {
		div = 1000
	}
	flag.Parse()

	files := flag.Args()

	for i := range files {
		file := files[i]
		handle, err = pcap.OpenOffline(file)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		deltas := make([]string, 0)
		var last *time.Time
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			ts := packet.Metadata().CaptureInfo.Timestamp
			if last == nil {
				last = &ts
			} else {
				deltas = append(deltas, strconv.FormatInt(ts.Sub(*last).Nanoseconds()/div, 10))
				last = &ts
			}
		}
		//fmt.Printf("%#v\n", deltas)
		fmt.Println(strings.Join(deltas, ","))
	}
}
