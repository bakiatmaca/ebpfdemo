package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var pPid = flag.Uint64("pid", 0, "process PID")

//go:generate ../../gen/bpf2go -type skinfo bpf main.bpf.c -- -I../../include
func main() {
	flag.Parse()

	fmt.Println("Start simple TCP tracker (eBPF-based)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	if *pPid <= 0 {
		log.Fatalln("pid cannot be null")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects %v", err)
	}
	defer objs.Close()

	objs.bpfMaps.Inmap.Put(uint32(1), *pPid)

	l, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TcpConnect,
	})
	if err != nil {
		log.Fatalf("Could not attach eBPF program: %s", err)
	}
	defer l.Close()

	go printEvent(objs.Eventtcp)

	//waiting
	<-sig

	log.Println("ebpf prog closed")

}

func printEvent(m *ebpf.Map) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	log.Printf("%-16s %-15s %-6s -> %-15s %-6s",
		"Comm",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
	)

	var event bpfSkinfo
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("%-16s %-15s %-6d -> %-15s %-6d",
			event.Comm,
			intToIP(event.Saddr),
			event.Sport,
			intToIP(event.Daddr),
			event.Dport,
		)
	}
}

func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
