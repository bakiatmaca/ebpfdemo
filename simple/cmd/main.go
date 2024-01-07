package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfEventTcp struct {
	Comm  [16]uint8
	Sport uint16
	Dport uint16
	Saddr uint32
	Daddr uint32
}

func main() {
	log.Println("Simple TCP tracker (eBPF-based)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		panic(err)
	}

	var objs struct {
		TraceTcpProg *ebpf.Program `ebpf:"tcp_connect"`
		EventTcp     *ebpf.Map     `ebpf:"eventtcp"`
	}

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		panic(err)
	}

	tlink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TraceTcpProg,
	})
	if err != nil {
		log.Fatalf("Could not attach eBPF program: %s", err)
	}

	go printEvent(objs.EventTcp)

	defer tlink.Close()
	defer objs.EventTcp.Close()
	defer objs.TraceTcpProg.Close()

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

	var event bpfEventTcp
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
