package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

type internalPcapEvent struct {
	Cookie    uint16
	PacketLen uint16
}

const (
	objectFilename = "elfs/send.o"
	mapName        = "my_map"
	programName    = "xdp_send_prog"
)

func run() error {
	ctx := context.Background()

	err := unlimitLockedMemory()
	if err != nil {
		return fmt.Errorf("error setting locked memory limit: %v", err)
	}

	bytecode, err := ioutil.ReadFile(objectFilename)
	if err != nil {
		return err
	}

	collSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bytecode))
	if err != nil {
		return err
	}

	coll, err := ebpf.NewCollection(collSpec)
	if err != nil {
		return err
	}

	loadedMap := coll.DetachMap(mapName)
	if loadedMap == nil {
		return fmt.Errorf("could not load map of name %s", mapName)
	}
	defer loadedMap.Close()

	rd, err := perf.NewReader(loadedMap, os.Getpagesize())
	if err != nil {
		return err
	}

	loadedProg := coll.DetachProgram(programName)
	if loadedProg == nil {
		return fmt.Errorf("could not load program %s", programName)
	}
	defer loadedProg.Close()

	if err = attachSocketEvent("eth0", loadedProg); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			break
		default:
		}

		r, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return nil
			}
			return err
		}

    if len(r.RawSample) == 0 {
      continue
    }

    fmt.Println(len(r.RawSample))

		var e internalPcapEvent
		if err = binary.Read(bytes.NewBuffer(r.RawSample), binary.LittleEndian, &e); err != nil {
			return err
		}
		packetData := make([]byte, e.PacketLen)
		offset := 4 // cookie (2 bytes) + packet len (2 bytes)
		if err = binary.Read(bytes.NewBuffer(r.RawSample[offset:]), binary.LittleEndian, &packetData); err != nil {
			return err
		}

		fmt.Println(packetData)
	}

	return nil
}

// unlimitLockedMemory removes any locked memory limits
func unlimitLockedMemory() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}

// XdpAttachMode selects a way how XDP program will be attached to interface
type XdpAttachMode int

const (
	// XdpAttachModeNone stands for "best effort" - kernel automatically
	// selects best mode (would try Drv first, then fallback to Generic).
	// NOTE: Kernel will not fallback to Generic XDP if NIC driver failed
	//       to install XDP program.
	XdpAttachModeNone XdpAttachMode = 0
	// XdpAttachModeSkb is "generic", kernel mode, less performant comparing to native,
	// but does not requires driver support.
	XdpAttachModeSkb XdpAttachMode = (1 << 1)
	// XdpAttachModeDrv is native, driver mode (support from driver side required)
	XdpAttachModeDrv XdpAttachMode = (1 << 2)
	// XdpAttachModeHw suitable for NICs with hardware XDP support
	XdpAttachModeHw XdpAttachMode = (1 << 3)
)

func attachSocketEvent(ifaceName string, loadedProg *ebpf.Program) error {
	// Lookup interface by given name, we need to extract iface index
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		// Most likely no such interface
		return fmt.Errorf("LinkByName() failed: %v", err)
	}

	// Attach program
	if err := netlink.LinkSetXdpFdWithFlags(link, loadedProg.FD(), int(XdpAttachModeSkb)); err != nil {
		return fmt.Errorf("LinkSetXdpFd() failed: %v", err)
	}

	return nil
}
