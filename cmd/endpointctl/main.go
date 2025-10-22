package main

import (
	"encoding/binary"
	"flag"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

const (
	bpfPinPath      = "/sys/fs/bpf/tc/globals"
	endpointMapName = "endpoint_map"
)

func main() {
	// --- 1. Setup Logging ---
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	// --- 2. Define and Parse CLI Flags ---
	addCmd := flag.NewFlagSet("add", flag.ExitOnError)
	addIP := addCmd.String("ip", "", "IP address of the endpoint")
	addID := addCmd.Uint("identity", 0, "Security identity of the endpoint")

	delCmd := flag.NewFlagSet("del", flag.ExitOnError)
	delIP := delCmd.String("ip", "", "IP address of the endpoint to delete")

	if len(os.Args) < 2 {
		logrus.Fatalf("Usage: %s <add|del> [options]", os.Args[0])
	}

	// --- 3. Load eBPF Map ---
	mapPath := filepath.Join(bpfPinPath, endpointMapName)
	endpointMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		logrus.Fatalf("Failed to load pinned map %s: %v", mapPath, err)
	}
	defer endpointMap.Close()

	// --- 4. Execute Command ---
	switch os.Args[1] {
	case "add":
		addCmd.Parse(os.Args[2:])
		if *addIP == "" || *addID == 0 {
			addCmd.Usage()
			os.Exit(1)
		}
		ip := net.ParseIP(*addIP)
		if ip == nil {
			logrus.Fatalf("Invalid IP address format: %s", *addIP)
		}
		// Convert IP to a 4-byte representation and then to a host-order uint32
		ip4 := ip.To4()
		if ip4 == nil {
			logrus.Fatalf("Only IPv4 addresses are supported")
		}
		key := binary.BigEndian.Uint32(ip4)
		value := uint32(*addID)

		if err := endpointMap.Put(&key, &value); err != nil {
			logrus.Fatalf("Failed to add endpoint: %v", err)
		}
		logrus.Infof("Successfully added endpoint: IP=%s, ID=%d", *addIP, *addID)

	case "del":
		delCmd.Parse(os.Args[2:])
		if *delIP == "" {
			delCmd.Usage()
			os.Exit(1)
		}
		ip := net.ParseIP(*delIP)
		if ip == nil {
			logrus.Fatalf("Invalid IP address format: %s", *delIP)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			logrus.Fatalf("Only IPv4 addresses are supported")
		}
		key := binary.BigEndian.Uint32(ip4)

		if err := endpointMap.Delete(&key); err != nil {
			logrus.Fatalf("Failed to delete endpoint: %v", err)
		}
		logrus.Infof("Successfully deleted endpoint: IP=%s", *delIP)

	default:
		logrus.Fatalf("Unknown command: %s", os.Args[1])
	}

	// --- 5. (Optional) Display Map Contents ---
	logrus.Info("\nCurrent endpoint map state:")
	var (
		key   uint32
		value uint32
	)
	iter := endpointMap.Iterate()
	for iter.Next(&key, &value) {
		// Convert the uint32 IP back to a string for display
		ipBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ipBytes, key)
		ip := net.IP(ipBytes)
		logrus.Infof("  - IP: %-15s | Identity: %d", ip.String(), value)
	}
	if err := iter.Err(); err != nil {
		logrus.Errorf("Failed to iterate map: %v", err)
	}
}
