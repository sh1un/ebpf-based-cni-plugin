package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

// Note: This must be kept in sync with bpf/include/api.h
type PolicyKey struct {
	SrcID uint32
	DstID uint32
}

const (
	bpfPinPath    = "/sys/fs/bpf/tc/globals"
	policyMapName = "policy_map"
	ActionAllow   = 1
)

func main() {
	// --- 1. Setup Logging ---
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	// --- 2. Define and Parse CLI Flags ---
	allowCmd := flag.NewFlagSet("allow", flag.ExitOnError)
	allowSrc := allowCmd.Uint("src", 0, "Source identity")
	allowDst := allowCmd.Uint("dst", 0, "Destination identity")
	allowSym := allowCmd.Bool("symmetric", false, "Create a symmetric rule (src <-> dst)")

	denyCmd := flag.NewFlagSet("deny", flag.ExitOnError)
	denySrc := denyCmd.Uint("src", 0, "Source identity")
	denyDst := denyCmd.Uint("dst", 0, "Destination identity")
	denySym := denyCmd.Bool("symmetric", false, "Remove a symmetric rule (src <-> dst)")

	if len(os.Args) < 2 {
		logrus.Fatalf("Usage: %s <allow|deny> [options]", os.Args[0])
	}

	// --- 3. Load eBPF Map ---
	mapPath := filepath.Join(bpfPinPath, policyMapName)
	policyMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		logrus.Fatalf("Failed to load pinned map %s: %v", mapPath, err)
	}
	defer policyMap.Close()

	// --- 4. Execute Command ---
	switch os.Args[1] {
	case "allow":
		allowCmd.Parse(os.Args[2:])
		if *allowSrc == 0 || *allowDst == 0 {
			allowCmd.Usage()
			os.Exit(1)
		}
		key := PolicyKey{SrcID: uint32(*allowSrc), DstID: uint32(*allowDst)}
		value := uint8(ActionAllow)
		if err := policyMap.Put(&key, &value); err != nil {
			logrus.Fatalf("Failed to add allow rule: %v", err)
		}
		logrus.Infof("Successfully allowed %d -> %d", key.SrcID, key.DstID)

		if *allowSym {
			key.SrcID, key.DstID = key.DstID, key.SrcID // Swap
			if err := policyMap.Put(&key, &value); err != nil {
				logrus.Fatalf("Failed to add symmetric allow rule: %v", err)
			}
			logrus.Infof("Successfully allowed %d -> %d (symmetric)", key.SrcID, key.DstID)
		}

	case "deny":
		denyCmd.Parse(os.Args[2:])
		if *denySrc == 0 || *denyDst == 0 {
			denyCmd.Usage()
			os.Exit(1)
		}
		key := PolicyKey{SrcID: uint32(*denySrc), DstID: uint32(*denyDst)}
		if err := policyMap.Delete(&key); err != nil {
			logrus.Fatalf("Failed to remove rule: %v", err)
		}
		logrus.Infof("Successfully denied %d -> %d", key.SrcID, key.DstID)

		if *denySym {
			key.SrcID, key.DstID = key.DstID, key.SrcID // Swap
			if err := policyMap.Delete(&key); err != nil {
				logrus.Fatalf("Failed to remove symmetric rule: %v", err)
			}
			logrus.Infof("Successfully denied %d -> %d (symmetric)", key.SrcID, key.DstID)
		}

	default:
		logrus.Fatalf("Unknown command: %s", os.Args[1])
	}

	// --- 5. (Optional) Display Map Contents ---
	logrus.Info("\nCurrent policy map state:")
	var (
		key   PolicyKey
		value uint8
	)
	iter := policyMap.Iterate()
	for iter.Next(&key, &value) {
		action := "deny"
		if value == ActionAllow {
			action = "allow"
		}
		logrus.Infof("  - SrcID: %-5d | DstID: %-5d | Action: %s", key.SrcID, key.DstID, action)
	}
	if err := iter.Err(); err != nil {
		logrus.Errorf("Failed to iterate map: %v", err)
	}
}
