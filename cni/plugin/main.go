package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	_ "github.com/cilium/ebpf"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc /opt/homebrew/opt/llvm/bin/clang -target bpf bpf ../../bpf/kernel/ebpfcni.bpf.c -- -I../../headers -I../../bpf/libbpf_headers -I../../bpf/include

const (
	// Use a global path for maps, similar to Cilium, to decouple map lifecycle from pod lifecycle.
	bpfPinPath    = "/sys/fs/bpf/tc/globals"
	cacheDir      = "/var/run/ebpfcni"
	defaultBridge = "cni0"
)

// CacheData defines the structure for storing network info.
type CacheData struct {
	HostVethName string `json:"host_veth_name"`
}

// NetConf defines the CNI network configuration.
type NetConf struct {
	types.NetConf
	Bridge string `json:"bridge"`
}

func init() {
	// Ensure the main function runs on the same OS thread.
	// This is necessary because network namespace operations (setns) are thread-local.
	runtime.LockOSThread()
}

// setupBridge creates and configures a bridge if it doesn't exist.
func setupBridge(n *NetConf) (*netlink.Bridge, error) {
	brName := n.Bridge
	if brName == "" {
		brName = defaultBridge
	}

	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
			MTU:  1500,
			// Let kernel handle MAC address generation
		},
	}

	// Try to get the bridge link
	l, err := netlink.LinkByName(brName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Bridge does not exist, create it
			logrus.Infof("Bridge %s does not exist, creating...", brName)
			if err := netlink.LinkAdd(br); err != nil {
				return nil, fmt.Errorf("could not create bridge %s: %v", brName, err)
			}
			l = br
		} else {
			return nil, fmt.Errorf("failed to find bridge %s: %v", brName, err)
		}
	}

	// Check if the link is a bridge
	if _, ok := l.(*netlink.Bridge); !ok {
		return nil, fmt.Errorf("link %s already exists but is not a bridge", brName)
	}

	// Set the bridge link up
	if err := netlink.LinkSetUp(l); err != nil {
		return nil, fmt.Errorf("failed to set bridge %s up: %v", err)
	}

	return l.(*netlink.Bridge), nil
}

// setupVeth creates a veth pair, moves one end to the container's namespace,
// and connects the other end to the bridge.
func setupVeth(netns ns.NetNS, br *netlink.Bridge, ifName, hostVethName string) (*current.Interface, *current.Interface, error) {
	hostIface := &current.Interface{}
	contIface := &current.Interface{}

	// Create the veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName,
			MTU:  br.MTU,
		},
		PeerName: hostVethName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, nil, fmt.Errorf("failed to create veth pair: %v", err)
	}

	// Get the host-side veth link
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find host veth peer %s: %v", hostVethName, err)
	}

	// Connect the host-side veth to the bridge
	if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
		return nil, nil, fmt.Errorf("failed to connect host veth %s to bridge %s: %v", hostVeth.Attrs().Name, br.Name, err)
	}

	// Set the host-side veth up
	if err := netlink.LinkSetUp(hostVeth); err != nil {
		return nil, nil, fmt.Errorf("failed to set host veth %s up: %v", hostVeth.Attrs().Name, err)
	}
	hostIface.Name = hostVeth.Attrs().Name

	// Get the container-side veth link
	contVeth, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find container veth %s: %v", ifName, err)
	}

	// Move the container-side veth into the container's namespace
	if err := netlink.LinkSetNsFd(contVeth, int(netns.Fd())); err != nil {
		return nil, nil, fmt.Errorf("failed to move veth %s to container netns: %v", ifName, err)
	}

	// Configure the interface inside the container's namespace
	err = netns.Do(func(_ ns.NetNS) error {
		// Get the interface link
		iface, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to find interface %s in container netns: %v", ifName, err)
		}

		// Set the interface up
		if err := netlink.LinkSetUp(iface); err != nil {
			return fmt.Errorf("failed to set interface %s up in container netns: %v", ifName, err)
		}
		contIface.Name = iface.Attrs().Name
		contIface.Mac = iface.Attrs().HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return hostIface, contIface, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	// Parse network configuration
	n := &NetConf{}
	if err := json.Unmarshal(args.StdinData, n); err != nil {
		return fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// --- 0. Generate unique names and paths ---
	if args.ContainerID == "" {
		return fmt.Errorf("ContainerID is missing from CNI arguments")
	}
	logrus.Infof("Received CNI ADD request for ContainerID: %s", args.ContainerID)
	if len(args.ContainerID) < 8 {
		return fmt.Errorf("container ID %s is too short", args.ContainerID)
	}
	hostVethName := "veth" + args.ContainerID[:8]
	containerCacheDir := filepath.Join(cacheDir, args.ContainerID)
	cacheFilePath := filepath.Join(containerCacheDir, "cni_cache.json")

	// --- 1. Network Setup ---
	br, err := setupBridge(n)
	if err != nil {
		return fmt.Errorf("failed to set up bridge: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	if oldLink, err := netlink.LinkByName(hostVethName); err == nil {
		if err := netlink.LinkDel(oldLink); err != nil {
			return fmt.Errorf("failed to delete old veth %s: %v", hostVethName, err)
		}
		logrus.Infof("Deleted old veth link %s", hostVethName)
	}

	hostIface, contIface, err := setupVeth(netns, br, args.IfName, hostVethName)
	if err != nil {
		return fmt.Errorf("failed to set up veth pair: %v", err)
	}

	// --- 2. IPAM ---
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to run IPAM plugin: %v", err)
	}
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return fmt.Errorf("failed to convert IPAM result: %v", err)
	}
	if len(result.IPs) == 0 {
		return fmt.Errorf("IPAM plugin returned no IP addresses")
	}

	err = netns.Do(func(_ ns.NetNS) error {
		iface, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to find interface %s in container netns: %v", args.IfName, err)
		}
		addr := &netlink.Addr{IPNet: &result.IPs[0].Address}
		if err := netlink.AddrAdd(iface, addr); err != nil {
			return fmt.Errorf("failed to add IP address %s to interface %s: %v", result.IPs[0].Address.String(), args.IfName, err)
		}
		gw := result.IPs[0].Gateway
		route := &netlink.Route{Dst: nil, Gw: gw}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("failed to add default route via %s: %v", gw.String(), err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// --- 3. eBPF Setup ---
	if err := os.MkdirAll(bpfPinPath, 0755); err != nil {
		return fmt.Errorf("failed to create global pin directory %s: %v", bpfPinPath, err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load bpf objects: %v", err)
	}
	defer objs.Close()

	// Pin maps and program idempotently.
	endpointMapPinPath := filepath.Join(bpfPinPath, "endpoint_map")
	if err := pinObject(objs.EndpointMap, endpointMapPinPath); err != nil {
		return fmt.Errorf("failed to pin endpoint_map: %v", err)
	}
	policyMapPinPath := filepath.Join(bpfPinPath, "policy_map")
	if err := pinObject(objs.PolicyMap, policyMapPinPath); err != nil {
		return fmt.Errorf("failed to pin policy_map: %v", err)
	}
	progPinPath := filepath.Join(bpfPinPath, "tc_prog")
	if err := pinObject(objs.ProcessTc, progPinPath); err != nil {
		return fmt.Errorf("failed to pin tc_prog: %v", err)
	}

	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return fmt.Errorf("failed to find host veth %s: %v", hostIface.Name, err)
	}

	cmd := exec.Command("tc", "qdisc", "add", "dev", hostVeth.Attrs().Name, "clsact")
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("failed to add clsact qdisc: %v, output: %s", err, string(output))
		}
	}

	cmd = exec.Command("tc", "filter", "replace", "dev", hostVeth.Attrs().Name, "ingress", "bpf", "da", "pinned", progPinPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to attach program to ingress: %v, output: %s", err, string(output))
	}
	logrus.Infof("Successfully attached eBPF program to ingress on iface %s", hostVeth.Attrs().Name)

	cmd = exec.Command("tc", "filter", "replace", "dev", hostVeth.Attrs().Name, "egress", "bpf", "da", "pinned", progPinPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to attach program to egress: %v, output: %s", err, string(output))
	}
	logrus.Infof("Successfully attached eBPF program to egress on iface %s", hostVeth.Attrs().Name)

	// --- 4. Create Cache ---
	if err := os.MkdirAll(containerCacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory %s: %v", containerCacheDir, err)
	}
	cacheFile, err := os.Create(cacheFilePath)
	if err != nil {
		return fmt.Errorf("failed to create cache file %s: %v", cacheFilePath, err)
	}
	defer cacheFile.Close()
	cacheData := CacheData{HostVethName: hostVethName}
	if err := json.NewEncoder(cacheFile).Encode(cacheData); err != nil {
		return fmt.Errorf("failed to write to cache file %s: %v", cacheFilePath, err)
	}
	logrus.Infof("Successfully wrote cache data to %s", cacheFilePath)

	// --- 5. Return CNI Result ---
	result.Interfaces = []*current.Interface{contIface, hostIface}
	return types.PrintResult(result, n.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n := &NetConf{}
	if err := json.Unmarshal(args.StdinData, n); err == nil {
		if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
			logrus.Warnf("failed to release IP address: %v", err)
		}
	} else {
		logrus.Warnf("failed to parse network config on DEL: %v", err)
	}

	if args.ContainerID == "" {
		logrus.Warn("ContainerID is not provided, cannot perform cleanup")
		return nil
	}

	containerCacheDir := filepath.Join(cacheDir, args.ContainerID)
	cacheFilePath := filepath.Join(containerCacheDir, "cni_cache.json")

	cacheFile, err := os.Open(cacheFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Infof("Cache file %s not found, assuming resources are already cleaned up.", cacheFilePath)
			return nil
		}
		logrus.Warnf("failed to open cache file %s: %v", cacheFilePath, err)
	}

	var hostVethName string
	if cacheFile != nil {
		var cacheData CacheData
		if err := json.NewDecoder(cacheFile).Decode(&cacheData); err != nil {
			logrus.Warnf("failed to decode cache file %s: %v", cacheFilePath, err)
		} else {
			hostVethName = cacheData.HostVethName
		}
		cacheFile.Close()
	}

	if hostVethName != "" {
		iface, err := netlink.LinkByName(hostVethName)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				logrus.Infof("host veth %s not found, assuming already deleted", hostVethName)
			} else {
				logrus.Warnf("failed to find host veth %s: %v", hostVethName, err)
			}
		} else {
			if err := netlink.LinkDel(iface); err != nil {
				logrus.Warnf("failed to delete host veth %s: %v", hostVethName, err)
			} else {
				logrus.Infof("Deleted host veth link %s", hostVethName)
			}
		}
	}

	// BPF resources are global and are not cleaned up on pod deletion.

	if err := os.RemoveAll(containerCacheDir); err != nil {
		logrus.Warnf("failed to remove cache directory %s: %v", containerCacheDir, err)
	}

	return nil
}

// pinner is an interface for objects that can be pinned to the BPF filesystem.
type pinner interface {
	Pin(string) error
}

// pinObject checks if a pin exists, and if not, pins the object.
func pinObject(p pinner, path string) error {
	if _, err := os.Stat(path); err == nil {
		logrus.Infof("BPF object already pinned at %s, skipping.", path)
		return nil
	}
	if err := p.Pin(path); err != nil {
		return fmt.Errorf("failed to pin object at %s: %w", path, err)
	}
	logrus.Infof("Successfully pinned BPF object at %s", path)
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: Implement health check logic
	return nil
}

func main() {
	f, err := os.OpenFile("/tmp/ebpfcni.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		logrus.SetOutput(f)
		defer f.Close()
	} else {
		logrus.SetOutput(os.Stderr)
	}
	logrus.SetLevel(logrus.InfoLevel)

	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "eBPF CNI plugin")
}
