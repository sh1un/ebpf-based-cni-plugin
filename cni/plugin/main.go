package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
)

// K8sArgs contains CNI arguments passed by the kubelet.
type K8sArgs struct {
	types.CommonArgs
	K8S_POD_NAME      types.UnmarshallableString
	K8S_POD_NAMESPACE types.UnmarshallableString
	K8S_POD_UID       types.UnmarshallableString
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf bpf ../../bpf/kernel/ebpfcni.bpf.c -- -I../../headers

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

// getK8sPodUID extracts the Pod UID from the CNI arguments.
func getK8sPodUID(args *skel.CmdArgs) (string, error) {
	k8sArgs := K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		return "", fmt.Errorf("failed to load CNI k8s args: %v", err)
	}

	podUID := string(k8sArgs.K8S_POD_UID)
	if podUID == "" {
		return "", fmt.Errorf("K8S_POD_UID is missing from CNI arguments")
	}
	return podUID, nil
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
	// Use ContainerID for temporary resources like veth and cache.
	if args.ContainerID == "" {
		return fmt.Errorf("ContainerID is missing from CNI arguments")
	}
	logrus.Infof("Received CNI ADD request for ContainerID: %s", args.ContainerID)
	// Use a short version of the ContainerID to create a unique host-side veth name.
	if len(args.ContainerID) < 8 {
		return fmt.Errorf("container ID %s is too short", args.ContainerID)
	}
	hostVethName := "veth" + args.ContainerID[:8]
	containerCacheDir := filepath.Join(cacheDir, args.ContainerID)
	cacheFilePath := filepath.Join(containerCacheDir, "cni_cache.json")

	// Use PodUID for persistent resources like BPF maps.
	podUID, err := getK8sPodUID(args)
	if err != nil {
		return err
	}
	logrus.Infof("Using PodUID %s for BPF map pinning", podUID)

	// --- 1. Network Setup ---
	// Create or get the bridge
	br, err := setupBridge(n)
	if err != nil {
		return fmt.Errorf("failed to set up bridge: %v", err)
	}

	// Get network namespace
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// Clean up old veth link if it exists to ensure a clean state.
	if oldLink, err := netlink.LinkByName(hostVethName); err == nil {
		if err := netlink.LinkDel(oldLink); err != nil {
			return fmt.Errorf("failed to delete old veth %s: %v", hostVethName, err)
		}
		logrus.Infof("Deleted old veth link %s", hostVethName)
	}

	// Create and configure the veth pair
	hostIface, contIface, err := setupVeth(netns, br, args.IfName, hostVethName)
	if err != nil {
		return fmt.Errorf("failed to set up veth pair: %v", err)
	}

	// --- 2. IPAM ---
	// Run the IPAM plugin
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to run IPAM plugin: %v", err)
	}
	// Convert the IPAM result to the current CNI version
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return fmt.Errorf("failed to convert IPAM result: %v", err)
	}
	if len(result.IPs) == 0 {
		return fmt.Errorf("IPAM plugin returned no IP addresses")
	}

	// Configure the container interface with the IP address from IPAM
	err = netns.Do(func(_ ns.NetNS) error {
		iface, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to find interface %s in container netns: %v", args.IfName, err)
		}

		// Add the IP address to the interface
		addr := &netlink.Addr{IPNet: &result.IPs[0].Address}
		if err := netlink.AddrAdd(iface, addr); err != nil {
			return fmt.Errorf("failed to add IP address %s to interface %s: %v", result.IPs[0].Address.String(), args.IfName, err)
		}

		// Add the default route
		gw := result.IPs[0].Gateway
		route := &netlink.Route{
			Dst: nil, // Default route
			Gw:  gw,
		}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("failed to add default route via %s: %v", gw.String(), err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// --- 3. eBPF Setup ---
	// The pin path is now global, not tied to a pod-specific directory.
	if err := os.MkdirAll(bpfPinPath, 0755); err != nil {
		return fmt.Errorf("failed to create global pin directory %s: %v", bpfPinPath, err)
	}
	// The map is pinned with a name unique to the Pod UID.
	iprulesMapPinPath := filepath.Join(bpfPinPath, fmt.Sprintf("iprules_%s", podUID))
	localCfgMapPinPath := filepath.Join(bpfPinPath, fmt.Sprintf("local_cfg_%s", podUID))
	// The program can be pinned with a unique name as well.
	progPinPath := filepath.Join(bpfPinPath, fmt.Sprintf("tc_prog_%s", podUID))

	var objs bpfObjects
	opts := ebpf.CollectionOptions{
		MapReplacements: make(map[string]*ebpf.Map),
	}
	defer func() {
		// Clean up maps that were successfully replaced, as they won't be closed by objs.Close()
		if m, ok := opts.MapReplacements["iprules"]; ok {
			m.Close()
		}
		if m, ok := opts.MapReplacements["local_cfg"]; ok {
			m.Close()
		}
	}()

	// Try to load a reusable iprules map.
	if m, err := ebpf.LoadPinnedMap(iprulesMapPinPath, nil); err == nil {
		logrus.Infof("Found existing pinned iprules map at %s, reusing it.", iprulesMapPinPath)
		opts.MapReplacements["iprules"] = m
	}

	// Try to load a reusable local_cfg map.
	if m, err := ebpf.LoadPinnedMap(localCfgMapPinPath, nil); err == nil {
		logrus.Infof("Found existing pinned local_cfg map at %s, reusing it.", localCfgMapPinPath)
		opts.MapReplacements["local_cfg"] = m
	}

	// Load the BPF objects, with replacement if applicable.
	if err := loadBpfObjects(&objs, &opts); err != nil {
		return fmt.Errorf("failed to load bpf objects: %v", err)
	}
	defer objs.Close()

	// If we didn't reuse the iprules map, we need to pin the new one.
	if _, ok := opts.MapReplacements["iprules"]; !ok {
		logrus.Infof("No existing iprules map found, creating and pinning a new one at %s.", iprulesMapPinPath)
		if err := ensurePinnedMap(objs.Iprules, iprulesMapPinPath); err != nil {
			return err
		}
	}

	// If we didn't reuse the local_cfg map, we need to pin the new one.
	if _, ok := opts.MapReplacements["local_cfg"]; !ok {
		logrus.Infof("No existing local_cfg map found, creating and pinning a new one at %s.", localCfgMapPinPath)
		if err := ensurePinnedMap(objs.LocalCfg, localCfgMapPinPath); err != nil {
			return err
		}
	}

	// Pin the program.
	if err := ensurePinnedProgram(objs.ProcessTc, progPinPath); err != nil {
		return err
	}

	// --- 3.1. Configure Local Pod IP in BPF Map ---
	// After loading the BPF objects, we configure the local_cfg map with the Pod's IP.
	// This allows the BPF program to identify which traffic is destined for itself.
	key := uint32(0)
	// The IP from IPAM is already in a net.IPNet, which contains the IP in network byte order.
	// We need to convert it to a uint32 in host byte order.
	ip := result.IPs[0].Address.IP.To4()
	if ip == nil {
		return fmt.Errorf("failed to parse IPv4 address from IPAM result")
	}
	// Convert the 4-byte IP representation to a uint32.
	// The IP from net.IP.To4() is in network order (big-endian). We need to store it
	// in the map in host byte order to match the eBPF program's expectation.
	// The IP from net.IP.To4() is in network byte order (big-endian).
	// We need to convert it to a uint32. The BPF program expects this
	// value to be in host byte order for its comparisons.
	// binary.BigEndian.Uint32 correctly reads the big-endian byte slice
	// into a uint32, which will be correctly interpreted as a host-order
	// value by the BPF program, regardless of the host's actual endianness.
	localIP := binary.BigEndian.Uint32(ip)

	logrus.Infof("DEBUG_CNI: Writing to local_cfg map. ContainerID: %s, PodUID: %s, IP: %s, IP(hex): %x, MapPinPath: %s",
		args.ContainerID, podUID, ip.String(), localIP, localCfgMapPinPath)

	if err := objs.LocalCfg.Put(&key, &localIP); err != nil {
		return fmt.Errorf("failed to update local_cfg map with local IP: %v", err)
	}
	logrus.Infof("Successfully configured local Pod IP %s in local_cfg map", ip.String())

	// Find the host-side veth interface to attach the eBPF program
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return fmt.Errorf("failed to find host veth %s: %v", hostIface.Name, err)
	}

	// Ensure the clsact qdisc is present.
	cmd := exec.Command("tc", "qdisc", "add", "dev", hostVeth.Attrs().Name, "clsact")
	if output, err := cmd.CombinedOutput(); err != nil {
		// Ignore "File exists" error, which is expected if the qdisc is already there.
		if !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("failed to add clsact qdisc: %v, output: %s", err, string(output))
		}
	}

	// Attach the eBPF program to the ingress hook (from-pod traffic).
	// Use "replace" to make the operation idempotent.
	cmd = exec.Command("tc", "filter", "replace", "dev", hostVeth.Attrs().Name, "ingress", "bpf", "da", "pinned", progPinPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to attach program to ingress: %v, output: %s", err, string(output))
	}
	logrus.Infof("Successfully attached eBPF program to ingress on iface %s", hostVeth.Attrs().Name)

	// Attach the same eBPF program to the egress hook (to-pod traffic).
	// This is the key for ingress policy and default deny.
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
	// --- 1. Release IP using IPAM ---
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

	// --- 2. Clean up network resources using cache ---
	containerCacheDir := filepath.Join(cacheDir, args.ContainerID)
	cacheFilePath := filepath.Join(containerCacheDir, "cni_cache.json")

	// Read cache data
	cacheFile, err := os.Open(cacheFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Infof("Cache file %s not found, assuming resources are already cleaned up.", cacheFilePath)
			return nil
		}
		logrus.Warnf("failed to open cache file %s: %v", cacheFilePath, err)
		// Continue to try cleanup anyway
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

	// If we have a host veth name, delete the link
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

	// --- 3. Clean up BPF resources ---
	// Use PodUID to find and remove the BPF map and program.
	podUID, err := getK8sPodUID(args)
	if err != nil {
		// If we can't get the PodUID, we can't clean up the BPF resources.
		// Log the warning but don't fail the DEL operation.
		logrus.Warnf("Could not get PodUID on DEL, skipping BPF cleanup: %v", err)
	} else {
		logrus.Infof("Cleaning up BPF resources for PodUID %s", podUID)
		iprulesMapPinPath := filepath.Join(bpfPinPath, fmt.Sprintf("iprules_%s", podUID))
		if err := os.Remove(iprulesMapPinPath); err != nil && !os.IsNotExist(err) {
			logrus.Warnf("failed to remove BPF iprules map pin %s: %v", iprulesMapPinPath, err)
		}
		localCfgMapPinPath := filepath.Join(bpfPinPath, fmt.Sprintf("local_cfg_%s", podUID))
		if err := os.Remove(localCfgMapPinPath); err != nil && !os.IsNotExist(err) {
			logrus.Warnf("failed to remove BPF local_cfg map pin %s: %v", localCfgMapPinPath, err)
		}
		progPinPath := filepath.Join(bpfPinPath, fmt.Sprintf("tc_prog_%s", podUID))
		if err := os.Remove(progPinPath); err != nil && !os.IsNotExist(err) {
			logrus.Warnf("failed to remove BPF prog pin %s: %v", progPinPath, err)
		}
	}

	// --- 4. Clean up Cache directory ---
	if err := os.RemoveAll(containerCacheDir); err != nil {
		logrus.Warnf("failed to remove cache directory %s: %v", containerCacheDir, err)
	}

	return nil
}

// ensurePinnedMap pins a map and verifies it really exists on bpffs.
// This prevents false positives where Pin() logs success but no file is created.
func ensurePinnedMap(m *ebpf.Map, path string) error {
	if err := m.Pin(path); err != nil {
		return fmt.Errorf("failed to pin map at %s: %v", path, err)
	}
	if _, err := os.Stat(path); err != nil {
		// If stat fails, try to clean up the pin.
		_ = m.Unpin()
		return fmt.Errorf("map not actually pinned at %s: %v", path, err)
	}
	logrus.Infof("Verified pinned map exists at %s", path)
	return nil
}

// ensurePinnedProgram pins a program and verifies it really exists on bpffs.
func ensurePinnedProgram(p *ebpf.Program, path string) error {
	if err := p.Pin(path); err != nil {
		return fmt.Errorf("failed to pin program at %s: %v", path, err)
	}
	if _, err := os.Stat(path); err != nil {
		// If stat fails, try to clean up the pin.
		_ = p.Unpin()
		return fmt.Errorf("program not actually pinned at %s: %v", path, err)
	}
	logrus.Infof("Verified pinned program exists at %s", path)
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: Implement health check logic
	// 1. Check if the bridge exists and is up.
	// 2. Check if the veth pair exists.
	// 3. Check if the container interface has the expected IP.
	// 4. Check if the eBPF program is attached.
	// 5. Check if the BPF map is pinned.
	return nil
}

func main() {
	// Set up logging
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
