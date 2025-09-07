module github.com/sh1un/ebpf-based-cni-plugin

go 1.24.3

require (
	github.com/cilium/ebpf v0.19.0
	github.com/containernetworking/cni v1.3.0
	github.com/containernetworking/plugins v1.8.0
	github.com/sirupsen/logrus v1.9.3
	github.com/vishvananda/netlink v1.3.1
)

require (
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/safchain/ethtool v0.6.2 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/sys v0.36.0 // indirect
	sigs.k8s.io/knftables v0.0.18 // indirect
)
