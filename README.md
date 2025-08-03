## Inspiration

This project is inspired by [asayah](https://github.com/asayah)'s talk on building an eBPF-based CNI plugin:
👉 [YouTube: Building an eBPF CNI plugin from scratch](https://www.youtube.com/watch?v=3cqCmtg-TOo)

I extended the original design by adapting it to work with **TC (Traffic Control)** hooks instead of XDP, and added some features.

## How to Use This Project

### Prerequisites

- A Kubernetes cluster initialized with `kubeadm` (e.g., Single node cluster on Ubuntu 22.04 LTS amd64)

### Installation Steps

Follow the [installation guide](INSTALL_GUIDE_ZH_TW.md) to set up the necessary tools and libraries.
