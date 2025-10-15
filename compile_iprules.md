```bash
# 編譯 iprules 工具
clang -O2 -g \
  -I./bpf/user \
  -c bpf/user/ebpfcni.c -o ebpfcni.o

clang -O2 -g \
  -I./bpf/user \
  ebpfcni.o -lbpf -o iprules

sudo cp iprules k8s/controller/
sudo chmod +x k8s/controller/iprules
```
