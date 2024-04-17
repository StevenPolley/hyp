# hypd server

hypd is the port knocking daemon which runs on an edge device connecting to an untrusted network.  Leveraging eBPF's XDP hook point, it extracts header information directly and sends to userspace the specific information required.  This method is faster than alternative methods such as using libpcap.  

### eBPF

The hyp_bpf.c program can be recompiled using go generate.

```bash
# Debian: sudo apt install git clang linux-headers-amd64 libbpf-dev
go generate .
```

### Generating vmlinux.h

vmlinux.h is included in hyp_bpf.c and can be regenerated with bpftool.

```bash
# Debian: sudo apt install bpftool
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../headers/vmlinux.h
```

### Building hypd

hypd has no CGO dependencies and so can run on musl systems as well.  

```bash
# To ensure it can run on  systems don't use CGO
CGO_ENABLED=0 go build .
```