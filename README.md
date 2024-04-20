# hyp | Hide Your Ports

[![Build Status](https://drone.deadbeef.codes/api/badges/steven/hyp/status.svg)](https://drone.deadbeef.codes/steven/hyp)

hyp is a [port knocking](https://www.youtube.com/watch?v=a7VJZEJVhD0) implementation written in Go and C.  hyp uses spread-spectrum UDP as an authentication mechanism and enables trusted agents to access services over the internet, wherever they are, and without the service being accessible by others. Your TCP and UDP ports are closed. They will not show in a port scan.  Nobody else can connect to them.  This is particularly useful as [there](https://nvd.nist.gov/vuln/detail/CVE-2024-21888) [have](https://nvd.nist.gov/vuln/detail/CVE-2023-20269) [been](https://nvd.nist.gov/vuln/detail/CVE-2021-26109) [a](https://nvd.nist.gov/vuln/detail/CVE-2024-22394) [few](https://nvd.nist.gov/vuln/detail/CVE-2024-21894) [VPN](https://nvd.nist.gov/vuln/detail/CVE-2024-3400) [gateway](https://nvd.nist.gov/vuln/detail/CVE-2023-27997) [vulnerabilities](https://nvd.nist.gov/vuln/detail/CVE-2024-21762) [over](https://nvd.nist.gov/vuln/detail/CVE-2022-3236) [the](https://nvd.nist.gov/vuln/detail/CVE-2024-21893) [years](https://nvd.nist.gov/vuln/detail/CVE-2022-42475).  I often wonder what's out there and hasn't been discovered.  Why take the chance of leaving your VPN open to the whole internet?  With hyp, you don't have to.  

Compared to most port knocking daemons, hyp is extremely fast, lightweight and has no dependency on libpcap.  Instead of libpcap, hyp uses eBPF technology which runs in the kernel and only sends data to userspace that's absolutely required.  hyp also provides additional protection against replay and sweep attacks. Each authentic knock sequence is a one time use, and new knock sequences are generated every 30 seconds.  hyp makes use of pre-shared keys and time to calculate an authentic knock sequence on both the client and server. The following process describes how hyp works:

1. The pre-shared key is generated and distributed between both the hyp client and the hyp server. 
2. The pre-shared key is run through a sha1-hmac algorithm along with the current system time, this produces the same 160 bits of output on both sides.
3. The 160 bits is reduced down to 64 bits. This helps protect the key by not revealing the entire output of the hmac... we assume you are transmitting over an untrusted network.
4. The 64 bits are divided into four 16-bit structures which are typecast to 16-bit unsigned integers. A 16-bit integer can have a value from 0-65535, the same as UDP port numbers. We have four of them now.
5. Transmit one empty datagram to the knock daemon at a time, one after another using the four integers from the previous calculation as the destination port numbers.
6. The knock daemon on the firewall verifies the sequence and performs the action of opening the firewall port configured for the client to let them in while remaining closed to everyone else. 
7. The client connects to their application which has its own authentication, authorization, and auditing. 

![Authentic Knock Sequence](https://deadbeef.codes/steven/hyp/raw/branch/main/docs/authentic-knock-sequence-calculation.png)

### Runtime Requirements

Port knocking clients have minimal requirements and can run on x86, ARM, MIPS, PowerPC, IBM390, or RISC-V. Currently only supported OS's are Linux and Windows, with support for Android planned to be added in the future.

The port knocking daemon has more strict requirements and is only available for Linux. It requires the kernel be built with CONFIG_DEBUG_INFO_BTF, which most major distributions have out of the box. 

### Build Requirements

Pre-built binaries for configurations I've tested are available on the [releases page](https://deadbeef.codes/steven/hyp/releases). This will likely run in many CPU architectures I haven't tested yet though. 

To build this yourself, you will need Linux with packages for: git, clang, linux-headers-<architecture> libbpf-dev and golang. Check out the [Dockerfile ](https://deadbeef.codes/steven/hyp/src/branch/main/Dockerfile) as a reference for how the build environment for official releases is configured. Once the environment is ready, you can clone the repo and build.

```sh
# Clone repository
git clone https://deadbeef.codes/steven/hyp.git

# Build eBPF program
cd hyp/hypd/server
go generate

# Build knock daemon
cd ..
go build -o hypd .
chmod +x hypd

# Run knock daemon and show help
./hypd -h
```

### References

* RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm
* RFC 6238 - TOTP: Time-Based One-Time Password Algorithm
* Techniques for Lightweight Concealment and Authentication in IP Networks