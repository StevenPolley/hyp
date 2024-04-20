# hyp | Hide Your Ports

[![Build Status](https://drone.deadbeef.codes/api/badges/steven/hyp/status.svg)](https://drone.deadbeef.codes/steven/hyp)

hyp is a [port knocking](https://www.youtube.com/watch?v=a7VJZEJVhD0) implementation written in Go, using spread-spectrum UDP as an authentication mechanism. It enables trusted agents to access services over the internet, wherever they are, and without the service being publicly accessible. Your TCP and UDP ports are closed. The benefit is that the ports are not open publicly on the internet, they won't show in a port scan and are therefore less likely to be attacked by a threat actor. Compared to most port knocking daemons, hyp provides additional protection against replay and sweep attacks. 

hyp makes use of pre-shared keys and time to calculate an authentic knock sequence on both the client and server. The following process describes how hyp works:

1. The pre-shared key is generated and distributed between both the hyp client and the hyp server. 
2. The pre-shared key is run through a sha1-hmac algorithm along with the current system time, this produces the same 160 bits of output on both sides.
3. The 160 bits is reduced down to 64 bits. This helps protect the key by not revealing the entire output of the hmac... we will be transmitting over an untrusted network after all.
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
git clone https://deadbeef.codes/steven/hyp.git
cd hyp/hypd/server
go generate
cd ..
go build -o hypd .
chmod +x hypd

./hypd -h

```

### References

* RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm
* RFC 6238 - TOTP: Time-Based One-Time Password Algorithm
* Techniques for Lightweight Concealment and Authentication in IP Networks