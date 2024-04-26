# Using hyp with OpenWrt Wireguard

This example case is to deploy hypd on OpenWrt to open up access to the WireGuard VPN service.

hyp utilizes eBPF technology to ensure runtime overhead is extremely small (in a way, but in a way not).  Most Linux distributions have support for this out of the box, however OpenWrt does not.  OpenWrt has a very stripped down, purpose-configured kernel and does not have the requirements built in to run hyp.  

The good news is, you can build OpenWrt yourself and configure it with the requirements.  Follow the directions at this page: https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem

When you run *make menuconfig*, make sure you check off *Enable additional BTF type information* which is also known as CONFIG_KERNEL_DEBUG_INFO_BTF.  This is required to support eBPF CO:RE. 

![Kernel Config](https://deadbeef.codes/steven/hyp/raw/branch/main/hypd/examples/openwrt-wireguard/kernel_config.png)

