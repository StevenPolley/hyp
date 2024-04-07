# hypd

hypd is the hyp (Hide Your Ports) server.  

### Requirements

On the server, libpcap-dev needs to be installed on linux or pcap from nmap.org on Windows.

### Usage

##### Generating a new shared key

```bash
# As user that can write to current directory
./hypd generatesecret
```

Then copy the file to a client

##### Starting the server

```bash
# As root - or user that can capture packets and modify IPTables
./hypd server eth0
```