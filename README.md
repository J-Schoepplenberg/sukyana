# Sukyana
A low-level, cross-platform port scanner and packet flooder written in pure, safe Rust.

Runs on any operating system. See the [requirements](#windows) for building on Windows.

The code is based on
 
 > Gordon Fyodor Lyon, Nmap network scanning: official Nmap project guide to network discovery and security scanning. Sunnyvale, Ca: Insecure.com, Llc, 2008. Available: https://nmap.org/book/toc.html.

The logic for interpreting host responses to probes has been implemented according to the [nmap documentation](https://nmap.org/book/scan-methods.html).

`Sukyana` processes raw packets, which means it is responsible for encapsulating layers, stripping headers, and explicitly analyzing response payloads, which is usually done automatically by the TCP/IP stack. As a result, `Sukyana` requires root privileges to run.

This allows us to go much further than simply using the standard Rust library `std::net::TcpStream`, which provides a TCP connect system call via `TcpStream::connect()`, where the operating system automatically handles the connection to a remote target. TCP connect gives much less control than raw packets and is simply less efficient. The system call completes a full TCP connection, requires multiple packets to be exchanged, and makes it more likely that the connection will be logged by the target.

## Table of Contents  
- [Networking Basics](#networking-basics) 
- [Port Scanning](#port-scanning)
- [Flooding](#flooding)
  - [Reflection Attack](#reflection-attack)
- [Usage](#usage)
  - [Config](#config)
  - [Scan](#scan)
  - [Flood](#flood)
  - [Options](#options)
  - [Windows](#windows)
- [Roadmap](#roadmap)
- [Legal Disclaimer](#legal-disclaimer)

## Networking Basics

**Packets** are essentially multiple layers that encapsulate some data. An Ethernet frame is the packaging that contains several different headers from other higher-level network protocols and their payloads. You can think of it like a messenger carrying a package with a letter inside that jumps on a car which is put on a cargo ship that sails across the ocean. At the destination, the car is unloaded from the ship, the messenger disembarks, and we open the package to read the letter.

For example, when we construct a TCP packet, we define an IP header, a TCP header, and finally encapsulate both in an Ethernet frame, which is simply a buffer containing the data encoded in bytes. When we receive a packet, we must deconstruct the Ethernet frame to extract the TCP payload. 

At the **data link layer** (Layer 2), we process Ethernet frames containing source and destination MAC addresses to deliver them locally between nodes at the same level of a network. They are exchanged at the physical layer. MAC addresses of local on-link destinations can be found in the ARP cache or obtained through ARP requests. ARP packets are encapsulated in such Ethernet frames, not in IP datagrams.

The **network layer** (Layer 3) is responsible for forwarding our packets across networks and handling routing across the Internet through intermediate routers. These routers are a network layer concept that is a layer above Ethernet frames. They deliver packets to their destinations by processing IP datagrams encapsulated in Ethernet frames. The time-to-live (TTL) header field, which is an eight-bit value, is decremented at each router where the datagram arrives, effectively representing a hop count. When the TTL reaches zero, the router discards the packet and it never arrives at its intended destination. This limits the routing process of the packet.

At the **transport layer** (Layer 4) we work with end-to-end communication protocols such as TCP and UDP, which are encapsulated in IP packets. ICMP is also encapsulated in IP packets, although it is fiercely debated to which layer it belongs. The transport layer is responsible to ensure packets arrive between sender and receiver at the destined service or application through a specific port. Packets can then be sorted and checked for errors.

A **socket** is an endpoint for communication, consisting of an IP address and a port number, allowing a transport protocol like TCP or UDP to connect applications across a network. It is nothing more than a way to connect one computer to another. Packets, layers, and their protocols are just tools we can use to make that connection. You can think of a computer as an apartment building, where the building can be addressed with a street address (IP) and each apartment inside the building has a number (port) to receive different mail (packets).

## Port Scanning

A port scan is a process of sending packets to a range of sockets. This is not a nefarious process in and of itself, and is used to determine the services available on a target system.  The information gathered has many legitimate uses, including network inventory and security auditing. However, it can also be used to compromise security by finding ports and services that are vulnerable to exploits.

It uses a combination of techniques to determine the state of ports on a target system. Services or applications that are available for networking require open ports to communicate. Common services have assigned port numbers, but can run on completely arbitrary ports. There are up to 65535 possible TCP/UDP ports that can be scanned by sending packets as probes and observing the responses to determine the status of ports. 

A port scan can be stealthy or overt, detectable by the volume of packets sent, unusual flags set in packet headers, or event logging on the target system. `Sukyana` shuffles the given ports to avoid scanning in order. In addition, many different scanning methods are implemented, providing a variety of techniques. The purpose and expected behavior of each scanning method according to standards such as RFC 793 has been commented in the source code.

| Method                             | Details       | 
| :--------------------------------- | :------------ |
| TCP SYN Scan    | Sends TCP packets with the SYN flag set. Determines if a port is: open, closed or filtered. Does not complete the three-way handshake and does not need to tear down connections. The most common scan type due to its speed and stealthiness.|
| TCP Connect Scan   | Establishes a full TCP connection using the TCP connect system call, completing the three-way handshake. If the handshake cannot be established, the port is considered as closed. Significantly more noisy and and less efficient than a TCP SYN scan. |
| TCP ACK Scan   | Sends TCP packets with the ACK flag set. Determines if a port is: unfiltered or filtered. |
| TCP FIN Scan  | Sends TCP packets with the FIN flag set. Determines if a port is: open\|filtered, closed or filtered. |
| TCP XMAS Scan   | Sends TCP packets with FIN, PSH and URG flags set. Determines if a port is: open\|filtered, closed or filtered. |
| TCP NULL Scan   | Sends TCP packets with no flags set. Determines if a port is: open\|filtered closed or filtered. |
| TCP Window Scan  | Works the same as TCP ACK scans, but examines the window field in the TCP header of RST flag packets. Determines if a port is: open, closed or filtered. |
| TCP Maimon Scan | Sends TCP packets with FIN and ACK flags set. Determines if a port is: open\|filtered, closed or filtered. |
| UDP Scan | Sends UDP packets. Determines if a port is: open, closed or filtered. Most popular services run over TCP, but UDP is used for services like DNS, DHCP, and SNMP. Since UDP is connectionless, it's not as reliable as TCP to receive a response. |
| ICMP Scan | Sends ICMP echo requests. Is also known as a ping scan. Determines if a host is: up or down. |
| ARP Scan | Sends ARP request packets. Determines the MAC address of hosts on the local network. |

## Flooding
A flood is a type of denial-of-service (DoS) attack in which a large volume of data packets is rapidly sent to a target system in order to exhaust its resources, potentially rendering the system inaccessible to its intended users.

`Sukyana` uses the low-level networking library [libpnet](https://github.com/libpnet/libpnet "libpnet") to create and manipulate packets at will. Large amounts of TCP/UDP traffic can be generated and sent to a target system. However, any network with reasonable defensive security measures in place should be able to quickly block such traffic.

| Method     | Details   |
| :--------- | :-------- |
| TCP Flood | Sends TCP packets to a target at a high rate. You may choose which TCP flags you want to set. TCP SYN initiates a connection to a socket by starting the three-way handshake without ever completing the connection. The target consumes resources waiting for half-open connections. TCP ACK prompts the target to search its half-open connections for a match, which may eventually exhaust it by keeping it too busy to process other packets. Other flags can also be set at your discretion. |
| UDP Flod | Sends UDP packets to a target at a high rate. The expected behavior is for the target to respond with ICMP destination unreachable packets after checking that no service listens at that port. The idea is that these packets consume a large amount of bandwidth that may prevent the target from providing other services. To avoid receiving ICMP packets back from the target, you can also spoof the IP address of the UDP packets sent. |
| ICMP Flood | Sends ICMP echo packets, also known as pings, to a target at a high rate. The target may become too busy responding to these echo requests, resulting in the target being unable to provide other services. |

### Reflection Attack
You can set a false source IP address and source port for each of the packets sent. This technique is also known as IP spoofing and can be used to perform a reflection attack. In this type of technique, request packets are sent to a third-party network with the source IP address spoofed to be that of a victim. The third-party network believes that the requests are legitimate and coming from the victim, which tricks it into sending its replies to the victim's IP address. This can result in the victim being flooded with response packets.

## Usage

To use `Sukyana`, follow these steps:

1. **Download the repository.**
2. **Obtain root or administrative privileges.**
3. **Run the application.**
    - You either compile the application and run the binary: 

      ```sh 
      cargo run --release -- --config <CONFIG> [OPTIONS] [COMMAND]
      ```
   - Or you run the compiled application binary:

      ```sh 
      .\sukyana.exe --config <CONFIG> [OPTIONS] [COMMAND]
      ```


### Config
You can specify variables in a `.toml` file, which is loaded via `--config <PATH>`:
```toml
# settings.toml

# Add the IP address that is set as the sender of packets.
# If you use a false IP address you effecively spoof the IP address of packets.
# However, in that case you may not receive responses anymore.
src_ip = "192.168.178.26"

# Add the source port of packets.
# Responses will be sent to src_ip:src_port.
src_port = 12345

# Add the target port of packets.
# Packets will be sent to a socket listening to that port.
# You can specify single ports in a list.
# Alternatively, you may also specify a range like: port_numbers = ["1-1000"].
port_numbers = ["22", "80", "443"]

# Add the target IP addresses of packets.
# Packets will be sent to a socket addressable by that IP address.
# You can specify single IP addresses in a list.
# Alternatively, you may also specify a subnet like: ip_addresses = ["192.168.178.0/24"].
ip_addresses = ["192.168.178.1"]

# Add the duration in seconds for how long the data link layer channel will listen to responses.
# After the timeout has run up, the channel will terminate. 
timeout = 1

# Add the number of packets that will be sent in a flooding attack to each socket.
# Use this setting very carefully as it may lead to a denial of service.
# Do not use this setting to attack systems that you do not own or have permission to flood.
number_of_packets = 10

# Add if the source port in flooding attacks should be randomized.
# This may prevent filtering of packet retransmissions by the target.
# Retransmissions are marked if the packet is identical to previous packets.
should_randomize_ports = false
```

### Scan

```sh
Usage: sukyana.exe --config <CONFIG> scan [OPTIONS]

Options:
      --tcp-syn      TCP SYN scan
      --tcp-connect  TCP connect scan
      --tcp-ack      TCP ACK scan
      --tcp-fin      TCP FIN scan
      --tcp-xmas     TCP XMAS scan
      --tcp-null     TCP NULL scan
      --tcp-window   TCP window scan
      --tcp-maimon   TCP Maimon scan
      --udp          UDP scan
  -h, --help         Print help
```

### Flood

```sh
Usage: sukyana.exe --config <CONFIG> flood [OPTIONS]

Options:
      --tcp   TCP flood
      --udp   UDP flood
      --icmp  ICMP flood
  -h, --help  Print help
```

### Options

```sh
Usage: sukyana.exe [OPTIONS] --config <CONFIG> [COMMAND]

Commands:
  scan   Scan ports on hosts
  flood  Flood hosts
  help   Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>
      --arp              ARP scan
      --ping             ICMP scan
  -h, --help             Print help
  -V, --version          Print version
```

Replace `<CONFIG>` with the actual path to your configuration file. The `[OPTIONS]` and `[COMMAND]` placeholders represent additional options and commands specific to your use case.

### Windows
To compile `Sukyana` you need to fulfill the requirements that are introduced through `libpnet`. These are namely:
- You must use a version of Rust which uses the MSVC toolchain
- You must have [WinPcap](https://www.winpcap.org/) or [npcap](https://npcap.com/) installed
- You must place `Packet.lib` from the [WinPcap Developers pack](https://www.winpcap.org/devel.htm "WinPcap Developers pack") directly in the root of this repository
  - For x64 (64-bit) systems you find the file in `WpdPack/Lib/x64/Packet.lib`
  - For x86 (32-bit) systems you find the file in `WpdPack/Lib/Packet.lib`

## Roadmap
- [x] Ensure complete cross-platform support.
- [ ] Add more and advanced DoS attack methods.
- [ ] Default scanning of top 1000 most common ports.
- [ ] Automatic remote detection of operating systems and services.

## Legal Disclaimer
The code provided in this repository is for educational and research purposes only. `Sukyana` has been written solely to aid in the understanding of low-level networking and network security. It should only be used for legitimate purposes, such as testing the security of your own systems or systems that you have explicit permission to test from the owner. Make sure you have proper authorization before using `Sukyana` to scan or test any network, system, or device. Unauthorized use against any system or network is strictly prohibited and may be illegal. The author of `Sukyana` is not responsible or liable for any misuse. You acknowledge and agree that you are solely responsible for your use of the code in this repository. This disclaimer must be included in all copies or distributions of this repository, and by downloading or using `Sukyana` you agree to be bound by the above terms.