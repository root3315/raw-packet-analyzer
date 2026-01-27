# Raw Packet Analyzer

A low-level network packet analyzer for deep packet inspection and protocol analysis. Written in modern C++17.

## Features

- **Multi-protocol Support**: Parse Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, and DNS packets
- **Deep Packet Inspection**: Extract header fields, payload data, and connection information
- **Traffic Statistics**: Real-time statistics on packet counts, byte counts, and protocol distribution
- **Connection Tracking**: Monitor active connections with packet and byte counts
- **PCAP File Support**: Read and analyze packets from pcap capture files
- **Filtering**: Apply filters by protocol, IP address, port, and packet size
- **Thread-safe**: All analyzer operations are thread-safe with mutex protection
- **Comprehensive Testing**: Full test suite with unit tests for all components

## Project Structure

```
raw-packet-analyzer/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── include/
│   ├── packet.h            # Packet structures and parser declarations
│   └── analyzer.h          # Analyzer class and statistics
├── src/
│   ├── main.cpp            # Main entry point and CLI
│   ├── packet.cpp          # Packet parsing implementation
│   └── analyzer.cpp        # Analyzer implementation
└── tests/
    └── test_packet.cpp     # Unit tests
```

## Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.10 or higher
- POSIX system (Linux, macOS) for network features
- libpcap (optional, for live capture - currently supports pcap file reading)

## Installation

### Build from Source

```bash
# Clone or navigate to the project directory
cd raw-packet-analyzer

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the project
make

# (Optional) Install system-wide
sudo make install
```

### Build Options

```bash
# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release ..
```

## Usage

### Basic Usage

```bash
# Run in demo mode (generates synthetic packets)
./packet-analyzer --demo

# Analyze a pcap file
./packet-analyzer -i capture.pcap

# Verbose output with statistics
./packet-analyzer -i capture.pcap --verbose --stats

# Filter for TCP packets only
./packet-analyzer -i capture.pcap --filter tcp

# Filter for specific port
./packet-analyzer -i capture.pcap --filter "port 80"

# Limit number of packets processed
./packet-analyzer -i capture.pcap --count 1000

# Write report to file
./packet-analyzer -i capture.pcap -o report.txt --stats
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --input FILE` | Read packets from pcap file |
| `-o, --output FILE` | Write analysis report to file |
| `-v, --verbose` | Enable verbose output |
| `-s, --stats` | Show detailed statistics |
| `-f, --filter FILTER` | Apply packet filter |
| `-c, --count N` | Limit to N packets |
| `-d, --demo` | Run demo mode with synthetic packets |
| `-h, --help` | Show help message |
| `-V, --version` | Show version information |

### Filter Syntax

The filter option supports:
- `tcp` - TCP packets only
- `udp` - UDP packets only
- `port N` - Packets to/from port N

Examples:
```bash
./packet-analyzer -i capture.pcap -f tcp
./packet-analyzer -i capture.pcap -f "port 443"
```

## How It Works

### Packet Parsing

The packet analyzer uses a layered parsing approach:

1. **Link Layer (Ethernet)**: Extracts MAC addresses and determines the network layer protocol
2. **Network Layer (IPv4/IPv6)**: Extracts IP addresses and determines the transport layer protocol
3. **Transport Layer (TCP/UDP/ICMP)**: Extracts ports and payload data

### Header Structures

All protocol headers are defined as packed C++ structs for efficient memory layout:

```cpp
struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    // ... more fields
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    // ... more fields
};
```

### Analysis Pipeline

1. **Parse**: Raw bytes are parsed into structured `ParsedPacket` objects
2. **Filter**: Optional filtering based on protocol, addresses, ports
3. **Statistics**: Update traffic statistics and connection tracking
4. **Callback**: Optional callback for real-time packet processing
5. **Report**: Generate comprehensive analysis reports

### Thread Safety

The `PacketAnalyzer` class uses mutex protection for all shared state, making it safe to use in multi-threaded applications:

```cpp
analyzer::PacketAnalyzer analyzer;

// Safe to call from multiple threads
analyzer.analyze(packet_data);
```

## API Reference

### PacketParser

```cpp
#include "packet.h"

packet::PacketParser parser;
packet::ParsedPacket pkt = parser.parse(data, length);

// Access parsed fields
std::cout << "Source IP: " << pkt.src_ip << "\n";
std::cout << "Dest Port: " << pkt.dest_port << "\n";
std::cout << "Protocol: " << packet::PacketParser::protocolToString(pkt.transport_layer) << "\n";
```

### PacketAnalyzer

```cpp
#include "analyzer.h"

analyzer::PacketAnalyzer analyzer;

// Set up filtering
analyzer::PacketFilter filter;
filter.protocols.insert(packet::Protocol::TCP);
analyzer.setFilter(filter);

// Set callback for real-time processing
analyzer.setPacketCallback([](const packet::ParsedPacket& pkt) {
    std::cout << "New packet: " << pkt.src_ip << " -> " << pkt.dest_ip << "\n";
});

// Analyze packets
analyzer.analyze(packet_data);

// Get statistics
analyzer::TrafficStats stats = analyzer.getStats();
std::cout << "Total packets: " << stats.total_packets << "\n";

// Get active connections
auto connections = analyzer.getConnections();

// Generate report
std::string report = analyzer.generateReport();
```

## Running Tests

```bash
cd build

# Build and run tests
make run-tests

# Or run directly
./packet-analyzer-tests
```

## Example Output

```
=== Packet Analyzer Report ===

Analysis Duration: 5 seconds
Total Packets: 1500
Total Bytes: 1.25 MB

--- Protocol Distribution ---
  IPv4 Packets: 1450
  IPv6 Packets: 50
  TCP Packets: 1200
  UDP Packets: 250
  ICMP Packets: 50
  DNS Packets: 100
  Malformed: 0

--- Top Source IPs ---
  192.168.1.100: 500 packets
  10.0.0.50: 300 packets
  172.16.0.1: 200 packets

--- Top Ports ---
  Port 80: 400 packets
  Port 443: 350 packets
  Port 53: 100 packets

--- Active Connections ---
  192.168.1.100:45678 -> 93.184.216.34:80 (150 pkts, 125.50 KB)
  192.168.1.100:45679 -> 172.217.14.99:443 (120 pkts, 98.25 KB)
```

## License

This project is provided as-is for educational and research purposes.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the test suite
5. Submit a pull request

## Troubleshooting

### Build Errors

- Ensure CMake 3.10+ is installed: `cmake --version`
- Ensure a C++17 compatible compiler is available
- Check that all source files are present in the correct directories

### Runtime Errors

- "Cannot open file": Verify the pcap file path is correct
- "Invalid pcap file format": Ensure the file is a valid pcap capture
- Permission denied: Run with appropriate permissions for network operations
