#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <getopt.h>
#include <csignal>
#include <atomic>

#include "packet.h"
#include "analyzer.h"

namespace {

std::atomic<bool> g_running(true);

void signalHandler(int signum) {
    g_running = false;
    std::cout << "\nReceived signal " << signum << ", shutting down...\n";
}

void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [OPTIONS] [INPUT_FILE]\n\n";
    std::cout << "Raw Packet Analyzer - Deep packet inspection and protocol analysis\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i, --input FILE      Read packets from pcap file\n";
    std::cout << "  -o, --output FILE     Write analysis report to file\n";
    std::cout << "  -v, --verbose         Enable verbose output\n";
    std::cout << "  -s, --stats           Show detailed statistics\n";
    std::cout << "  -f, --filter FILTER   Apply packet filter (e.g., 'tcp', 'port 80')\n";
    std::cout << "  -c, --count N         Limit to N packets\n";
    std::cout << "  -h, --help            Show this help message\n";
    std::cout << "  -V, --version         Show version information\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program << " -i capture.pcap\n";
    std::cout << "  " << program << " -i capture.pcap -o report.txt -s\n";
    std::cout << "  " << program << " --verbose -i traffic.pcap --count 1000\n";
}

void printVersion() {
    std::cout << "Raw Packet Analyzer v1.0.0\n";
    std::cout << "A low-level network packet analyzer for deep packet inspection\n";
    std::cout << "and protocol analysis.\n";
}

std::vector<uint8_t> createTestPacket(uint8_t protocol, size_t payload_size) {
    std::vector<uint8_t> packet;
    
    size_t eth_header_size = 14;
    size_t ip_header_size = 20;
    size_t transport_header_size = 0;
    
    if (protocol == 6) {
        transport_header_size = 20;
    } else if (protocol == 17) {
        transport_header_size = 8;
    }
    
    size_t total_size = eth_header_size + ip_header_size + transport_header_size + payload_size;
    packet.resize(total_size, 0);
    
    size_t offset = 0;
    
    packet[offset + 0] = 0x00;
    packet[offset + 1] = 0x1a;
    packet[offset + 2] = 0x2b;
    packet[offset + 3] = 0x3c;
    packet[offset + 4] = 0x4d;
    packet[offset + 5] = 0x5e;
    
    packet[offset + 6] = 0x00;
    packet[offset + 7] = 0x11;
    packet[offset + 8] = 0x22;
    packet[offset + 9] = 0x33;
    packet[offset + 10] = 0x44;
    packet[offset + 11] = 0x55;
    
    packet[offset + 12] = 0x08;
    packet[offset + 13] = 0x00;
    
    offset += eth_header_size;
    
    packet[offset + 0] = 0x45;
    packet[offset + 1] = 0x00;
    
    uint16_t ip_total_len = static_cast<uint16_t>(ip_header_size + transport_header_size + payload_size);
    packet[offset + 2] = (ip_total_len >> 8) & 0xFF;
    packet[offset + 3] = ip_total_len & 0xFF;
    
    packet[offset + 6] = 0x40;
    packet[offset + 7] = 0x00;
    packet[offset + 8] = 0x40;
    packet[offset + 9] = protocol;
    
    packet[offset + 12] = 192;
    packet[offset + 13] = 168;
    packet[offset + 14] = 1;
    packet[offset + 15] = 100;
    
    packet[offset + 16] = 10;
    packet[offset + 17] = 0;
    packet[offset + 18] = 0;
    packet[offset + 19] = 1;
    
    offset += ip_header_size;
    
    if (protocol == 6) {
        uint16_t src_port = 12345;
        uint16_t dest_port = 80;
        
        packet[offset + 0] = (src_port >> 8) & 0xFF;
        packet[offset + 1] = src_port & 0xFF;
        packet[offset + 2] = (dest_port >> 8) & 0xFF;
        packet[offset + 3] = dest_port & 0xFF;
        
        packet[offset + 12] = 0x50;
        packet[offset + 13] = 0x02;
        packet[offset + 14] = 0xFF;
        packet[offset + 15] = 0xFF;
    } else if (protocol == 17) {
        uint16_t src_port = 53;
        uint16_t dest_port = 53;
        uint16_t udp_len = static_cast<uint16_t>(8 + payload_size);
        
        packet[offset + 0] = (src_port >> 8) & 0xFF;
        packet[offset + 1] = src_port & 0xFF;
        packet[offset + 2] = (dest_port >> 8) & 0xFF;
        packet[offset + 3] = dest_port & 0xFF;
        packet[offset + 4] = (udp_len >> 8) & 0xFF;
        packet[offset + 5] = udp_len & 0xFF;
    }
    
    for (size_t i = 0; i < payload_size; ++i) {
        packet[offset + transport_header_size + i] = static_cast<uint8_t>(i % 256);
    }
    
    return packet;
}

void runDemoMode(analyzer::PacketAnalyzer& analyzer, bool verbose) {
    std::cout << "Running demo mode with synthetic packets...\n\n";
    
    std::vector<uint8_t> tcp_packet = createTestPacket(6, 100);
    std::vector<uint8_t> udp_packet = createTestPacket(17, 50);
    std::vector<uint8_t> tcp_large = createTestPacket(6, 1400);
    
    for (int i = 0; i < 10; ++i) {
        analyzer.analyze(tcp_packet);
        if (verbose) {
            std::cout << "Analyzed TCP packet " << (i + 1) << "\n";
        }
    }
    
    for (int i = 0; i < 5; ++i) {
        analyzer.analyze(udp_packet);
        if (verbose) {
            std::cout << "Analyzed UDP packet " << (i + 1) << "\n";
        }
    }
    
    analyzer.analyze(tcp_large);
    
    if (verbose) {
        std::cout << "Analyzed large TCP packet\n";
    }
}

bool processPcapFile(const std::string& filename, analyzer::PacketAnalyzer& analyzer, 
                     bool verbose, size_t max_packets) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file '" << filename << "'\n";
        return false;
    }
    
    analyzer::PcapReader::PcapHeader pcap_header;
    file.read(reinterpret_cast<char*>(&pcap_header), sizeof(pcap_header));
    
    if (!analyzer::PcapReader::isValidPcap(pcap_header)) {
        std::cerr << "Error: Invalid pcap file format\n";
        return false;
    }
    
    bool swap_bytes = (pcap_header.magic_number == 0xd4c3b2a1);
    
    if (verbose) {
        std::cout << "Opened pcap file: " << filename << "\n";
        std::cout << "Pcap version: " << pcap_header.version_major << "." 
                  << pcap_header.version_minor << "\n";
        std::cout << "Snaplen: " << pcap_header.snaplen << "\n";
        std::cout << "Network: " << pcap_header.network << "\n\n";
    }
    
    size_t packet_count = 0;
    analyzer::PcapReader::PcapPacketHeader pkt_header;
    
    while (g_running && file.good()) {
        file.read(reinterpret_cast<char*>(&pkt_header), sizeof(pkt_header));
        if (!file.good()) {
            break;
        }
        
        uint32_t incl_len = pkt_header.incl_len;
        if (swap_bytes) {
            incl_len = ((incl_len & 0xFF000000) >> 24) |
                       ((incl_len & 0x00FF0000) >> 8) |
                       ((incl_len & 0x0000FF00) << 8) |
                       ((incl_len & 0x000000FF) << 24);
        }
        
        if (incl_len > pcap_header.snaplen || incl_len > 65535) {
            std::cerr << "Warning: Invalid packet length " << incl_len << ", skipping\n";
            file.seekg(pkt_header.orig_len, std::ios::cur);
            continue;
        }
        
        std::vector<uint8_t> packet_data(incl_len);
        file.read(reinterpret_cast<char*>(packet_data.data()), incl_len);
        
        if (!file.good()) {
            break;
        }
        
        analyzer.analyze(packet_data);
        packet_count++;
        
        if (verbose && packet_count % 100 == 0) {
            std::cout << "Processed " << packet_count << " packets...\n";
        }
        
        if (max_packets > 0 && packet_count >= max_packets) {
            break;
        }
    }
    
    if (verbose) {
        std::cout << "\nFinished processing " << packet_count << " packets\n";
    }
    
    return true;
}

void printPacketSummary(const packet::ParsedPacket& pkt) {
    std::cout << "[" << packet::PacketParser::protocolToString(pkt.network_layer)
              << "/" << packet::PacketParser::protocolToString(pkt.transport_layer) << "] ";
    
    if (!pkt.src_ip.empty() && !pkt.dest_ip.empty()) {
        std::cout << pkt.src_ip << ":" << pkt.src_port 
                  << " -> " << pkt.dest_ip << ":" << pkt.dest_port;
    } else if (!pkt.src_mac.empty() && !pkt.dest_mac.empty()) {
        std::cout << pkt.src_mac << " -> " << pkt.dest_mac;
    }
    
    std::cout << " (" << pkt.packet_size << " bytes)";
    
    if (!pkt.is_valid) {
        std::cout << " [INVALID: " << pkt.error_message << "]";
    }
    
    std::cout << "\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    std::string input_file;
    std::string output_file;
    std::string filter_str;
    bool verbose = false;
    bool show_stats = false;
    size_t max_packets = 0;
    bool demo_mode = false;
    
    static struct option long_options[] = {
        {"input",   required_argument, 0, 'i'},
        {"output",  required_argument, 0, 'o'},
        {"verbose", no_argument,       0, 'v'},
        {"stats",   no_argument,       0, 's'},
        {"filter",  required_argument, 0, 'f'},
        {"count",   required_argument, 0, 'c'},
        {"demo",    no_argument,       0, 'd'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "i:o:vsf:c:dhV", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 's':
                show_stats = true;
                break;
            case 'f':
                filter_str = optarg;
                break;
            case 'c':
                max_packets = std::stoul(optarg);
                break;
            case 'd':
                demo_mode = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 'V':
                printVersion();
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    analyzer::PacketAnalyzer analyzer;
    
    if (!filter_str.empty()) {
        analyzer::PacketFilter filter;
        
        if (filter_str.find("tcp") != std::string::npos ||
            filter_str.find("TCP") != std::string::npos) {
            filter.protocols.insert(packet::Protocol::TCP);
        }
        if (filter_str.find("udp") != std::string::npos ||
            filter_str.find("UDP") != std::string::npos) {
            filter.protocols.insert(packet::Protocol::UDP);
        }
        if (filter_str.find("port ") != std::string::npos) {
            size_t pos = filter_str.find("port ") + 5;
            uint16_t port = static_cast<uint16_t>(std::stoul(filter_str.substr(pos)));
            filter.dest_ports.insert(port);
            filter.src_ports.insert(port);
        }
        
        analyzer.setFilter(filter);
    }
    
    analyzer.setPacketCallback([&verbose](const packet::ParsedPacket& pkt) {
        if (verbose) {
            printPacketSummary(pkt);
        }
    });
    
    if (demo_mode || input_file.empty()) {
        runDemoMode(analyzer, verbose);
    } else {
        if (!processPcapFile(input_file, analyzer, verbose, max_packets)) {
            return 1;
        }
    }
    
    std::string report = analyzer.generateReport();
    
    if (!output_file.empty()) {
        std::ofstream out(output_file);
        if (out.is_open()) {
            out << report;
            out.close();
            std::cout << "Report written to: " << output_file << "\n";
        } else {
            std::cerr << "Error: Cannot write to output file '" << output_file << "'\n";
        }
    }
    
    if (show_stats || verbose) {
        std::cout << "\n" << report;
    }
    
    auto connections = analyzer.getConnections();
    if (!connections.empty() && (show_stats || verbose)) {
        std::cout << "\n--- Connection Summary ---\n";
        size_t count = 0;
        for (const auto& conn : connections) {
            if (++count > 5) break;
            std::cout << "  " << conn.src_ip << ":" << conn.src_port
                      << " <-> " << conn.dest_ip << ":" << conn.dest_port
                      << " [" << conn.packet_count << " packets]\n";
        }
    }
    
    std::cout << "\nAnalysis complete.\n";
    
    return 0;
}
