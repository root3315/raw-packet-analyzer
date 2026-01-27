#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstdint>
#include <cstring>

#include "packet.h"
#include "analyzer.h"

namespace {

int tests_passed = 0;
int tests_failed = 0;

void test_passed(const std::string& name) {
    std::cout << "[PASS] " << name << "\n";
    tests_passed++;
}

void test_failed(const std::string& name, const std::string& reason) {
    std::cout << "[FAIL] " << name << ": " << reason << "\n";
    tests_failed++;
}

std::vector<uint8_t> createEthernetIPv4TCPPacket() {
    std::vector<uint8_t> packet(54, 0);
    
    packet[0] = 0x00;
    packet[1] = 0x1a;
    packet[2] = 0x2b;
    packet[3] = 0x3c;
    packet[4] = 0x4d;
    packet[5] = 0x5e;
    
    packet[6] = 0x00;
    packet[7] = 0x11;
    packet[8] = 0x22;
    packet[9] = 0x33;
    packet[10] = 0x44;
    packet[11] = 0x55;
    
    packet[12] = 0x08;
    packet[13] = 0x00;
    
    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[16] = 0x00;
    packet[17] = 0x28;
    packet[18] = 0x00;
    packet[19] = 0x01;
    packet[20] = 0x00;
    packet[21] = 0x00;
    packet[22] = 0x40;
    packet[23] = 0x06;
    packet[24] = 0x00;
    packet[25] = 0x00;
    
    packet[26] = 192;
    packet[27] = 168;
    packet[28] = 1;
    packet[29] = 100;
    
    packet[30] = 10;
    packet[31] = 0;
    packet[32] = 0;
    packet[33] = 1;
    
    packet[34] = 0x30;
    packet[35] = 0x39;
    packet[36] = 0x00;
    packet[37] = 0x50;
    
    packet[46] = 0x50;
    packet[47] = 0x02;
    
    return packet;
}

std::vector<uint8_t> createEthernetIPv4UDPPacket() {
    std::vector<uint8_t> packet(42, 0);
    
    packet[0] = 0x00;
    packet[1] = 0xaa;
    packet[2] = 0xbb;
    packet[3] = 0xcc;
    packet[4] = 0xdd;
    packet[5] = 0xee;
    
    packet[6] = 0x00;
    packet[7] = 0x11;
    packet[8] = 0x22;
    packet[9] = 0x33;
    packet[10] = 0x44;
    packet[11] = 0x55;
    
    packet[12] = 0x08;
    packet[13] = 0x00;
    
    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[16] = 0x00;
    packet[17] = 0x1e;
    packet[18] = 0x00;
    packet[19] = 0x01;
    packet[20] = 0x00;
    packet[21] = 0x00;
    packet[22] = 0x40;
    packet[23] = 0x11;
    packet[24] = 0x00;
    packet[25] = 0x00;
    
    packet[26] = 172;
    packet[27] = 16;
    packet[28] = 0;
    packet[29] = 1;
    
    packet[30] = 8;
    packet[31] = 8;
    packet[32] = 8;
    packet[33] = 8;
    
    packet[34] = 0xc0;
    packet[35] = 0x00;
    packet[36] = 0x00;
    packet[37] = 0x35;
    packet[38] = 0x00;
    packet[39] = 0x0a;
    
    return packet;
}

std::vector<uint8_t> createTooSmallPacket() {
    return std::vector<uint8_t>{0x00, 0x11, 0x22};
}

void test_mac_to_string() {
    const uint8_t mac[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
    std::string result = packet::PacketParser::macToString(mac);
    
    if (result == "00:1a:2b:3c:4d:5e") {
        test_passed("test_mac_to_string");
    } else {
        test_failed("test_mac_to_string", "Expected '00:1a:2b:3c:4d:5e', got '" + result + "'");
    }
}

void test_ipv4_to_string() {
    uint32_t addr = (192 << 24) | (168 << 16) | (1 << 8) | 100;
    std::string result = packet::PacketParser::ipv4ToString(addr);
    
    if (result == "192.168.1.100") {
        test_passed("test_ipv4_to_string");
    } else {
        test_failed("test_ipv4_to_string", "Expected '192.168.1.100', got '" + result + "'");
    }
}

void test_protocol_to_string() {
    std::string tcp = packet::PacketParser::protocolToString(packet::Protocol::TCP);
    std::string udp = packet::PacketParser::protocolToString(packet::Protocol::UDP);
    std::string unknown = packet::PacketParser::protocolToString(packet::Protocol::UNKNOWN);
    
    if (tcp == "TCP" && udp == "UDP" && unknown == "Unknown") {
        test_passed("test_protocol_to_string");
    } else {
        test_failed("test_protocol_to_string", "Protocol string conversion failed");
    }
}

void test_parse_tcp_packet() {
    packet::PacketParser parser;
    std::vector<uint8_t> pkt = createEthernetIPv4TCPPacket();
    
    packet::ParsedPacket result = parser.parse(pkt);
    
    if (result.is_valid &&
        result.link_layer == packet::Protocol::ETHERNET &&
        result.network_layer == packet::Protocol::IPv4 &&
        result.transport_layer == packet::Protocol::TCP &&
        result.src_ip == "192.168.1.100" &&
        result.dest_ip == "10.0.0.1" &&
        result.src_port == 12345 &&
        result.dest_port == 80) {
        test_passed("test_parse_tcp_packet");
    } else {
        std::string reason = "Valid: " + std::to_string(result.is_valid) +
                            ", Network: " + std::to_string(static_cast<int>(result.network_layer)) +
                            ", Transport: " + std::to_string(static_cast<int>(result.transport_layer)) +
                            ", SrcIP: " + result.src_ip +
                            ", DstIP: " + result.dest_ip +
                            ", SrcPort: " + std::to_string(result.src_port) +
                            ", DstPort: " + std::to_string(result.dest_port);
        test_failed("test_parse_tcp_packet", reason);
    }
}

void test_parse_udp_packet() {
    packet::PacketParser parser;
    std::vector<uint8_t> pkt = createEthernetIPv4UDPPacket();
    
    packet::ParsedPacket result = parser.parse(pkt);
    
    if (result.is_valid &&
        result.link_layer == packet::Protocol::ETHERNET &&
        result.network_layer == packet::Protocol::IPv4 &&
        result.transport_layer == packet::Protocol::DNS &&
        result.src_ip == "172.16.0.1" &&
        result.dest_ip == "8.8.8.8" &&
        result.src_port == 49152 &&
        result.dest_port == 53) {
        test_passed("test_parse_udp_packet");
    } else {
        std::string reason = "Valid: " + std::to_string(result.is_valid) +
                            ", Transport: " + std::to_string(static_cast<int>(result.transport_layer)) +
                            ", SrcIP: " + result.src_ip +
                            ", DstIP: " + result.dest_ip;
        test_failed("test_parse_udp_packet", reason);
    }
}

void test_parse_invalid_packet() {
    packet::PacketParser parser;
    std::vector<uint8_t> pkt = createTooSmallPacket();
    
    packet::ParsedPacket result = parser.parse(pkt);
    
    if (!result.is_valid && !result.error_message.empty()) {
        test_passed("test_parse_invalid_packet");
    } else {
        test_failed("test_parse_invalid_packet", "Expected invalid packet detection");
    }
}

void test_analyzer_stats() {
    analyzer::PacketAnalyzer analyzer;
    
    std::vector<uint8_t> tcp_pkt = createEthernetIPv4TCPPacket();
    std::vector<uint8_t> udp_pkt = createEthernetIPv4UDPPacket();
    
    for (int i = 0; i < 5; ++i) {
        analyzer.analyze(tcp_pkt);
    }
    for (int i = 0; i < 3; ++i) {
        analyzer.analyze(udp_pkt);
    }
    
    analyzer::TrafficStats stats = analyzer.getStats();
    
    if (stats.total_packets == 8 &&
        stats.tcp_packets == 5 &&
        (stats.udp_packets + stats.dns_packets) == 3 &&
        stats.ipv4_packets == 8) {
        test_passed("test_analyzer_stats");
    } else {
        std::string reason = "Total: " + std::to_string(stats.total_packets) +
                            ", TCP: " + std::to_string(stats.tcp_packets) +
                            ", UDP: " + std::to_string(stats.udp_packets) +
                            ", DNS: " + std::to_string(stats.dns_packets) +
                            ", IPv4: " + std::to_string(stats.ipv4_packets);
        test_failed("test_analyzer_stats", reason);
    }
}

void test_analyzer_connections() {
    analyzer::PacketAnalyzer analyzer;
    
    std::vector<uint8_t> tcp_pkt = createEthernetIPv4TCPPacket();
    
    for (int i = 0; i < 10; ++i) {
        analyzer.analyze(tcp_pkt);
    }
    
    std::vector<analyzer::ConnectionInfo> connections = analyzer.getConnections();
    
    if (connections.size() == 1 && connections[0].packet_count == 10) {
        test_passed("test_analyzer_connections");
    } else {
        std::string reason = "Connections: " + std::to_string(connections.size());
        if (!connections.empty()) {
            reason += ", Packet count: " + std::to_string(connections[0].packet_count);
        }
        test_failed("test_analyzer_connections", reason);
    }
}

void test_packet_filter() {
    analyzer::PacketFilter filter;
    filter.protocols.insert(packet::Protocol::TCP);
    filter.dest_ports.insert(80);
    
    packet::PacketParser parser;
    std::vector<uint8_t> tcp_pkt = createEthernetIPv4TCPPacket();
    packet::ParsedPacket pkt = parser.parse(tcp_pkt);
    
    if (filter.matches(pkt)) {
        test_passed("test_packet_filter");
    } else {
        test_failed("test_packet_filter", "Filter should match TCP packet on port 80");
    }
}

void test_analyzer_report() {
    analyzer::PacketAnalyzer analyzer;
    
    std::vector<uint8_t> tcp_pkt = createEthernetIPv4TCPPacket();
    for (int i = 0; i < 3; ++i) {
        analyzer.analyze(tcp_pkt);
    }
    
    std::string report = analyzer.generateReport();
    
    if (report.find("Total Packets: 3") != std::string::npos &&
        report.find("TCP Packets: 3") != std::string::npos) {
        test_passed("test_analyzer_report");
    } else {
        test_failed("test_analyzer_report", "Report does not contain expected statistics");
    }
}

void test_ntohs_ntohl() {
    uint16_t h16 = 0x1234;
    uint16_t n16 = packet::PacketParser::swap16(h16);
    
    uint32_t h32 = 0x12345678;
    uint32_t n32 = packet::PacketParser::swap32(h32);
    
    if (n16 == 0x3412 && n32 == 0x78563412) {
        test_passed("test_ntohs_ntohl");
    } else {
        test_failed("test_ntohs_ntohl", "Byte order conversion failed");
    }
}

void test_format_bytes() {
    std::string b = analyzer::PacketAnalyzer::formatBytes(512);
    std::string kb = analyzer::PacketAnalyzer::formatBytes(2048);
    std::string mb = analyzer::PacketAnalyzer::formatBytes(2097152);
    
    if (b.find("512 B") != std::string::npos &&
        kb.find("2.00 KB") != std::string::npos &&
        mb.find("2.00 MB") != std::string::npos) {
        test_passed("test_format_bytes");
    } else {
        test_failed("test_format_bytes", "Byte formatting failed");
    }
}

void test_analyzer_reset() {
    analyzer::PacketAnalyzer analyzer;
    
    std::vector<uint8_t> tcp_pkt = createEthernetIPv4TCPPacket();
    for (int i = 0; i < 10; ++i) {
        analyzer.analyze(tcp_pkt);
    }
    
    analyzer.reset();
    analyzer::TrafficStats stats = analyzer.getStats();
    
    if (stats.total_packets == 0 && stats.tcp_packets == 0) {
        test_passed("test_analyzer_reset");
    } else {
        test_failed("test_analyzer_reset", "Reset did not clear statistics");
    }
}

} // anonymous namespace

int main() {
    std::cout << "=== Raw Packet Analyzer Test Suite ===\n\n";
    
    test_mac_to_string();
    test_ipv4_to_string();
    test_protocol_to_string();
    test_ntohs_ntohl();
    test_format_bytes();
    
    test_parse_tcp_packet();
    test_parse_udp_packet();
    test_parse_invalid_packet();
    
    test_packet_filter();
    
    test_analyzer_stats();
    test_analyzer_connections();
    test_analyzer_report();
    test_analyzer_reset();
    
    std::cout << "\n=== Test Summary ===\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";
    std::cout << "Total:  " << (tests_passed + tests_failed) << "\n";
    
    return tests_failed > 0 ? 1 : 0;
}
