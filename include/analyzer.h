#ifndef ANALYZER_H
#define ANALYZER_H

#include "packet.h"
#include <map>
#include <set>
#include <mutex>
#include <functional>
#include <chrono>

namespace analyzer {

struct TrafficStats {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t dns_packets;
    uint64_t arp_packets;
    uint64_t malformed_packets;

    std::map<std::string, uint64_t> src_ip_counts;
    std::map<std::string, uint64_t> dest_ip_counts;
    std::map<uint16_t, uint64_t> port_counts;
    std::set<std::string> unique_macs;

    TrafficStats()
        : total_packets(0)
        , total_bytes(0)
        , tcp_packets(0)
        , udp_packets(0)
        , icmp_packets(0)
        , ipv4_packets(0)
        , ipv6_packets(0)
        , dns_packets(0)
        , arp_packets(0)
        , malformed_packets(0) {}
};

struct ConnectionInfo {
    std::string src_ip;
    std::string dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint64_t packet_count;
    uint64_t byte_count;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    ConnectionInfo()
        : src_port(0)
        , dest_port(0)
        , packet_count(0)
        , byte_count(0)
        , first_seen(std::chrono::steady_clock::now())
        , last_seen(std::chrono::steady_clock::now()) {}
};

struct PacketFilter {
    std::set<std::string> src_ips;
    std::set<std::string> dest_ips;
    std::set<uint16_t> src_ports;
    std::set<uint16_t> dest_ports;
    std::set<packet::Protocol> protocols;
    size_t min_packet_size;
    size_t max_packet_size;
    
    PacketFilter()
        : min_packet_size(0)
        , max_packet_size(SIZE_MAX) {}
    
    bool matches(const packet::ParsedPacket& pkt) const;
};

class PacketAnalyzer {
public:
    using PacketCallback = std::function<void(const packet::ParsedPacket&)>;
    
    PacketAnalyzer();
    ~PacketAnalyzer();
    
    void analyze(const uint8_t* data, size_t length);
    void analyze(const std::vector<uint8_t>& data);
    
    void setPacketCallback(PacketCallback callback);
    void setFilter(const PacketFilter& filter);
    void clearFilter();
    
    TrafficStats getStats() const;
    std::vector<ConnectionInfo> getConnections() const;
    std::vector<packet::ParsedPacket> getRecentPackets(size_t count = 100) const;
    
    void reset();
    std::string generateReport() const;
    
    static std::string formatBytes(uint64_t bytes);
    static std::string formatTimestamp(std::chrono::steady_clock::time_point tp);
    
private:
    void updateStats(const packet::ParsedPacket& pkt);
    void updateConnections(const packet::ParsedPacket& pkt);
    std::string makeConnectionKey(const packet::ParsedPacket& pkt) const;
    
    mutable std::mutex mutex_;
    packet::PacketParser parser_;
    PacketFilter filter_;
    PacketCallback callback_;
    
    TrafficStats stats_;
    std::map<std::string, ConnectionInfo> connections_;
    std::vector<packet::ParsedPacket> recent_packets_;
    size_t max_recent_packets_;
    
    std::chrono::steady_clock::time_point start_time_;
};

class PcapReader {
public:
    struct PcapHeader {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    };
    
    struct PcapPacketHeader {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    };
    
    static bool openFile(const std::string& filename, std::ifstream& file, PcapHeader& header);
    static bool readPacket(std::ifstream& file, std::vector<uint8_t>& packet, PcapPacketHeader& pkt_header);
    static bool isValidPcap(const PcapHeader& header);
};

} // namespace analyzer

#endif // ANALYZER_H
