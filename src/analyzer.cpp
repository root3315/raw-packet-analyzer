#include "analyzer.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>

namespace analyzer {

bool PacketFilter::matches(const packet::ParsedPacket& pkt) const {
    if (!pkt.is_valid) {
        return false;
    }
    
    if (pkt.packet_size < min_packet_size || pkt.packet_size > max_packet_size) {
        return false;
    }
    
    if (!src_ips.empty() && src_ips.find(pkt.src_ip) == src_ips.end()) {
        return false;
    }
    
    if (!dest_ips.empty() && dest_ips.find(pkt.dest_ip) == dest_ips.end()) {
        return false;
    }
    
    if (!src_ports.empty() && src_ports.find(pkt.src_port) == src_ports.end()) {
        return false;
    }
    
    if (!dest_ports.empty() && dest_ports.find(pkt.dest_port) == dest_ports.end()) {
        return false;
    }
    
    if (!protocols.empty()) {
        bool proto_match = (protocols.count(pkt.network_layer) > 0) ||
                          (protocols.count(pkt.transport_layer) > 0);
        if (!proto_match) {
            return false;
        }
    }
    
    return true;
}

PacketAnalyzer::PacketAnalyzer()
    : max_recent_packets_(100)
    , start_time_(std::chrono::steady_clock::now()) {
}

PacketAnalyzer::~PacketAnalyzer() = default;

void PacketAnalyzer::analyze(const uint8_t* data, size_t length) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    packet::ParsedPacket pkt = parser_.parse(data, length);
    
    if (!pkt.is_valid) {
        stats_.malformed_packets++;
        return;
    }
    
    if (!filter_.matches(pkt)) {
        return;
    }
    
    updateStats(pkt);
    updateConnections(pkt);
    
    recent_packets_.push_back(pkt);
    while (recent_packets_.size() > max_recent_packets_) {
        recent_packets_.erase(recent_packets_.begin());
    }
    
    if (callback_) {
        callback_(pkt);
    }
}

void PacketAnalyzer::analyze(const std::vector<uint8_t>& data) {
    analyze(data.data(), data.size());
}

void PacketAnalyzer::setPacketCallback(PacketCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(callback);
}

void PacketAnalyzer::setFilter(const PacketFilter& filter) {
    std::lock_guard<std::mutex> lock(mutex_);
    filter_ = filter;
}

void PacketAnalyzer::clearFilter() {
    std::lock_guard<std::mutex> lock(mutex_);
    filter_ = PacketFilter();
}

TrafficStats PacketAnalyzer::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

std::vector<ConnectionInfo> PacketAnalyzer::getConnections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ConnectionInfo> result;
    result.reserve(connections_.size());
    
    for (const auto& pair : connections_) {
        result.push_back(pair.second);
    }
    
    std::sort(result.begin(), result.end(),
        [](const ConnectionInfo& a, const ConnectionInfo& b) {
            return a.packet_count > b.packet_count;
        });
    
    return result;
}

std::vector<packet::ParsedPacket> PacketAnalyzer::getRecentPackets(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<packet::ParsedPacket> result;
    size_t start = (recent_packets_.size() > count) ? 
                   (recent_packets_.size() - count) : 0;
    
    for (size_t i = start; i < recent_packets_.size(); ++i) {
        result.push_back(recent_packets_[i]);
    }
    
    return result;
}

void PacketAnalyzer::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    stats_ = TrafficStats();
    connections_.clear();
    recent_packets_.clear();
    start_time_ = std::chrono::steady_clock::now();
}

std::string PacketAnalyzer::generateReport() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ostringstream oss;
    oss << "=== Packet Analyzer Report ===\n\n";
    
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
    
    oss << "Analysis Duration: " << duration.count() << " seconds\n";
    oss << "Total Packets: " << stats_.total_packets << "\n";
    oss << "Total Bytes: " << formatBytes(stats_.total_bytes) << "\n\n";
    
    oss << "--- Protocol Distribution ---\n";
    oss << "  IPv4 Packets: " << stats_.ipv4_packets << "\n";
    oss << "  IPv6 Packets: " << stats_.ipv6_packets << "\n";
    oss << "  TCP Packets: " << stats_.tcp_packets << "\n";
    oss << "  UDP Packets: " << stats_.udp_packets << "\n";
    oss << "  ICMP Packets: " << stats_.icmp_packets << "\n";
    oss << "  DNS Packets: " << stats_.dns_packets << "\n";
    oss << "  Malformed: " << stats_.malformed_packets << "\n\n";
    
    oss << "--- Top Source IPs ---\n";
    std::vector<std::pair<std::string, uint64_t>> src_ips(
        stats_.src_ip_counts.begin(), stats_.src_ip_counts.end());
    std::sort(src_ips.begin(), src_ips.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    size_t count = 0;
    for (const auto& pair : src_ips) {
        if (++count > 10) break;
        oss << "  " << pair.first << ": " << pair.second << " packets\n";
    }
    
    oss << "\n--- Top Destination IPs ---\n";
    std::vector<std::pair<std::string, uint64_t>> dest_ips(
        stats_.dest_ip_counts.begin(), stats_.dest_ip_counts.end());
    std::sort(dest_ips.begin(), dest_ips.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    count = 0;
    for (const auto& pair : dest_ips) {
        if (++count > 10) break;
        oss << "  " << pair.first << ": " << pair.second << " packets\n";
    }
    
    oss << "\n--- Top Ports ---\n";
    std::vector<std::pair<uint16_t, uint64_t>> ports(
        stats_.port_counts.begin(), stats_.port_counts.end());
    std::sort(ports.begin(), ports.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    count = 0;
    for (const auto& pair : ports) {
        if (++count > 10) break;
        oss << "  Port " << pair.first << ": " << pair.second << " packets\n";
    }
    
    oss << "\n--- Active Connections ---\n";
    count = 0;
    for (const auto& pair : connections_) {
        if (++count > 10) break;
        const auto& conn = pair.second;
        oss << "  " << conn.src_ip << ":" << conn.src_port 
            << " -> " << conn.dest_ip << ":" << conn.dest_port
            << " (" << conn.packet_count << " pkts, " 
            << formatBytes(conn.byte_count) << ")\n";
    }
    
    oss << "\n--- Unique MAC Addresses ---\n";
    oss << "  Count: " << stats_.unique_macs.size() << "\n";
    
    return oss.str();
}

std::string PacketAnalyzer::formatBytes(uint64_t bytes) {
    std::ostringstream oss;
    if (bytes >= 1073741824) {
        oss << std::fixed << std::setprecision(2) 
            << (bytes / 1073741824.0) << " GB";
    } else if (bytes >= 1048576) {
        oss << std::fixed << std::setprecision(2) 
            << (bytes / 1048576.0) << " MB";
    } else if (bytes >= 1024) {
        oss << std::fixed << std::setprecision(2) 
            << (bytes / 1024.0) << " KB";
    } else {
        oss << bytes << " B";
    }
    return oss.str();
}

std::string PacketAnalyzer::formatTimestamp(std::chrono::steady_clock::time_point tp) {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void PacketAnalyzer::updateStats(const packet::ParsedPacket& pkt) {
    stats_.total_packets++;
    stats_.total_bytes += pkt.packet_size;
    
    if (pkt.network_layer == packet::Protocol::IPv4) {
        stats_.ipv4_packets++;
    } else if (pkt.network_layer == packet::Protocol::IPv6) {
        stats_.ipv6_packets++;
    }
    
    if (pkt.transport_layer == packet::Protocol::TCP) {
        stats_.tcp_packets++;
    } else if (pkt.transport_layer == packet::Protocol::UDP) {
        stats_.udp_packets++;
    } else if (pkt.transport_layer == packet::Protocol::ICMP) {
        stats_.icmp_packets++;
    }
    
    if (pkt.transport_layer == packet::Protocol::DNS) {
        stats_.dns_packets++;
    }
    
    if (!pkt.src_ip.empty()) {
        stats_.src_ip_counts[pkt.src_ip]++;
    }
    if (!pkt.dest_ip.empty()) {
        stats_.dest_ip_counts[pkt.dest_ip]++;
    }
    
    if (pkt.src_port > 0) {
        stats_.port_counts[pkt.src_port]++;
    }
    if (pkt.dest_port > 0) {
        stats_.port_counts[pkt.dest_port]++;
    }
    
    if (!pkt.src_mac.empty()) {
        stats_.unique_macs.insert(pkt.src_mac);
    }
    if (!pkt.dest_mac.empty()) {
        stats_.unique_macs.insert(pkt.dest_mac);
    }
}

void PacketAnalyzer::updateConnections(const packet::ParsedPacket& pkt) {
    if (pkt.transport_layer != packet::Protocol::TCP &&
        pkt.transport_layer != packet::Protocol::UDP) {
        return;
    }
    
    std::string key = makeConnectionKey(pkt);
    auto it = connections_.find(key);
    
    auto now = std::chrono::steady_clock::now();
    
    if (it == connections_.end()) {
        ConnectionInfo conn;
        conn.src_ip = pkt.src_ip;
        conn.dest_ip = pkt.dest_ip;
        conn.src_port = pkt.src_port;
        conn.dest_port = pkt.dest_port;
        conn.packet_count = 1;
        conn.byte_count = pkt.packet_size;
        conn.first_seen = now;
        conn.last_seen = now;
        connections_[key] = conn;
    } else {
        it->second.packet_count++;
        it->second.byte_count += pkt.packet_size;
        it->second.last_seen = now;
    }
}

std::string PacketAnalyzer::makeConnectionKey(const packet::ParsedPacket& pkt) const {
    std::ostringstream oss;
    oss << pkt.src_ip << ":" << pkt.src_port 
        << "-" << pkt.dest_ip << ":" << pkt.dest_port;
    return oss.str();
}

bool PcapReader::openFile(const std::string& filename, std::ifstream& file, PcapHeader& header) {
    file.open(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file.read(reinterpret_cast<char*>(&header), sizeof(PcapHeader));
    if (!file.good()) {
        return false;
    }
    
    return isValidPcap(header);
}

bool PcapReader::readPacket(std::ifstream& file, std::vector<uint8_t>& packet, PcapPacketHeader& pkt_header) {
    file.read(reinterpret_cast<char*>(&pkt_header), sizeof(PcapPacketHeader));
    if (!file.good()) {
        return false;
    }
    
    packet.resize(pkt_header.incl_len);
    file.read(reinterpret_cast<char*>(packet.data()), pkt_header.incl_len);
    
    return file.good();
}

bool PcapReader::isValidPcap(const PcapHeader& header) {
    return (header.magic_number == 0xa1b2c3d4) || 
           (header.magic_number == 0xd4c3b2a1);
}

} // namespace analyzer
