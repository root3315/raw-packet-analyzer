#include "packet.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

namespace packet {

uint16_t PacketParser::swap16(uint16_t value) {
    return (value >> 8) | ((value & 0xFF) << 8);
}

uint32_t PacketParser::swap32(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x000000FF) << 24);
}

std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string PacketParser::ipv4ToString(uint32_t addr) {
    uint8_t bytes[4];
    bytes[0] = (addr >> 24) & 0xFF;
    bytes[1] = (addr >> 16) & 0xFF;
    bytes[2] = (addr >> 8) & 0xFF;
    bytes[3] = addr & 0xFF;
    
    std::ostringstream oss;
    oss << static_cast<int>(bytes[0]) << "."
        << static_cast<int>(bytes[1]) << "."
        << static_cast<int>(bytes[2]) << "."
        << static_cast<int>(bytes[3]);
    return oss.str();
}

std::string PacketParser::ipv6ToString(const uint8_t* addr) {
    std::ostringstream oss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t word = (addr[i] << 8) | addr[i + 1];
        oss << std::hex << std::setfill('0') << std::setw(4) << word;
    }
    return oss.str();
}

std::string PacketParser::protocolToString(Protocol proto) {
    switch (proto) {
        case Protocol::ETHERNET: return "Ethernet";
        case Protocol::IPv4: return "IPv4";
        case Protocol::IPv6: return "IPv6";
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        case Protocol::ICMP: return "ICMP";
        case Protocol::ARP: return "ARP";
        case Protocol::DNS: return "DNS";
        default: return "Unknown";
    }
}

ParsedPacket PacketParser::parse(const uint8_t* data, size_t length) {
    ParsedPacket packet;
    packet.raw_data.assign(data, data + length);
    packet.packet_size = static_cast<uint32_t>(length);
    
    if (length < sizeof(EthernetHeader)) {
        packet.is_valid = false;
        packet.error_message = "Packet too small for Ethernet header";
        return packet;
    }
    
    if (!parseEthernet(data, length, packet)) {
        return packet;
    }
    
    packet.is_valid = true;
    return packet;
}

ParsedPacket PacketParser::parse(const std::vector<uint8_t>& data) {
    return parse(data.data(), data.size());
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t length, ParsedPacket& packet) {
    const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
    
    packet.link_layer = Protocol::ETHERNET;
    packet.src_mac = macToString(eth->src_mac);
    packet.dest_mac = macToString(eth->dest_mac);
    
    uint16_t ether_type = swap16(eth->ether_type);
    size_t header_size = sizeof(EthernetHeader);
    
    const uint8_t* payload = data + header_size;
    size_t remaining = length - header_size;
    
    if (ether_type == 0x0800) {
        packet.network_layer = Protocol::IPv4;
        if (!parseIPv4(payload, remaining, packet)) {
            return false;
        }
    } else if (ether_type == 0x86DD) {
        packet.network_layer = Protocol::IPv6;
        if (!parseIPv6(payload, remaining, packet)) {
            return false;
        }
    } else if (ether_type == 0x0806) {
        packet.network_layer = Protocol::ARP;
        if (!parseARP(payload, remaining, packet)) {
            return false;
        }
    } else {
        packet.header_size = static_cast<uint32_t>(header_size);
        packet.payload_size = static_cast<uint32_t>(remaining);
    }
    
    return true;
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t length, ParsedPacket& packet) {
    if (length < sizeof(IPv4Header)) {
        packet.is_valid = false;
        packet.error_message = "Packet too small for IPv4 header";
        return false;
    }
    
    const auto* ip = reinterpret_cast<const IPv4Header*>(data);
    
    uint8_t ihl = ip->version_ihl & 0x0F;
    uint8_t version = (ip->version_ihl >> 4) & 0x0F;
    
    if (version != 4) {
        packet.is_valid = false;
        packet.error_message = "Invalid IPv4 version";
        return false;
    }
    
    size_t ip_header_size = ihl * 4;
    if (length < ip_header_size) {
        packet.is_valid = false;
        packet.error_message = "Invalid IPv4 header length";
        return false;
    }
    
    packet.src_ip = ipv4ToString(swap32(ip->src_addr));
    packet.dest_ip = ipv4ToString(swap32(ip->dest_addr));
    packet.header_size = static_cast<uint32_t>(sizeof(EthernetHeader) + ip_header_size);
    
    uint8_t protocol = ip->protocol;
    const uint8_t* payload = data + ip_header_size;
    size_t remaining = length - ip_header_size;
    
    if (protocol == 6) {
        packet.transport_layer = Protocol::TCP;
        if (!parseTCP(payload, remaining, packet)) {
            return true;
        }
    } else if (protocol == 17) {
        packet.transport_layer = Protocol::UDP;
        if (!parseUDP(payload, remaining, packet)) {
            return true;
        }
    } else if (protocol == 1) {
        packet.transport_layer = Protocol::ICMP;
        if (!parseICMP(payload, remaining, packet)) {
            return true;
        }
    } else {
        packet.payload_size = static_cast<uint32_t>(remaining);
    }
    
    return true;
}

bool PacketParser::parseIPv6(const uint8_t* data, size_t length, ParsedPacket& packet) {
    if (length < sizeof(IPv6Header)) {
        packet.is_valid = false;
        packet.error_message = "Packet too small for IPv6 header";
        return false;
    }
    
    const auto* ip = reinterpret_cast<const IPv6Header*>(data);
    
    uint32_t version = (swap32(ip->version_tc_fl) >> 28) & 0x0F;
    if (version != 6) {
        packet.is_valid = false;
        packet.error_message = "Invalid IPv6 version";
        return false;
    }
    
    packet.src_ip = ipv6ToString(ip->src_addr);
    packet.dest_ip = ipv6ToString(ip->dest_addr);
    packet.header_size = static_cast<uint32_t>(sizeof(EthernetHeader) + sizeof(IPv6Header));
    
    uint8_t next_header = ip->next_header;
    const uint8_t* payload = data + sizeof(IPv6Header);
    size_t remaining = length - sizeof(IPv6Header);
    
    if (next_header == 6) {
        packet.transport_layer = Protocol::TCP;
        parseTCP(payload, remaining, packet);
    } else if (next_header == 17) {
        packet.transport_layer = Protocol::UDP;
        parseUDP(payload, remaining, packet);
    } else if (next_header == 58) {
        packet.transport_layer = Protocol::ICMP;
        parseICMP(payload, remaining, packet);
    } else {
        packet.payload_size = static_cast<uint32_t>(remaining);
    }
    
    return true;
}

bool PacketParser::parseTCP(const uint8_t* data, size_t length, ParsedPacket& packet) {
    if (length < sizeof(TCPHeader)) {
        packet.payload_size = static_cast<uint32_t>(length);
        return false;
    }
    
    const auto* tcp = reinterpret_cast<const TCPHeader*>(data);
    
    packet.src_port = swap16(tcp->src_port);
    packet.dest_port = swap16(tcp->dest_port);
    
    uint8_t data_offset = (tcp->data_offset >> 4) * 4;
    if (data_offset < sizeof(TCPHeader)) {
        data_offset = sizeof(TCPHeader);
    }
    
    packet.header_size += data_offset;
    
    if (length > data_offset) {
        packet.payload.assign(data + data_offset, data + length);
        packet.payload_size = static_cast<uint32_t>(length - data_offset);
    } else {
        packet.payload_size = 0;
    }
    
    if (packet.dest_port == 53 || packet.src_port == 53) {
        packet.transport_layer = Protocol::DNS;
    }
    
    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t length, ParsedPacket& packet) {
    if (length < sizeof(UDPHeader)) {
        packet.payload_size = static_cast<uint32_t>(length);
        return false;
    }
    
    const auto* udp = reinterpret_cast<const UDPHeader*>(data);
    
    packet.src_port = swap16(udp->src_port);
    packet.dest_port = swap16(udp->dest_port);
    
    uint16_t udp_len = swap16(udp->length);
    packet.header_size += sizeof(UDPHeader);
    
    if (length > sizeof(UDPHeader)) {
        packet.payload.assign(data + sizeof(UDPHeader), data + length);
        packet.payload_size = static_cast<uint32_t>(length - sizeof(UDPHeader));
    } else {
        packet.payload_size = 0;
    }
    
    if (packet.dest_port == 53 || packet.src_port == 53) {
        packet.transport_layer = Protocol::DNS;
    }
    
    return true;
}

bool PacketParser::parseICMP(const uint8_t* data, size_t length, ParsedPacket& packet) {
    if (length < sizeof(ICMPHeader)) {
        packet.payload_size = static_cast<uint32_t>(length);
        return false;
    }

    const auto* icmp = reinterpret_cast<const ICMPHeader*>(data);

    packet.header_size += sizeof(ICMPHeader);

    if (length > sizeof(ICMPHeader)) {
        packet.payload.assign(data + sizeof(ICMPHeader), data + length);
        packet.payload_size = static_cast<uint32_t>(length - sizeof(ICMPHeader));
    } else {
        packet.payload_size = 0;
    }

    return true;
}

bool PacketParser::parseARP(const uint8_t* data, size_t length, ParsedPacket& packet) {
    if (length < sizeof(ARPPacket)) {
        packet.is_valid = false;
        packet.error_message = "Packet too small for ARP header";
        return false;
    }

    const auto* arp = reinterpret_cast<const ARPPacket*>(data);

    packet.arp_info.hardware_type = swap16(arp->hardware_type);
    packet.arp_info.protocol_type = swap16(arp->protocol_type);
    packet.arp_info.hardware_size = arp->hardware_size;
    packet.arp_info.protocol_size = arp->protocol_size;
    packet.arp_opcode = swap16(arp->opcode);

    std::memcpy(packet.arp_info.sender_mac, arp->sender_mac, 6);
    std::memcpy(packet.arp_info.sender_ip, arp->sender_ip, 4);
    std::memcpy(packet.arp_info.target_mac, arp->target_mac, 6);
    std::memcpy(packet.arp_info.target_ip, arp->target_ip, 4);

    packet.header_size = static_cast<uint32_t>(sizeof(EthernetHeader) + sizeof(ARPPacket));
    packet.payload_size = 0;

    if (packet.arp_info.hardware_size == 6 && packet.arp_info.protocol_size == 4) {
        packet.src_mac = macToString(arp->sender_mac);
        packet.dest_mac = macToString(arp->target_mac);

        uint32_t sender_ip = (static_cast<uint32_t>(arp->sender_ip[0]) << 24) |
                             (static_cast<uint32_t>(arp->sender_ip[1]) << 16) |
                             (static_cast<uint32_t>(arp->sender_ip[2]) << 8) |
                             static_cast<uint32_t>(arp->sender_ip[3]);
        uint32_t target_ip = (static_cast<uint32_t>(arp->target_ip[0]) << 24) |
                             (static_cast<uint32_t>(arp->target_ip[1]) << 16) |
                             (static_cast<uint32_t>(arp->target_ip[2]) << 8) |
                             static_cast<uint32_t>(arp->target_ip[3]);

        packet.src_ip = ipv4ToString(sender_ip);
        packet.dest_ip = ipv4ToString(target_ip);
    }

    return true;
}

} // namespace packet
