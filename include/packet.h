#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace packet {

#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_addr;
    uint32_t dest_addr;
};

struct IPv6Header {
    uint32_t version_tc_fl;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dest_addr[16];
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header;
};

struct ARPPacket {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

#pragma pack(pop)

enum class Protocol {
    UNKNOWN = 0,
    ETHERNET,
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS
};

enum class TCPFlags {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20
};

struct ParsedPacket {
    Protocol link_layer;
    Protocol network_layer;
    Protocol transport_layer;
    
    std::string src_mac;
    std::string dest_mac;
    std::string src_ip;
    std::string dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    
    uint32_t packet_size;
    uint32_t header_size;
    uint32_t payload_size;
    
    bool is_valid;
    std::string error_message;
    
    std::vector<uint8_t> raw_data;
    std::vector<uint8_t> payload;

    ARPPacket arp_info;
    uint16_t arp_opcode;

    ParsedPacket()
        : link_layer(Protocol::UNKNOWN)
        , network_layer(Protocol::UNKNOWN)
        , transport_layer(Protocol::UNKNOWN)
        , src_port(0)
        , dest_port(0)
        , packet_size(0)
        , header_size(0)
        , payload_size(0)
        , is_valid(false)
        , arp_opcode(0) {}
};

class PacketParser {
public:
    PacketParser() = default;
    ~PacketParser() = default;
    
    ParsedPacket parse(const uint8_t* data, size_t length);
    ParsedPacket parse(const std::vector<uint8_t>& data);
    
    static std::string macToString(const uint8_t* mac);
    static std::string ipv4ToString(uint32_t addr);
    static std::string ipv6ToString(const uint8_t* addr);
    static std::string protocolToString(Protocol proto);
    static uint16_t swap16(uint16_t value);
    static uint32_t swap32(uint32_t value);
    
private:
    bool parseEthernet(const uint8_t* data, size_t length, ParsedPacket& packet);
    bool parseIPv4(const uint8_t* data, size_t length, ParsedPacket& packet);
    bool parseIPv6(const uint8_t* data, size_t length, ParsedPacket& packet);
    bool parseTCP(const uint8_t* data, size_t length, ParsedPacket& packet);
    bool parseUDP(const uint8_t* data, size_t length, ParsedPacket& packet);
    bool parseICMP(const uint8_t* data, size_t length, ParsedPacket& packet);
    bool parseARP(const uint8_t* data, size_t length, ParsedPacket& packet);
};

} // namespace packet

#endif // PACKET_H
