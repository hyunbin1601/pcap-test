#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/in.h>

using namespace std;

void usage() {
    std::cout << "syntax: pcap-test <interface>" << std::endl;
    std::cout << "sample: pcap-test wlan0" << std::endl;
}

struct Param {
    const char* dev_;
};

Param param = {
    .dev_ = nullptr
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }

    param -> dev_ = argv[1];
    return true;
}

struct Ethernet_header { // total 14byte
    uint8_t dst_mac[6]; // 6byte
    uint8_t src_mac[6]; // 6byte
    uint16_t type; // 16bit var type
};

struct Ipv4_header {
    uint8_t version_ihl; // high 4bit -> version low 4bit -> header length
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct Tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;  // 4bit -> data offset
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

void printMac(const uint8_t* mac) { // mac address -> hexadecimal
    for (int i = 0; i<6; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
        if (i < 5) {
            std::cout << ":";
        }
    }
    std::cout << std::dec;
}

int main(int argc, char* argv[])
{
    if (!parse(&param, argc, argv)) {
        return -1;
    }

    char errorBuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcapHandle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errorBuf);
    if(pcapHandle == nullptr) {
        std::cerr << "pcap_open_live(" << param.dev_ << ") return null - " << errorBuf << std::endl;
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int respond = pcap_next_ex(pcapHandle, &header, &packet);
        if (respond == 0) {
            continue;
        }
        if (respond == PCAP_ERROR || respond == PCAP_ERROR_BREAK) {
            std::cerr << "pcap_next_ex return " << respond << " (" << pcap_geterr(pcapHandle) << ")" << std::endl;
            break;
        }

        if (header -> caplen < sizeof(Ethernet_header)) {
            continue;
        }

        const Ethernet_header* ethernet = reinterpret_cast<const Ethernet_header*>(packet);
        uint16_t ethernetType = ntohs(ethernet -> type);
        if (ethernetType != 0x0800) {
            continue; // ipv4
        }
        if (header -> caplen < sizeof(Ethernet_header) + sizeof(Ipv4_header)) {

            continue;
        }

        const Ipv4_header* ip = reinterpret_cast<const Ipv4_header*>(packet + sizeof(Ethernet_header));
        int ipHeaderLen = (ip -> version_ihl & 0x0f) * 4;

        if (header -> caplen < sizeof(Ethernet_header) + ipHeaderLen) {
            continue;
        }

        if (ip -> protocol != IPPROTO_TCP) {
            continue;
        }

        const Tcp_header* tcp = reinterpret_cast<const Tcp_header*>(packet + sizeof(Ethernet_header) + ipHeaderLen);
        int tcpHeaderLen = ((tcp -> data_offset >> 4) & 0x0f) * 4;
        if (header -> caplen < sizeof(Ethernet_header) + ipHeaderLen + tcpHeaderLen) {
            continue;
        } // tcp packet -> eth + ip + tcp + data

        std::cout << "\nPacket captured: " << header -> caplen << " bytes" << std::endl;
        std::cout << "Ethernet Header:" << std::endl;
        std::cout << " Src MAC: ";
        printMac(ethernet -> src_mac);
        std::cout << "\n Dst MAC: ";
        printMac(ethernet -> dst_mac);
        std::cout << std::endl; // \n

        struct in_addr srcAddr, dstAddr;
        srcAddr.s_addr = ip->src_addr;
        dstAddr.s_addr = ip->dst_addr;
        std::cout << "IP Header:" << std::endl;
        std::cout << "  Src IP: " << inet_ntoa(srcAddr) << std::endl;
        std::cout << "  Dst IP: " << inet_ntoa(dstAddr) << std::endl;

        std::cout << "TCP Header:" << std::endl;
        std::cout << "  Src Port: " << ntohs(tcp->src_port) << std::endl;
        std::cout << "  Dst Port: " << ntohs(tcp->dst_port) << std::endl;

        int totalHeaderLen = sizeof(Ethernet_header) + ipHeaderLen + tcpHeaderLen;
        int payloadLen = header -> caplen - totalHeaderLen;
        int displayLen = (payloadLen < 20) ? payloadLen : 20; // true -> payloadLen false? -> 20
        std::cout << "Payload" << payloadLen << " bytes :" << std::endl;
        if (displayLen > 0) {
            std::cout << " ";
            for (int i = 0; i < displayLen; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[totalHeaderLen + i]) << " ";
            }
            std::cout << std::dec << std::endl;
        }
        else {
            std::cout << "  No payload" << std::endl;
        }

    }

    pcap_close(pcapHandle);
    return 0;
}
