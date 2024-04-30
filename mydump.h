#ifndef DEFINE_H
#define DEFINE_H
#include <stdlib.h>
#include <stdint.h>
#include <vector>

#define TLS_HANDSHAKE             22
#define TLS_CHANGE_CIPHER_SPEC    20
#define TLS_APPLICATION_DATA      23
#define TLS_ALERT                 21
#define TLS_HEARTBEAT             24

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800

#define STRSIZE 1024

typedef int32_t bpf_int32;
typedef uint32_t bpf_u_int32;
typedef uint16_t u_short;
typedef uint32_t u_int32;
typedef uint16_t u_int16;
typedef uint8_t u_int8;

// pcap文件头结构体
struct pcap_file_header {
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;
    bpf_u_int32 sigfigs;
    bpf_u_int32 snaplen;
    bpf_u_int32 linktype;
};

//时间戳结构体
struct time_val {
    int tv_sec;
    int tv_usec;
};

// pcap数据包头结构体
struct pcap_pkthdr {
    struct time_val ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

//数据帧头
typedef struct FramHeader_t {
    u_int8 DstMAC[6];
    u_int8 SrcMAC[6];
    u_short FrameType;
} FramHeader_t;

// IP数据报头
typedef struct IPHeader_t {
    u_int8 Ver_HLen;
    u_int8 TOS;
    u_int16 TotalLen;
    u_int16 ID;
    u_int16 Flag_Segment;
    u_int8 TTL;
    u_int8 Protocol;
    u_int16 Checksum;
    u_int32 SrcIP;
    u_int32 DstIP;
} IPHeader_t;

// TCP数据报头
typedef struct TCPHeader_t {
    u_int16 SrcPort;
    u_int16 DstPort;
    u_int32 SeqNO;
    u_int32 AckNO;
    u_int8 HeaderLen;
    u_int8 Flags;
    u_int16 Window;
    u_int16 Checksum;
    u_int16 UrgentPointer;
} TCPHeader_t;

typedef struct UDPHeader_t {
    u_int16 SrcPort;
    u_int16 DstPort;
    u_int16 Len;
    u_int16 Checksum;
} UDPHeader_t;

typedef struct DNSHeader_t {
    u_int16 TransactionID;
    u_int16 Flags;
    u_int16 Questions;
    u_int16 AnswerRRs;
    u_int16 AuthRRs;
    u_int16 AddRRs;
} DNSHeader_t;

typedef struct __attribute__((packed))TlsHeader_t {
    uint8_t contentType;
    uint16_t tlsVersion;
    uint16_t length;
}TlsHeader_t;

struct HandshakeHeader {
    uint8_t handshakeType;
    uint8_t length[3];  // Length is 3 bytes in the TLS protocol
    // Helper function to get the length as a 32-bit integer
    uint32_t getLength() const {
        return (static_cast<uint32_t>(length[0]) << 16) |
               (static_cast<uint32_t>(length[1]) << 8) |
               (static_cast<uint32_t>(length[2]));
    }
};

// struct ClientHelloMessage {
//     uint16_t version;
//     uint8_t random[32];
//     uint8_t sessionIdLength;
//     uint8_t sessionId[256];  // 假设会话ID最大长度为256
//     uint16_t cipherSuitesLength;
//     uint16_t cipherSuites[128];  // 假设最多128个密码套件
//     uint8_t compressionMethodsLength;
//     uint8_t compressionMethods[32];  // 假设最多32种压缩方法
//     uint16_t extensionsLength;
//     // 假设扩展的处理方式根据实际情况而定，这里不直接读取
// };


// struct ServerHelloMessage {
//     uint16_t version;
//     uint8_t random[32];
//     uint8_t sessionIdLength;
//     uint8_t sessionId[256];  // 假设会话ID最大长度为256
//     uint16_t cipherSuite;
//     // 可能还有其他字段，例如扩展，这里不包括
// };

struct ClientHelloMessage {
    uint16_t version;
    std::vector<uint8_t> random;  // 替换为 vector
    uint8_t sessionIdLength;
    std::vector<uint8_t> sessionId;  // 替换为 vector
    uint16_t cipherSuitesLength;
    std::vector<uint16_t> cipherSuites;  // 替换为 vector
    uint8_t compressionMethodsLength;
    std::vector<uint8_t> compressionMethods;  // 替换为 vector
    uint16_t extensionsLength;
    // 扩展可以根据实际情况设计更复杂的数据结构
};

struct ServerHelloMessage {
    uint16_t version;
    std::vector<uint8_t> random;  // 替换为 vector
    uint8_t sessionIdLength;
    std::vector<uint8_t> sessionId;  // 替换为 vector
    uint16_t cipherSuite;
    // 可以根据需要添加更多字段
};


#endif // DEFINE_H
