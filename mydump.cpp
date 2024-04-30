#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <map>
#include <vector>
#include <string>
#include <inttypes.h>
#include <ctype.h>
#include "mydump.h"
using namespace std;

char file_input[1024];
char file_output[1024];
struct pcap_file_header *file_header;
struct pcap_pkthdr *pkt_header;
FramHeader_t *mac_header;
IPHeader_t *ip_header;
TCPHeader_t *tcp_header;
UDPHeader_t *udp_header;
DNSHeader_t *dns_header;
TlsHeader_t *tls_header;


FILE *fp, *output;
int pkt_offset, pkt_id = 0;
int ip_len, http_len, ip_proto, dns_len;

int src_port, dst_port, tcp_flags;

char my_time[STRSIZE];
char src_ip[STRSIZE], dst_ip[STRSIZE];
map<u_int16, char *> cipher_suites_table;

map<u_int16, char *> Init_Cipher_Suites_Table() // TLS1.2
{
    map<u_int16, char *> cipher_suites_table;
    cipher_suites_table.insert(make_pair(0xC02F, (char *)"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0xC027, (char *)"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0xC013, (char *)"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xC030, (char *)"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0xC028, (char *)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"));
    cipher_suites_table.insert(make_pair(0xC014, (char *)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xC061, (char *)"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0xC060, (char *)"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0xC077, (char *)"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"));
    cipher_suites_table.insert(make_pair(0xC076, (char *)"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0x9D, (char *)"TLS_RSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0xC0A1, (char *)"TLS_RSA_WITH_AES_256_CCM_8"));
    cipher_suites_table.insert(make_pair(0xC09D, (char *)"TLS_RSA_WITH_AES_256_CCM"));
    cipher_suites_table.insert(make_pair(0xC051, (char *)"TLS_RSA_WITH_ARIA_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0x9C, (char *)"TLS_RSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0xC0A0, (char *)"TLS_RSA_WITH_AES_128_CCM_8"));
    cipher_suites_table.insert(make_pair(0xC02C, (char *)"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0xC09C, (char *)"TLS_RSA_WITH_AES_128_CCM"));
    cipher_suites_table.insert(make_pair(0xC050, (char *)"TLS_RSA_WITH_ARIA_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0x3D, (char *)"TLS_RSA_WITH_AES_256_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0xC0, (char *)"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0x3C, (char *)"TLS_RSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0xBA, (char *)"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0x35, (char *)"TLS_RSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0x84, (char *)"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0x2F, (char *)"TLS_RSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0x96, (char *)"TLS_RSA_WITH_SEED_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0x41, (char *)"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xCCA8, (char *)"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
    cipher_suites_table.insert(make_pair(0xC02B, (char *)"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0xCCA9, (char *)"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"));
    cipher_suites_table.insert(make_pair(0xC009, (char *)"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xC00A, (char *)"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xA, (char *)"TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xc023, (char *)"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0xc028, (char *)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"));
    cipher_suites_table.insert(make_pair(0xc024, (char *)"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"));

    // both TLS1.2 and TLS1.3
    cipher_suites_table.insert(make_pair(0x1301, (char *)"TLS_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0x1302, (char *)"TLS_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0x1303, (char *)"TLS_CHACHA20_POLY1305_SHA256"));

    // more for TLS1.3
    cipher_suites_table.insert(make_pair(0x0A13, (char *)"TLS_AES_128_CCM_SHA256"));
    cipher_suites_table.insert(make_pair(0x0A0C, (char *)"TLS_AES_128_CCM_8_SHA256"));

    return cipher_suites_table;
}

void match_http(char *http_content, int http_len, char *head, char *tail)
{
    int head_len = strlen(head);
    int tail_len = strlen(tail);
    int i = 0;
    int j = 0;
    int head_pos = -1, tail_pos = -1;
    for (; i < http_len;)
    {
        if (http_content[i] == head[j])
        {
            i++;
            j++;
            if (head_len == j)
            {
                head_pos = i;
                break;
            }
        }
        else
        {
            i = i - j + 1;
            j = 0;
        }
    }

    j = 0;
    for (; i < http_len;)
    {
        if (http_content[i] == tail[j])
        {
            i++;
            j++;
            if (tail_len == j)
            {
                tail_pos = i - 3;
                break;
            }
        }
        else
        {
            i = i - j + 1;
            j = 0;
        }
    }
    if (head_pos != -1 && tail_pos != -1)
    {
        printf("%s", head);
        for (int p = head_pos; p <= tail_pos; p++)
        {
            printf("%c", http_content[p]);
        }
        printf("\n");
    }
    else
    {
        printf("%s: None\n", head);
    }
}

void process_request(const char* request_type, char* http_content, int http_len) {
    printf("%s\n", request_type);

    if (strncmp(request_type, "HTTP(response)", 14) == 0) {
        // 处理响应
        match_http(http_content, http_len, (char *)"GET", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Connection", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Accept", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"User-Agent", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Host", (char *)"\r\n");
    } else if (strncmp(request_type, "HTTP(request: POST)", 19) == 0) {
        match_http(http_content, http_len, (char *)"POST", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Connection", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Accept", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"User-Agent", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Host", (char *)"\r\n");
    } else if (strncmp(request_type, "HTTP(request: GET)", 18) == 0) {
        match_http(http_content, http_len, (char *)"GET", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Connection", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Accept", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"User-Agent", (char *)"\r\n");
        match_http(http_content, http_len, (char *)"Host", (char *)"\r\n");
    }
}

void analyze_http(char* http_content, int http_len) {
    char* line_end = strchr(http_content, '\n'); // 查找第一行的结束
    if (line_end && line_end > http_content) {
        *line_end = '\0'; // 截断字符串，便于处理
        if (strncmp(http_content, "HTTP/", 5) == 0) {
            // 处理HTTP响应
            process_request("HTTP(response)", http_content, http_len);
        } else {
            // 处理HTTP请求
            if (strncmp(http_content, "POST ", 5) == 0) {
                process_request("HTTP(request: POST)", http_content, http_len);
            } else if (strncmp(http_content, "GET ", 4) == 0) {
                process_request("HTTP(request: GET)", http_content, http_len);
            } else {
                printf("Unknown request type\n");
            }
        }
    }
}

bool handle_http(){
    printf("应用层\n");
    printf("HTTP\n");
    char http_content[10000];
    memset(http_content, 0, sizeof(http_content));
    if (fread(http_content, sizeof(char), http_len, fp) != http_len) {
        printf("Cannot read http_content\n");
        return false;
    }
    http_content[http_len] = '\0'; // 确保字符串结束
    analyze_http(http_content, http_len);
    return true;
}

bool handle_DNS(){
    printf("应用层\n");
    printf("DNS\n");
    if (fread(dns_header, sizeof(DNSHeader_t), 1, fp) != 1)
    {
        printf("Can not read dns_header\n");
        return false;
    }
    u_int16 TransactionID = ntohs(dns_header->TransactionID);
    u_int16 Questions = ntohs(dns_header->Questions);
    u_int16 AnswerRRs = ntohs(dns_header->AnswerRRs);

    printf("TransactionID: 0x%04x\nQuestions: %d\nAnswerRRs: %d\n", TransactionID, Questions, AnswerRRs);

    u_int8 dns_content_ascii[10000];
    char dns_content[10000];
    memset(dns_content_ascii, 0, sizeof(u_int8));
    dns_len = ip_len -8 -12; // dns 报文长度
    if (fread(dns_content_ascii, sizeof(u_int8), dns_len, fp) != dns_len)
    {
        printf("Can not read dns_header\n");
        return false;
    }
    int p = 0;
    bool flag = true;
    for (int j = 0; j < dns_len; j++)
    {
        dns_content[j] = (char)dns_content_ascii[j];
        if (isprint(dns_content_ascii[j]) == 0)
        {
            if (flag)
            {
                flag = false;
            }
            else
            {
                p = j;
                break;
            }
        }
        else
        {
            flag = true;
        }
    }
    printf("Domain Name: ");
    for (int j = 1; j < p - 1; j++)
    {
        if (isprint(dns_content_ascii[j]))
        {
            printf("%c", dns_content[j]);
        }
        else
        {
            printf(".");
        }
    }
    printf("\n");
    if (AnswerRRs)
    {
        printf("Answer IP: ");
        for (int j = 0; j < 4; j++)
        {
            if (j)
            {
                printf(".");
            }
            printf("%d", dns_content_ascii[j + dns_len - 4]);
        }
        printf("\n");
    }
    return true;
}

int detect_application_protocol() {
    // Detect application protocol
    // Check for TLS
    // Check for HTTP
    // no Check for DNS
    // Check for other protocols
    // Return the protocol number
    // 1: HTTP, 2: TLS, 3: DNS, 4: can't read, 0: other 
    if(http_len<5&&dns_len<5)
    {
        printf("too short for detect http or TLS or DNS\n");
        return 4;
    }
    u_int8 content[6];
    memset(content, 0, sizeof(content));
    int num_elements_read = fread(content, sizeof(uint8_t), 5, fp);
    fseek(fp, -5, SEEK_CUR);

    uint16_t flags = ntohs(*(uint16_t *)(content + 2));
    uint16_t questions = ntohs(*(uint16_t *)(content + 4));
    uint16_t opcode = (flags >> 11) & 0x0F;  // Opcode: bits 11-14 in the flags field
    
    if (num_elements_read != 5)
    {
        printf("Can not read application_protocol_header\n");
        return 4;
    }
    uint8_t content_type = content[0];
    uint16_t version = ntohs(*(uint16_t *)(content + 1));
    if (content_type >= 20 && content_type <= 24) {
        // printf("TLS detected\n");
        return 2;
    }
    else if (strncmp((const char *)content, "GET ", 4) == 0 ||
               strncmp((const char *)content, "POST ", 5) == 0 ||
               strncmp((const char *)content, "HTTP/", 5) == 0) {
        // printf("HTTP detected\n");
        return 1;
    }
    else if(!(opcode > 2 || questions == 0)){ // DNS
        // Only 0, 1, 2 are typically valid for opcode
            return 3;
    }
    return 0;
}

bool handle_handshake(){
    HandshakeHeader handshakeHeader;
    if (fread(&handshakeHeader.handshakeType, sizeof(uint8_t), 1, fp) != 1)
    {
        printf("Can not read tls_handshaketype\n");
        return false;
    }
    if (fread(&handshakeHeader.length, sizeof(uint8_t), 3, fp) != 3)
    {
        printf("Can not read tls_handshaketype\n");
        return false;
    }
    if (handshakeHeader.handshakeType == 1) {
        printf("Client Hello\n");
        ClientHelloMessage clientHelloMessage;
        if (fread(&clientHelloMessage.version, sizeof(uint16_t), 1, fp) != 1) {
            printf("Can not read tls_version\n");
            return false;
        }
        clientHelloMessage.random.resize(32);  // 确保有足够的空间
        if (fread(clientHelloMessage.random.data(), sizeof(uint8_t), 32, fp) != 32) {
            printf("Can not read tls_random\n");
            return false;
        }
        if (fread(&clientHelloMessage.sessionIdLength, sizeof(uint8_t), 1, fp) != 1) {
            printf("Can not read tls_sessionIdLength\n");
            return false;
        }
        clientHelloMessage.sessionId.resize(clientHelloMessage.sessionIdLength);
        if (fread(clientHelloMessage.sessionId.data(), sizeof(uint8_t), clientHelloMessage.sessionIdLength, fp) != clientHelloMessage.sessionIdLength) {
            printf("Can not read tls_sessionId\n");
            return false;
        }
        if (fread(&clientHelloMessage.cipherSuitesLength, sizeof(uint16_t), 1, fp) != 1) {
            printf("Can not read tls_cipherSuitesLength\n");
            return false;
        }
        clientHelloMessage.cipherSuites.resize(clientHelloMessage.cipherSuitesLength);
        if (fread(clientHelloMessage.cipherSuites.data(), sizeof(uint16_t), clientHelloMessage.cipherSuitesLength, fp) != clientHelloMessage.cipherSuitesLength) {
            printf("Can not read tls_cipherSuites\n");
            return false;
        }
        if (fread(&clientHelloMessage.compressionMethodsLength, sizeof(uint8_t), 1, fp) != 1) {
            printf("Can not read tls_compressionMethodsLength\n");
            return false;
        }
        clientHelloMessage.compressionMethods.resize(clientHelloMessage.compressionMethodsLength);
        if (fread(clientHelloMessage.compressionMethods.data(), sizeof(uint8_t), clientHelloMessage.compressionMethodsLength, fp) != clientHelloMessage.compressionMethodsLength) {
            printf("Can not read tls_compressionMethods\n");
            return false;
        }
        // 假设extensions的处理方式略

        printf("ClientHello Version: 0x%04x\n", ntohs(clientHelloMessage.version));
        printf("ClientHello Random: ");
        for (int i = 0; i < 32; ++i) {
            printf("%02x", clientHelloMessage.random[i]);
        }
        printf("\nSession ID Length: %u\n", clientHelloMessage.sessionIdLength);
        printf("Session ID: ");
        for (unsigned int i = 0; i < clientHelloMessage.sessionIdLength; ++i) {
            printf("%02x", clientHelloMessage.sessionId[i]);
        }
        // 输出密码套件
        // printf("\nCipher Suites: ");
        // for (unsigned int i = 0; i < clientHelloMessage.cipherSuitesLength / 2; ++i) {
        //     printf("0x%04x ", ntohs(clientHelloMessage.cipherSuites[i]));
        // }
        // printf("\nCompression Methods: ");
        // for (unsigned int i = 0; i < clientHelloMessage.compressionMethodsLength; ++i) {
        //     printf("%u ", clientHelloMessage.compressionMethods[i]);
        // }
        printf("\n");
    }
    else if (handshakeHeader.handshakeType == 2) {
        printf("Server Hello\n");
        ServerHelloMessage serverHelloMessage;
        if (fread(&serverHelloMessage.version, sizeof(uint16_t), 1, fp) != 1) {
            printf("Can not read tls_version\n");
            return false;
        }
        serverHelloMessage.random.resize(32);  // 确保有足够的空间
        if (fread(serverHelloMessage.random.data(), sizeof(uint8_t), 32, fp) != 32) {
            printf("Can not read tls_random\n");
            return false;
        }
        if (fread(&serverHelloMessage.sessionIdLength, sizeof(uint8_t), 1, fp) != 1) {
            printf("Can not read tls_sessionIdLength\n");
            return false;
        }
        serverHelloMessage.sessionId.resize(serverHelloMessage.sessionIdLength);
        if (fread(serverHelloMessage.sessionId.data(), sizeof(uint8_t), serverHelloMessage.sessionIdLength, fp) != serverHelloMessage.sessionIdLength) {
            printf("Can not read tls_sessionId\n");
            return false;
        }

        // 输出ServerHello信息
        printf("ServerHello Version: 0x%04x\n", ntohs(serverHelloMessage.version));
        printf("ServerHello Random: ");
        for (int i = 0; i < 32; ++i) {
            printf("%02x", serverHelloMessage.random[i]);
        }
        printf("\nSession ID Length: %u\n", serverHelloMessage.sessionIdLength);
        printf("Session ID: ");
        for (unsigned int i = 0; i < serverHelloMessage.sessionIdLength; ++i) {
            printf("%02x", serverHelloMessage.sessionId[i]);
        }
        // printf("\nCipher Suite: 0x%04x\n", ntohs(serverHelloMessage.cipherSuite));
    }
    else if (handshakeHeader.handshakeType == 15) {  // CertificateVerify类型
        printf("CertificateVerifyMessage\n");
    }
    else if (handshakeHeader.handshakeType == 16) {  // ClientKeyExchange类型
        printf("ClientKeyExchangeMessage\n");
    }
    else if (handshakeHeader.handshakeType == 20) {  // Finished类型
        printf("FinishedMessage\n");
    }
    return true;
}

bool handle_tls() {
    printf("应用层\n");
    printf("TLS\n");
    
    if (fread(tls_header, sizeof(TlsHeader_t), 1, fp) != 1)
    {
        printf("Can not read tls_header\n");
        return false;
    }
    uint8_t content_type = tls_header->contentType;
    uint16_t version = ntohs(tls_header->tlsVersion);
    uint16_t record_length = ntohs(tls_header->length);

    printf("TLS Content Type: %d, Version: 0x%04x, Length: %d\n", content_type, version, record_length);

    // 更详细的处理，例如解析TLS握手消息
    switch (content_type) {
        case TLS_HANDSHAKE:
            printf("TLS Handshake\n");
            if(handle_handshake()) {
                // Handshake packet successfully handled
            }
            else {
                // Handshake packet not handled
                return false;
            }
            break;
        case TLS_CHANGE_CIPHER_SPEC:
            printf("TLS Change Cipher Spec\n");
            break;
        case TLS_APPLICATION_DATA:
            printf("TLS Application Data\n");
            break;
        case TLS_ALERT:
            printf("TLS Alert\n");
            break;
        case TLS_HEARTBEAT:
            printf("TLS Heartbeat\n");
            break;
        default:
            printf("Unknown TLS Content Type: %d\n", content_type);
            break;}
    switch (version) {
        case 0x0301:
            printf("TLS version 1.0\n");
            break;
        case 0x0302:
            printf("TLS version 1.1\n");
            break;
        case 0x0303:
            printf("TLS version 1.2\n");
            break;
        case 0x0304:
            printf("TLS version 1.3\n");
            break;
        default:
            printf("Unknown TLS version\n");
    }
    return true;
}

bool handle_tcp() {
    // This function would handle TCP data and check for TLS
    // if (length < 20) return; // TCP header size check
    // Further processing for TCP/TLS
    if (fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1)
    {
        printf("Can not read tcp_header\n");
        return false;
    }
    src_port = ntohs(tcp_header->SrcPort);
    dst_port = ntohs(tcp_header->DstPort);
    tcp_flags = tcp_header->Flags;
    uint32_t seq_number = ntohl(tcp_header->SeqNO);
    uint32_t ack_number = ntohl(tcp_header->AckNO);
    printf("Src Port: %d\nDst Port: %d\nSeq Number: %" PRIu32 "\n%" PRIu32 "\nFlag: 0x%02x\n", src_port, dst_port, seq_number, ack_number, tcp_flags);
    if (tcp_flags)
    {
        char flag_name[6][10] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
        int k = 0;
        printf("Flags:[");
        int tmp = tcp_flags;
        while (tmp)
        {
            int a = tmp % 2;
            tmp /= 2;
            if (a == 1)
            {
                printf("%s, ", flag_name[k]);
            }
            k++;
        }
        printf("]\n");
    }
    // "FIN", "SYN", "RST", "PSH", "ACK", "URG": 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
    if ((tcp_flags & 0x02) && (tcp_flags & 0x10)) {
        printf("Connection Stage: SYN-ACK\n");
    }
    else if (tcp_flags & 0x02) {
        printf("Connection Stage: Connection initiation\n");
    }
    else if (tcp_flags & 0x10) {
        printf("Connection Stage: Connection established or ongoing\n");
    }
    else if (tcp_flags & 0x01) {
        printf("Connection Stage: Connection termination\n");
    }
    // handle http or TLS
    http_len = ip_len - (tcp_header->HeaderLen>> 4) * 4;
    int which_protocol = detect_application_protocol();
    if (which_protocol==1||dst_port == 80 || src_port == 80)
    {
        if(handle_http()) {
            // HTTP packet successfully handled
        }
        else {
            // HTTP packet not handled
            return false;
        }
    }
    else if(which_protocol==2)
    {
        if(handle_tls()){
            // TLS packet successfully handled
        }
        else {
            // TLS packet not handled
            return false;
        }
    }
    else
    {
        printf("应用层\nOther Application Protocol based on TCP.\n");
    }
    return true;
}

bool handle_udp()
{
    // UDP头 8字节
    if (fread(udp_header, sizeof(UDPHeader_t), 1, fp) != 1)
    {
        printf("Can not read udp_header\n");
        return false;
    }
    src_port = ntohs(udp_header->SrcPort);
    dst_port = ntohs(udp_header->DstPort);
    int udp_len = ntohs(udp_header->Len);
    dns_len = udp_len - 8;
    int udp_checksum = ntohs(udp_header->Checksum);
    printf("Src Port: %d\nDst Port: %d\nLen: %d\nCheckSum: 0x%04x\n", src_port, dst_port, udp_len, udp_checksum);
    int which_protocol = detect_application_protocol();
    if (which_protocol==3||dst_port == 53 || src_port == 53)
    {
        if(handle_DNS()) {
            // DNS packet successfully handled
        }
        else {
            // DNS packet not handled
            return false;
        }
    }
    else
    {
        printf("应用层\nOther Application Protocol based on TCP.\n");
    }
    return true;
}

bool handle_transport(){
    printf("传输层\n");
    switch (ip_proto) {
        case IP_PROTO_ICMP:
            printf("ICMP Packet Detected\n");
            // Handle ICMP packet
            break;
        case IP_PROTO_TCP:
            printf("TCP Packet Detected\n");
            if(handle_tcp()) {
                // TCP packet successfully handled
            }
            else {
                // TCP packet not handled
                return false;
            }
            break;
        case IP_PROTO_UDP:
            printf("UDP Packet Detected\n");
            if(handle_udp()) {
                // UDP packet successfully handled
            }
            else {
                // UDP packet not handled
                return false;
            }
            break;
        default:
            printf("Unknown IP Protocol: %d\n", ip_proto);
            break;}
    return true;
}

bool handle_ip(u_int16 ethertype) {
    // const u_int8 *packet; int length;  u_int8 ip_proto;
    // Switch based on Ethernet type
    printf("网络层\n");
    switch (ethertype) {
        case ETHERTYPE_ARP:
            printf("ARP Packet Detected\n");
            // Handle ARP packet
            break;
        case ETHERTYPE_IP:{
            printf("IP Packet Detected\n");
            // Handle different IP protocols
            memset(ip_header, 0, sizeof(IPHeader_t));
            if (fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1)
            {
                printf("Can not read ip_header\n");
                return false;
            }

            inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
            inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);

            ip_proto = ip_header->Protocol;

            printf("Src IP: %s\nDst IP: %s\nIp Protocol: %d\n", src_ip, dst_ip, ip_proto);
            uint8_t ip_header_length = (ip_header->Ver_HLen & 0x0F) * 4;  // 提取低4位并乘以4
            uint16_t total_length = ntohs(ip_header->TotalLen);  
            ip_len = total_length - ip_header_length; // IP数据报总长度；从网络的大端字节序转换为主机的小端字节序
            if(handle_transport()) {
                // Transport layer packet successfully handled
            }
            else {
                // Transport layer packet not handled
                return false;
            }
            break;}
        default:
            printf("Unknown Ethernet Type: 0x%04x\n", ethertype);
            break;
    }
    return true;
}
bool handle_ether()
{
    printf("链路层\n");
    //数据帧头 14字节
    memset(mac_header, 0, sizeof(FramHeader_t));
    if (fread(mac_header, sizeof(FramHeader_t), 1, fp) != 1)
    {
        printf("Can not read frame_header\n");
        return false;
    }
    printf("Src Mac: ");
    for (int j = 0; j < 6; j++){
        if (j){
            printf(":");
        }
        printf("%02x", mac_header->SrcMAC[j]);
    }
    printf("\n");
    printf("Dst Mac: ");
    for (int j = 0; j < 6; j++){
        if (j){
            printf(":");
        }
        printf("%02x", mac_header->DstMAC[j]);
    }
    printf("\nEthernet Type: 0x%04x\n", ntohs(mac_header->FrameType));

    u_int16 ethertype = ntohs(mac_header->FrameType);
    if(handle_ip(ethertype)) {
        // IP packet successfully handled
    }
    else {
        // IP packet not handled
        return false;
    }
    return true;
}
void handle_pkt()
{
    //开始读数据包
    pkt_offset = 24; // pcap文件头结构 24个字节

    while (fseek(fp, pkt_offset, SEEK_SET) == 0) //遍历数据包；SEEK_SET：从文件开头开始计算偏移量
    {
        pkt_id++;
        memset(pkt_header, 0, sizeof(struct pcap_pkthdr));
        if (fread(pkt_header, 16, 1, fp) != 1) //读pcap数据包头结构
        {
            printf("\nread end of pcap file\n");
            break;
        }
        printf("\n####################\n");
        printf("Packet ID: %d\n", pkt_id);

        pkt_offset += 16 + pkt_header->caplen; //下一个数据包的偏移值
        // caplen: 数据包捕获时的长度，即实际捕获到的数据包长度，可信

        if(handle_ether()) {
            // Ethernet packet successfully handled
        }
        else {
            // Ethernet packet not handled
            continue;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3)
    {
        return 1;
    }
    strcpy(file_input, argv[1]);
    strcpy(file_output, argv[2]);

    printf("pcap包解析结果: \n");
    if ((fp = fopen(file_input, "rb")) == NULL)
    {
        printf("error: Can not open pcap file\n");
        exit(0);
    }

    freopen(file_output, "w", stdout);

    cipher_suites_table = Init_Cipher_Suites_Table();
    //初始化
    pkt_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    mac_header = (FramHeader_t *)malloc(sizeof(FramHeader_t));
    ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
    tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
    udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));
    dns_header = (DNSHeader_t *)malloc(sizeof(DNSHeader_t));
    tls_header = (TlsHeader_t *)malloc(sizeof(TlsHeader_t));
    
    handle_pkt();

    fclose(fp);
    free(pkt_header);
    free(mac_header);
    free(ip_header);
    free(tcp_header);
    free(udp_header);
    free(dns_header);

    return 0;
}
