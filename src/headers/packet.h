#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>

#define PORT 12345
#define DATA_SIZE 1000
#define MAX_FILENAME 50
#define USERNAME_MAX 32

struct Packet
{
    // CORE (Phase 1-2)
    uint16_t seq_num; // Sequence number (1,2,3...)
    uint16_t ack_num; // Next expected sequence (ACK)
    uint8_t type;     // 0=data,1=ACK,2=start,3=end,4=NAK

    // ERROR DETECTION (Phase 2)
    uint32_t crc32;    // CRC32 checksum
    uint8_t parity;    // Simple parity bit
    uint16_t checksum; // Internet checksum
    uint16_t data_len; // Actual data length in this packet
    // FILE TRANSFER (Phase 2)
    uint32_t file_size;          // Total file bytes
    uint32_t chunk_offset;       // Byte position in file
    char filename[MAX_FILENAME]; // "document.pdf"

    // PERFORMANCE (Phase 2.5-5)
    uint8_t stream_id;   // Multi-connection (0-3)
    uint8_t window_size; // Go-Back-N window
    uint16_t rtt_sample; // Congestion control

    // SECURITY (Phase 7)
    uint8_t hmac[32]; // Message authentication
    uint8_t iv[16];   // AES initialization vector

    // ADVANCED (Phase 5+)
    uint8_t fec_parity; // Forward error correction
    uint16_t bitmap;    // Selective Repeat bitmap

    // METADATA
    char username[USERNAME_MAX]; // "john_doe"

    // PAYLOAD (compressed/encrypted data)
    char data[DATA_SIZE + 1]; // File chunk/message
} __attribute__((packed));    // Zero padding!

// Serialize packet: convert host byte order to network byte order
inline void serialize_packet(struct Packet *pkt)
{
    pkt->seq_num = htons(pkt->seq_num);
    pkt->ack_num = htons(pkt->ack_num);
    pkt->crc32 = htonl(pkt->crc32);
    pkt->file_size = htonl(pkt->file_size);
    pkt->data_len = htons(pkt->data_len);
    pkt->chunk_offset = htonl(pkt->chunk_offset);
    pkt->checksum = htons(pkt->checksum);
    pkt->rtt_sample = htons(pkt->rtt_sample);
}

// Deserialize packet: convert network byte order to host byte order
inline void deserialize_packet(struct Packet *pkt)
{
    pkt->seq_num = ntohs(pkt->seq_num);
    pkt->ack_num = ntohs(pkt->ack_num);
    pkt->crc32 = ntohl(pkt->crc32);
    pkt->file_size = ntohl(pkt->file_size);
    pkt->data_len = ntohs(pkt->data_len);
    pkt->chunk_offset = ntohl(pkt->chunk_offset);
    pkt->checksum = ntohs(pkt->checksum);
    pkt->rtt_sample = ntohs(pkt->rtt_sample);
}

#endif
