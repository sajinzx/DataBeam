#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#define PORT 12345
#define DATA_SIZE 1000
#define FILENAME_MAX 64
#define USERNAME_MAX 32

// Production-grade packet for ALL features
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

    // FILE TRANSFER (Phase 2)
    uint32_t file_size;          // Total file bytes
    uint32_t chunk_offset;       // Byte position in file
    char filename[FILENAME_MAX]; // "document.pdf"

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
    char data[DATA_SIZE];  // File chunk/message
} __attribute__((packed)); // Zero padding!

#endif
