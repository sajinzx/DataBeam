#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>

#define PORT 12345
#define DATA_SIZE 1440 // 1500 - 20 (IP) - 8 (UDP) - 32 (custom header)
#define MAX_FILENAME 50
#define USERNAME_MAX 32
#pragma pack(push, 1)
struct ACKPacket
{
    uint32_t ack_num; // The sequence number being acknowledged
    uint16_t bitmap;  // For Selective Repeat (which neighbors are also here)
    uint8_t type;     // Always set to 1 (ACK)
    uint32_t crc32;   // Integrity check for the ACK itself
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SlimDataPacket
{
    // --- 14 Bytes Core Header ---
    uint8_t type;
    uint32_t seq_num;      // 4 bytes (Essential for files > 65MB)
    uint32_t crc32;        // 4 bytes (Hardware-accelerated)
    uint16_t data_len;     // 2 bytes (Actual payload size)
                           // 1 byte  (Always 0)
    uint8_t flags;         // 1 byte  (Bit 0: Encrypted, Bit 1-2: Stream ID)
    uint16_t reserved;     // 2 bytes (Padding for 4-byte alignment)
    uint32_t chunk_offset; // 4 bytes (Offset within the file)
    // --- Phase 7 Security Hook (Reserved) ---
    uint64_t packet_iv; // 8 bytes (Nonce for AES-GCM)
    uint8_t hmac[16];   // 16 bytes (Auth tag)

    // --- 1440 Bytes Payload ---
    char data[DATA_SIZE]; // The "Cargo"
};
#pragma pack(pop)
#pragma pack(push, 1)
struct StartPacket
{
    uint8_t type;          // Always 2
    uint32_t file_size;    // Total file size
    uint32_t total_chunks; // Total number of packets
    char filename[256];    // "stranger_things_s01e01.mkv"
    char username[32];     // "student_id_123"
    uint16_t window_size;  // Initial negotiated window
};
#pragma pack(pop)
// Serialize packet: convert host byte order to network byte order
// Serialize Slim Data: Host -> Network
inline void serialize_slim_packet(struct SlimDataPacket *pkt)
{
    pkt->seq_num = htonl(pkt->seq_num); // UPGRADED to 32-bit
    pkt->crc32 = htonl(pkt->crc32);
    pkt->data_len = htons(pkt->data_len);
    pkt->chunk_offset = htonl(pkt->chunk_offset);
    pkt->packet_iv = htonll(pkt->packet_iv); // 64-bit for Phase 7 IV
    // Note: type, flags, and hmac (bytes) don't need conversion
}

// Deserialize Slim Data: Network -> Host
inline void deserialize_slim_packet(struct SlimDataPacket *pkt)
{
    pkt->seq_num = ntohl(pkt->seq_num); // UPGRADED to 32-bit
    pkt->crc32 = ntohl(pkt->crc32);
    pkt->data_len = ntohs(pkt->data_len);
    pkt->chunk_offset = ntohl(pkt->chunk_offset);
    pkt->packet_iv = ntohll(pkt->packet_iv); // 64-bit for Phase 7 IV
}

inline void serialize_start_packet(struct StartPacket *pkt)
{
    pkt->file_size = htonl(pkt->file_size);
    pkt->total_chunks = htonl(pkt->total_chunks);
    pkt->window_size = htons(pkt->window_size);
    // Filename and Username are char arrays; they do NOT need conversion
}

inline void deserialize_start_packet(struct StartPacket *pkt)
{
    pkt->file_size = ntohl(pkt->file_size);
    pkt->total_chunks = ntohl(pkt->total_chunks);
    pkt->window_size = ntohs(pkt->window_size);
}
inline void serialize_ack_packet(struct ACKPacket *pkt)
{
    pkt->ack_num = htonl(pkt->ack_num); // Match 32-bit seq_num
    pkt->bitmap = htons(pkt->bitmap);

    pkt->crc32 = htonl(pkt->crc32);
}

inline void deserialize_ack_packet(struct ACKPacket *pkt)
{
    pkt->ack_num = ntohl(pkt->ack_num);
    pkt->bitmap = ntohs(pkt->bitmap);

    pkt->crc32 = ntohl(pkt->crc32);
}
#endif
