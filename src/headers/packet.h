#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "./crchw.h"
#include "constants.h"
#pragma pack(push, 1)
static inline uint64_t htonll_portable(uint64_t v) {
  // Byte-swap each 32-bit half independently, keep them in their original
  // halves. high word stays in high 32 bits; low word stays in low 32 bits —
  // each reversed.
  return (((uint64_t)htonl((uint32_t)(v >> 32))) << 32) |
         ((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL)));
}
static inline uint64_t ntohll_portable(uint64_t v) {
  return htonll_portable(v); // symmetric
}
#define htonll htonll_portable
#define ntohll ntohll_portable
struct ACKPacket {
  uint32_t ack_num; // Cumulative ACK watermark (next seq server needs)
  uint64_t bitmap[DataBeam::SR_SACK_BITMAP_CHUNKS]; // SACK bitmap: 64 chunks ×
                                                    // 64 bits = 4096 bits =
                                                    // SR_WINDOW_SIZE
  uint8_t type;                                     // Always set to 1 (ACK)
  uint64_t connection_id; // Phase 6: Connection Migration ID
  uint32_t crc32; // Integrity check for the ACK itself (MUST be last field)
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SlimDataPacket {
  // --- Core Header ---
  uint8_t type;
  uint32_t seq_num;      // 4 bytes (Essential for files > 65MB)
  uint32_t crc32;        // 4 bytes (Hardware-accelerated)
  uint16_t data_len;     // 2 bytes (Actual payload size)

  uint8_t flags;             // 1 byte  (Bit 0: Encrypted, Bit 1-2: Stream ID)
  uint64_t connection_id;    // 8 bytes (Phase 6: Connection Migration ID)
  uint32_t chunk_offset;     // 4 bytes (Offset within the file)

  // --- Security ---
  uint64_t packet_iv; // 8 bytes (Nonce for AES-CTR)
  uint8_t hmac[16];   // 16 bytes (Auth tag)

  // --- Payload ---
  char data[DataBeam::PACKET_DATA_SIZE + 1]; // The "Cargo"
};
#pragma pack(pop)

#pragma pack(push, 1)
struct StartPacket {
  uint8_t type;                              // Always 2
  uint32_t file_size;                        // Total file size
  uint32_t total_chunks;                     // Total number of packets
  char filename[DataBeam::MAX_FILENAME_LEN]; // "stranger_things_s01e01.mkv"
  char username[DataBeam::MAX_USERNAME_LEN]; // "student_id_123"
  uint16_t window_size;                      // Initial negotiated window
  uint64_t connection_id;                    // Phase 6: Connection Migration ID
};
#pragma pack(pop)
// Serialize packet: convert host byte order to network byte order
// Serialize Slim Data: Host -> Network
inline uint32_t compute_ack_crc(const ACKPacket *pkt) {
  // Hash all fields except crc32 (last 4 bytes)
  return calculate_crc32(reinterpret_cast<const unsigned char *>(pkt),
                         sizeof(ACKPacket) - sizeof(uint32_t));
}

inline void serialize_slim_packet(struct SlimDataPacket *pkt) {
  pkt->seq_num = htonl(pkt->seq_num);
  pkt->crc32 = htonl(pkt->crc32);
  pkt->data_len = htons(pkt->data_len);
  pkt->connection_id = htonll(pkt->connection_id);
  pkt->chunk_offset = htonl(pkt->chunk_offset);
  pkt->packet_iv = htonll(pkt->packet_iv);
}

inline void deserialize_slim_packet(struct SlimDataPacket *pkt) {
  pkt->seq_num = ntohl(pkt->seq_num);
  pkt->crc32 = ntohl(pkt->crc32);
  pkt->data_len = ntohs(pkt->data_len);
  pkt->connection_id = ntohll(pkt->connection_id);
  pkt->chunk_offset = ntohl(pkt->chunk_offset);
  pkt->packet_iv = ntohll(pkt->packet_iv);
}

inline void serialize_start_packet(struct StartPacket *pkt) {
  pkt->file_size = htonl(pkt->file_size);
  pkt->total_chunks = htonl(pkt->total_chunks);
  pkt->window_size = htons(pkt->window_size);
  pkt->connection_id = htonll(pkt->connection_id);
}

inline void deserialize_start_packet(struct StartPacket *pkt) {
  pkt->file_size = ntohl(pkt->file_size);
  pkt->total_chunks = ntohl(pkt->total_chunks);
  pkt->window_size = ntohs(pkt->window_size);
  pkt->connection_id = ntohll(pkt->connection_id);
}

inline void serialize_ack_packet(struct ACKPacket *pkt) {
  pkt->ack_num = htonl(pkt->ack_num);
  for (int i = 0; i < DataBeam::SR_SACK_BITMAP_CHUNKS; i++) {
    pkt->bitmap[i] = htonll(pkt->bitmap[i]);
  }
  pkt->connection_id = htonll(pkt->connection_id);
  pkt->crc32 = htonl(pkt->crc32);
}

inline void deserialize_ack_packet(struct ACKPacket *pkt) {
  pkt->ack_num = ntohl(pkt->ack_num);
  for (int i = 0; i < DataBeam::SR_SACK_BITMAP_CHUNKS; i++) {
    pkt->bitmap[i] = ntohll(pkt->bitmap[i]);
  }
  pkt->connection_id = ntohll(pkt->connection_id);
  pkt->crc32 = ntohl(pkt->crc32);
}
#endif
