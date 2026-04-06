// =============================================================================
// probe.h — Pre-Flight Network Probing Protocol (Phase 6.1)
//
// Eliminates "Slow Start" by measuring the pipe's physical ceiling during
// the handshake phase. The client sends a 32-packet train at line speed;
// the server measures inter-packet dispersion to estimate bandwidth.
//
// ProbePacket   (type=5)  — Client → Server (32 full-size packets)
// ProbeResult   (type=6)  — Server → Client (bandwidth + recommendation)
// =============================================================================
#ifndef DATABEAM_PROBE_H
#define DATABEAM_PROBE_H

#include <cstdint>
#include <cstring>
#include "constants.h"
#include "packet.h" // for htonll/ntohll

#pragma pack(push, 1)

// Client sends 32 of these at maximum line speed
struct ProbePacket {
  uint8_t type;           // Always PROBE_PACKET_TYPE (5)
  uint8_t probe_seq;      // 0–31
  uint64_t timestamp_ns;  // High-resolution sender timestamp
  uint64_t connection_id; // CID from handshake
  char padding[1400];     // Full MTU-sized for accurate dispersion
};

// Server sends one of these back after receiving all 32 probes
struct ProbeResultPacket {
  uint8_t type;              // Always PROBE_RESULT_TYPE (6)
  uint64_t bandwidth_bps;    // Estimated bandwidth in bits/sec
  uint64_t rtt_echo_ns;      // Echo of first probe's timestamp (for RTT)
  uint32_t recommended_cwnd; // Server's BDP-based recommendation
  uint64_t connection_id;    // Echo CID
};

#pragma pack(pop)

// Serialize ProbeResultPacket to network byte order
inline void serialize_probe_result(ProbeResultPacket *pkt) {
  pkt->bandwidth_bps = htonll(pkt->bandwidth_bps);
  pkt->rtt_echo_ns = htonll(pkt->rtt_echo_ns);
  pkt->recommended_cwnd = htonl(pkt->recommended_cwnd);
  pkt->connection_id = htonll(pkt->connection_id);
}

// Deserialize ProbeResultPacket to host byte order
inline void deserialize_probe_result(ProbeResultPacket *pkt) {
  pkt->bandwidth_bps = ntohll(pkt->bandwidth_bps);
  pkt->rtt_echo_ns = ntohll(pkt->rtt_echo_ns);
  pkt->recommended_cwnd = ntohl(pkt->recommended_cwnd);
  pkt->connection_id = ntohll(pkt->connection_id);
}

// Serialize ProbePacket — only the 64-bit fields need byte-swapping
inline void serialize_probe_packet(ProbePacket *pkt) {
  pkt->timestamp_ns = htonll(pkt->timestamp_ns);
  pkt->connection_id = htonll(pkt->connection_id);
}

// Deserialize ProbePacket
inline void deserialize_probe_packet(ProbePacket *pkt) {
  pkt->timestamp_ns = ntohll(pkt->timestamp_ns);
  pkt->connection_id = ntohll(pkt->connection_id);
}

#endif // DATABEAM_PROBE_H
