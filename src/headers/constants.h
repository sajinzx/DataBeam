#ifndef DATABEAM_CONSTANTS_H
#define DATABEAM_CONSTANTS_H

#include <stdint.h>

namespace DataBeam {

// --- Network & Protocol Core ---
constexpr uint16_t DEFAULT_PORT = 12345;
constexpr uint32_t PACKET_DATA_SIZE =
    1400; // 1500 - 20 (IP) - 8 (UDP) - 42 (custom header)
constexpr uint32_t MAX_FILENAME_LEN = 256;
constexpr uint32_t MAX_USERNAME_LEN = 32;

// --- Selective Repeat (SR) ARQ ---
constexpr uint32_t SR_WINDOW_SIZE = 4096;
constexpr uint32_t SR_WINDOW_MASK = SR_WINDOW_SIZE - 1;
constexpr uint32_t SR_SACK_BITMAP_CHUNKS =
    64; // 64 chunks * 64 bits = 4096 bits
constexpr uint32_t SR_SACK_BITS_PER_CHUNK = 64;
constexpr uint32_t SR_BASE_TIMEOUT_MS = 100;
constexpr uint32_t SR_MAX_RETRANSMITS = 200;

// --- Go-Back-N (GBN) ARQ ---
constexpr uint8_t GBN_WINDOW_SIZE = 8;
constexpr uint32_t GBN_INITIAL_RTO_MS = 500;
constexpr uint32_t GBN_MAX_RTO_MS = 60000;
constexpr double CC_AIMD_INCREASE = 1.0;
constexpr double CC_INITIAL_THRESHOLD = 32.0;
constexpr double ALPHA_RTT = 0.125;
constexpr double BETA_RTTVAR = 0.25;

// --- Congestion Control (AIMD) ---
constexpr double CC_ALPHA_RTT = 0.125;   // EMA smoothing factor (1/8)
constexpr double CC_BETA_RTTVAR = 0.25;  // RTT variance smoothing factor
constexpr double CC_AIMD_DECREASE = 0.5; // Multiplicative Decrease

// --- Performance & Tuning ---
constexpr uint32_t SERVER_RECV_BUFFER_SIZE = 32768;
constexpr uint32_t SERVER_ACK_BATCH_SIZE = 64;
constexpr uint32_t SERVER_SOCKET_BUFFER_MB = 32;
constexpr uint32_t SERVER_BUNCH_CAPACITY = 1024 * 1024; // 1MB staging buffer

constexpr uint32_t SERVER_DECOMPRESSOR_THREADS = 4;
constexpr uint32_t CLIENT_COMPRESSOR_THREADS = 6;
constexpr uint32_t CLIENT_QUEUE_CAPACITY = 8192;
constexpr uint32_t CLIENT_SOCKET_BUFFER_MB = 32;

// --- Timeouts & Intervals ---
constexpr uint32_t RECV_TIMEOUT_MS = 100;
constexpr uint32_t SOCKET_RETRY_DELAY_US = 500;
constexpr uint32_t IDLE_TIMEOUT_COUNT = 100; // 100 * 100ms = 10s
constexpr uint32_t ADAPTIVE_MIN_RTO_MS = 50;
constexpr uint32_t ADAPTIVE_MAX_RTO_MS = 2000;
constexpr uint32_t CHECKPOINT_INTERVAL_PACKETS = 1000;

// --- Security & Integrity ---
constexpr uint32_t SHARED_SECRET_KEY_LEN = 16;
constexpr uint8_t SHARED_SECRET_KEY[SHARED_SECRET_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
constexpr uint32_t HMAC_TAG_LEN = 16;
constexpr uint32_t CRYPTO_IV_LEN = 8;

// --- Utilities ---
constexpr uint32_t MS_PER_SEC = 1000;
constexpr uint32_t NS_PER_MS = 1000000;
constexpr uint32_t US_PER_MS = 1000;

} // namespace DataBeam

#endif // DATABEAM_CONSTANTS_H
