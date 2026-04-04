// LinkFlow Phase 5: UDP Client — 3-Stage Concurrent Pipeline
// File: src/client.cpp
// Purpose: High-throughput file transfer with SR sliding window using Pthreads
//
// Pipeline Architecture:
//   Stage 1 (dispatcher) — reads file chunks, assigns seq_nums
//   Stage 2 (compressors) — N threads compress + encrypt + CRC in parallel
//   Stage 3 (sender) — reorders, serializes, HMAC, WSASendTo, ARQ record

#include "./headers/compress.h"
#include "./headers/concurrentqueue.h"
#include <atomic>
#include <chrono>
#include <signal.h>
#include <cstring>
#include <filesystem> // C++17
#include <fstream>
#include <intrin.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <zlib.h>

#include "./headers/crchw.h"
#include "./headers/crypto.h"
#include "./headers/packet.h"
#include "./headers/ringbuf.h"
#include "./headers/selectrepeat.h"
#define BITMAP_ACK 4096 // Bitmap covers the full SR_WINDOW_SIZE (64 chunks × 64 bits)
#define SOC_BUFFER 128   // Socket buffer size in MB (both send and receive)
#define RECV_TIMEOUT 100 // 30-second recv timeout for ACKs
// #define BITMAP_SIZE 512 // Bitmap size ACKs cover 1024 packets beyond the
// cumulative ACK set 20% of window size Number of compressor threads -- tune to
// CPU core count
#define COMPRESSOR_THREADS 6 // increase to 8 on 8+ core machines
using namespace std;

static const size_t RAW_Q_CAP = 8192; // always 2*windowsize
static const size_t READY_Q_CAP = 8192;

struct ClientPerf {
  // Stage Latencies (Microseconds)
  std::atomic<long long> total_disk_read_us{0};
  std::atomic<long long> total_compress_us{0};
  std::atomic<long long> total_crypto_us{0}; // AES-GCM time
  std::atomic<long long> total_send_syscall_us{0};
  std::atomic<long long> total_lock_wait_us{
      0}; // Time spent waiting for arq_mutex
  std::atomic<long long> total_bit_scan_us{
      0}; // Time spent processing the 512-bit bitmap
  std::atomic<long long> total_ack_send_us{0};
  std::atomic<uint32_t> acks_processed{0};
  // Waiting/Blocking Metrics
  std::atomic<long long> total_window_wait_us{
      0}; // Time spent waiting for ACKs/Window Slide

  // Counters
  std::atomic<uint32_t> packets_sent{0};
  std::atomic<uint32_t> window_full_events{0};

  static long long now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::high_resolution_clock::now().time_since_epoch())
        .count();
  }

  void reset() {
    total_disk_read_us = total_compress_us = total_crypto_us = 0;
    total_send_syscall_us = total_window_wait_us = 0;
    packets_sent = window_full_events = 0;
  }
};

ClientPerf g_cperf; // Global client performance object
void print_client_report() {
  uint32_t count = g_cperf.packets_sent.load();
  if (count == 0)
    return;

  std::cout << "\n--- CLIENT PERFORMANCE REPORT (Average per Packet) ---"
            << std::endl;
  std::cout << std::fixed << std::setprecision(2);

  std::cout << "1. Window Wait:   "
            << (double)g_cperf.total_window_wait_us / count << " us"
            << " (If high, increase Server ACK Batch size)" << std::endl;

  std::cout << "2. Disk Read:     "
            << (double)g_cperf.total_disk_read_us / count << " us" << std::endl;

  std::cout << "3. Compression:   " << (double)g_cperf.total_compress_us / count
            << " us"
            << " (If high for video, DISABLE it)" << std::endl;

  std::cout << "4. Crypto/AES:    " << (double)g_cperf.total_crypto_us / count
            << " us" << std::endl;

  std::cout << "5. Network Send:  "
            << (double)g_cperf.total_send_syscall_us / count << " us"
            << " (If high, use Batch/WSASendTo)" << std::endl;

  std::cout << "Window Full Count: " << g_cperf.window_full_events << std::endl;
  uint32_t ack_count = g_cperf.acks_processed.load();
  std::cout << "Lock Contention: "
            << (double)g_cperf.total_lock_wait_us / ack_count << " us"
            << std::endl;
  std::cout << "Bit Scanning:   "
            << (double)g_cperf.total_bit_scan_us / ack_count << " us"
            << std::endl;
  std::cout << "ACK Syscall:    "
            << (double)g_cperf.total_ack_send_us / ack_count << " us"
            << std::endl;
  std::cout << "------------------------------------------------------"
            << std::endl;
}
// ----------------------------------------------------------------------------
// Shared State (Protected by Mutex)
// ----------------------------------------------------------------------------
SelectiveRepeatARQ arq;
pthread_mutex_t arq_mutex = PTHREAD_MUTEX_INITIALIZER;

int sockfd;
struct sockaddr_in server_addr;
socklen_t addr_len;
string filename;
const char *filename_str;
uint32_t file_size;
uint32_t chunk_offset = 0;
int total_chunks;
int chunks_sent = 0;
int acks_received = 0;
uint64_t total_bytes_sent = 0;
int peak_inflight =
    0; // actual peak in-flight count (was misnamed total_inflights)
int retransmissions = 0;
volatile bool transfer_complete = false;
bool disable_compression = false;

// ----------------------------------------------------------------------------
// AdaptiveParams — dynamic tuning based on observed loss and throughput
//
// RTO: starts at SR_PACKET_TIMEOUT_MS, doubles on each consecutive timeout
//      (exponential backoff per RFC 6298), resets to base on successful ACK.
// max_retransmits: scales with RTO so we don't abort too early under high loss.
// ----------------------------------------------------------------------------
struct AdaptiveParams {
  // RTO state
  std::atomic<int> rto_ms{SR_PACKET_TIMEOUT_MS};
  std::atomic<int> consecutive_timeouts{0};
  static constexpr int MIN_RTO_MS = 50;   // floor
  static constexpr int MAX_RTO_MS = 2000; // ceiling (2s)

  // Max retransmits: proportional to how long we're willing to wait
  // Formula: at MIN_RTO each retry costs 50ms → 200*50ms=10s window
  //          at MAX_RTO each retry costs 2000ms → 15 retries = 30s window
  int get_max_retransmits() const {
    // Allow up to 10 seconds of total retry time per packet
    int budget_ms = 10000;
    return std::max(10, budget_ms / rto_ms.load());
  }

  // Called when a packet times out — doubles RTO up to MAX
  void on_timeout() {
    int t = consecutive_timeouts.fetch_add(1) + 1;
    int new_rto =
        SR_PACKET_TIMEOUT_MS * (1 << std::min(t, 5)); // cap doubling at 32x
    rto_ms.store(std::min(new_rto, MAX_RTO_MS));
  }

  // Called when an ACK arrives — resets backoff
  void on_ack() {
    if (consecutive_timeouts.load() > 0) {
      consecutive_timeouts.store(0);
      rto_ms.store(SR_PACKET_TIMEOUT_MS);
    }
  }
};
AdaptiveParams g_adapt;

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// ---- Pipeline packet structs -----------------------------------------------

struct RawChunk {
  char data[DATA_SIZE];
  size_t bytes_read;
  uint32_t offset;
  uint32_t seq_num;
  bool is_last;
};

struct ReadyPacket {
  SlimDataPacket pkt;  // fully built, CRC set, ready to serialize+send
  size_t original_len; // uncompressed chunk size (for counter updates)
};

// ============================================================================
// ReorderBuf -- zero-allocation O(1) reorder buffer
//
// Replaces std::map<uint32_t,ReadyPacket> in the sender thread.
// Indexed by (seq_num & MASK): no heap allocations, no tree traversal.
// Capacity must be >= SR_WINDOW_SIZE (4096) and a power of 2.
// Safety: only the sender thread reads/writes slots, so no lock needed.
// ============================================================================
struct ReorderSlot {
  ReadyPacket pkt;
  bool valid = false;
};

static_assert((SR_WINDOW_SIZE & (SR_WINDOW_SIZE - 1)) == 0,
              "SR_WINDOW_SIZE must be power of 2");
static const uint32_t REORDER_CAP = SR_WINDOW_SIZE; // 4096
static const uint32_t REORDER_MASK = REORDER_CAP - 1;

struct ReorderBuf {
  ReorderSlot slots[REORDER_CAP];
  uint32_t pending_count = 0; // how many valid slots are occupied

  // Store a packet -- O(1)
  void insert(uint32_t seq, const ReadyPacket &rp) {
    uint32_t idx = seq & REORDER_MASK;
    slots[idx].pkt = rp;
    slots[idx].valid = true;
    pending_count++;
  }

  // Check if next expected seq is ready -- O(1)
  bool has(uint32_t seq) const { return slots[seq & REORDER_MASK].valid; }

  // Consume and return the slot -- O(1)
  ReadyPacket &get(uint32_t seq) { return slots[seq & REORDER_MASK].pkt; }

  // Mark slot as consumed -- O(1)
  void erase(uint32_t seq) {
    slots[seq & REORDER_MASK].valid = false;
    pending_count--;
  }

  bool empty() const { return pending_count == 0; }
};

// ---- Pipeline queues (Lock-Free MPMC) ---------------------------------------
moodycamel::ConcurrentQueue<RawChunk> raw_queue;
moodycamel::ConcurrentQueue<ReadyPacket> ready_queue;

// Dispatcher state
atomic<uint32_t> dispatch_offset{0};
atomic<uint32_t> dispatch_seq{1};
atomic<bool> dispatch_done{false};
atomic<int> compressors_done{0};

uint32_t get_file_size(const char *filename) {
  struct _stat64 st;

  if (_stat64(filename, &st) != 0)
    return 0;

  if (st.st_size > 0xFFFFFFFF) {
    std::cerr << "[ERROR] File exceeds 4GB limit\n";
    return 0;
  }

  return static_cast<uint32_t>(st.st_size);
}

// ============================================================================
// STAGE 1: Dispatcher Thread (1 thread)  — Memory-Mapped File (Zero-Copy)
//
// Uses Win32 CreateFileMapping + MapViewOfFile to map the entire file into
// virtual address space. The dispatcher simply memcpy's from a pointer —
// no kernel read() syscalls, no context switches per chunk. The OS's virtual
// memory manager automatically prefetches sequential pages from the SSD.
// ============================================================================

void *dispatcher_thread(void *arg) {
  // --- Open file with Win32 API for memory mapping --------------------------
  HANDLE hFile = CreateFileA(
      filename_str, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN, // Hint to OS: we read sequentially → prefetch
                                 // aggressively
      NULL);

  if (hFile == INVALID_HANDLE_VALUE) {
    cerr << " [DISPATCHER] Cannot open file: " << filename_str
         << " (Win32 error " << GetLastError() << ")" << endl;
    dispatch_done.store(true, std::memory_order_release);
    transfer_complete = true;
    return nullptr;
  }

  // --- Create file mapping object ------------------------------------------
  HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hMapping == NULL) {
    cerr << " [DISPATCHER] CreateFileMapping failed (Win32 error "
         << GetLastError() << ")" << endl;
    CloseHandle(hFile);
    dispatch_done.store(true, std::memory_order_release);
    transfer_complete = true;
    return nullptr;
  }

  // --- Map entire file into process address space --------------------------
  const char *mapped_ptr =
      (const char *)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
  if (mapped_ptr == NULL) {
    cerr << " [DISPATCHER] MapViewOfFile failed (Win32 error " << GetLastError()
         << ")" << endl;
    CloseHandle(hMapping);
    CloseHandle(hFile);
    dispatch_done.store(true, std::memory_order_release);
    transfer_complete = true;
    return nullptr;
  }

  uint32_t local_offset = chunk_offset; // honours resume checkpoint
  moodycamel::ProducerToken ptok(raw_queue);

  while (local_offset < (uint32_t)file_size && !transfer_complete) {
    // Back-pressure: total pipeline + in-flight must stay under window
    while (!transfer_complete) {
      pthread_mutex_lock(&arq_mutex);
      int in_flight = arq.get_in_flight_count();
      pthread_mutex_unlock(&arq_mutex);
      if (in_flight + (int)raw_queue.size_approx() +
              (int)ready_queue.size_approx() <
          SR_WINDOW_SIZE)
        break;
      SwitchToThread();
    }
    if (transfer_complete)
      break;

    // Back-pressure: raw_queue limit check
    while (raw_queue.size_approx() > RAW_Q_CAP && !transfer_complete)
      SwitchToThread();
    if (transfer_complete)
      break;

    // Zero-copy read: just memcpy from the mapped pointer
    RawChunk rc;
    uint32_t remaining = (uint32_t)file_size - local_offset;
    rc.bytes_read = (remaining < DATA_SIZE) ? remaining : DATA_SIZE;

    long long t_read = g_cperf.now_us();
    memcpy(rc.data, mapped_ptr + local_offset, rc.bytes_read);
    g_cperf.total_disk_read_us.fetch_add(g_cperf.now_us() - t_read,
                                         std::memory_order_relaxed);

    rc.offset = local_offset;
    rc.seq_num = dispatch_seq.fetch_add(1, std::memory_order_relaxed);
    rc.is_last = (local_offset + rc.bytes_read >= (uint32_t)file_size);

    raw_queue.enqueue(ptok, rc);

    local_offset += (uint32_t)rc.bytes_read;
    if (rc.is_last)
      break;
  }

  dispatch_done.store(true, std::memory_order_release);

  // --- Cleanup memory mapping ----------------------------------------------
  UnmapViewOfFile(mapped_ptr);
  CloseHandle(hMapping);
  CloseHandle(hFile);
  return nullptr;
}

// ============================================================================
// STAGE 2: Compressor Thread (N threads, default COMPRESSOR_THREADS = 4)
// Pops raw chunks, compresses, encrypts, builds SlimDataPacket with CRC,
// then pushes ReadyPacket into ready_queue for the sender.
// ============================================================================

void *compressor_thread(void *arg) {
  moodycamel::ConsumerToken ctok_raw(raw_queue);
  moodycamel::ProducerToken ptok_ready(ready_queue);

  while (!transfer_complete) {
    RawChunk rc;
    bool got = raw_queue.try_dequeue(ctok_raw, rc);

    if (!got) {
      if (dispatch_done.load(std::memory_order_acquire)) {
        // Final check
        got = raw_queue.try_dequeue(ctok_raw, rc);
        if (!got)
          break; // truly done
      }
      SwitchToThread();
      continue;
    }

    // 1. Compress
    char compressed_data[DATA_SIZE + 1];
    size_t compressed_len = sizeof(compressed_data);
    bool is_compressed = false;

    long long t_comp = g_cperf.now_us();
    if (!disable_compression &&
        compress_data(rc.data, rc.bytes_read, compressed_data,
                      compressed_len) == 0) {
      is_compressed = ((uint8_t)compressed_data[0] == 0x01);
    } else {
      memcpy(compressed_data + 1, rc.data, rc.bytes_read);
      compressed_data[0] = 0x00;
      compressed_len = rc.bytes_read + 1;
    }
    g_cperf.total_compress_us.fetch_add(g_cperf.now_us() - t_comp,
                                        std::memory_order_relaxed);

    // 2. Build packet
    ReadyPacket rp;
    memset(&rp.pkt, 0, sizeof(rp.pkt));
    generate_iv(&rp.pkt.packet_iv);

    // 3. Encrypt
    char encrypted_data[DATA_SIZE + 1];
    long long t_crypto = g_cperf.now_us();
    if (!aes_encrypt((const uint8_t *)compressed_data, compressed_len,
                     SHARED_SECRET_KEY, &rp.pkt.packet_iv,
                     (uint8_t *)encrypted_data)) {
      cerr << " [COMPRESSOR] Encryption failed at seq=" << rc.seq_num << endl;
      transfer_complete = true;
      compressors_done.fetch_add(1, std::memory_order_release);
      return nullptr;
    }
    g_cperf.total_crypto_us.fetch_add(g_cperf.now_us() - t_crypto,
                                      std::memory_order_relaxed);

    rp.pkt.type = rc.is_last ? 3 : 0;
    rp.pkt.seq_num = rc.seq_num;
    rp.pkt.chunk_offset = rc.offset;
    rp.pkt.data_len = (uint16_t)compressed_len;
    rp.pkt.flags = is_compressed ? 0x01 : 0x00;
    memset(rp.pkt.hmac, 0, 16);
    memcpy(rp.pkt.data, encrypted_data, compressed_len);

    // 4. CRC on whole struct (crc32=0, hmac=0) -- server-compatible
    rp.pkt.crc32 = 0;
    rp.pkt.crc32 =
        calculate_crc32(reinterpret_cast<const unsigned char *>(&rp.pkt),
                        sizeof(SlimDataPacket));

    rp.original_len = rc.bytes_read;

    // 5. Push to ready_queue
    ready_queue.enqueue(ptok_ready, rp);
  }

  compressors_done.fetch_add(1, std::memory_order_release);
  return nullptr;
}

// ============================================================================
// STAGE 3: Sender Thread (1 thread)
//
// Reorder buffer: ReorderBuf (circular array, O(1), zero heap alloc)
//   replaces the old std::map which did a heap alloc+free per packet.
//   For a 1GB file (~715K packets) that eliminates ~1.4M heap operations.
//
// Window-space check: uses arq.get_in_flight_count() under arq_mutex.
//   The check only runs when the window is FULL -- in the happy path
//   (window has space) it hits the fast-path break immediately.
// ============================================================================

void *sender_thread(void *arg) {
  // Heap-allocated reorder buffer -- ~6 MB, avoids Windows 1MB thread stack
  // overflow crash
  auto pending = std::make_unique<ReorderBuf>();
  moodycamel::ConsumerToken ctok(ready_queue);

  // Recover starting seq from ARQ send_base (honours resume checkpoint)
  uint32_t next_send_seq = arq.get_send_base();

  while (!transfer_complete) {
    // ---- 1. Drain ready_queue into circular reorder buffer (O(1) each) --
    ReadyPacket rp;
    while (ready_queue.try_dequeue(ctok, rp))
      pending->insert(rp.pkt.seq_num, rp);

    // ---- 2. Send packets in strict seq_num order ----------------------
    while (pending->has(next_send_seq)) {
      // Window-space check: only lock when the window might be full
      pthread_mutex_lock(&arq_mutex);
      int in_flight = arq.get_in_flight_count();
      pthread_mutex_unlock(&arq_mutex);

      if (in_flight >= SR_WINDOW_SIZE) {
        // Window full -- spin until an ACK slides it
        g_cperf.window_full_events.fetch_add(1, std::memory_order_relaxed);
        long long t_wait = g_cperf.now_us();
        while (!transfer_complete) {
          SwitchToThread();
          pthread_mutex_lock(&arq_mutex);
          in_flight = arq.get_in_flight_count();
          pthread_mutex_unlock(&arq_mutex);
          if (in_flight < SR_WINDOW_SIZE)
            break;
        }
        g_cperf.total_window_wait_us.fetch_add(g_cperf.now_us() - t_wait,
                                               std::memory_order_relaxed);
      }
      if (transfer_complete)
        return nullptr;

      ReadyPacket &cur = pending->get(next_send_seq);

      // Wire copy: byte-swap then HMAC (cur.pkt stays host-order for ARQ)
      SlimDataPacket wire = cur.pkt;
      serialize_slim_packet(&wire);
      memset(wire.hmac, 0, 16);
      generate_hmac((const uint8_t *)&wire, sizeof(wire), SHARED_SECRET_KEY,
                    wire.hmac);
      memcpy(cur.pkt.hmac, wire.hmac, 16);

      // WSASendTo
      WSABUF wsabuf;
      wsabuf.buf = reinterpret_cast<CHAR *>(&wire);
      wsabuf.len = sizeof(wire);
      DWORD bytes_sent_dword = 0;

      long long t0 = g_cperf.now_us();
      int result = WSASendTo((SOCKET)sockfd, &wsabuf, 1, &bytes_sent_dword, 0,
                             reinterpret_cast<SOCKADDR *>(&server_addr),
                             (int)addr_len, NULL, NULL);

      g_cperf.total_send_syscall_us.fetch_add(g_cperf.now_us() - t0,
                                              std::memory_order_relaxed);

      if (result == SOCKET_ERROR)
      {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAENOBUFS)
        {
          Sleep(1); // Give OS network buffer a chance to drain
          continue; // retry same packet
        }
        cerr << " [SENDER] WSASendTo failed: " << err << endl;
        transfer_complete = true;
        return nullptr;
      }

      // Record in ARQ + update all global counters under one lock
      pthread_mutex_lock(&arq_mutex);
      arq.record_sent_packet(cur.pkt);
      arq.increment_seq_num();
      chunks_sent++;
      total_bytes_sent += cur.original_len;
      chunk_offset += (uint32_t)cur.original_len;
      pthread_mutex_unlock(&arq_mutex);

      g_cperf.packets_sent.fetch_add(1, std::memory_order_relaxed);

      pending->erase(next_send_seq); // O(1) -- just clears valid flag
      next_send_seq++;
    }

    // ---- 3. Termination check ----------------------------------------
    if (compressors_done.load(std::memory_order_acquire) ==
            COMPRESSOR_THREADS &&
        ready_queue.size_approx() == 0 && pending->empty()) {
      pthread_mutex_lock(&arq_mutex);
      int in_flight = arq.get_in_flight_count();
      pthread_mutex_unlock(&arq_mutex);

      if (in_flight == 0) {
        transfer_complete = true;
        return nullptr;
      }
    }

    SwitchToThread();
  }

  return nullptr;
}

// ----------------------------------------------------------------------------
// Receiver Thread
// ----------------------------------------------------------------------------
void *receiver_thread(void *arg) {
  int idle_timeouts = 0;
  while (!transfer_complete) {
    struct ACKPacket ack_pkt;

    int bytes_recv = recvfrom(sockfd, (char *)&ack_pkt, sizeof(ack_pkt), 0,
                              (struct sockaddr *)&server_addr, &addr_len);

    if (bytes_recv <= 0) {
      int err = WSAGetLastError();
      if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
        idle_timeouts++;
        if (idle_timeouts > 100) { // 100 * 100ms = 10s inactivity
          cerr << "\n[CLIENT] Server inactivity timeout (10s). Aborting transfer..." << endl;
          ACKPacket abort_ack;
          memset(&abort_ack, 0, sizeof(abort_ack));
          abort_ack.type = 4; // ABORT signal
          abort_ack.ack_num = 0;
          abort_ack.crc32 = compute_ack_crc(&abort_ack);
          serialize_ack_packet(&abort_ack);
          sendto(sockfd, (const char *)&abort_ack, sizeof(abort_ack), 0, (struct sockaddr *)&server_addr, addr_len);
          transfer_complete = true;
          break;
        }
      }
      continue;
    }
    
    idle_timeouts = 0; // reset on valid packet received

    if (bytes_recv > 0) {
      long long t_start = ClientPerf::now_us();
      deserialize_ack_packet(&ack_pkt);
      uint32_t received_crc = ack_pkt.crc32;
      uint32_t computed = compute_ack_crc(&ack_pkt);
      if (computed == received_crc) {
        if (ack_pkt.type == 4) {
          cerr << "\n[CLIENT] Received ABORT signal from server! Stopping transfer..." << endl;
          transfer_complete = true;
          continue;
        }
        if (ack_pkt.ack_num == 0)
          continue;
        pthread_mutex_lock(&arq_mutex);
        long long t_locked = ClientPerf::now_us();
        uint32_t cum = ack_pkt.ack_num;

        // 1. Slide the window
        arq.handle_cumulative_ack(cum);
        // Heap-allocate to avoid stack overflow risk (BITMAP_ACK=512 * 4B = 2KB
        // on receiver stack)
        static uint32_t
            fast_retransmit_seqs[BITMAP_ACK]; // static: single receiver thread,
                                              // no race
        int fast_retransmit_count = 0;

        // 2. Mark specific received packets (scan all 64 bitmap chunks)
        for (int chunk_idx = 0; chunk_idx < 64; chunk_idx++) {
          uint64_t chunk = ack_pkt.bitmap[chunk_idx];
          if (chunk == 0xFFFFFFFFFFFFFFFFULL) {
            for (int b = 0; b < 64; b++)
              arq.mark_packet_acked(cum + (chunk_idx * 64) + b);
          } else if (chunk != 0) {
            for (int bit = 0; bit < 64; bit++) {
              if (chunk & (1ULL << bit))
                arq.mark_packet_acked(cum + (chunk_idx * 64) + bit);
            }
          }
        }

        acks_received++;

        // Only reset backoff when the cumulative window actually ADVANCES.
        // Calling on_ack() for every SACK where cum=1 (stuck) defeats the
        // backoff.
        static uint32_t last_cum_ack_seen = 0;
        if (cum > last_cum_ack_seen) {
          g_adapt.on_ack();
          last_cum_ack_seen = cum;
        }

        // Track actual peak in-flight count
        int cur_inflight = arq.get_in_flight_count();
        if (cur_inflight > peak_inflight)
          peak_inflight = cur_inflight;

        // 3. Find highest SACK bit across all 64 chunks
        int max_sack_idx = -1;
        for (int chunk_idx = 63; chunk_idx >= 0; chunk_idx--) {
          if (ack_pkt.bitmap[chunk_idx] != 0) {
            unsigned long highest_bit = 0;
            _BitScanReverse64(&highest_bit, ack_pkt.bitmap[chunk_idx]);
            max_sack_idx = (chunk_idx * 64) + highest_bit;
            break;
          }
        }

        // 4. Identify holes and schedule fast retransmit (scan all 64 chunks)
        if (max_sack_idx >= 0) {
          for (int chunk_idx = 0; chunk_idx < 64; chunk_idx++) {
            uint64_t chunk = ack_pkt.bitmap[chunk_idx];
            uint64_t holes = ~chunk; // Flip bits: 0s (holes) become 1s

            int base_offset = chunk_idx * 64;
            if (base_offset > max_sack_idx) {
              holes = 0; // Everything above max_sack_idx is unsent/unreceived,
                         // not a hole
            } else if (base_offset + 63 > max_sack_idx) {
              int valid_bits = max_sack_idx - base_offset;
              uint64_t mask = ~0ULL;
              if (valid_bits < 63) {
                mask = (1ULL << (valid_bits + 1)) - 1;
              }
              holes &= mask;
            }

            if (holes != 0) {
              unsigned long bit_pos;
              // _BitScanForward64 finds the first '1' (our hole) in 1 clock
              // cycle
              while (_BitScanForward64(&bit_pos, holes)) {
                fast_retransmit_seqs[fast_retransmit_count++] =
                    cum + base_offset + bit_pos;
                holes &=
                    ~(1ULL << bit_pos); // Clear this hole to find the next one
                if (holes == 0)
                  break;
              }
            }
          }
        }

        arq.advance_window();
        pthread_mutex_unlock(&arq_mutex);

        long long t_scan_done = ClientPerf::now_us();

        // 5. Fast retransmit OUTSIDE the lock using try_fast_retransmit.
        // This has a built-in cooldown (rto_ms/4) so a flood of SACKs with the
        // same hole does NOT burn through retransmit_count for that packet.
        for (int i = 0; i < fast_retransmit_count; i++) {
          SlimDataPacket rpkt;
          if (arq.try_fast_retransmit(fast_retransmit_seqs[i], rpkt)) {
            serialize_slim_packet(&rpkt);
            sendto(sockfd, (const char *)&rpkt, sizeof(rpkt), 0,
                   (struct sockaddr *)&server_addr, addr_len);
            retransmissions++;
          }
        }

        // 6. Update Receiver Performance Metrics
        g_cperf.total_lock_wait_us += (t_locked - t_start);
        g_cperf.total_bit_scan_us += (t_scan_done - t_locked);
        g_cperf.acks_processed++;
      } else {
        cerr << "[CLIENT] Corrupt ACK dropped! Seq=" << ack_pkt.ack_num << endl;
      }
    }
  }
  return nullptr;
}

// ----------------------------------------------------------------------------
// Timeout Thread — Adaptive RTO with exponential backoff
// RTO doubles on each consecutive timeout (RFC 6298), resets on ACK receipt.
// max_retransmits is dynamically derived from the current RTO so we never
// abort prematurely under high latency, nor spin forever under total loss.
// ----------------------------------------------------------------------------
void *timeout_thread(void *arg) {
  while (!transfer_complete) {
    uint32_t timed_out_seq = 0;

    pthread_mutex_lock(&arq_mutex);
    timed_out_seq = arq.check_for_timeout();
    pthread_mutex_unlock(&arq_mutex);

    if (timed_out_seq != 0) {
      SlimDataPacket retransmit_pkt;
      bool ready = false;

      pthread_mutex_lock(&arq_mutex);
      // Use dynamic max_retransmits instead of the old hardcoded 200
      int dyn_max = g_adapt.get_max_retransmits();
      arq.set_max_retransmits(dyn_max);
      ready = arq.prepare_retransmit(timed_out_seq, retransmit_pkt);
      if (ready) {
        retransmissions++;
        g_adapt.on_timeout(); // double the RTO
        // Update ARQ's internal RTO so check_for_timeout uses new value
        arq.set_rto(g_adapt.rto_ms.load());
      }
      pthread_mutex_unlock(&arq_mutex);

      if (ready) {
        SlimDataPacket pkt_send = retransmit_pkt;
        serialize_slim_packet(&pkt_send);
        sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
               (struct sockaddr *)&server_addr, addr_len);
      } else {
        cerr << " [TIMEOUT] Max retries exceeded for seq=" << timed_out_seq
             << ". Aborting." << endl;
        ACKPacket abort_ack;
        memset(&abort_ack, 0, sizeof(abort_ack));
        abort_ack.type = 4; // ABORT signal
        abort_ack.ack_num = 0;
        abort_ack.crc32 = compute_ack_crc(&abort_ack);
        serialize_ack_packet(&abort_ack);
        sendto(sockfd, (const char *)&abort_ack, sizeof(abort_ack), 0, (struct sockaddr *)&server_addr, addr_len);
        transfer_complete = true;
      }
    }

    // Pro-Tip: 5ms is okay for local testing, but for 95 Mbps,
    // a 1ms sleep makes the client respond to loss much faster.
    Sleep(1);
  }
  return nullptr;
}

// ----------------------------------------------------------------------------
// Logger Thread (UNCHANGED -- currently disabled)
// ----------------------------------------------------------------------------
void *logger_thread(void *arg) {
  while (!transfer_complete) {
    // Sleep(1000);
    //  if (transfer_complete)
    //      break;

    // pthread_mutex_lock(&arq_mutex);
    // int in_flight = arq.get_in_flight_count();
    // int acks = acks_received;
    // int sent = chunks_sent;
    // // [CHANGED] Print SR window state snapshot instead of cwnd/RTT
    // //arq.print_window_state();
    // pthread_mutex_unlock(&arq_mutex);
    continue;
    // cout << "[LOGGER] InFlight=" << in_flight << "/" << SR_WINDOW_SIZE
    //      << " | ACKs=" << acks << "/" << sent << endl;
  }
  return nullptr;
}

void handle_sigint(int sig)
{
  cout << "\n[CLIENT] Caught signal " << sig << ", shutting down gracefully..." << endl;
  ACKPacket abort_ack;
  memset(&abort_ack, 0, sizeof(abort_ack));
  abort_ack.type = 4; // ABORT signal
  abort_ack.ack_num = 0;
  abort_ack.crc32 = compute_ack_crc(&abort_ack);
  serialize_ack_packet(&abort_ack);
  sendto(sockfd, (const char *)&abort_ack, sizeof(abort_ack), 0, (struct sockaddr *)&server_addr, addr_len);
  transfer_complete = true;
}

// ----------------------------------------------------------------------------
// Main function
// ----------------------------------------------------------------------------
int main(int argc, char *argv[]) {
  signal(SIGINT, handle_sigint);
  cout << " LinkFlow Phase 5 Client Starting (3-Stage Pipeline + SR ARQ)..."
       << endl;
  cout << "CRC32 hardware acceleration: "
       << (has_hw_crc32() ? "ENABLED (SSE4.2)" : "fallback (slicing-by-8)")
       << endl;
  if (argc < 2) {
    cerr << "Usage: " << argv[0] << " <filename>" << endl;
    return 1;
  }

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    cerr << " WSAStartup failed." << endl;
    return 1;
  }

  filename_str = argv[1];
  string filenames = filename_str;
  // strcpy(filenames, filename_str);

  filename = filenames.substr(filenames.find_last_of("/\\") + 1);
  // Now 'filename' is just "tata-motor-IAR-2024-25.pdf"
  file_size = get_file_size(filename_str);

  // Auto-detect incompressible files
  string lower_filename = filename;
  for (char &c : lower_filename)
    c = tolower(c);
  if (lower_filename.find(".mp4") != string::npos ||
      lower_filename.find(".mkv") != string::npos ||
      lower_filename.find(".zip") != string::npos ||
      lower_filename.find(".rar") != string::npos ||
      lower_filename.find(".7z") != string::npos ||
      lower_filename.find(".gz") != string::npos ||
      lower_filename.find(".jpg") != string::npos ||
      lower_filename.find(".jpeg") != string::npos ||
      lower_filename.find(".png") != string::npos) {
    disable_compression = true;
    cout
        << " Auto-detected incompressible file format. Compression is DISABLED."
        << endl;
  }

  if (file_size < 0) {
    cerr << " Cannot open file: " << filename_str << endl;
    std::cerr << "Reason1: " << std::strerror(errno) << std::endl;
    return 1;
  }

  total_chunks = (file_size + DATA_SIZE - 1) / DATA_SIZE;
  cout << " File: " << filename_str << " (" << file_size << " bytes, "
       << total_chunks << " chunks)" << endl;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    cerr << "Socket creation failed: " << strerror(errno) << endl;
    return 1;
  }

  DWORD recv_timeout_ms = RECV_TIMEOUT;       // 200ms timeout
  int buffer_size = SOC_BUFFER * 1024 * 1024; // 64 MB
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&buffer_size,
             sizeof(buffer_size));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&buffer_size,
             sizeof(buffer_size));
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_timeout_ms,
             sizeof(recv_timeout_ms));

  addr_len = sizeof(server_addr);
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT);

  if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
    cerr << " Invalid address" << endl;
    closesocket(sockfd); // [FIXED] close() → closesocket() on Windows/Winsock
    return 1;
  }

  cout << " SR Window=" << SR_WINDOW_SIZE << ", RTO=" << SR_PACKET_TIMEOUT_MS
       << "ms"
       << ", Pipeline=" << COMPRESSOR_THREADS << " compressors" << endl;

  // Check for resume checkpoint
  uint32_t starting_seq = 1;
  uint32_t starting_offset = 0;
  ifstream in("resume.json");
  if (in.is_open()) {
    stringstream buf;
    buf << in.rdbuf();
    string content = buf.str();
    size_t f_pos = content.find("\"filename\"");
    size_t s_pos = content.find("\"expected_seq\"");
    if (f_pos != string::npos && s_pos != string::npos) {
      size_t f_start = content.find("\"", f_pos + 10) + 1;
      size_t f_end = content.find("\"", f_start);
      string saved = content.substr(f_start, f_end - f_start);
      if (saved == filename) {
        size_t s_start = content.find(":", s_pos) + 1;
        while (isspace(content[s_start]))
          s_start++;
        size_t s_end = content.find_first_of(",}", s_start);
        while (s_end > s_start && isspace(content[s_end - 1]))
          s_end--;
        uint32_t expected_seq =
            (uint32_t)stoul(content.substr(s_start, s_end - s_start));
        starting_seq = expected_seq;
        starting_offset = (expected_seq - 1) * DATA_SIZE;
        cout << " Resuming transfer from checkpoint: seq=" << starting_seq
             << ", offset=" << starting_offset << endl;
      }
    }
  }

  chunk_offset = starting_offset;
  arq.set_start_seq(starting_seq);

  // Initialize pipeline atomics for resume support
  dispatch_seq.store(starting_seq, std::memory_order_relaxed);
  dispatch_done.store(false, std::memory_order_relaxed);
  compressors_done.store(0, std::memory_order_relaxed);

  cout << "\n Starting 3-Stage Pipeline Selective Repeat Transmission...\n"
       << endl;

  auto start_time = chrono::high_resolution_clock::now();

  StartPacket start_pkt;
  start_pkt.type = 2;
  start_pkt.file_size = file_size;
  start_pkt.total_chunks = total_chunks;
  strncpy(start_pkt.filename, filename.c_str(), MAX_FILENAME);
  serialize_start_packet(&start_pkt);
  sendto(sockfd, (const char *)&start_pkt, sizeof(start_pkt), 0,
         (struct sockaddr *)&server_addr, addr_len);
  cout << "[CLIENT] Waiting for server handshake..." << endl;
  bool handshake_done = false;
  auto handshake_start = chrono::steady_clock::now();

  while (!handshake_done) {
    ACKPacket ack;
    int r = recvfrom(sockfd, (char *)&ack, sizeof(ack), 0,
                     (struct sockaddr *)&server_addr, &addr_len);
    if (r > 0) {
      deserialize_ack_packet(&ack);
      uint32_t received_crc = ack.crc32;
      uint32_t computed = compute_ack_crc(&ack);

      if (computed == received_crc && ack.ack_num == 0 && ack.type == 1) {
        cout << "[CLIENT] Handshake confirmed! Server ready." << endl;
        cout << "[CLIENT] Starting data transfer in 200ms..." << endl;
        Sleep(200); // brief pause — matches server's Sleep(200)
        handshake_done = true;
      }
    }

    // Timeout — retransmit StartPacket
    auto elapsed = chrono::steady_clock::now() - handshake_start;
    if (chrono::duration_cast<chrono::milliseconds>(elapsed).count() > 1000) {
      cout << "[CLIENT] No handshake response -- retrying StartPacket..."
           << endl;
      StartPacket start_pkt;
      start_pkt.type = 2;
      start_pkt.file_size = file_size;
      start_pkt.total_chunks = total_chunks;
      strncpy(start_pkt.filename, filename.c_str(), 256);
      serialize_start_packet(&start_pkt);
      sendto(sockfd, (const char *)&start_pkt, sizeof(start_pkt), 0,
             (struct sockaddr *)&server_addr, addr_len);
      handshake_start = chrono::steady_clock::now();
    }
  }

  // ---- Launch 3-stage pipeline + receiver + timeout threads ----
  pthread_t t_dispatcher;
  pthread_t t_compressors[COMPRESSOR_THREADS];
  pthread_t t_sender, t_receiver, t_timeout;

  pthread_create(&t_dispatcher, nullptr, dispatcher_thread, nullptr);
  for (int i = 0; i < COMPRESSOR_THREADS; i++)
    pthread_create(&t_compressors[i], nullptr, compressor_thread, nullptr);
  pthread_create(&t_sender, nullptr, sender_thread, nullptr);
  pthread_create(&t_receiver, nullptr, receiver_thread, nullptr);
  pthread_create(&t_timeout, nullptr, timeout_thread, nullptr);
  // pthread_create(&t_logger, nullptr, logger_thread, nullptr);

  pthread_join(t_dispatcher, nullptr);
  for (int i = 0; i < COMPRESSOR_THREADS; i++)
    pthread_join(t_compressors[i], nullptr);
  pthread_join(t_sender, nullptr);
  pthread_join(t_receiver, nullptr);
  pthread_join(t_timeout, nullptr);
  // pthread_join(t_logger, nullptr);

  closesocket(sockfd); // [FIXED] close() → closesocket() on Windows/Winsock
  WSACleanup();

  auto end_time = chrono::high_resolution_clock::now();
  double elapsed =
      chrono::duration_cast<chrono::milliseconds>(end_time - start_time)
          .count() /
      1000.0;
  double throughput = (total_bytes_sent * 8.0) / (elapsed * 1e6);

  cout << "\n File transfer COMPLETE!" << endl;
  cout << " Performance Summary:" << endl;
  cout << "   - Total chunks transmitted: " << chunks_sent << endl;
  cout << "   - Total bytes sent:         " << total_bytes_sent << endl;
  cout << "   - ACKs received:            " << acks_received << endl;
  cout << "   - Elapsed time:             " << fixed << setprecision(2)
       << elapsed << "s" << endl;
  cout << "   - Throughput:               " << throughput << " Mbps" << endl;
  cout << "   - Peak in-flight packets:   " << peak_inflight << " / "
       << SR_WINDOW_SIZE << endl;
  cout << "   - Total retransmissions:    " << retransmissions << endl;
  print_client_report();
}
