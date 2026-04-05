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
#include <cstring>
#include <filesystem> // C++17
#include <fstream>
#include <intrin.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <zlib.h>

#include "./headers/constants.h"
#include "./headers/crchw.h"
#include "./headers/crypto.h"
#include "./headers/livestate.h"
#include "./headers/packet.h"
#include "./headers/probe.h"
#include "./headers/ringbuf.h"
#include "./headers/selectrepeat.h"
#include "./headers/sysprofile.h"

// Tuning Constants (Now moved to constants.h)
using namespace std;

LPFN_WSASENDMSG WSASendMsg_ptr = nullptr;

static const size_t RAW_Q_CAP =
    DataBeam::CLIENT_QUEUE_CAPACITY; // always 2*windowsize
static const size_t READY_Q_CAP = DataBeam::CLIENT_QUEUE_CAPACITY;

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
uint64_t chunk_offset = 0;
int total_chunks;
int chunks_sent = 0;
int acks_received = 0;
uint64_t total_bytes_sent = 0;
int peak_inflight =
    0; // actual peak in-flight count (was misnamed total_inflights)
int retransmissions = 0;
volatile bool transfer_complete = false;
bool disable_compression = false;

// Phase 6: System profile and dynamic runtime state
DataBeam::SystemProfile g_profile;
DataBeam::LiveState g_live;
uint64_t g_connection_id = 0;
uint32_t g_num_compressors =
    DataBeam::CLIENT_COMPRESSOR_THREADS; // set at startup

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// ---- Pipeline packet structs -----------------------------------------------

struct RawChunk {
  char data[DataBeam::PACKET_DATA_SIZE];
  size_t bytes_read;
  uint32_t offset;
  uint32_t seq_num;
  bool is_last;
};

struct ReadyPacket {
  SlimDataPacket pkt;      // Original (host-order) for ARQ record
  SlimDataPacket wire_pkt; // Serialized + HMAC'd for the network syscall
  size_t original_len;     // uncompressed chunk size (for counter updates)
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

static_assert((DataBeam::SR_WINDOW_SIZE & (DataBeam::SR_WINDOW_SIZE - 1)) == 0,
              "SR_WINDOW_SIZE must be power of 2");
static const uint32_t REORDER_CAP = DataBeam::SR_WINDOW_SIZE; // 4096
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

  uint64_t local_offset = chunk_offset; // honours resume checkpoint
  moodycamel::ProducerToken ptok(raw_queue);

  while (local_offset < (uint32_t)file_size && !transfer_complete) {
    // Back-pressure: total pipeline + in-flight must stay under window
    while (!transfer_complete) {
      int in_flight = arq.get_in_flight_count();
      uint32_t dispatched_in_flight = dispatch_seq.load() - arq.get_send_base();
      
      if (dispatched_in_flight < (uint32_t)g_live.cwnd.load() &&
          (int)(raw_queue.size_approx() + ready_queue.size_approx()) <
              (int)DataBeam::SR_WINDOW_SIZE / 4)
             break;
      Sleep(1);
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
    rc.bytes_read = (remaining < DataBeam::PACKET_DATA_SIZE)
                        ? remaining
                        : DataBeam::PACKET_DATA_SIZE;

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
    char compressed_data[DataBeam::PACKET_DATA_SIZE + 1];
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
    char encrypted_data[DataBeam::PACKET_DATA_SIZE + 1];
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
    rp.pkt.connection_id = g_connection_id; // Phase 6: CID
    memset(rp.pkt.hmac, 0, 16);
    memcpy(rp.pkt.data, encrypted_data, compressed_len);

    // 4. CRC on whole struct (crc32=0, hmac=0) -- server-compatible
    rp.pkt.crc32 = 0;
    rp.pkt.crc32 =
        calculate_crc32(reinterpret_cast<const unsigned char *>(&rp.pkt),
                        sizeof(SlimDataPacket));

    rp.original_len = rc.bytes_read;

    // 5. Wire copy: byte-swap then HMAC (now parallelized in compressor pool!)
    rp.wire_pkt = rp.pkt;
    serialize_slim_packet(&rp.wire_pkt);
    memset(rp.wire_pkt.hmac, 0, 16);
    generate_hmac((const uint8_t *)&rp.wire_pkt, sizeof(rp.wire_pkt),
                  SHARED_SECRET_KEY, rp.wire_pkt.hmac);
    memcpy(rp.pkt.hmac, rp.wire_pkt.hmac, 16);

    // 6. Push to ready_queue
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
    int drain_limit = 512;
    while (drain_limit-- > 0 && ready_queue.try_dequeue(ctok, rp)) {
      pending->insert(rp.pkt.seq_num, rp);
      if (pending->has(next_send_seq)) {
        break; // Stop draining and go send it to update next_seq_num!
      }
    }

    // ---- 2. Send packets in strict seq_num order ----------------------
    while (pending->has(next_send_seq)) {
      // Window-space check: only lock when the window might be full
      int in_flight = arq.get_in_flight_count();

      if (in_flight >= g_live.cwnd.load()) {
        // Window full -- spin until an ACK slides it
        g_cperf.window_full_events.fetch_add(1, std::memory_order_relaxed);
        long long t_wait = g_cperf.now_us();
        while (!transfer_complete) {
          SwitchToThread();
          in_flight = arq.get_in_flight_count();
          if (in_flight < g_live.cwnd.load())
            break;
        }
        g_cperf.total_window_wait_us.fetch_add(g_cperf.now_us() - t_wait,
                                               std::memory_order_relaxed);
      }
      
      if (in_flight > peak_inflight) {
        peak_inflight = in_flight;
      }
      if (transfer_complete)
        return nullptr;

      // Batching setup for USO
      const int MAX_BATCH = 16;
      int batch_count = 0;
      WSABUF wsabufs[MAX_BATCH];
      ReadyPacket* batch_pkts[MAX_BATCH];
      
      // Determine how many we can send in one burst (bounded by window limitation)
      int allowed_to_send = g_live.cwnd.load() - arq.get_in_flight_count();
      int batch_limit = std::min(MAX_BATCH, allowed_to_send);
      if (batch_limit <= 0) batch_limit = 1; 
      
      for (int i = 0; i < batch_limit; i++) {
        if (!pending->has(next_send_seq + i)) break;
        batch_pkts[batch_count] = &pending->get(next_send_seq + i);
        wsabufs[batch_count].buf = reinterpret_cast<CHAR *>(&batch_pkts[batch_count]->wire_pkt);
        wsabufs[batch_count].len = sizeof(batch_pkts[batch_count]->wire_pkt);
        batch_count++;
      }

      long long t0 = g_cperf.now_us();
      DWORD bytes_sent_dword = 0;
      int result = SOCKET_ERROR;

      if (WSASendMsg_ptr != nullptr && batch_count > 1) {
        // USE USO (UDP Segmentation Offload)
        char ctrl_buf[WSA_CMSG_SPACE(sizeof(DWORD))] = {0};
        
        WSAMSG msg = {0};
        msg.name = reinterpret_cast<LPSOCKADDR>(&server_addr);
        msg.namelen = sizeof(server_addr);
        msg.lpBuffers = wsabufs;
        msg.dwBufferCount = batch_count;
        msg.Control.buf = ctrl_buf;
        msg.Control.len = sizeof(ctrl_buf);
        msg.dwFlags = 0;

        WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_UDP;
        cmsg->cmsg_type = UDP_SEND_MSG_SIZE;
        cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(DWORD));
        *(DWORD *)WSA_CMSG_DATA(cmsg) = sizeof(SlimDataPacket); // Segment size is 1435

        result = WSASendMsg_ptr((SOCKET)sockfd, &msg, 0, &bytes_sent_dword, NULL, NULL);
      } else {
        // Fallback or single packet
        batch_count = 1;
        result = WSASendTo((SOCKET)sockfd, &wsabufs[0], 1, &bytes_sent_dword, 0,
                           reinterpret_cast<SOCKADDR *>(&server_addr),
                           (int)addr_len, NULL, NULL);
      }

      g_cperf.total_send_syscall_us.fetch_add(g_cperf.now_us() - t0,
                                              std::memory_order_relaxed);

      if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAENOBUFS) {
          std::this_thread::sleep_for(std::chrono::microseconds(500));
          continue; // retry same batch
        }
        cerr << " [SENDER] Send failed: " << err << endl;
        transfer_complete = true;
        return nullptr;
      }

      // Record in ARQ + update all global counters under one lock
      pthread_mutex_lock(&arq_mutex);
      for (int i = 0; i < batch_count; i++) {
        arq.record_sent_packet(batch_pkts[i]->pkt);
        arq.increment_seq_num();
        chunks_sent++;
        total_bytes_sent += batch_pkts[i]->original_len;
        chunk_offset += (uint64_t)batch_pkts[i]->original_len;
        pending->erase(next_send_seq); // O(1) -- just clears valid flag
        next_send_seq++;
      }
      pthread_mutex_unlock(&arq_mutex);

      g_cperf.packets_sent.fetch_add(batch_count, std::memory_order_relaxed);
    }

    // ---- 3. Termination check ----------------------------------------
    if (compressors_done.load(std::memory_order_acquire) ==
            (int)g_num_compressors &&
        ready_queue.size_approx() == 0 && pending->empty()) {
      int in_flight = arq.get_in_flight_count();

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
        // If EOF was already sent (transfer_complete set by sender),
        // the server may have shut down — exit cleanly, not as an error.
        if (transfer_complete)
          break;
        idle_timeouts++;
        if (idle_timeouts > DataBeam::IDLE_TIMEOUT_COUNT) {
          cerr << "\n[CLIENT] Server inactivity timeout (10s). Aborting "
                  "transfer..."
               << endl;
          ACKPacket abort_ack;
          memset(&abort_ack, 0, sizeof(abort_ack));
          abort_ack.type = 4; // ABORT signal
          abort_ack.ack_num = 0;
          abort_ack.crc32 = compute_ack_crc(&abort_ack);
          serialize_ack_packet(&abort_ack);
          sendto(sockfd, (const char *)&abort_ack, sizeof(abort_ack), 0,
                 (struct sockaddr *)&server_addr, addr_len);
          transfer_complete = true;
          break;
        }
      }
      continue;
    }

    idle_timeouts = 0; // reset on valid packet received

    if (bytes_recv > 0) {
      // // Temporary diagnostic — remove after confirming fix
      // static uint32_t last_reported_base = 0;
      // uint32_t cur_base = arq.get_send_base();
      // if (cur_base != last_reported_base)
      // {
      //   cout << "[RECV] Window sliding: send_base " << last_reported_base
      //        << " -> " << cur_base
      //        << " | in-flight=" << arq.get_in_flight_count() << endl;
      //   last_reported_base = cur_base;
      // }
      long long t_start = ClientPerf::now_us();
      deserialize_ack_packet(&ack_pkt);
      uint32_t received_crc = ack_pkt.crc32;
      uint32_t computed = compute_ack_crc(&ack_pkt);
      if (computed == received_crc) {
        if (ack_pkt.type == 4) {
          cerr << "\n[CLIENT] Received ABORT signal from server! Stopping "
                  "transfer..."
               << endl;
          transfer_complete = true;
          continue;
        }
        if (ack_pkt.ack_num == 0)
          continue;
        pthread_mutex_lock(&arq_mutex);
        long long t_locked = ClientPerf::now_us();
        uint32_t cum = ack_pkt.ack_num;
        // Phase 6: extract RTT sample for Jacobson's algorithm
        int64_t rtt_sample_us = -1;
        arq.handle_cumulative_ack(cum, &rtt_sample_us);

        // Heap-allocate to avoid stack overflow risk (BITMAP_ACK=512 * 4B = 2KB
        // on receiver stack)
        static uint32_t
            fast_retransmit_seqs[DataBeam::SR_WINDOW_SIZE]; // static: single
                                                            // receiver thread,
                                                            // no race
        int fast_retransmit_count = 0;

        // 2. Mark specific received packets (scan all 64 bitmap chunks)
        for (int chunk_idx = 0; chunk_idx < DataBeam::SR_SACK_BITMAP_CHUNKS;
             chunk_idx++) {
          uint64_t chunk = ack_pkt.bitmap[chunk_idx];
          if (chunk == 0xFFFFFFFFFFFFFFFFULL) {
            for (int b = 0; b < DataBeam::SR_SACK_BITS_PER_CHUNK; b++)
              arq.mark_packet_acked(
                  cum + (chunk_idx * DataBeam::SR_SACK_BITS_PER_CHUNK) + b);
          } else if (chunk != 0) {
            for (int bit = 0; bit < DataBeam::SR_SACK_BITS_PER_CHUNK; bit++) {
              if (chunk & (1ULL << bit))
                arq.mark_packet_acked(
                    cum + (chunk_idx * DataBeam::SR_SACK_BITS_PER_CHUNK) + bit);
            }
          }
        }

        acks_received++;

        // Only reset backoff when the cumulative window actually ADVANCES.
        // Calling on_ack() for every SACK where cum=1 (stuck) defeats the
        // backoff.
        static uint32_t last_cum_ack_seen = 0;
        if (cum > last_cum_ack_seen) {
          g_live.on_ack();
          // Phase 6: Feed RTT sample to Jacobson's algorithm
          if (rtt_sample_us > 0) {
            g_live.update_rtt(rtt_sample_us);
            arq.set_rto(g_live.rto_ms.load());
          }
          last_cum_ack_seen = cum;
        }

        // Phase 6: Vegas congestion control (every N ACKs)
        static uint32_t vegas_counter = 0;
        vegas_counter++;
        if (vegas_counter >= DataBeam::VEGAS_ADJUST_INTERVAL) {
          int adj = g_live.vegas_adjust();
          arq.set_effective_cwnd(g_live.cwnd.load());
          vegas_counter = 0;
        }

        // Track actual peak in-flight count now correctly done in sender thread

        // 3. Find highest SACK bit across all 64 chunks
        int max_sack_idx = -1;
        for (int chunk_idx = DataBeam::SR_SACK_BITMAP_CHUNKS - 1;
             chunk_idx >= 0; chunk_idx--) {
          if (ack_pkt.bitmap[chunk_idx] != 0) {
            unsigned long highest_bit = 0;
            _BitScanReverse64(&highest_bit, ack_pkt.bitmap[chunk_idx]);
            max_sack_idx =
                (chunk_idx * DataBeam::SR_SACK_BITS_PER_CHUNK) + highest_bit;
            break;
          }
        }

        // 4. Identify holes and schedule fast retransmit (scan all 64 chunks)
        if (max_sack_idx >= 0) {
          for (int i = 0; i <= max_sack_idx; i++) {
            int chunk_idx = i >> 6; // i / 64
            int bit_idx = i & 63;   // i % 64
            uint64_t chunk = ack_pkt.bitmap[chunk_idx];

            // If the bit is 0, it's a hole.
            if (!(chunk & (1ULL << bit_idx))) {
              fast_retransmit_seqs[fast_retransmit_count++] = cum + i;
              if (fast_retransmit_count >= (int)DataBeam::SR_WINDOW_SIZE)
                break;
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
      int ready = 0;

      pthread_mutex_lock(&arq_mutex);
      int dyn_max = g_live.get_max_retransmits();
      arq.set_max_retransmits(dyn_max);
      ready = arq.prepare_retransmit(timed_out_seq, retransmit_pkt);
      if (ready == 1) {
        retransmissions++;
        g_live.on_timeout(); // Vegas: halve window + double RTO
        arq.set_rto(g_live.rto_ms.load());
        arq.set_effective_cwnd(g_live.cwnd.load());
      }
      pthread_mutex_unlock(&arq_mutex);

      if (ready == 1) {
        // Only print when we actually retransmit — avoids spurious noise
        // when packet was already ACKed between check and prepare
        cout << "[TIMEOUT] Retransmitting seq=" << timed_out_seq
             << " (rto=" << g_live.rto_ms.load() << "ms"
             << " cwnd=" << g_live.cwnd.load() << ")" << endl;
        SlimDataPacket pkt_send = retransmit_pkt;
        serialize_slim_packet(&pkt_send);
        sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
               (struct sockaddr *)&server_addr, addr_len);
      } else if (ready == -1) {
        cerr << "[TIMEOUT] Max retries exceeded for seq=" << timed_out_seq
             << ". Aborting." << endl;
        ACKPacket abort_ack;
        memset(&abort_ack, 0, sizeof(abort_ack));
        abort_ack.type = 4; // ABORT signal
        abort_ack.ack_num = 0;
        abort_ack.crc32 = compute_ack_crc(&abort_ack);
        serialize_ack_packet(&abort_ack);
        sendto(sockfd, (const char *)&abort_ack, sizeof(abort_ack), 0,
               (struct sockaddr *)&server_addr, addr_len);
        transfer_complete = true;
      }
      // ready == 0: packet was already ACKed concurrently — nothing to do
    }

    // Pro-Tip: 5ms is okay for local testing, but for 95 Mbps,
    // a 1ms sleep makes the client respond to loss much faster.
    Sleep(3);
  }
  return nullptr;
}

// ----------------------------------------------------------------------------
// Logger Thread (UNCHANGED -- currently disabled)
// ----------------------------------------------------------------------------
void *logger_thread(void *arg) {
  while (!transfer_complete) {
    Sleep(1000);
    pthread_mutex_lock(&arq_mutex);
    uint32_t sb = arq.get_send_base();
    pthread_mutex_unlock(&arq_mutex);
    cout << "[LOGGER] send_base=" << sb << endl;
  }
  return nullptr;
}

void handle_sigint(int sig) {
  cout << "\n[CLIENT] Caught signal " << sig << ", shutting down gracefully..."
       << endl;
  ACKPacket abort_ack;
  memset(&abort_ack, 0, sizeof(abort_ack));
  abort_ack.type = 4; // ABORT signal
  abort_ack.ack_num = 0;
  abort_ack.crc32 = compute_ack_crc(&abort_ack);
  serialize_ack_packet(&abort_ack);
  sendto(sockfd, (const char *)&abort_ack, sizeof(abort_ack), 0,
         (struct sockaddr *)&server_addr, addr_len);
  transfer_complete = true;
}

// ----------------------------------------------------------------------------
// Main function
// ----------------------------------------------------------------------------
int main(int argc, char *argv[]) {

  signal(SIGINT, handle_sigint);
  cout << " DataBeam Phase 6 Client Starting (Autonomous Transport)..." << endl;
  cout << "CRC32 hardware acceleration: "
       << (has_hw_crc32() ? "ENABLED (SSE4.2)" : "fallback (slicing-by-8)")
       << endl;

  // Phase 6: System Profiling
  g_profile = DataBeam::SystemProfile::probe();
  g_profile.print();
  g_live.init_from_profile(g_profile);
  g_num_compressors = g_live.compressor_threads;

  // Generate Connection ID
  generate_iv(&g_connection_id);
  cout << " Connection ID: 0x" << hex << g_connection_id << dec << endl;

  // Apply initial cwnd to ARQ
  arq.set_effective_cwnd(g_live.cwnd.load());

  if (argc < 2) {
    cerr << "Usage: " << argv[0] << " <filename>" << endl;
    return 1;
  }

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    cerr << " WSAStartup failed." << endl;
    return 1;
  }

  // Obtain WSASendMsg function pointer for UDP Batching
  SOCKET test_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (test_sock != INVALID_SOCKET) {
    GUID guidWSASendMsg = WSAID_WSASENDMSG;
    DWORD dwBytes = 0;
    int rc = WSAIoctl(test_sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                      &guidWSASendMsg, sizeof(guidWSASendMsg),
                      &WSASendMsg_ptr, sizeof(WSASendMsg_ptr),
                      &dwBytes, NULL, NULL);
    if (rc == SOCKET_ERROR) {
      cerr << " Failed to obtain WSASendMsg: " << WSAGetLastError() << endl;
    } else {
      cout << " USO / WSASendMsg natively supported!" << endl;
    }
    closesocket(test_sock);
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

  total_chunks =
      (file_size + DataBeam::PACKET_DATA_SIZE - 1) / DataBeam::PACKET_DATA_SIZE;
  cout << " File: " << filename_str << " (" << file_size << " bytes, "
       << total_chunks << " chunks)" << endl;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    cerr << "Socket creation failed: " << strerror(errno) << endl;
    return 1;
  }

  DWORD recv_timeout_ms = DataBeam::RECV_TIMEOUT_MS; // 200ms timeout
  int buffer_size = DataBeam::SERVER_RECV_BUFFER_SIZE * 1024 * 1024; // 64 MB
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&buffer_size,
             sizeof(buffer_size));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&buffer_size,
             sizeof(buffer_size));
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_timeout_ms,
             sizeof(recv_timeout_ms));

  addr_len = sizeof(server_addr);
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(DataBeam::DEFAULT_PORT);

  if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
    cerr << " Invalid address" << endl;
    closesocket(sockfd); // [FIXED] close() → closesocket() on Windows/Winsock
    return 1;
  }

  cout << " SR Window=" << DataBeam::SR_WINDOW_SIZE
       << ", cwnd=" << g_live.cwnd.load() << ", RTO=" << g_live.rto_ms.load()
       << "ms"
       << ", Pipeline=" << g_num_compressors << " compressors" << endl;

  // Check for resume checkpoint
  uint32_t starting_seq = 1;
  uint64_t starting_offset = 0;
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
        starting_offset =
            (uint64_t)(expected_seq - 1) * (uint64_t)DataBeam::PACKET_DATA_SIZE;
        if (starting_seq > total_chunks) {
          cout << " File already 100% complete according to checkpoint. "
                  "Skipping transfer."
               << endl;
          return 0;
        }
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
  start_pkt.connection_id = g_connection_id; // Phase 6: CID
  strncpy(start_pkt.filename, filename.c_str(), DataBeam::MAX_FILENAME_LEN);
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

        // Phase 6: Measure handshake RTT
        auto handshake_end = chrono::steady_clock::now();
        int64_t handshake_rtt_us = chrono::duration_cast<chrono::microseconds>(
                                       handshake_end - handshake_start)
                                       .count();
        cout << "[CLIENT] Handshake RTT: " << handshake_rtt_us << " us" << endl;

        // Phase 6: Network Probing — send 32-packet train
        cout << "[CLIENT] Starting network probe ("
             << DataBeam::PROBE_PACKET_COUNT << " packets)..." << endl;
        for (uint32_t i = 0; i < DataBeam::PROBE_PACKET_COUNT; i++) {
          ProbePacket pp;
          memset(&pp, 0, sizeof(pp));
          pp.type = DataBeam::PROBE_PACKET_TYPE;
          pp.probe_seq = (uint8_t)i;
          pp.timestamp_ns =
              (uint64_t)chrono::duration_cast<chrono::nanoseconds>(
                  chrono::high_resolution_clock::now().time_since_epoch())
                  .count();
          pp.connection_id = g_connection_id;
          serialize_probe_packet(&pp);
          sendto(sockfd, (const char *)&pp, sizeof(pp), 0,
                 (struct sockaddr *)&server_addr, addr_len);
        }

        // Wait for ProbeResult
        auto probe_start = chrono::steady_clock::now();
        bool probe_done = false;
        while (!probe_done) {
          char probe_buf[sizeof(ProbeResultPacket) + 64];
          int pr = recvfrom(sockfd, probe_buf, sizeof(probe_buf), 0,
                            (struct sockaddr *)&server_addr, &addr_len);
          if (pr > 0 && (uint8_t)probe_buf[0] == DataBeam::PROBE_RESULT_TYPE) {
            ProbeResultPacket result;
            memcpy(&result, probe_buf, sizeof(result));
            deserialize_probe_result(&result);

            g_live.init_from_probe(result.bandwidth_bps, handshake_rtt_us);
            
            // USER OVERRIDE: Set initial window exactly to server's raw measured capacity
            g_live.cwnd.store(std::max((int32_t)DataBeam::CWND_MIN, std::min((int32_t)result.recommended_cwnd, (int32_t)DataBeam::SR_WINDOW_SIZE)));
            g_live.recompute_derived();
            
            arq.set_effective_cwnd(g_live.cwnd.load());

            cout << "[PROBE] Bandwidth: " << result.bandwidth_bps / 1000000.0
                 << " Mbps" << endl;
            cout << "[PROBE] Initial cwnd: " << g_live.cwnd.load() << endl;
            probe_done = true;
          }
          auto probe_elapsed = chrono::steady_clock::now() - probe_start;
          if (chrono::duration_cast<chrono::milliseconds>(probe_elapsed)
                  .count() > DataBeam::PROBE_TIMEOUT_MS) {
            cout << "[PROBE] Timeout — using default cwnd="
                 << g_live.cwnd.load() << endl;
            probe_done = true;
          }
        }

        cout << "[CLIENT] Starting data transfer in 200ms..." << endl;
        Sleep(200); // brief pause — matches server's Sleep(200)
        handshake_done = true;
        break;
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
      start_pkt.connection_id = g_connection_id;
      strncpy(start_pkt.filename, filename.c_str(), DataBeam::MAX_FILENAME_LEN);
      serialize_start_packet(&start_pkt);
      sendto(sockfd, (const char *)&start_pkt, sizeof(start_pkt), 0,
             (struct sockaddr *)&server_addr, addr_len);
      handshake_start = chrono::steady_clock::now();
    }
  }

  // ---- Launch 3-stage pipeline + receiver + timeout threads ----
  pthread_t t_dispatcher;
  pthread_t *t_compressors = new pthread_t[g_num_compressors];
  pthread_t t_sender, t_timeout;
  pthread_t t_receiver;
  // pthread_t t_logger;
  pthread_create(&t_receiver, nullptr, receiver_thread, nullptr);
  pthread_create(&t_timeout, nullptr, timeout_thread, nullptr);
  pthread_create(&t_dispatcher, nullptr, dispatcher_thread, nullptr);

  for (uint32_t i = 0; i < g_num_compressors; i++)
    pthread_create(&t_compressors[i], nullptr, compressor_thread, nullptr);
  pthread_create(&t_sender, nullptr, sender_thread, nullptr);
  // pthread_create(&t_logger, nullptr, logger_thread, nullptr);

  pthread_join(t_dispatcher, nullptr);
  for (uint32_t i = 0; i < g_num_compressors; i++)
    pthread_join(t_compressors[i], nullptr);
  pthread_join(t_sender, nullptr);
  pthread_join(t_receiver, nullptr);
  pthread_join(t_timeout, nullptr);
  // pthread_join(t_logger, nullptr);
  delete[] t_compressors;

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
       << DataBeam::SR_WINDOW_SIZE << endl;
  cout << "   - Total retransmissions:    " << retransmissions << endl;
  print_client_report();
}
