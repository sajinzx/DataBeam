// DataBeam Phase 5 Server — Multi-Threaded Pipeline
// Architecture:
//   Network Thread  — WSARecvFrom, HMAC/CRC verify, SACK send, enqueue
//   Decompressor×4  — decrypt + decompress → atomic PoolSlot
//   Writer Thread   — in-order drain, 1MB staging buffer → disk
//
// Mirrors the client's 3-stage pipeline for symmetric throughput.

#include "./headers/packet.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <pthread.h>
#include <sstream>
#include <sys/stat.h>
#include <vector>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "./headers/compress.h"
#include "./headers/concurrentqueue.h"
#include "./headers/crchw.h"
#include "./headers/crypto.h"
#include <atomic>
#include <chrono>
#include <csignal>

using namespace std;

// =============================================================================
// Tuning Constants
// =============================================================================
#define BUFFER_SIZE 4096 // Must match SR_WINDOW_SIZE (client's sliding window)
// #define ACK_BATCH_SIZE 32 // Send SACK every N in-order packets
#define RECV_TIMEOUT 100 // 100ms — responsive to client (was 1000ms)
#define SOC_BUFFER 64    // 64MB socket buffers (was 32MB)
#define DECOMPRESSOR_THREADS 2
#define IDLE_TIMEOUT_COUNT 100 // 100 × 100ms = 10s of true inactivity (was 10s)

// =============================================================================
// Work Queue Item — CRC/HMAC-verified raw packet waiting for decompression
// =============================================================================
struct WorkItem {
  SlimDataPacket pkt;
  size_t compressed_len;
};

// =============================================================================
// Pool Slot — decompressed data with atomic ready flag
//
// Decompressor threads write data and set ready=true (release).
// Writer thread reads data when ready=true (acquire) and clears ready=false.
// Indexed by seq_num % BUFFER_SIZE — no collision because window == buffer.
// =============================================================================
struct PoolSlot {
  char data[DATA_SIZE + 1];
  size_t data_len;
  uint8_t type;
  uint32_t chunk_offset;
  uint32_t seq_num;
  std::atomic<bool> ready;

  PoolSlot() : data_len(0), type(0), chunk_offset(0), seq_num(0), ready(false) {
    memset(data, 0, sizeof(data));
  }
};

// =============================================================================
// Performance Counters
// =============================================================================
struct PerfStats {
  std::atomic<long long> total_net_recv_time_us{0};
  std::atomic<long long> total_decrypt_time_us{0};
  std::atomic<long long> total_decomp_time_us{0};
  std::atomic<long long> total_disk_write_us{0};

  std::atomic<uint32_t> packets_processed{0};
  std::atomic<uint32_t> crc_fails{0};
  std::atomic<uint32_t> pool_spin_events{0};

  static long long now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::high_resolution_clock::now().time_since_epoch())
        .count();
  }
};

PerfStats g_perf;

// =============================================================================
// Global State
// =============================================================================

// Lock-free concurrent queue (same moodycamel library as client)
moodycamel::ConcurrentQueue<WorkItem> work_queue;

// Pool — shared between decompressors (write) and writer (read)
PoolSlot *g_pool = nullptr;

// Synchronization flags
std::atomic<bool> server_done{false};
std::atomic<bool> net_recv_done{false};
std::atomic<int> decompressors_done{0};

// Shared init state (protected by init_mutex)
pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
string shared_filename = "";
uint32_t shared_file_size = 0;
std::atomic<bool> start_received{false};

void handle_sigint(int sig) {
  cout << "\n[SERVER] Caught signal " << sig << ", shutting down gracefully..."
       << endl;
  server_done.store(true, std::memory_order_relaxed);
}

// =============================================================================
// Utility Functions
// =============================================================================
void create_received_dir() {
  struct stat st = {0};
  if (stat("received", &st) == -1)
    mkdir("received");
}

void save_checkpoint(const string &filename, uint32_t expected_seq) {
  ofstream out("resume.json");
  if (out.is_open()) {
    out << "{\n  \"filename\": \"" << filename << "\",\n";
    out << "  \"expected_seq\": " << expected_seq << "\n}\n";
  }
}

uint32_t load_checkpoint(const string &target_filename) {
  ifstream in("resume.json");
  if (!in.is_open())
    return 1;
  stringstream buf;
  buf << in.rdbuf();
  string content = buf.str();
  size_t f_pos = content.find("\"filename\"");
  size_t s_pos = content.find("\"expected_seq\"");
  if (f_pos == string::npos || s_pos == string::npos)
    return 1;
  size_t f_start = content.find("\"", f_pos + 10) + 1;
  size_t f_end = content.find("\"", f_start);
  string saved = content.substr(f_start, f_end - f_start);
  if (saved != target_filename)
    return 1;
  size_t s_start = content.find(":", s_pos) + 1;
  while (isspace(content[s_start]))
    s_start++;
  size_t s_end = content.find_first_of(",}", s_start);
  while (s_end > s_start && isspace(content[s_end - 1]))
    s_end--;
  return (uint32_t)stoul(content.substr(s_start, s_end - s_start));
}

// =============================================================================
// DECOMPRESSOR THREAD (×4)
//
// Producer-Consumer: pulls WorkItems from ConcurrentQueue, decrypts,
// decompresses, stores result in PoolSlot with atomic ready flag.
// Multiple decompressors never collide because each packet has a unique
// seq_num → unique pool index.
// =============================================================================
void *decompressor_thread(void *arg) {
  moodycamel::ConsumerToken ctok(work_queue);

  while (!server_done.load(std::memory_order_relaxed)) {
    WorkItem item;
    bool got = work_queue.try_dequeue(ctok, item);

    if (!got) {
      if (net_recv_done.load(std::memory_order_acquire)) {
        // Final drain attempt after network thread finished
        got = work_queue.try_dequeue(ctok, item);
        if (!got)
          break; // truly done
      }
      SwitchToThread();
      continue;
    }

    SlimDataPacket &pkt = item.pkt;

    // ---- 1. DECRYPT --------------------------------------------------------
    char decrypted_data[DATA_SIZE + 1];
    long long t_decrypt = PerfStats::now_us();
    if (!aes_decrypt((const uint8_t *)pkt.data, item.compressed_len,
                     SHARED_SECRET_KEY, &pkt.packet_iv,
                     (uint8_t *)decrypted_data)) {
      cerr << "[DECOMP] Decrypt failed seq=" << pkt.seq_num << endl;
      continue;
    }
    g_perf.total_decrypt_time_us.fetch_add(PerfStats::now_us() - t_decrypt,
                                           std::memory_order_relaxed);

    // ---- 2. DECOMPRESS -----------------------------------------------------
    char decompressed_buffer[DATA_SIZE + 1];
    size_t decomp_len = sizeof(decompressed_buffer);

    long long decomp_start = PerfStats::now_us();
    if (pkt.type & 0x80) {
      int ret = decompress_data(decrypted_data, item.compressed_len,
                                decompressed_buffer, decomp_len);
      g_perf.total_decomp_time_us.fetch_add(PerfStats::now_us() - decomp_start,
                                            std::memory_order_relaxed);
      if (ret != 0) {
        cerr << "[DECOMP] Decomp failed seq=" << pkt.seq_num << " err=" << ret
             << endl;
        continue;
      }
    } else {
      // Uncompressed
      memcpy(decompressed_buffer, decrypted_data, item.compressed_len);
      decomp_len = item.compressed_len;
    }

    // Clear the compression flag for the writer (so EOF check works)
    pkt.type &= ~0x80;

    // ---- 3. STORE IN POOL (atomic handoff to writer) -----------------------
    int idx = pkt.seq_num % BUFFER_SIZE;
    PoolSlot &slot = g_pool[idx];

    // Spin-wait if slot is still occupied (backpressure from slow writer)
    while (slot.ready.load(std::memory_order_acquire) &&
           !server_done.load(std::memory_order_relaxed)) {
      g_perf.pool_spin_events.fetch_add(1, std::memory_order_relaxed);
      SwitchToThread();
    }
    if (server_done.load(std::memory_order_relaxed))
      break;

    // Write all data fields BEFORE setting ready flag
    memcpy(slot.data, decompressed_buffer, decomp_len);
    slot.data_len = decomp_len;
    slot.type = pkt.type;
    slot.chunk_offset = pkt.chunk_offset;
    slot.seq_num = pkt.seq_num;

    // Release fence: all writes above visible to writer's acquire load
    slot.ready.store(true, std::memory_order_release);

    g_perf.packets_processed.fetch_add(1, std::memory_order_relaxed);
  }

  decompressors_done.fetch_add(1, std::memory_order_release);
  return nullptr;
}

// =============================================================================
// WRITER THREAD (×1)
//
// The "Janitor" — reads pool slots in strict sequence order, stages
// contiguous data into a 1MB bunch buffer, flushes to disk in one
// seekp+write syscall per bunch (~32× fewer disk ops than per-packet).
// =============================================================================
void *writer_thread(void *arg) {
  // Wait for start packet
  while (!start_received.load(std::memory_order_acquire) &&
         !server_done.load(std::memory_order_relaxed)) {
    Sleep(3);
  }
  if (!start_received.load(std::memory_order_acquire)) {
    cout << "[WRITER] Shutting down before any file transfer started." << endl;
    return nullptr;
  }

  pthread_mutex_lock(&init_mutex);
  string current_filename = shared_filename;
  uint32_t total_file_size = shared_file_size;
  pthread_mutex_unlock(&init_mutex);

  string out_filepath = "received/recv_" + current_filename;

  uint32_t expected_seq_num = load_checkpoint(current_filename);
  if (expected_seq_num == 0)
    expected_seq_num = 1;

  ofstream outfile;
  if (expected_seq_num > 1) {
    outfile.open(out_filepath, ios::binary | ios::out | ios::in);
    if (!outfile.is_open()) {
      expected_seq_num = 1;
      outfile.open(out_filepath, ios::binary | ios::out | ios::trunc);
    }
  } else {
    outfile.open(out_filepath, ios::binary | ios::out | ios::trunc);
  }

  if (!outfile.is_open()) {
    cerr << "[WRITER] Cannot create: " << out_filepath << endl;
    server_done.store(true, std::memory_order_relaxed);
    return nullptr;
  }
  cout << "[WRITER] File opened: " << out_filepath
       << ". Expecting seq=" << expected_seq_num << endl;

  // ── 1MB staging buffer ────────────────────────────────────────────────────
  static const size_t BUNCH_CAPACITY = 1u * 1024u * 1024u;
  char *bunch_buffer = new char[BUNCH_CAPACITY];
  size_t bunch_size = 0;
  uint64_t bunch_start_offset = 0;
  bool transfer_success = false;

  auto flush_bunch = [&]() -> bool {
    if (bunch_size == 0)
      return true;
    long long disk_start = PerfStats::now_us();
    outfile.seekp((streamoff)bunch_start_offset, ios::beg);
    outfile.write(bunch_buffer, (streamsize)bunch_size);
    g_perf.total_disk_write_us.fetch_add(PerfStats::now_us() - disk_start,
                                         std::memory_order_relaxed);
    if (outfile.fail()) {
      cerr << "[WRITER] Bunch write failed at offset=" << bunch_start_offset
           << endl;
      outfile.clear();
      return false;
    }
    bunch_size = 0;
    return true;
  };

  // ── Main writer loop ─────────────────────────────────────────────────────
  while (!server_done.load(std::memory_order_relaxed)) {
    int idx = expected_seq_num % BUFFER_SIZE;
    PoolSlot &slot = g_pool[idx];

    // Check if the next expected slot is ready
    if (!slot.ready.load(std::memory_order_acquire)) {
      // Not ready — check if all decompressors finished (nothing more coming)
      if (decompressors_done.load(std::memory_order_acquire) ==
              DECOMPRESSOR_THREADS &&
          work_queue.size_approx() == 0) {
        // No more data will ever arrive for this slot
        break;
      }
      SwitchToThread();
      continue;
    }

    // Verify correct sequence (not stale data from a previous window cycle)
    if (slot.seq_num != expected_seq_num) {
      slot.ready.store(false, std::memory_order_release);
      SwitchToThread();
      continue;
    }

    // Start new bunch if needed
    if (bunch_size == 0)
      bunch_start_offset = slot.chunk_offset;

    // Flush if this slot would overflow the staging buffer
    if (bunch_size + slot.data_len > BUNCH_CAPACITY) {
      flush_bunch();
      bunch_start_offset = slot.chunk_offset;
    }

    memcpy(bunch_buffer + bunch_size, slot.data, slot.data_len);
    bunch_size += slot.data_len;

    bool hit_eof = (slot.type == 3);

    // Release slot for reuse by decompressors
    slot.ready.store(false, std::memory_order_release);
    expected_seq_num++;

    if (expected_seq_num % 500 == 0)
      save_checkpoint(current_filename, expected_seq_num);

    if (hit_eof) {
      flush_bunch();
      transfer_success = true;
      outfile.flush();
      outfile.close();
      remove("resume.json");
      cout << "[WRITER] Transfer complete: " << out_filepath << endl;
      server_done.store(true, std::memory_order_relaxed);
      break;
    }
  }

  // ── Cleanup on abort ──────────────────────────────────────────────────────
  if (!transfer_success && expected_seq_num > 1) {
    flush_bunch();
    if (outfile.is_open()) {
      outfile.flush();
      outfile.close();
    }
    save_checkpoint(current_filename, expected_seq_num);
    cout << "[WRITER] Saved checkpoint at seq=" << expected_seq_num << endl;
  }

  delete[] bunch_buffer;
  cout << "[WRITER] Writer thread exiting." << endl;
  return nullptr;
}

// =============================================================================
// MAIN — Network Thread
//
// Receives packets via WSARecvFrom, verifies HMAC+CRC, builds SACK,
// enqueues verified packets into the lock-free ConcurrentQueue.
// =============================================================================
int main() {
  signal(SIGINT, handle_sigint);
  cout << " DataBeam Phase 5 Server Starting (Multi-Threaded Pipeline)..."
       << endl;
  SetConsoleOutputCP(CP_UTF8);

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    cerr << " WSAStartup failed." << endl;
    return 1;
  }

  create_received_dir();

  // Allocate pool on heap (~6MB: 4096 slots × ~1.5KB each)
  g_pool = new PoolSlot[BUFFER_SIZE]();

  SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == INVALID_SOCKET) {
    cerr << " Socket failed." << endl;
    return 1;
  }

  // 64MB socket buffers — absorb bursts without dropping
  int buf_size = SOC_BUFFER * 1024 * 1024;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&buf_size,
             sizeof(buf_size));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&buf_size,
             sizeof(buf_size));

  // 100ms recv timeout — 10× more responsive than before
  DWORD recv_timeout_ms = RECV_TIMEOUT;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_timeout_ms,
             sizeof(recv_timeout_ms));

  struct sockaddr_in server_addr = {};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);

  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    cerr << " Bind failed." << endl;
    return 1;
  }
  cout << " Listening on port " << PORT << "..." << endl;
  cout << " Pipeline: " << DECOMPRESSOR_THREADS << " decompressors, 1 writer"
       << endl;
  cout << " Socket buffers: " << SOC_BUFFER
       << "MB, Recv timeout: " << RECV_TIMEOUT << "ms" << endl;

  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);

  // ── Launch pipeline threads ───────────────────────────────────────────────
  pthread_t t_decompressors[DECOMPRESSOR_THREADS];
  pthread_t t_writer;

  for (int i = 0; i < DECOMPRESSOR_THREADS; i++)
    pthread_create(&t_decompressors[i], nullptr, decompressor_thread, nullptr);
  pthread_create(&t_writer, nullptr, writer_thread, nullptr);

  // ── Hybrid SACK state ────────────────────────────────────────────────────
  uint32_t ack_seq = 1;
  int ack_counter = 0;
  int hole_sack_counter = 0;
  uint32_t recv_mark[BUFFER_SIZE];
  memset(recv_mark, 0, sizeof(recv_mark));

  int idle_timeouts = 0;
  bool is_receiving = true;

  // WSARecvFrom setup
  WSABUF wsabuf_recv;
  char raw_buffer[sizeof(SlimDataPacket) + 64];
  wsabuf_recv.buf = raw_buffer;
  wsabuf_recv.len = sizeof(raw_buffer);

  while (is_receiving) {
    long long start_recv = PerfStats::now_us();

    DWORD bytes_recv_dword = 0;
    DWORD flags = 0;
    int from_len = (int)addr_len;

    int result =
        WSARecvFrom(sockfd, &wsabuf_recv, 1, &bytes_recv_dword, &flags,
                    (struct sockaddr *)&client_addr, &from_len, NULL, NULL);

    int bytes_recv = (result == 0) ? (int)bytes_recv_dword : result;

    if (bytes_recv <= 0) {
      if (start_received.load(std::memory_order_relaxed)) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
          idle_timeouts++;
          if (idle_timeouts > IDLE_TIMEOUT_COUNT) {
            cerr << "\n[SERVER] Client inactivity timeout ("
                 << (IDLE_TIMEOUT_COUNT * RECV_TIMEOUT / 1000)
                 << "s). Aborting transfer..." << endl;
            server_done.store(true, std::memory_order_relaxed);
            break;
          }
        } else if (err != WSAECONNRESET) {
          cerr << "[SERVER] WSARecvFrom error: " << err << endl;
        }
      }
      continue;
    }
    idle_timeouts = 0; // reset on successful packet

    g_perf.total_net_recv_time_us.fetch_add(PerfStats::now_us() - start_recv,
                                            std::memory_order_relaxed);

    uint8_t p_type = (uint8_t)raw_buffer[0];

    // ═══════════════════════════════════════════════════════════════════════
    // START PACKET (type == 2)
    // ═══════════════════════════════════════════════════════════════════════
    if (p_type == 2 && !start_received.load(std::memory_order_relaxed)) {
      if (bytes_recv < (int)sizeof(StartPacket)) {
        cerr << "[SERVER] Short StartPacket — ignoring" << endl;
        continue;
      }
      StartPacket sp;
      memcpy(&sp, raw_buffer, sizeof(StartPacket));
      deserialize_start_packet(&sp);

      pthread_mutex_lock(&init_mutex);
      shared_filename = string(sp.filename);
      shared_file_size = sp.file_size;

      uint32_t saved_seq = load_checkpoint(shared_filename);
      if (saved_seq > 1)
        ack_seq = saved_seq;
      pthread_mutex_unlock(&init_mutex);

      // Set start_received AFTER init data is written (release semantics)
      start_received.store(true, std::memory_order_release);

      cout << "[SERVER] Connection established! Resume seq=" << ack_seq << endl;
      cout << "[SERVER] File: " << sp.filename << " (" << sp.file_size
           << " bytes, " << sp.total_chunks << " chunks)" << endl;

      ACKPacket start_ack;
      memset(&start_ack, 0, sizeof(start_ack));
      start_ack.type = 1;
      start_ack.ack_num = 0;
      memset(start_ack.bitmap, 0, sizeof(start_ack.bitmap));
      start_ack.crc32 =
          calculate_crc32(reinterpret_cast<const unsigned char *>(&start_ack),
                          sizeof(ACKPacket) - sizeof(uint32_t));
      serialize_ack_packet(&start_ack);
      sendto(sockfd, (const char *)&start_ack, sizeof(start_ack), 0,
             (struct sockaddr *)&client_addr, addr_len);

      cout << "[SERVER] Handshake ACK sent. Waiting for data..." << endl;
      Sleep(200);
    }
    // ═══════════════════════════════════════════════════════════════════════
    // DATA PACKET (type == 0) or EOF PACKET (type == 3)
    // ═══════════════════════════════════════════════════════════════════════
    else if (p_type == 0 || p_type == 3) {
      if (!start_received.load(std::memory_order_relaxed))
        continue;

      if (bytes_recv < (int)(sizeof(SlimDataPacket) - DATA_SIZE)) {
        cerr << "[SERVER] Short data packet — dropping" << endl;
        continue;
      }

      SlimDataPacket pkt;
      memset(&pkt, 0, sizeof(pkt));
      memcpy(&pkt, raw_buffer, min((size_t)bytes_recv, sizeof(pkt)));

      // ── HMAC Verification ──────────────────────────────────────────────
      uint8_t received_hmac[16];
      memcpy(received_hmac, pkt.hmac, 16);
      memset(pkt.hmac, 0, 16);

      if (!verify_hmac((const uint8_t *)&pkt, sizeof(pkt), SHARED_SECRET_KEY,
                       received_hmac)) {
        cerr << "[SERVER] HMAC FAIL seq=" << ntohl(pkt.seq_num) << endl;
        continue;
      }

      deserialize_slim_packet(&pkt);
      size_t compressed_len = pkt.data_len;

      if (compressed_len == 0 || compressed_len > (size_t)(DATA_SIZE + 1)) {
        cerr << "[SERVER] Bad data_len=" << compressed_len
             << " seq=" << pkt.seq_num << endl;
        continue;
      }

      // ── CRC Check ─────────────────────────────────────────────────────
      uint32_t received_crc = pkt.crc32;
      pkt.crc32 = 0;
      uint32_t computed =
          calculate_crc32(reinterpret_cast<const unsigned char *>(&pkt),
                          sizeof(SlimDataPacket));
      pkt.crc32 = received_crc;
      memcpy(pkt.hmac, received_hmac, 16);

      if (computed != received_crc) {
        cerr << "[SERVER] CRC FAIL seq=" << pkt.seq_num << " expected=0x" << hex
             << received_crc << " got=0x" << computed << dec << endl;
        g_perf.crc_fails.fetch_add(1, std::memory_order_relaxed);
        continue;
      }

      // ── Hybrid SACK: track, decide, and send ──────────────────────────
      bool duplicate = false;
      if (pkt.seq_num < ack_seq) {
        duplicate = true;
      } else if (pkt.seq_num >= ack_seq &&
                 pkt.seq_num < ack_seq + BUFFER_SIZE) {
        if (recv_mark[pkt.seq_num % BUFFER_SIZE] == pkt.seq_num) {
          duplicate = true;
        }
        recv_mark[pkt.seq_num % BUFFER_SIZE] = pkt.seq_num;
      }

      if (duplicate) {
        // Silently ignore strictly-in-window true duplicates as network echoes
        // are common, but if it's wildly out of order this helps debug:
        if (pkt.seq_num < ack_seq && (ack_seq - pkt.seq_num) > 1000) {
          cerr << " [DEBUG] Wildly late duplicate received: seq=" << pkt.seq_num
               << " (ack_seq=" << ack_seq << ")" << endl;
        }
      }

      bool hole_detected = (pkt.seq_num > ack_seq);
      bool is_eof = (pkt.type == 3);
      bool gap_filled = false;

      // Advance cumulative watermark
      if (pkt.seq_num == ack_seq) {
        uint32_t before = ack_seq;
        while (recv_mark[ack_seq % BUFFER_SIZE] == ack_seq) {
          recv_mark[ack_seq % BUFFER_SIZE] = 0;
          ack_seq++;
        }
        gap_filled = (ack_seq > before + 1);
        ack_counter++;
      }

      // Rate-limit hole SACKs (1 per 8 OOO events)
      bool send_sack = (hole_detected && (++hole_sack_counter % 8 == 0)) ||
                       is_eof || gap_filled || duplicate;

      if (send_sack) {
        ACKPacket sack;
        memset(&sack, 0, sizeof(sack));
        sack.type = 1;
        sack.ack_num = ack_seq;

        // Build SACK bitmap: bit i = 1 if (ack_seq + i) already buffered
        for (int i = 0; i < 4096; i++) {
          uint32_t c = ack_seq + (uint32_t)i;
          if (recv_mark[c % BUFFER_SIZE] == c) {
            sack.bitmap[i >> 6] |= (1ULL << (i & 63));
          }
        }

        sack.crc32 =
            calculate_crc32(reinterpret_cast<const unsigned char *>(&sack),
                            sizeof(ACKPacket) - sizeof(uint32_t));
        serialize_ack_packet(&sack);
        sendto(sockfd, (const char *)&sack, sizeof(sack), 0,
               (struct sockaddr *)&client_addr, addr_len);

        if (!hole_detected && !gap_filled)
          ack_counter = 0;
      }

      // ── Enqueue for decompression (lock-free) ─────────────────────────
      if (!duplicate) {
        WorkItem item;
        item.pkt = pkt;
        item.compressed_len = compressed_len;
        work_queue.enqueue(item);
      }

      if (pkt.type == 3) {
        // EOF received — stop receiving, let pipeline drain
        break;
      }
    }

    if (server_done.load(std::memory_order_relaxed)) {
      is_receiving = false;
      break;
    }
  }

  // If server ended prematurely (timeout, SIGINT, etc.) and handshake was done,
  // send ABORT ACK
  if (server_done.load(std::memory_order_relaxed) &&
      start_received.load(std::memory_order_relaxed)) {
    ACKPacket abort_ack;
    memset(&abort_ack, 0, sizeof(abort_ack));
    abort_ack.type = 4; // ABORT signal
    abort_ack.ack_num = 0;
    // We can use calculate_crc32 directly exactly as done earlier
    abort_ack.crc32 =
        calculate_crc32(reinterpret_cast<const unsigned char *>(&abort_ack),
                        sizeof(ACKPacket) - sizeof(uint32_t));
    serialize_ack_packet(&abort_ack);
    sendto(sockfd, (const char *)&abort_ack, sizeof(abort_ack), 0,
           (struct sockaddr *)&client_addr, addr_len);
    cout << "\n[SERVER] Sent ABORT signal to client." << endl;
  }

  // ── Signal decompressors that no more packets are coming ────────────────
  net_recv_done.store(true, std::memory_order_release);

  // Wait for decompressors to drain the queue
  for (int i = 0; i < DECOMPRESSOR_THREADS; i++)
    pthread_join(t_decompressors[i], nullptr);

  // Wait for writer to finish (it exits on EOF or termination check)
  // DO NOT set server_done before this — writer needs to finish processing
  pthread_join(t_writer, nullptr);

  server_done.store(true, std::memory_order_relaxed); // safety net for cleanup

  cout << "[SERVER] Transfer finished. Shutting down server..." << endl;

  // NOTE: resume.json is only removed by writer on successful transfer.
  // On abort, the checkpoint persists for the next run (fixing original bug).

  closesocket(sockfd);
  WSACleanup();

  // ── Performance Report ─────────────────────────────────────────────────
  uint32_t count = g_perf.packets_processed.load();
  if (count > 0) {
    double avg_net = (double)g_perf.total_net_recv_time_us / count;
    double avg_decrypt = (double)g_perf.total_decrypt_time_us / count;
    double avg_decomp = (double)g_perf.total_decomp_time_us / count;
    double avg_disk = (double)g_perf.total_disk_write_us / count;

    cout << "\n--- SERVER PERFORMANCE REPORT (Average per Packet) ---" << endl;
    cout << "Network Recv:    " << avg_net << " us" << endl;
    cout << "Decrypt:         " << avg_decrypt << " us" << endl;
    cout << "Decompress:      " << avg_decomp << " us (across "
         << DECOMPRESSOR_THREADS << " threads)" << endl;
    cout << "Disk Write:      " << avg_disk
         << " us (If high, check SSD/HDD speed)" << endl;
    cout << "CRC Failures:    " << g_perf.crc_fails << endl;
    cout << "Pool Spin Waits: " << g_perf.pool_spin_events
         << " (If >0, writer is bottleneck)" << endl;
    cout << "-----------------------------------------------" << endl;
  }

  delete[] g_pool;
  return 0;
}
