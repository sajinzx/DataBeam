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
#include <mswsock.h>

#include "./headers/compress.h"
#include "./headers/concurrentqueue.h"
#include "./headers/constants.h"
#include "./headers/crchw.h"
#include "./headers/crypto.h"
#include "./headers/livestate.h"
#include "./headers/probe.h"
#include "./headers/sysprofile.h"
#include <atomic>
#include <chrono>
#include <csignal>

using namespace std;

// =============================================================================
// Tuning Constants (Now moved to constants.h)
// =============================================================================
// Tuning Constants are now in constants.h

// =============================================================================
// Work Queue Item — CRC/HMAC-verified raw packet waiting for decompression
// =============================================================================
struct WorkItem {
  SlimDataPacket pkt;
};

// =============================================================================
// Pool Slot — decompressed data with atomic ready flag
//
// Decompressor threads write data and set ready=true (release).
// Writer thread reads data when ready=true (acquire) and clears ready=false.
// Indexed by seq_num % BUFFER_SIZE — no collision because window == buffer.
// =============================================================================
struct PoolSlot {
  char data[DataBeam::PACKET_DATA_SIZE + 1];
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

// Phase 6: System profile and dynamic runtime state
DataBeam::SystemProfile g_profile;
DataBeam::LiveState g_live;
uint64_t g_connection_id = 0; // Set during handshake from client's StartPacket
uint32_t g_pool_size = DataBeam::SERVER_RECV_BUFFER_SIZE; // dynamic, power-of-2
uint32_t g_pool_mask = DataBeam::SERVER_RECV_BUFFER_SIZE - 1;
uint32_t g_num_decompressors = DataBeam::SERVER_DECOMPRESSOR_THREADS;

// Lock-free concurrent queue (same moodycamel library as client)
moodycamel::ConcurrentQueue<WorkItem> work_queue;

// Pool — shared between decompressors (write) and writer (read)
PoolSlot *g_pool = nullptr;

// Synchronization flags
std::atomic<bool> server_done{false};
std::atomic<uint32_t> g_ack_seq{1};
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

void *logger_thread(void *arg) {
  while (!server_done.load(std::memory_order_relaxed)) {
    Sleep(DataBeam::MS_PER_SEC);
    if (server_done.load(std::memory_order_relaxed))
      break;
    cout << "[LOGGER] ack_seq=" << g_ack_seq.load() << endl;
  }
  return nullptr;
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
        got = work_queue.try_dequeue(ctok, item);
        if (!got)
          break;
      }
      SwitchToThread();
      continue;
    }

    SlimDataPacket &pkt = item.pkt;

    // ---- 1. DEFERRED VERIFICATION (Parallelized in worker pool) -----------
    // pkt is still in wire-format (big-endian)
    uint8_t received_hmac[16];
    memcpy(received_hmac, pkt.hmac, 16);
    memset(pkt.hmac, 0, 16);

    // Security keys are now in constants.h
    const uint8_t *SHARED_SECRET_KEY = DataBeam::SHARED_SECRET_KEY;
    if (!verify_hmac((const uint8_t *)&pkt, sizeof(pkt), SHARED_SECRET_KEY,
                     received_hmac)) {
      cerr << "[DECOMP] HMAC FAIL seq=" << ntohl(pkt.seq_num) << endl;
      continue;
    }

    // Now convert to host-order for CRC and processing
    deserialize_slim_packet(&pkt);

    uint32_t received_crc = pkt.crc32;
    pkt.crc32 = 0;
    uint32_t computed = calculate_crc32(
        reinterpret_cast<const unsigned char *>(&pkt), sizeof(SlimDataPacket));
    pkt.crc32 = received_crc;
    memcpy(pkt.hmac, received_hmac, 16);

    if (computed != received_crc) {
      cerr << "[DECOMP] CRC FAIL seq=" << pkt.seq_num << endl;
      g_perf.crc_fails.fetch_add(1, std::memory_order_relaxed);
      continue;
    }

    // ---- 2. DECRYPT & DECOMPRESS -------------------------------------------
    uint8_t decrypted_data[DataBeam::PACKET_DATA_SIZE + 1];
    long long t_decrypt = PerfStats::now_us();
    if (!aes_decrypt((const uint8_t *)pkt.data, (size_t)pkt.data_len,
                     SHARED_SECRET_KEY, &pkt.packet_iv, decrypted_data)) {
      continue;
    }
    g_perf.total_decrypt_time_us.fetch_add(PerfStats::now_us() - t_decrypt,
                                           std::memory_order_relaxed);

    char decompressed_buffer[DataBeam::PACKET_DATA_SIZE + 1];
    size_t decomp_len = sizeof(decompressed_buffer);
    long long decomp_start = PerfStats::now_us();
    if (pkt.flags & 0x01) {
      int ret = decompress_data((char *)decrypted_data, (size_t)pkt.data_len,
                                decompressed_buffer, decomp_len);
      g_perf.total_decomp_time_us.fetch_add(PerfStats::now_us() - decomp_start,
                                            std::memory_order_relaxed);
      if (ret != 0) {
        continue;
      }
    } else {
      memcpy(decompressed_buffer, decrypted_data, pkt.data_len);
      decomp_len = pkt.data_len;
    }

    pkt.flags &= ~0x01;

    // ---- 3. STORE IN POOL (atomic handoff to writer) -----------------------
    uint32_t pool_idx = pkt.seq_num & g_pool_mask;
    PoolSlot &slot = g_pool[pool_idx];

    while (slot.ready.load(std::memory_order_acquire) &&
           !server_done.load(std::memory_order_relaxed)) {
      g_perf.pool_spin_events.fetch_add(1, std::memory_order_relaxed);
      SwitchToThread();
    }
    if (server_done.load(std::memory_order_relaxed))
      break;

    memcpy(slot.data, decompressed_buffer, decomp_len);
    slot.data_len = decomp_len;
    slot.type = pkt.type;
    slot.chunk_offset = pkt.chunk_offset;
    slot.seq_num = pkt.seq_num;
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
  char *bunch_buffer = new char[DataBeam::SERVER_BUNCH_CAPACITY];
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
    int idx = expected_seq_num & g_pool_mask;
    PoolSlot &slot = g_pool[idx];

    // Check if the next expected slot is ready
    if (!slot.ready.load(std::memory_order_acquire)) {
      // Not ready — check if all decompressors finished (nothing more coming)
      if (decompressors_done.load(std::memory_order_acquire) ==
              (int)g_num_decompressors &&
          work_queue.size_approx() == 0) {
        // No more data will ever arrive for this slot
        break;
      }
      SwitchToThread();
      continue;
    }

    // Verify correct sequence (not stale data from a previous window cycle)
    if (slot.seq_num != expected_seq_num) {
      // This slot contains data from a FUTURE window cycle or is stale.
      // With BUFFER_SIZE >> WINDOW_SIZE, this is rare.
      // We must NOT clear ready here if it's from the future.
      if (slot.seq_num < expected_seq_num) {
        slot.ready.store(false, std::memory_order_release);
      }
      SwitchToThread();
      continue;
    }

    // Start new bunch if needed
    if (bunch_size == 0)
      bunch_start_offset = slot.chunk_offset;

    // Flush if this slot would overflow the staging buffer
    if (bunch_size + slot.data_len > DataBeam::SERVER_BUNCH_CAPACITY) {
      flush_bunch();
      bunch_start_offset = slot.chunk_offset;
    }

    memcpy(bunch_buffer + bunch_size, slot.data, slot.data_len);
    bunch_size += slot.data_len;

    bool hit_eof = (slot.type == 3);

    // Release slot for reuse by decompressors
    slot.ready.store(false, std::memory_order_release);
    expected_seq_num++;

    if (expected_seq_num % DataBeam::CHECKPOINT_INTERVAL_PACKETS == 0)
      save_checkpoint(current_filename, expected_seq_num);

    if (hit_eof) {
      flush_bunch();
      transfer_success = true;
      // Robust checkpoint cleanup — retry with delays for Windows file locking
      bool deleted = false;
      for (int attempt = 0; attempt < 5 && !deleted; attempt++) {
        if (remove("resume.json") == 0) {
          deleted = true;
          cout << "[WRITER] Checkpoint deleted successfully." << endl;
        } else {
          Sleep(100); // Wait for file lock release (e.g., VS Code)
        }
      }
      if (!deleted) {
        // Fallback: truncate the file so stale data doesn't cause wrong resume
        ofstream trunc("resume.json", ios::trunc);
        if (trunc.is_open()) {
          trunc << "{}\n";
          trunc.close();
          cout << "[WRITER] Checkpoint truncated (could not delete — file may "
                  "be open in editor)."
               << endl;
        } else {
          cerr << "[WRITER] WARNING: Could not delete or truncate resume.json! "
                  "Close it in your editor."
               << endl;
        }
      }
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
  cout << " DataBeam Phase 6 Server Starting (Autonomous Transport)..."
       << endl;
  SetConsoleOutputCP(CP_UTF8);

  // Phase 6: System Profiling
  g_profile = DataBeam::SystemProfile::probe();
  g_profile.print();
  g_live.init_from_profile(g_profile);
  g_num_decompressors = g_live.decompressor_threads;
  g_pool_size = g_live.pool_slot_count;
  g_pool_mask = g_pool_size - 1;

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    cerr << " WSAStartup failed." << endl;
    return 1;
  }

  create_received_dir();

  // Phase 6: Dynamic pool allocation based on system profile
  cout << " Allocating " << g_pool_size << " pool slots (" 
       << (g_pool_size * sizeof(PoolSlot)) / (1024*1024) << " MB)" << endl;
  g_pool = new PoolSlot[g_pool_size]();

  SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == INVALID_SOCKET) {
    cerr << " Socket failed." << endl;
    return 1;
  }

  // Socket buffers — absorb bursts without dropping
  int buf_size = DataBeam::SERVER_SOCKET_BUFFER_MB * 1024 * 1024;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&buf_size,
             sizeof(buf_size));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&buf_size,
             sizeof(buf_size));

  DWORD recv_timeout_ms = DataBeam::RECV_TIMEOUT_MS;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_timeout_ms,
             sizeof(recv_timeout_ms));

  struct sockaddr_in server_addr = {};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(DataBeam::DEFAULT_PORT);
  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    cerr << " Bind failed." << endl;
    return 1;
  }
  cout << " Listening on port " << DataBeam::DEFAULT_PORT << "..." << endl;
  cout << " Pipeline: " << g_num_decompressors
       << " decompressors, 1 writer" << endl;
  cout << " Pool: " << g_pool_size << " slots, Socket buffers: "
       << DataBeam::SERVER_SOCKET_BUFFER_MB
       << "MB, Recv timeout: " << DataBeam::RECV_TIMEOUT_MS << "ms" << endl;

  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);

  // ── Launch pipeline threads (dynamic count from system profile) ──────────
  pthread_t *t_decompressors = new pthread_t[g_num_decompressors];
  pthread_t t_writer, t_logger;

  for (uint32_t i = 0; i < g_num_decompressors; i++)
    pthread_create(&t_decompressors[i], nullptr, decompressor_thread, nullptr);
  pthread_create(&t_writer, nullptr, writer_thread, nullptr);
  // pthread_create(&t_logger, nullptr, logger_thread, nullptr);

  // ── Hybrid SACK state (dynamic pool size) ─────────────────────────────
  int ack_counter = 0;
  int hole_sack_counter = 0;
  uint32_t *recv_mark = new uint32_t[g_pool_size]();

  // Phase 6: Probe state
  int probe_count = 0;
  int64_t probe_arrival_ns[DataBeam::PROBE_PACKET_COUNT] = {0};
  int64_t probe_total_bytes = 0;
  uint64_t probe_first_timestamp_ns = 0;

  int idle_timeouts = 0;
  bool is_receiving = true;

  // Enable UDP Receive Offload (URO)
  DWORD uro_max = 65536; // Maximum coalesced size
  DWORD bytes_ret = 0;
  if (WSAIoctl(sockfd, SIO_UDP_RECV_MAX_COALESCED_SIZE, &uro_max, sizeof(uro_max), NULL, 0, &bytes_ret, NULL, NULL) == SOCKET_ERROR) {
    // cerr << " [SERVER] URO not natively supported" << endl;
  } else {
    cout << " [SERVER] URO (UDP Receive Coalescing) ENABLED!" << endl;
  }

  // WSARecvFrom setup
  WSABUF wsabuf_recv;
  char raw_buffer[65536]; // 64KB for URO capacity
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

    int bytes_recv = (result == 0) ? (int)bytes_recv_dword : -1;

    if (bytes_recv <= 0) {
      if (start_received.load(std::memory_order_relaxed)) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
          idle_timeouts++;
          if (idle_timeouts > DataBeam::IDLE_TIMEOUT_COUNT) {
            cerr << "\n[SERVER] Client inactivity timeout ("
                 << (DataBeam::IDLE_TIMEOUT_COUNT * DataBeam::RECV_TIMEOUT_MS /
                     DataBeam::MS_PER_SEC)
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

      // Phase 6: Store Connection ID from client
      g_connection_id = sp.connection_id;
      cout << "[SERVER] Connection ID: 0x" << hex << g_connection_id << dec << endl;

      pthread_mutex_lock(&init_mutex);
      shared_filename = string(sp.filename);
      shared_file_size = sp.file_size;

      uint32_t saved_seq = load_checkpoint(shared_filename);
      if (saved_seq > 1)
        g_ack_seq.store(saved_seq);
      pthread_mutex_unlock(&init_mutex);

      start_received.store(true, std::memory_order_release);

      cout << "[SERVER] Connection established! Resume seq=" << g_ack_seq.load()
           << endl;
      cout << "[SERVER] File: " << sp.filename << " (" << sp.file_size
           << " bytes, " << sp.total_chunks << " chunks)" << endl;

      ACKPacket start_ack;
      memset(&start_ack, 0, sizeof(start_ack));
      start_ack.type = 1;
      start_ack.ack_num = 0;
      start_ack.connection_id = g_connection_id; // Phase 6: CID
      memset(start_ack.bitmap, 0, sizeof(start_ack.bitmap));
      start_ack.crc32 =
          calculate_crc32(reinterpret_cast<const unsigned char *>(&start_ack),
                          sizeof(ACKPacket) - sizeof(uint32_t));
      serialize_ack_packet(&start_ack);
      sendto(sockfd, (const char *)&start_ack, sizeof(start_ack), 0,
             (struct sockaddr *)&client_addr, addr_len);

      cout << "[SERVER] Handshake ACK sent. Waiting for probe/data..." << endl;
      Sleep(200);
    }
    // ═══════════════════════════════════════════════════════════════════════
    // PROBE PACKET (type == 5) — Phase 6 Network Probing
    // ═══════════════════════════════════════════════════════════════════════
    else if (p_type == DataBeam::PROBE_PACKET_TYPE) {
      if (!start_received.load(std::memory_order_relaxed))
        continue;

      ProbePacket pp;
      memcpy(&pp, raw_buffer, sizeof(ProbePacket));
      deserialize_probe_packet(&pp);

      // Record arrival time
      auto now_tp = chrono::high_resolution_clock::now();
      int64_t arrival_ns = chrono::duration_cast<chrono::nanoseconds>(
          now_tp.time_since_epoch()).count();

      if (pp.probe_seq < DataBeam::PROBE_PACKET_COUNT) {
        probe_arrival_ns[pp.probe_seq] = arrival_ns;
        if (pp.probe_seq == 0)
          probe_first_timestamp_ns = pp.timestamp_ns;
        probe_count++;
        probe_total_bytes += bytes_recv;
      }

      if (probe_count >= (int)DataBeam::PROBE_PACKET_COUNT) {
        // Compute bandwidth via inter-packet dispersion
        int64_t total_ns = probe_arrival_ns[DataBeam::PROBE_PACKET_COUNT - 1]
                         - probe_arrival_ns[0];
        uint64_t bandwidth_bps = 0;
        if (total_ns > 0) {
          bandwidth_bps = (uint64_t)(
              (double)probe_total_bytes * 8.0 * 1e9 / (double)total_ns);
        }

        cout << "[PROBE] Measured bandwidth: " << bandwidth_bps / 1e6
             << " Mbps (" << probe_count << " packets, "
             << total_ns / 1e6 << " ms)" << endl;

        // Send ProbeResult back to client
        ProbeResultPacket result;
        memset(&result, 0, sizeof(result));
        result.type = DataBeam::PROBE_RESULT_TYPE;
        result.bandwidth_bps = bandwidth_bps;
        result.rtt_echo_ns = probe_first_timestamp_ns;
        result.recommended_cwnd = std::min(
            (uint32_t)(bandwidth_bps / 8 / DataBeam::PACKET_DATA_SIZE),
            (uint32_t)DataBeam::SR_WINDOW_SIZE);
        result.connection_id = g_connection_id;
        serialize_probe_result(&result);
        sendto(sockfd, (const char *)&result, sizeof(result), 0,
               (struct sockaddr *)&client_addr, addr_len);

        cout << "[PROBE] Sent result: cwnd=" << ntohl(result.recommended_cwnd)
             << endl;
        // Reset for potential re-probe
        probe_count = 0;
        probe_total_bytes = 0;
      }
    }
    // ═══════════════════════════════════════════════════════════════════════
    // DATA PACKET (type == 0) or EOF PACKET (type == 3)
    // ═══════════════════════════════════════════════════════════════════════
    else if (p_type == 0 || p_type == 3) {
      if (!start_received.load(std::memory_order_relaxed))
        continue;

      if (bytes_recv <
          (int)(sizeof(SlimDataPacket) - DataBeam::PACKET_DATA_SIZE)) {
        cerr << "[NET] Dropped small packet: " << bytes_recv << " bytes"
             << endl;
        continue;
      }

      // ── DATA PACKET: DEFER VERIFICATION ──────────────────────────────
      // This is the primary speed boost: purely copy and peek seq_num
      SlimDataPacket pkt;
      memcpy(&pkt, raw_buffer, sizeof(pkt));

      // Extract seq_num/type manually from big-endian wire format for SACK
      // processing. WE DO NOT modify pkt itself here because HMAC verification
      // in the decompressor thread needs the packet to be in its original wire
      // format.
      uint32_t net_seq;
      memcpy(&net_seq, raw_buffer + 1, 4);
      uint32_t peek_seq = ntohl(net_seq);
      uint8_t peek_type = raw_buffer[0];

      // ── Hybrid SACK: track, decide, and send ──────────────────────────
      bool duplicate = false;
      if (peek_seq < g_ack_seq.load()) {
        duplicate = true;
      } else if (peek_seq >= g_ack_seq.load() &&
                 peek_seq <
                     g_ack_seq.load() + g_pool_size) {
        if (recv_mark[peek_seq & g_pool_mask] ==
            peek_seq) {
          duplicate = true;
        }
        recv_mark[peek_seq & g_pool_mask] =
            peek_seq;
      }

      bool hole_detected = (peek_seq > g_ack_seq.load());
      bool is_eof = (peek_type == 3);
      bool gap_filled = false;

      // Advance cumulative watermark
      if (peek_seq == g_ack_seq.load()) {
        uint32_t before = g_ack_seq.load();
        while (recv_mark[g_ack_seq.load() & g_pool_mask] == g_ack_seq.load()) {
          recv_mark[g_ack_seq.load() & g_pool_mask] = 0;
          g_ack_seq.fetch_add(1);
        }
        gap_filled = (g_ack_seq.load() > before + 1);
        ack_counter++;
      }

      // Rate-limit hole SACKs (1 per 32 in-order or on any OOO event)
      bool send_sack = (hole_detected) || is_eof || gap_filled || duplicate ||
                       (ack_counter >= DataBeam::SERVER_ACK_BATCH_SIZE);

      if (send_sack) {
        ACKPacket sack;
        memset(&sack, 0, sizeof(sack));
        sack.type = 1;
        sack.ack_num = g_ack_seq.load();
        sack.connection_id = g_connection_id; // Phase 6: CID

        // Build SACK bitmap: bit i = 1 if (ack_seq + i) already buffered
        for (int i = 0; i < DataBeam::SR_WINDOW_SIZE; i++) {
          uint32_t c = g_ack_seq.load() + (uint32_t)i;
          if (recv_mark[c & g_pool_mask] == c) {
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
  for (uint32_t i = 0; i < g_num_decompressors; i++)
    pthread_join(t_decompressors[i], nullptr);
  delete[] t_decompressors;

  // Wait for writer to finish (it exits on EOF or termination check)
  // DO NOT set server_done before this — writer needs to finish processing
  pthread_join(t_writer, nullptr);
  // pthread_join(t_logger, nullptr);

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
         << g_num_decompressors << " threads)" << endl;
    cout << "Disk Write:      " << avg_disk
         << " us (If high, check SSD/HDD speed)" << endl;
    cout << "CRC Failures:    " << g_perf.crc_fails << endl;
    cout << "Pool Spin Waits: " << g_perf.pool_spin_events
         << " (If >0, writer is bottleneck)" << endl;
    cout << "-----------------------------------------------" << endl;
  }

  delete[] recv_mark;
  delete[] g_pool;
  return 0;
}
