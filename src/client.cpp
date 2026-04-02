// LinkFlow Phase 5: UDP Client — 3-Stage Concurrent Pipeline
// File: src/client.cpp
// Purpose: High-throughput file transfer with SR sliding window using Pthreads
//
// Pipeline Architecture:
//   Stage 1 (dispatcher) — reads file chunks, assigns seq_nums
//   Stage 2 (compressors) — N threads compress + encrypt + CRC in parallel
//   Stage 3 (sender) — reorders, serializes, HMAC, WSASendTo, ARQ record

#include <iostream>
#include <cstring>
#include <iomanip>
#include <unistd.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <fstream>
#include <chrono>
#include <zlib.h>
#include <pthread.h>
#include "./headers/packet.h"
#include "./headers/selectrepeat.h"
#include "./headers/compress.h"
#include "./headers/crchw.h"
#include "./headers/crypto.h"
#include "./headers/ringbuf.h"
#include <filesystem> // C++17

#include <atomic>
#include <vector>
#include <map>
#include <sys/stat.h>



#define BITMAP_ACK 64   // Bitmap ACKs cover 64 packets beyond the cumulative ACK
#define SOC_BUFFER 128  // Socket buffer size in MB (both send and receive)
#define RECV_TIMEOUT 30 // 30-second recv timeout for ACKs
#define BITMAP_SIZE 64  // Bitmap size ACKs cover 64 packets beyond the cumulative ACK
// Number of compressor threads -- tune to CPU core count
#define COMPRESSOR_THREADS 6 // increase to 8 on 8+ core machines
using namespace std;


struct ClientPerf {
    // Stage Latencies (Microseconds)
    std::atomic<long long> total_disk_read_us{0};
    std::atomic<long long> total_compress_us{0};
    std::atomic<long long> total_crypto_us{0};    // AES-GCM time
    std::atomic<long long> total_send_syscall_us{0}; 
    
    // Waiting/Blocking Metrics
    std::atomic<long long> total_window_wait_us{0}; // Time spent waiting for ACKs/Window Slide
    
    // Counters
    std::atomic<uint32_t> packets_sent{0};
    std::atomic<uint32_t> window_full_events{0};

    static long long now_us() {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    }

    void reset() {
        total_disk_read_us = total_compress_us = total_crypto_us = 0;
        total_send_syscall_us = total_window_wait_us = 0;
        packets_sent = window_full_events = 0;
    }
};

ClientPerf g_cperf; // Global client performance object
void print_client_report()
{
    uint32_t count = g_cperf.packets_sent.load();
    if (count == 0)
        return;

    std::cout << "\n--- CLIENT PERFORMANCE REPORT (Average per Packet) ---" << std::endl;
    std::cout << std::fixed << std::setprecision(2);

    std::cout << "1. Window Wait:   " << (double)g_cperf.total_window_wait_us / count << " us"
              << " (If high, increase Server ACK Batch size)" << std::endl;

    std::cout << "2. Disk Read:     " << (double)g_cperf.total_disk_read_us / count << " us" << std::endl;

    std::cout << "3. Compression:   " << (double)g_cperf.total_compress_us / count << " us"
              << " (If high for video, DISABLE it)" << std::endl;

    std::cout << "4. Crypto/AES:    " << (double)g_cperf.total_crypto_us / count << " us" << std::endl;

    std::cout << "5. Network Send:  " << (double)g_cperf.total_send_syscall_us / count << " us"
              << " (If high, use Batch/WSASendTo)" << std::endl;

    std::cout << "Window Full Count: " << g_cperf.window_full_events << std::endl;
    std::cout << "------------------------------------------------------" << std::endl;
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
int total_inflights = 0;
int retransmissions = 0;
volatile bool transfer_complete = false;

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// ---- Pipeline packet structs -----------------------------------------------

struct RawChunk
{
    char data[DATA_SIZE];
    size_t bytes_read;
    uint32_t offset;
    uint32_t seq_num;
    bool is_last;
};

struct ReadyPacket
{
    SlimDataPacket pkt;  // fully built, CRC set, ready to serialize+send
    size_t original_len; // uncompressed chunk size (for counter updates)
};

// ---- Pipeline queues -------------------------------------------------------
// Raw queue: dispatcher -> compressor threads (SPMC: one dispatcher, N compressors)
// Ready queue: compressor threads -> sender thread (MPSC: N compressors, one sender)

static const size_t RAW_Q_CAP = 4096;
static const size_t READY_Q_CAP = 4096;

// Raw queue uses mutex pop (multiple compressors pop, one dispatcher pushes)
RingBuf<RawChunk, RAW_Q_CAP> raw_queue;
pthread_mutex_t raw_pop_mutex = PTHREAD_MUTEX_INITIALIZER;

// Ready queue uses mutex push (multiple compressors push, one sender pops)
MPRingBuf<ReadyPacket, READY_Q_CAP> ready_queue;

// Dispatcher state
atomic<uint32_t> dispatch_offset{0};
atomic<uint32_t> dispatch_seq{1};
atomic<bool> dispatch_done{false};
atomic<int> compressors_done{0};

struct PerfStats
{
    // Latency Metrics
    atomic<long long> total_net_recv_time_us{0};
    atomic<long long> total_worker_wait_us{0};
    atomic<long long> total_decomp_time_us{0};
    atomic<long long> total_disk_write_us{0};

    // Throughput & Buffer Metrics
    atomic<uint32_t> packets_processed{0};
    atomic<uint32_t> buffer_full_events{0};
    atomic<uint32_t> crc_fails{0};

    static long long now_us()
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::high_resolution_clock::now().time_since_epoch())
            .count();
    }
};

PerfStats g_perf;
uint32_t get_file_size(const char *filename)
{
    struct _stat64 st;

    if (_stat64(filename, &st) != 0)
        return 0;

    if (st.st_size > 0xFFFFFFFF)
    {
        std::cerr << "[ERROR] File exceeds 4GB limit\n";
        return 0;
    }

    return static_cast<uint32_t>(st.st_size);
}

// ============================================================================
// STAGE 1: Dispatcher Thread (1 thread)
// Reads file chunks sequentially, assigns monotonic seq_nums, pushes into
// raw_queue. Applies back-pressure when ARQ window or raw_queue is saturated.
// ============================================================================

void *dispatcher_thread(void *arg)
{
    ifstream infile(filename_str, ios::binary);
    if (!infile.is_open())
    {
        cerr << " [DISPATCHER] Cannot open file: " << filename_str << endl;
        cerr << "Reason: " << strerror(errno) << endl;
        dispatch_done.store(true, std::memory_order_release);
        transfer_complete = true;
        return nullptr;
    }

    uint32_t local_offset = chunk_offset; // honours resume checkpoint

    while (local_offset < (uint32_t)file_size && !transfer_complete)
    {
        // Back-pressure: total pipeline + in-flight must stay under window
        while (!transfer_complete)
        {
            pthread_mutex_lock(&arq_mutex);
            int in_flight = arq.get_in_flight_count();
            pthread_mutex_unlock(&arq_mutex);
            if (in_flight + (int)raw_queue.size() + (int)ready_queue.size() < SR_WINDOW_SIZE)
                break;
            SwitchToThread();
        }
        if (transfer_complete)
            break;

        // Back-pressure: raw_queue 75% full
        while (raw_queue.size() > (RAW_Q_CAP * 3) / 4 && !transfer_complete)
            SwitchToThread();
        if (transfer_complete)
            break;

        // Read one chunk
        RawChunk rc;
        infile.seekg(local_offset);
        infile.read(rc.data, DATA_SIZE);
        rc.bytes_read = (size_t)infile.gcount();
        if (rc.bytes_read == 0)
            break;

        rc.offset = local_offset;
        rc.seq_num = dispatch_seq.fetch_add(1, std::memory_order_relaxed);
        rc.is_last = (local_offset + rc.bytes_read >= (uint32_t)file_size);

        while (!raw_queue.push(rc))
        {
            if (transfer_complete)
                break;
            SwitchToThread();
        }

        local_offset += (uint32_t)rc.bytes_read;
        if (rc.is_last)
            break;
    }

    dispatch_done.store(true, std::memory_order_release);
    infile.close();
    return nullptr;
}

// ============================================================================
// STAGE 2: Compressor Thread (N threads, default COMPRESSOR_THREADS = 4)
// Pops raw chunks, compresses, encrypts, builds SlimDataPacket with CRC,
// then pushes ReadyPacket into ready_queue for the sender.
// ============================================================================

void *compressor_thread(void *arg)
{
    while (!transfer_complete)
    {
        RawChunk rc;
        bool got = false;

        // Pop from raw_queue (mutex for SPMC safety)
        pthread_mutex_lock(&raw_pop_mutex);
        got = raw_queue.pop(rc);
        pthread_mutex_unlock(&raw_pop_mutex);

        if (!got)
        {
            if (dispatch_done.load(std::memory_order_acquire))
            {
                // Double-check: acquire fence guarantees visibility of all
                // dispatcher pushes that happened before dispatch_done was set
                pthread_mutex_lock(&raw_pop_mutex);
                got = raw_queue.pop(rc);
                pthread_mutex_unlock(&raw_pop_mutex);
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

        if (compress_data(rc.data, rc.bytes_read,
                          compressed_data, compressed_len) == 0)
        {
            is_compressed = ((uint8_t)compressed_data[0] == 0x01);
        }
        else
        {
            memcpy(compressed_data + 1, rc.data, rc.bytes_read);
            compressed_data[0] = 0x00;
            compressed_len = rc.bytes_read + 1;
        }

        // 2. Build packet
        ReadyPacket rp;
        memset(&rp.pkt, 0, sizeof(rp.pkt));
        generate_iv(&rp.pkt.packet_iv);

        // 3. Encrypt
        char encrypted_data[DATA_SIZE + 1];
        if (!aes_encrypt((const uint8_t *)compressed_data, compressed_len,
                         SHARED_SECRET_KEY, &rp.pkt.packet_iv,
                         (uint8_t *)encrypted_data))
        {
            cerr << " [COMPRESSOR] Encryption failed at seq="
                 << rc.seq_num << endl;
            transfer_complete = true;
            compressors_done.fetch_add(1, std::memory_order_release);
            return nullptr;
        }

        rp.pkt.type = rc.is_last ? 3 : 0;
        rp.pkt.seq_num = rc.seq_num;
        rp.pkt.chunk_offset = rc.offset;
        rp.pkt.data_len = (uint16_t)compressed_len;
        rp.pkt.flags = is_compressed ? 0x01 : 0x00;
        memset(rp.pkt.hmac, 0, 16);
        memcpy(rp.pkt.data, encrypted_data, compressed_len);

        // 4. CRC on whole struct (crc32=0, hmac=0) -- server-compatible
        rp.pkt.crc32 = 0;
        rp.pkt.crc32 = calculate_crc32(
            reinterpret_cast<const unsigned char *>(&rp.pkt),
            sizeof(SlimDataPacket));

        rp.original_len = rc.bytes_read;

        // 5. Push to ready_queue
        while (!ready_queue.push(rp))
        {
            if (transfer_complete)
            {
                compressors_done.fetch_add(1, std::memory_order_release);
                return nullptr;
            }
            SwitchToThread();
        }
    }

    compressors_done.fetch_add(1, std::memory_order_release);
    return nullptr;
}

// ============================================================================
// STAGE 3: Sender Thread (1 thread)
// Pops ReadyPackets, reorders by seq_num, serializes, computes HMAC,
// sends via WSASendTo, records in ARQ.  Reorder buffer ensures packets
// are sent in strict seq_num order even if compressors finish out of order.
// ============================================================================

void *sender_thread(void *arg)
{
    std::map<uint32_t, ReadyPacket> pending;
    // Recover starting seq from ARQ send_base (set in main before threads)
    uint32_t next_send_seq = arq.get_send_base();

    while (!transfer_complete)
    {
        // 1. Drain ready_queue into reorder buffer
        ReadyPacket rp;
        while (ready_queue.pop(rp))
            pending[rp.pkt.seq_num] = rp;

        // 2. Send packets in strict seq_num order
        while (pending.count(next_send_seq))
        {
            // Wait for ARQ window space
            while (!transfer_complete)
            {
                pthread_mutex_lock(&arq_mutex);
                int in_flight = arq.get_in_flight_count();
                pthread_mutex_unlock(&arq_mutex);
                if (in_flight < SR_WINDOW_SIZE)
                    break;
                SwitchToThread();
            }
            if (transfer_complete)
                return nullptr;

            ReadyPacket &cur = pending[next_send_seq];

            // Wire copy: serialize then HMAC
            SlimDataPacket wire = cur.pkt;
            serialize_slim_packet(&wire);
            memset(wire.hmac, 0, 16);
            generate_hmac((const uint8_t *)&wire, sizeof(wire),
                          SHARED_SECRET_KEY, wire.hmac);
            memcpy(cur.pkt.hmac, wire.hmac, 16);

            // WSASendTo
            WSABUF wsabuf;
            wsabuf.buf = reinterpret_cast<CHAR *>(&wire);
            wsabuf.len = sizeof(wire);
            DWORD bytes_sent_dword = 0;

            int result = WSASendTo(
                (SOCKET)sockfd, &wsabuf, 1, &bytes_sent_dword, 0,
                reinterpret_cast<SOCKADDR *>(&server_addr), (int)addr_len,
                NULL, NULL);

            if (result == SOCKET_ERROR)
            {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK)
                {
                    SwitchToThread();
                    continue; // retry same packet
                }
                cerr << " [SENDER] WSASendTo failed: " << err << endl;
                transfer_complete = true;
                return nullptr;
            }

            // Record in ARQ + update counters
            pthread_mutex_lock(&arq_mutex);
            arq.record_sent_packet(cur.pkt);
            arq.increment_seq_num();
            chunks_sent++;
            total_bytes_sent += cur.original_len;
            chunk_offset += (uint32_t)cur.original_len;
            pthread_mutex_unlock(&arq_mutex);

            pending.erase(next_send_seq);
            next_send_seq++;
        }

        // 3. Check termination
        if (compressors_done.load(std::memory_order_acquire) == COMPRESSOR_THREADS && ready_queue.empty() && pending.empty())
        {
            pthread_mutex_lock(&arq_mutex);
            int in_flight = arq.get_in_flight_count();
            pthread_mutex_unlock(&arq_mutex);

            if (in_flight == 0)
            {
                transfer_complete = true;
                return nullptr;
            }
        }

        SwitchToThread();
    }

    return nullptr;
}

// ----------------------------------------------------------------------------
// Receiver Thread (UNCHANGED)
// ----------------------------------------------------------------------------
void *receiver_thread(void *arg)
{
    while (!transfer_complete)
    {
        struct ACKPacket ack_pkt;

        int bytes_recv = recvfrom(sockfd, (char *)&ack_pkt, sizeof(ack_pkt), 0,
                                  (struct sockaddr *)&server_addr, &addr_len);

        if (bytes_recv > 0)
        {
            deserialize_ack_packet(&ack_pkt);
            uint32_t received_crc = ack_pkt.crc32;
            uint32_t computed = compute_ack_crc(&ack_pkt);
            if (computed == received_crc)
            {
                if (ack_pkt.ack_num == 0)
                    continue;
                pthread_mutex_lock(&arq_mutex);

                uint32_t cum = ack_pkt.ack_num;
                uint64_t sack_bm = ack_pkt.bitmap;

                // 1. Slide the window
                arq.handle_cumulative_ack(cum);

                // 2. Mark bitmap-confirmed out-of-order packets
                for (int i = 0; i < BITMAP_ACK; i++)
                {
                    if (sack_bm & (1u << i))
                        arq.mark_packet_acked(cum + (uint32_t)i);
                }
                arq.advance_window();
                acks_received++;

                if (arq.get_in_flight_count() > 1000)
                    total_inflights++;

                // 3. Fast retransmit: scan bitmap for holes
                int highest_bit = -1;
                for (int i = ((sizeof(sack_bm) * 8) - 1); i >= 0; i--)
                {
                    if (sack_bm & (1u << i))
                    {
                        highest_bit = i;
                        break;
                    }
                }

                uint32_t fast_retransmit_seqs[BITMAP_SIZE];
                int fast_retransmit_count = 0;
                for (int i = 0; i < highest_bit; i++)
                {
                    if (!(sack_bm & (1u << i)))
                        fast_retransmit_seqs[fast_retransmit_count++] = cum + (uint32_t)i;
                }

                // 4. Check transfer completion
                if (chunk_offset >= (uint32_t)file_size && arq.get_in_flight_count() == 0)
                    transfer_complete = true;

                pthread_mutex_unlock(&arq_mutex);

                // 5. Fast retransmit outside the lock
                for (int i = 0; i < fast_retransmit_count; i++)
                {
                    SlimDataPacket rpkt;
                    if (arq.prepare_retransmit(fast_retransmit_seqs[i], rpkt))
                    {
                        SlimDataPacket pkt_send = rpkt;
                        serialize_slim_packet(&pkt_send);
                        sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
                               (struct sockaddr *)&server_addr, addr_len);
                        retransmissions++;
                    }
                }
            }
            else
            {
                cerr << "[CLIENT] Corrupt ACK dropped! Seq=" << ack_pkt.ack_num << endl;
            }
        }
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// Timeout Thread (UNCHANGED)
// ----------------------------------------------------------------------------
void *timeout_thread(void *arg)
{
    while (!transfer_complete)
    {
        uint32_t timed_out_seq = 0;

        pthread_mutex_lock(&arq_mutex);
        timed_out_seq = arq.check_for_timeout();
        pthread_mutex_unlock(&arq_mutex);

        if (timed_out_seq != 0)
        {
            // [CHANGED] Use SlimDataPacket to match the new network protocol
            SlimDataPacket retransmit_pkt;
            bool ready = false;

            pthread_mutex_lock(&arq_mutex);
            // prepare_retransmit fills our 'retransmit_pkt' from its internal buffer
            ready = arq.prepare_retransmit(timed_out_seq, retransmit_pkt);
            if (ready)
                retransmissions++;
            pthread_mutex_unlock(&arq_mutex);

            if (ready)
            {
                // Serialize specifically for the Slim structure
                SlimDataPacket pkt_send = retransmit_pkt;
                serialize_slim_packet(&pkt_send);

                // bytes_sent will now be ~1.4KB instead of the old ~1.8KB
                sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
                       (struct sockaddr *)&server_addr, addr_len);
            }
            else
            {
                cerr << " [TIMEOUT] Max retries exceeded for seq=" << timed_out_seq << ". Aborting." << endl;
                transfer_complete = true;
            }
        }

        // Pro-Tip: 5ms is okay for local testing, but for 95 Mbps,
        // a 1ms sleep makes the client respond to loss much faster.
        Sleep(5);
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// Logger Thread (UNCHANGED -- currently disabled)
// ----------------------------------------------------------------------------
void *logger_thread(void *arg)
{
    while (!transfer_complete)
    {
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

// ----------------------------------------------------------------------------
// Main function
// ----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    cout << " LinkFlow Phase 5 Client Starting (3-Stage Pipeline + SR ARQ)..." << endl;
    cout << "CRC32 hardware acceleration: "
         << (has_hw_crc32() ? "ENABLED (SSE4.2)" : "fallback (slicing-by-8)")
         << endl;
    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <filename>" << endl;
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cerr << " WSAStartup failed." << endl;
        return 1;
    }

    filename_str = argv[1];
    string filenames = filename_str;
    // strcpy(filenames, filename_str);

    filename = filenames.substr(filenames.find_last_of("/\\") + 1);
    // Now 'filename' is just "tata-motor-IAR-2024-25.pdf"
    file_size = get_file_size(filename_str);

    if (file_size < 0)
    {
        cerr << " Cannot open file: " << filename_str << endl;
        std::cerr << "Reason1: " << std::strerror(errno) << std::endl;
        return 1;
    }

    total_chunks = (file_size + DATA_SIZE - 1) / DATA_SIZE;
    cout << " File: " << filename_str
         << " (" << file_size << " bytes, " << total_chunks << " chunks)" << endl;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        cerr << "Socket creation failed: " << strerror(errno) << endl;
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RECV_TIMEOUT * 1000;           // changed to 200ms to better accommodate SR's per-packet timeouts and avoid excessive looping on recvfrom
    int buffer_size = SOC_BUFFER * 1024 * 1024; // 64 MB
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&buffer_size, sizeof(buffer_size));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&buffer_size, sizeof(buffer_size));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    addr_len = sizeof(server_addr);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
    {
        cerr << " Invalid address" << endl;
        closesocket(sockfd); // [FIXED] close() → closesocket() on Windows/Winsock
        return 1;
    }

    cout << " SR Window=" << SR_WINDOW_SIZE << ", RTO=" << SR_PACKET_TIMEOUT_MS << "ms"
         << ", Pipeline=" << COMPRESSOR_THREADS << " compressors" << endl;

    // Check for resume checkpoint
    uint32_t starting_seq = 1;
    uint32_t starting_offset = 0;
    ifstream in("resume.json");
    if (in.is_open())
    {
        stringstream buf;
        buf << in.rdbuf();
        string content = buf.str();
        size_t f_pos = content.find("\"filename\"");
        size_t s_pos = content.find("\"expected_seq\"");
        if (f_pos != string::npos && s_pos != string::npos)
        {
            size_t f_start = content.find("\"", f_pos + 10) + 1;
            size_t f_end = content.find("\"", f_start);
            string saved = content.substr(f_start, f_end - f_start);
            if (saved == filename)
            {
                size_t s_start = content.find(":", s_pos) + 1;
                while (isspace(content[s_start]))
                    s_start++;
                size_t s_end = content.find_first_of(",}", s_start);
                while (s_end > s_start && isspace(content[s_end - 1]))
                    s_end--;
                uint32_t expected_seq = (uint32_t)stoul(content.substr(s_start, s_end - s_start));
                starting_seq = expected_seq;
                starting_offset = (expected_seq - 1) * DATA_SIZE;
                cout << " Resuming transfer from checkpoint: seq=" << starting_seq << ", offset=" << starting_offset << endl;
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
    sendto(sockfd, (const char *)&start_pkt, sizeof(start_pkt), 0, (struct sockaddr *)&server_addr, addr_len);
    cout << "[CLIENT] Waiting for server handshake..." << endl;
    bool handshake_done = false;
    auto handshake_start = chrono::steady_clock::now();

    while (!handshake_done)
    {
        ACKPacket ack;
        int r = recvfrom(sockfd, (char *)&ack, sizeof(ack), 0,
                         (struct sockaddr *)&server_addr, &addr_len);
        if (r > 0)
        {
            deserialize_ack_packet(&ack);
            uint32_t received_crc = ack.crc32;
            uint32_t computed = compute_ack_crc(&ack);

            if (computed == received_crc && ack.ack_num == 0 && ack.type == 1)
            {
                cout << "[CLIENT] Handshake confirmed! Server ready." << endl;
                cout << "[CLIENT] Starting data transfer in 200ms..." << endl;
                Sleep(200); // brief pause — matches server's Sleep(200)
                handshake_done = true;
            }
        }

        // Timeout — retransmit StartPacket
        auto elapsed = chrono::steady_clock::now() - handshake_start;
        if (chrono::duration_cast<chrono::milliseconds>(elapsed).count() > 1000)
        {
            cout << "[CLIENT] No handshake response -- retrying StartPacket..." << endl;
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
    double elapsed = chrono::duration_cast<chrono::milliseconds>(end_time - start_time).count() / 1000.0;
    double throughput = (total_bytes_sent * 8.0) / (elapsed * 1e6);

    cout << "\n File transfer COMPLETE!" << endl;
    cout << " Performance Summary:" << endl;
    cout << "   - Total chunks transmitted: " << chunks_sent << endl;
    cout << "   - Total bytes sent:         " << total_bytes_sent << endl;
    cout << "   - ACKs received:            " << acks_received << endl;
    cout << "   - Elapsed time:             " << fixed << setprecision(2) << elapsed << "s" << endl;
    cout << "   - Throughput:               " << throughput << " Mbps" << endl;
    cout << "   - Max in-flight packets:    " << total_inflights << endl;
    cout << "   - Total retransmissions:    " << retransmissions << endl;
}
