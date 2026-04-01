// LinkFlow Phase 4: UDP Client with Selective Repeat ARQ
// File: src/client.cpp
// Purpose: High-throughput file transfer with SR sliding window using Pthreads

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
#include "./headers/selectrepeat.h" // [CHANGED] GBN → SR header
#include "./headers/compress.h"
#include "./headers/crchw.h"
#include "./headers/crypto.h"
#include "./headers/ringbuf.h"
#include <filesystem> // C++17
#include <chrono>
#include <atomic>
#include <vector>
#define BITMAP_ACK 64
#define SOC_BUFFER 64
#define RECV_TIMEOUT 30
#define BITMAP_SIZE 64
// Number of compressor threads — tune to CPU core count
#define COMPRESSOR_THREADS 4 // increase to 8 on 8+ core machines
using namespace std;

// ----------------------------------------------------------------------------
// Shared State (Protected by Mutex)
// ----------------------------------------------------------------------------
SelectiveRepeatARQ arq; // [CHANGED] GoBackNARQ → SelectiveRepeatARQ
pthread_mutex_t arq_mutex = PTHREAD_MUTEX_INITIALIZER;

int sockfd;
struct sockaddr_in server_addr;
socklen_t addr_len;
string filename;
const char *filename_str;
long file_size;
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
    SlimDataPacket pkt; // fully built, ready to sendto()
    size_t wire_len;    // actual bytes to send (sizeof pkt always, but tracked)
};

// ---- Pipeline queues -------------------------------------------------------
// Raw queue: dispatcher → compressor threads (SPMC: one dispatcher, N compressors)
// Ready queue: compressor threads → sender thread (MPSC: N compressors, one sender)

static const size_t RAW_Q_CAP = 4096;
static const size_t READY_Q_CAP = 4096;

// Raw queue uses mutex push (multiple compressors pop, one dispatcher pushes)
RingBuf<RawChunk, RAW_Q_CAP> raw_queue;
pthread_mutex_t raw_pop_mutex = PTHREAD_MUTEX_INITIALIZER;

// Ready queue uses mutex push (multiple compressors push, one sender pops)
MPRingBuf<ReadyPacket, READY_Q_CAP> ready_queue;

// Dispatcher state
atomic<uint32_t> dispatch_offset{0};
atomic<uint32_t> dispatch_seq{1};
atomic<bool> dispatch_done{false};

struct PerfStats
{
    // Latency Metrics
    atomic<long long> total_net_recv_time_us{0}; // Time spent in recvfrom
    atomic<long long> total_worker_wait_us{0};   // Time worker spent sleeping/waiting for queue
    atomic<long long> total_decomp_time_us{0};   // Time spent decompressing
    atomic<long long> total_disk_write_us{0};    // Time spent in seekp/write

    // Throughput & Buffer Metrics
    atomic<uint32_t> packets_processed{0};
    atomic<uint32_t> buffer_full_events{0}; // How often queue reached MAX_SIZE
    atomic<uint32_t> crc_fails{0};

    // Function to get current time in microseconds
    static long long now_us()
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::high_resolution_clock::now().time_since_epoch())
            .count();
    }
};

PerfStats g_perf; // Global performance object

long get_file_size(const char *filename)
{
    ifstream file(filename, ios::binary | ios::ate);
    if (!file.is_open())
        return -1;
    return file.tellg();
}

bool read_file_chunk(const char *filename, uint32_t offset, char *buffer, size_t &bytes_read)
{
    ifstream file(filename, ios::binary);
    if (!file.is_open())
        return false;
    file.seekg(offset);
    file.read(buffer, DATA_SIZE);
    bytes_read = file.gcount();
    return true;
}

// ----------------------------------------------------------------------------
// Thread 1: Sender Thread — Burst / Batch Mode
//
// Architecture:
//   • One lock snapshot per burst (not per packet) to read ARQ state.
//   • Packets are fully built (read → compress → encrypt → CRC → serialize → HMAC)
//     outside any mutex, maximising CPU utilisation on the hot path.
//   • WSASendTo loop flushes the whole burst before yielding to the OS.
//   • One trailing lock acquisition commits all pkts_built to the ARQ buffer.
// ----------------------------------------------------------------------------

#define BURST_SIZE 32   // packets per burst cycle

void *sender_thread(void *arg)
{
    // Persistent file handle — avoids reopening the file BURST_SIZE times per cycle.
    ifstream infile(filename_str, ios::binary);
    if (!infile.is_open())
    {
        cerr << " [SENDER] Cannot open file: " << filename_str << endl;
        transfer_complete = true;
        return nullptr;
    }

    // Per-burst packet arrays (stack-allocated, ~96 KB — well within the 1 MB stack limit)
    // wire_pkts: serialized network-byte-order packets sent via WSASendTo
    // arq_pkts:  host-byte-order packets with CRC stored in the ARQ retransmit buffer
    SlimDataPacket wire_pkts[BURST_SIZE];
    SlimDataPacket arq_pkts[BURST_SIZE];
    WSABUF         wsabufs[BURST_SIZE];

    while (!transfer_complete)
    {
        // ── 1. Snapshot ARQ state (one lock for the whole batch check) ──────
        pthread_mutex_lock(&arq_mutex);
        int      in_flight    = arq.get_in_flight_count(); // acquires window_mutex internally
        uint32_t start_offset = chunk_offset;
        uint32_t base_seq     = arq.get_next_seq_num();
        pthread_mutex_unlock(&arq_mutex);

        bool has_data   = (start_offset < (uint32_t)file_size);
        int  free_slots = SR_WINDOW_SIZE - in_flight;

        if (!has_data || free_slots <= 0)
        {
            Sleep(1);
            continue;
        }

        // Congestion-aware batch size: never overfill the window.
        int batch_size = (free_slots < BURST_SIZE) ? free_slots : BURST_SIZE;

        // ── 2. Build batch outside the lock ───────────────────────────────
        int      pkts_built       = 0;
        uint32_t cur_offset       = start_offset;
        size_t   batch_bytes_read = 0;

        for (int b = 0; b < batch_size && cur_offset < (uint32_t)file_size; b++)
        {
            // 2a. Read chunk using the persistent handle (no open/close overhead)
            char chunk_data[DATA_SIZE];
            infile.seekg(cur_offset);
            infile.read(chunk_data, DATA_SIZE);
            size_t bytes_read = (size_t)infile.gcount();
            if (bytes_read == 0)
                break;

            // 2b. Compress
            char   compressed_data[DATA_SIZE + 1];
            size_t compressed_len  = sizeof(compressed_data);
            bool   is_compressed   = false;

            if (compress_data(chunk_data, bytes_read, compressed_data, compressed_len) == 0)
            {
                is_compressed = ((uint8_t)compressed_data[0] == 0x01);
            }
            else
            {
                memcpy(compressed_data + 1, chunk_data, bytes_read);
                compressed_data[0] = 0x00;  // raw marker
                compressed_len     = bytes_read + 1;
            }

            // 2c. Build packet header (zero-copy: only update changing fields per burst)
            SlimDataPacket &arq_pkt = arq_pkts[b];
            memset(&arq_pkt, 0, sizeof(arq_pkt));

            generate_iv(&arq_pkt.packet_iv);   // unique IV per packet — MUST NOT be zeroed

            // 2d. Encrypt compressed payload
            char encrypted_data[DATA_SIZE + 1];
            if (!aes_encrypt((const uint8_t *)compressed_data, compressed_len,
                             SHARED_SECRET_KEY, &arq_pkt.packet_iv,
                             (uint8_t *)encrypted_data))
            {
                cerr << " [SENDER] Encryption failed at seq=" << (base_seq + b) << endl;
                transfer_complete = true;
                goto sender_abort;
            }

            bool is_last = (cur_offset + bytes_read >= (uint32_t)file_size);

            arq_pkt.type         = is_last ? 3 : 0;
            arq_pkt.seq_num      = base_seq + (uint32_t)b;
            arq_pkt.chunk_offset = cur_offset;
            arq_pkt.data_len     = (uint16_t)compressed_len;
            arq_pkt.flags        = is_compressed ? 0x01 : 0x00;
            memset(arq_pkt.hmac, 0, 16);
            memcpy(arq_pkt.data, encrypted_data, compressed_len);

            // 2e. CRC (on host-byte-order struct with crc32=0 and hmac=0)
            arq_pkt.crc32 = 0;
            arq_pkt.crc32 = calculate_crc32(
                reinterpret_cast<const unsigned char *>(&arq_pkt),
                sizeof(SlimDataPacket));

            // 2f. Wire copy: serialize (byte-swap) then compute HMAC
            SlimDataPacket &wire = wire_pkts[b];
            wire = arq_pkt;                       // copy host-order packet (with CRC)
            serialize_slim_packet(&wire);          // byte-swap in place for the wire
            // hmac[] is 16 bytes — memset MUST be exactly 16 (not 32) to avoid
            // overflowing into data[] and invalidating the CRC just computed.
            memset(wire.hmac, 0, 16);
            generate_hmac((const uint8_t *)&wire, sizeof(wire),
                          SHARED_SECRET_KEY, wire.hmac);
            memcpy(arq_pkt.hmac, wire.hmac, 16);  // keep ARQ copy consistent

            // 2g. Set up WSABUF — points directly into wire_pkts[] (zero copy)
            wsabufs[b].buf = reinterpret_cast<CHAR *>(&wire);
            wsabufs[b].len = sizeof(wire);

            cur_offset       += bytes_read;
            batch_bytes_read += bytes_read;
            pkts_built++;

            if (is_last) break;
        }

        if (pkts_built == 0)
        {
            Sleep(1);
            continue;
        }

        // ── 3. WSASendTo burst — tight loop, minimal context switches ─────
        int pkts_sent = 0;
        for (int b = 0; b < pkts_built; b++)
        {
            DWORD bytes_sent_dword = 0;
            int result = WSASendTo(
                (SOCKET)sockfd, &wsabufs[b], 1, &bytes_sent_dword, 0,
                reinterpret_cast<SOCKADDR *>(&server_addr), (int)addr_len,
                NULL, NULL);

            if (result == SOCKET_ERROR)
            {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK)
                {
                    // Socket buffer full — back off and retry remaining later
                    Sleep(1);
                    break;
                }
                cerr << " [SENDER] WSASendTo failed: " << err << endl;
                transfer_complete = true;
                goto sender_abort;
            }
            pkts_sent++;
        }

        if (pkts_sent == 0)
        {
            Sleep(1);
            continue;
        }

        // ── 4. Batch-commit ARQ state (single lock for whole burst) ───────
        pthread_mutex_lock(&arq_mutex);
        for (int b = 0; b < pkts_sent; b++)
        {
            arq.record_sent_packet(arq_pkts[b]); // host-order copy, correct CRC
            arq.increment_seq_num();              // advance next_seq_num by 1
        }
        chunk_offset     += batch_bytes_read;
        chunks_sent      += pkts_sent;
        total_bytes_sent += batch_bytes_read;
        pthread_mutex_unlock(&arq_mutex);
    }

sender_abort:
    infile.close();
    return nullptr;
}



// ----------------------------------------------------------------------------
// Thread 2: Receiver Thread
// ----------------------------------------------------------------------------
void *receiver_thread(void *arg)
{
    while (!transfer_complete)
    {
        struct ACKPacket ack_pkt;
        // memset(&ack_pkt, 0, sizeof(ack_pkt));

        int bytes_recv = recvfrom(sockfd, (char *)&ack_pkt, sizeof(ack_pkt), 0,
                                  (struct sockaddr *)&server_addr, &addr_len);

        if (bytes_recv > 0)
        {
            // [FIX Bug 3] Deserialize first so all fields are in host byte order,
            // then use compute_ack_crc() which correctly excludes the crc32 tail field.
            // The old code called ntohl(ack_pkt.crc32) BEFORE deserialize_ack_packet(),
            // which also swaps crc32 — causing a double byte-swap.
            deserialize_ack_packet(&ack_pkt);
            uint32_t received_crc = ack_pkt.crc32;         // now host order after deserialize
            uint32_t computed = compute_ack_crc(&ack_pkt); // hashes host-order fields, excludes crc32
            if (computed == received_crc)
            {
                if (ack_pkt.ack_num == 0)
                    continue;
                pthread_mutex_lock(&arq_mutex);

                uint32_t cum = ack_pkt.ack_num;    // cumulative watermark (server's next expected seq)
                uint64_t sack_bm = ack_pkt.bitmap; // bit i = server has packet (cum + i)

                // 1. Slide the window: bulk-free all RAM for packets below the watermark
                arq.handle_cumulative_ack(cum);

                // 2. Mark bitmap-confirmed out-of-order packets as individually acked
                for (int i = 0; i < BITMAP_ACK; i++)
                {
                    if (sack_bm & (1u << i))
                        arq.mark_packet_acked(cum + (uint32_t)i);
                }
                arq.advance_window();
                acks_received++;

                if (arq.get_in_flight_count() > 1000)
                    total_inflights++;

                // 3. Fast retransmit: scan bitmap for holes below the highest received bit
                //    e.g. bitmap = 0b1101 → cum+0, cum+2 received; cum+1 is a hole → retransmit now
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

                // 5. Fast retransmit outside the lock — prepare_retransmit re-acquires
                //    window_mutex internally, no deadlock with arq_mutex.
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
                // Ignore WSAETIMEDOUT / WSAEWOULDBLOCK — just loop again
            }
            // Ignore WSAETIMEDOUT / WSAEWOULDBLOCK — just loop again
        }
    }
    return nullptr;
}
// ----------------------------------------------------------------------------
// Thread 3: Timeout Thread
// [CHANGED] SR checks timeouts per-packet and retransmits only the timed-out
//           packet (not the whole window like GBN). API is also different:
//           check_for_timeout() returns a seq_num (0 = none), then
//           prepare_retransmit() resets the timer and gives back the packet.
// ----------------------------------------------------------------------------
void *timeout_thread(void *arg)
{
    while (!transfer_complete)
    {
        // [CHANGED] Must be uint32_t to handle 1GB files (947,000+ packets)
        uint32_t timed_out_seq = 0;

        pthread_mutex_lock(&arq_mutex);
        // SR returns the 32-bit seq_num of the first timed-out packet (0 = none)
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
        Sleep(1);
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// Thread 4: Logger Thread
// [CHANGED] Removed GBN-specific cwnd and EWMA RTT (not in SR).
//           Logs window fill level and packet counts instead.
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
    cout << " LinkFlow Phase 4 Client Starting (Selective Repeat ARQ)..." << endl;
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

    // 50ms receive timeout so receiver_thread doesn't block forever
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RECV_TIMEOUT * 1000;           // changed to 200ms to better accommodate SR's per-packet timeouts and avoid excessive looping on recvfrom
    int buffer_size = SOC_BUFFER * 1024 * 1024; // 16 MB
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

    cout << " SR Window=" << SR_WINDOW_SIZE << ", RTO=" << SR_PACKET_TIMEOUT_MS << "ms" << endl;

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

    cout << "\n Starting Multithreaded Selective Repeat Transmission...\n"
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
            // [FIX Bug 3] Same pattern as receiver_thread — deserialize first.
            deserialize_ack_packet(&ack);
            uint32_t received_crc = ack.crc32; // host order after deserialize
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
            cout << "[CLIENT] No handshake response — retrying StartPacket..." << endl;
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
    pthread_t t_sender, t_receiver, t_timeout, t_logger;
    pthread_create(&t_sender, nullptr, sender_thread, nullptr);
    pthread_create(&t_receiver, nullptr, receiver_thread, nullptr);
    pthread_create(&t_timeout, nullptr, timeout_thread, nullptr);
    // pthread_create(&t_logger, nullptr, logger_thread, nullptr);

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
