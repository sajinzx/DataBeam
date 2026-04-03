#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <sys/stat.h>
#include <queue>
#include <pthread.h>
#include "./headers/packet.h"
// #include "./headers/arq.h"
#include "./headers/compress.h"
#include "./headers/crchw.h"
#include "./headers/crypto.h"
#include <chrono>
#include <atomic>
#include <vector>
#include <csignal>
using namespace std;
#define BUFFER_SIZE 4096 // Enough for 512 packets in flight (assuming 8KB window) increase i window increase the buffer size to accomodate more packets in flight
#define ACK_BATCH_SIZE 128
#define RECV_TIMEOUT 1000
#define SOC_BUFFER 16
// Work queue — holds CRC-verified raw packets waiting to be decompressed
struct WorkItem
{
    SlimDataPacket pkt;
    size_t compressed_len;
};

struct PerfStats
{
    // Latency Metrics
    std::atomic<long long> total_net_recv_time_us{0}; // Time spent in recvfrom
    std::atomic<long long> total_worker_wait_us{0};   // Time worker spent sleeping/waiting for queue
    std::atomic<long long> total_decomp_time_us{0};   // Time spent decompressing
    std::atomic<long long> total_disk_write_us{0};    // Time spent in seekp/write

    // Throughput & Buffer Metrics
    std::atomic<uint32_t> packets_processed{0};
    std::atomic<uint32_t> buffer_full_events{0}; // How often queue reached MAX_SIZE
    std::atomic<uint32_t> crc_fails{0};

    // Function to get current time in microseconds
    static long long now_us()
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::high_resolution_clock::now().time_since_epoch())
            .count();
    }
};

PerfStats g_perf; // Global performance object
queue<WorkItem> work_queue;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
volatile bool server_done = false;

void handle_sigint(int sig)
{
    cout << "\n[SERVER] Caught signal " << sig << ", shutting down gracefully..." << endl;
    server_done = true;
    pthread_cond_signal(&queue_cond);
}

pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
string shared_filename = "";
uint32_t shared_file_size = 0;
bool start_received = false;

void create_received_dir()
{
    struct stat st = {0};
    if (stat("received", &st) == -1)
        mkdir("received");
}

void save_checkpoint(const string &filename, uint32_t expected_seq)
{
    ofstream out("resume.json");
    if (out.is_open())
    {
        out << "{\n  \"filename\": \"" << filename << "\",\n";
        out << "  \"expected_seq\": " << expected_seq << "\n}\n";
    }
}

uint32_t load_checkpoint(const string &target_filename)
{
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

vector<uint32_t> compute_file_hashes(const string &filepath)
{
    vector<uint32_t> hashes;
    ifstream file(filepath, ios::binary);
    if (!file.is_open())
        return hashes;
    char buffer[DATA_SIZE];
    while (file.read(buffer, DATA_SIZE) || file.gcount() > 0)
    {
        size_t n = file.gcount();
        hashes.push_back(calculate_crc32(
            reinterpret_cast<unsigned char *>(buffer), n));
    }
    return hashes;
}

// =============================================================================
// Decoded packet — stores decompressed payload so the buffer drain loop
// never has to decompress or CRC-check twice
// =============================================================================
struct DecodedPacket
{
    char data[DATA_SIZE + 1];
    size_t data_len;
    uint8_t type;
    uint32_t file_size;
    uint32_t chunk_offset;
    bool occupied;
    uint32_t seq_num;
};

struct PoolSlot
{
    char data[DATA_SIZE + 1];
    size_t data_len;
    uint8_t type;
    uint32_t chunk_offset;

    bool occupied;
    uint32_t seq_num; // to detect hash collisions in the pool
};

void *worker_thread(void *arg)
{

    // Use SlimDataPacket as the base for the pool.
    while (!start_received && !server_done)
    {
        Sleep(3);
    }
    if (!start_received) {
        cout << "[WORKER] Shutting down before any file transfer started." << endl;
        return nullptr;
    }
    pthread_mutex_lock(&init_mutex);
    string current_filename = shared_filename;
    uint32_t total_file_size = shared_file_size;
    pthread_mutex_unlock(&init_mutex);

    string out_filepath = "received/recv_" + current_filename;

    uint32_t expected_seq_num = load_checkpoint(current_filename);
    if (expected_seq_num == 0) expected_seq_num = 1;

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

    if (!outfile.is_open())
    {
        cerr << "[WORKER] Cannot create: " << out_filepath << endl;
        server_done = true;
        return nullptr;
    }
    cout << "[WORKER] File opened: " << out_filepath << ". Expecting seq=" << expected_seq_num << endl;
    
    // this was used in phase 3 for GBN, we can reuse the same pool for SR since it's just a buffer of decoded packets. The logic of how we fill and drain it changes, but the underlying storage can be the same.

    PoolSlot *pool = new PoolSlot[BUFFER_SIZE];
    memset(pool, 0, sizeof(PoolSlot) * BUFFER_SIZE);
    
    bool transfer_success = false;

    // ── Staging bunch buffer (1 MB) ──────────────────────────────────────────
    // Contiguous decompressed packets are accumulated here; a single seekp+write
    // fires per bunch instead of per packet (~32× fewer disk syscalls per burst).
    static const size_t BUNCH_CAPACITY = 1u * 1024u * 1024u; // 1 MB
    char *bunch_buffer = new char[BUNCH_CAPACITY];
    size_t bunch_size = 0;           // bytes staged in bunch_buffer
    uint64_t bunch_start_offset = 0; // file offset of bunch_buffer[0]

    while (!server_done)
    {
        long long wait_start = PerfStats::now_us();
        WorkItem item;
        {
            pthread_mutex_lock(&queue_mutex);
            while (work_queue.empty() && !server_done)
                pthread_cond_wait(&queue_cond, &queue_mutex);
            g_perf.total_worker_wait_us += (PerfStats::now_us() - wait_start);
            if (server_done && work_queue.empty())
            {
                pthread_mutex_unlock(&queue_mutex);
                break;
            }
            item = work_queue.front();
            work_queue.pop();
            g_perf.packets_processed++;
            pthread_mutex_unlock(&queue_mutex);
        }

        // Use the SlimDataPacket structure
        SlimDataPacket &pkt = item.pkt;
        // ---- Decrypt -------------------------------------------------------
        char decrypted_data[DATA_SIZE + 1];
        if (!aes_decrypt((const uint8_t *)pkt.data, item.compressed_len, SHARED_SECRET_KEY, &pkt.packet_iv, (uint8_t *)decrypted_data))
        {
            cerr << "[WORKER] Decrypt failed seq=" << pkt.seq_num << endl;
            continue;
        }

        // ---- 2. DECOMPRESS INTO TEMPORARY BUFFER ---------------------------
        char decompressed_buffer[DATA_SIZE + 1];
        size_t decomp_len = sizeof(decompressed_buffer);

        // Only decompress if the compression flag is set in the header
        long long decomp_start = PerfStats::now_us();
        int ret = decompress_data(decrypted_data, item.compressed_len,
                                  decompressed_buffer, decomp_len);
        g_perf.total_decomp_time_us += (PerfStats::now_us() - decomp_start);
        if (ret != 0)
        {
            cerr << "[WORKER] Decomp failed seq=" << pkt.seq_num
                 << " err=" << ret << endl;
            continue;
        }

        // Raw copy if not compressed

        // ---- 3. IN-ORDER OR OUT-OF-ORDER LOGIC -----------------------------
        if (pkt.seq_num == expected_seq_num)
        {
            // ── Start a new bunch at the trigger packet's file offset ─────
            bunch_start_offset = pkt.chunk_offset;
            bunch_size = 0;

            // Helper lambda: flush the current bunch in one seekp+write.
            // Defined as a local variable (C++11 generic lambda with captures).
            auto flush_bunch = [&]() -> bool
            {
                if (bunch_size == 0)
                    return true;
                long long disk_start = PerfStats::now_us();
                outfile.seekp((streamoff)bunch_start_offset, ios::beg);
                outfile.write(bunch_buffer, (streamsize)bunch_size);
                g_perf.total_disk_write_us += (PerfStats::now_us() - disk_start);
                if (outfile.fail())
                {
                    cerr << "[WORKER] Bunch write failed at offset="
                         << bunch_start_offset << endl;
                    outfile.clear();
                    return false;
                }
                bunch_size = 0;
                return true;
            };

            // Stage the trigger (in-order) packet.
            if (bunch_size + decomp_len > BUNCH_CAPACITY)
                flush_bunch(); // shouldn't happen on the first packet, but guard it
            memcpy(bunch_buffer + bunch_size, decompressed_buffer, decomp_len);
            bunch_size += decomp_len;

            expected_seq_num++;

            bool hit_eof = (pkt.type == 3);

            // ── 4. DRAIN THE POOL — accumulate into bunch, flush when full ─
            while (!hit_eof)
            {
                int idx = expected_seq_num % BUFFER_SIZE;
                PoolSlot &slot = pool[idx];

                if (!slot.occupied || slot.seq_num != expected_seq_num)
                    break;

                hit_eof = (slot.type == 3);

                // If this slot's data would overflow the bunch, flush first.
                if (bunch_size + slot.data_len > BUNCH_CAPACITY)
                {
                    if (!flush_bunch())
                        break; // write error — stop draining
                    // New bunch starts at this slot's file offset.
                    bunch_start_offset = slot.chunk_offset;
                }

                memcpy(bunch_buffer + bunch_size, slot.data, slot.data_len);
                bunch_size += slot.data_len;

                slot.occupied = false;
                expected_seq_num++;

                if (expected_seq_num % 500 == 0)
                    save_checkpoint(current_filename, expected_seq_num);
            }

            // ── Flush remaining partial bunch ─────────────────────────────
            flush_bunch();

            if (expected_seq_num % 500 == 0)
                save_checkpoint(current_filename, expected_seq_num);

            // ── EOF: close file and signal done ───────────────────────────
            if (hit_eof || pkt.type == 3)
            {
                transfer_success = true;
                outfile.flush();
                outfile.close();
                remove("resume.json");
                cout << "[WORKER] Transfer complete: " << out_filepath << endl;
                server_done = true;
                goto cleanup;
            }
        }
        else if (pkt.seq_num > expected_seq_num)
        {
            // Buffer out-of-order — store decompressed data in pool
            int idx = pkt.seq_num % BUFFER_SIZE;
            PoolSlot &slot = pool[idx];

            if (!slot.occupied)
            {
                memcpy(slot.data, decompressed_buffer, decomp_len);
                slot.data_len = decomp_len;
                slot.type = pkt.type;
                slot.chunk_offset = pkt.chunk_offset;

                slot.seq_num = pkt.seq_num;
                slot.occupied = true;
            }
            // If occupied and seq_num differs → collision (window > POOL_SIZE)
            // Increase POOL_SIZE if this happens
        }
        // pkt.seq_num < expected_seq_num → duplicate, ignore
    }
cleanup:
    if (!transfer_success && expected_seq_num > 1) {
         if (bunch_size > 0 && outfile.is_open()) {
             outfile.seekp((streamoff)bunch_start_offset, ios::beg);
             outfile.write(bunch_buffer, (streamsize)bunch_size);
         }
         if (outfile.is_open()) {
             outfile.flush();
             outfile.close();
         }
         save_checkpoint(current_filename, expected_seq_num);
         cout << "[WORKER] Saved checkpoint abruptly at seq=" << expected_seq_num << endl;
    }
    delete[] pool;
    delete[] bunch_buffer;
    cout << "[WORKER] Worker thread exiting." << endl;
    return nullptr;
}

int main()
{
    signal(SIGINT, handle_sigint);
    cout << " DataBeam Phase 4 Server Starting..." << endl;
    SetConsoleOutputCP(CP_UTF8);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cerr << " WSAStartup failed." << endl;
        return 1;
    }

    create_received_dir();

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        cerr << " Socket failed." << endl;
        return 1;
    }

    // Large socket buffers — absorb bursts without dropping
    int buf_size = SOC_BUFFER * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&buf_size, sizeof(buf_size));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&buf_size, sizeof(buf_size));

    // FIX: 1ms recv timeout — server must be responsive for ACK sending
    DWORD recv_timeout_ms = RECV_TIMEOUT;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_timeout_ms, sizeof(recv_timeout_ms));

    struct sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cerr << " Bind failed." << endl;
        return 1;
    }
    cout << " Listening on port " << PORT << "..." << endl;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    pthread_t t_worker;
    pthread_create(&t_worker, nullptr, worker_thread, nullptr);

    bool is_receiving = true;

    // --- Hybrid SACK state ---
    // ack_seq:    cumulative watermark — the next in-order seq the server needs
    // ack_counter: in-order packets received since last batched SACK
    // recv_mark:  recv_mark[seq % BUFFER_SIZE] == seq means that packet is buffered
    uint32_t ack_seq = 1;
    int ack_counter = 0;
    uint32_t recv_mark[BUFFER_SIZE];
    memset(recv_mark, 0, sizeof(recv_mark));

    int idle_timeouts = 0;
    while (is_receiving)
    {
        long long start_recv = PerfStats::now_us();
        char raw_buffer[sizeof(SlimDataPacket) + 64];
        int bytes_recv = recvfrom(sockfd, raw_buffer, sizeof(raw_buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (bytes_recv <= 0)
        {
            if (start_received) {
                idle_timeouts++;
                if (idle_timeouts > 10) { // 10 * RECV_TIMEOUT = 10s roughly
                    cerr << "\n[SERVER] Client inactivity timeout. Aborting transfer..." << endl;
                    server_done = true;
                    pthread_cond_signal(&queue_cond);
                    break;
                }
            }
            continue;
        }
        idle_timeouts = 0; // reset on successful packet

        uint8_t p_type = (uint8_t)raw_buffer[0]; // Peek at type without deserializing full packet (type is at fixed offset)

        if (p_type == 2 && !start_received)
        {
            if (bytes_recv < (int)sizeof(StartPacket))
            {
                cerr << "[SERVER] Short StartPacket — ignoring" << endl;
                continue;
            }
            g_perf.total_net_recv_time_us += (PerfStats::now_us() - start_recv);
            StartPacket sp;
            memcpy(&sp, raw_buffer, sizeof(StartPacket));

            deserialize_start_packet(&sp);
            pthread_mutex_lock(&init_mutex);
            shared_filename = string(sp.filename);
            shared_file_size = sp.file_size;
            start_received = true;
            
            uint32_t saved_seq = load_checkpoint(shared_filename);
            if (saved_seq > 1) {
                ack_seq = saved_seq;
            }
            pthread_mutex_unlock(&init_mutex);
            cout << "[SERVER] Connection established! Resume seq=" << ack_seq << endl;
            cout << "[SERVER] File: " << sp.filename
                 << " (" << sp.file_size << " bytes, "
                 << sp.total_chunks << " chunks)" << endl;

            ACKPacket start_ack;
            memset(&start_ack, 0, sizeof(start_ack));
            start_ack.type = 1;
            start_ack.ack_num = 0; // 0 = handshake ACK (not a data ACK)
            memset(start_ack.bitmap, 0, sizeof(start_ack.bitmap));

            // BUG FIX 2: compute CRC on host-order fields BEFORE serializing
            start_ack.crc32 = calculate_crc32(
                reinterpret_cast<const unsigned char *>(&start_ack),
                sizeof(ACKPacket) - sizeof(uint32_t));

            serialize_ack_packet(&start_ack);
            sendto(sockfd, (const char *)&start_ack, sizeof(start_ack), 0,
                   (struct sockaddr *)&client_addr, addr_len);

            cout << "[SERVER] Handshake ACK sent. Waiting for data..." << endl;

            // Small delay — gives client time to display "connection confirmed"
            // before the data burst starts. Client uses this window to show UI.
            Sleep(200); // 200ms — enough for frontend update, negligible overhead
        }
        else if (p_type == 0 || p_type == 3) // Data packet or End packet
        {
            if (!start_received)
            {
                // Data arrived before handshake — ignore, client will retransmit
                continue;
            }

            if (bytes_recv < (int)(sizeof(SlimDataPacket) - DATA_SIZE))
            {
                cerr << "[SERVER] Short data packet — dropping" << endl;
                continue;
            }
            SlimDataPacket pkt;

            memset(&pkt, 0, sizeof(pkt));
            memcpy(&pkt, raw_buffer, min((size_t)bytes_recv, sizeof(pkt)));
            // ----- HMAC Verification -----
            uint8_t received_hmac[16];
            memcpy(received_hmac, pkt.hmac, 16);
            memset(pkt.hmac, 0, 16); // zero for verification

            if (!verify_hmac((const uint8_t *)&pkt, sizeof(pkt), SHARED_SECRET_KEY, received_hmac))
            {
                cerr << "[SERVER] HMAC VERIFICATION FAILED! Tampering detected. seq=" << ntohs(pkt.seq_num) << endl;
                continue; // drop packet silently
            }

            // HMAC verified. pkt.hmac is currently 0 (zeroed for verification).
            // CRC was computed by the client with hmac[]=0, so we must keep
            // it zeroed here too — do NOT restore hmac before the CRC check.
            deserialize_slim_packet(&pkt);
            size_t compressed_len = pkt.data_len;

            if (compressed_len == 0 || compressed_len > (size_t)(DATA_SIZE + 1))
            {
                cerr << "[SERVER] Bad data_len=" << compressed_len
                     << " seq=" << pkt.seq_num << endl;
                continue;
            }

            // ---- CRC check -------------------------------------------------------
            // crc32 sits in the MIDDLE of SlimDataPacket; save, zero, hash, compare.
            // hmac[] is still 0 here — matches what the client hashed over.
            uint32_t received_crc = pkt.crc32;
            pkt.crc32 = 0;
            uint32_t computed = calculate_crc32(
                reinterpret_cast<const unsigned char *>(&pkt),
                sizeof(SlimDataPacket));
            pkt.crc32 = received_crc; // restore for downstream use

            // Restore hmac AFTER the CRC check (client hashed with hmac=0)
            memcpy(pkt.hmac, received_hmac, 16);

            if (computed != received_crc)
            {
                cerr << "[SERVER] CRC FAIL seq=" << pkt.seq_num
                     << " expected=0x" << hex << received_crc
                     << " got=0x" << computed << dec << endl;
                continue;
            }

            // --- Hybrid SACK: track, decide, and send ---

            // Mark this packet as received in the tracking table
            if (pkt.seq_num >= ack_seq && pkt.seq_num < ack_seq + BUFFER_SIZE)
                recv_mark[pkt.seq_num % BUFFER_SIZE] = pkt.seq_num;

            bool hole_detected = (pkt.seq_num > ack_seq); // gap before this packet
            bool is_eof = (pkt.type == 3);                // always ACK immediately
            bool gap_filled = false;

            // Advance cumulative watermark if this was the next expected packet
            if (pkt.seq_num == ack_seq)
            {
                uint32_t before = ack_seq;
                while (recv_mark[ack_seq % BUFFER_SIZE] == ack_seq)
                {
                    recv_mark[ack_seq % BUFFER_SIZE] = 0;
                    ack_seq++;
                }
                gap_filled = (ack_seq > before + 1);
                ack_counter++;
            }

            bool duplicate = (pkt.seq_num < ack_seq);
            bool send_sack = hole_detected || is_eof || gap_filled || duplicate ||
                             (ack_counter >= ACK_BATCH_SIZE);

            if (send_sack)
            {
                ACKPacket sack;
                memset(&sack, 0, sizeof(sack));
                sack.type = 1;
                sack.ack_num = ack_seq; // cumulative watermark
                
                // Build SACK bitmap: bit i = 1 if (ack_seq + i) already buffered
                for (int i = 0; i < 256; i++)
                {
                    uint32_t c = ack_seq + (uint32_t)i;
                    if (recv_mark[c % BUFFER_SIZE] == c)
                    {
                        int chunk_idx = i / 64;
                        int bit_idx = i % 64;
                        sack.bitmap[chunk_idx] |= (1ULL << bit_idx);
                    }
                }
                sack.crc32 = calculate_crc32(
                    reinterpret_cast<const unsigned char *>(&sack),
                    sizeof(ACKPacket) - sizeof(uint32_t));
                serialize_ack_packet(&sack);
                sendto(sockfd, (const char *)&sack, sizeof(sack), 0,
                       (struct sockaddr *)&client_addr, addr_len);

                // Only reset the batch counter for normal batched SACKs;
                // hole/gap SACKs don't drain the counter so batching continues.
                if (!hole_detected && !gap_filled)
                    ack_counter = 0;
            }
            if (!duplicate) {
                WorkItem item;
                item.pkt = pkt;
                item.compressed_len = compressed_len;

                pthread_mutex_lock(&queue_mutex);
                work_queue.push(item);
                pthread_cond_signal(&queue_cond); // wake worker thread
                pthread_mutex_unlock(&queue_mutex);
            }
            if (pkt.type == 3)
            {
                // [FIX Bug 8] The worker sets server_done itself after writing
                // the final chunk and closing the file (goto cleanup path).
                // Breaking here races: server_done=true fires before the worker
                // drains its queue. Just signal the worker — the if(server_done)
                // check below will exit the main loop once the worker is done.
                pthread_cond_signal(&queue_cond);
                // DO NOT break here — wait for worker to finish via server_done
                break;
            }
        }
        if (server_done)
        {
            is_receiving = false;
            break; // Exit the loop cleanly
        }
        // pkt.seq_num < expected_seq_num → duplicate, already processed, ignore
    }

    server_done = true;
    pthread_cond_signal(&queue_cond); // wake worker if it's waiting
    pthread_join(t_worker, nullptr);
    cout << "[SERVER] Transfer finished. Shutting down server..." << endl;
    remove("resume.json");
    closesocket(sockfd);
    WSACleanup();
    uint32_t count = g_perf.packets_processed.load();
    if (count == 0)
        return 0;

    double avg_net = (double)g_perf.total_net_recv_time_us / count;
    double avg_wait = (double)g_perf.total_worker_wait_us / count;
    double avg_decomp = (double)g_perf.total_decomp_time_us / count;
    double avg_disk = (double)g_perf.total_disk_write_us / count;

    cout << "\n--- PERFORMANCE REPORT (Average per Packet) ---" << endl;
    cout << "Network Recv:  " << avg_net << " us" << endl;
    cout << "Worker Idle:   " << avg_wait << " us (If high, increase Window Size)" << endl;
    cout << "Decompress:    " << avg_decomp << " us (If high, add more Worker Threads)" << endl;
    cout << "Disk Write:    " << avg_disk << " us (If high, check SSD/HDD speed)" << endl;
    cout << "Buffer Fulls:  " << g_perf.buffer_full_events << " (If >0, Increase BUFFER_SIZE)" << endl;
    cout << "-----------------------------------------------" << endl;
    return 0;
}
