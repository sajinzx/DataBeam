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
using namespace std;
#define BUFFER_SIZE 4096 // Enough for 512 packets in flight (assuming 8KB window)
// Work queue — holds CRC-verified raw packets waiting to be decompressed
struct WorkItem
{
    SlimDataPacket pkt;
    size_t compressed_len;
};

queue<WorkItem> work_queue;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
volatile bool server_done = false;
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

void save_checkpoint(const string &filename, uint16_t expected_seq)
{
    ofstream out("resume.json");
    if (out.is_open())
    {
        out << "{\n  \"filename\": \"" << filename << "\",\n";
        out << "  \"expected_seq\": " << expected_seq << "\n}\n";
    }
}

uint16_t load_checkpoint(const string &target_filename)
{
    ifstream in("resume.json");
    if (!in.is_open())
        return 1;
    stringstream buf;
    buf << in.rdbuf();
    string content = buf.str();
    size_t f_pos = content.find("\"filename\"");
    size_t s_pos = content.find("\"last_seq\"");
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
    return (uint16_t)stoi(content.substr(s_start, s_end - s_start)) + 1;
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
        Sleep(1);

    pthread_mutex_lock(&init_mutex);
    string current_filename = shared_filename;
    uint32_t total_file_size = shared_file_size;
    pthread_mutex_unlock(&init_mutex);

    string out_filepath = "received/recv_" + current_filename;

    ofstream outfile(out_filepath, ios::binary | ios::out | ios::trunc);
    if (!outfile.is_open())
    {
        cerr << "[WORKER] Cannot create: " << out_filepath << endl;
        server_done = true;
        return nullptr;
    }
    cout << "[WORKER] File opened: " << out_filepath << endl;
    // this was used in phase 3 for GBN, we can reuse the same pool for SR since it's just a buffer of decoded packets. The logic of how we fill and drain it changes, but the underlying storage can be the same.

    PoolSlot *pool = new PoolSlot[BUFFER_SIZE];
    memset(pool, 0, sizeof(PoolSlot) * BUFFER_SIZE);
    uint32_t expected_seq_num = 1; // [CRITICAL] Must be 32-bit for 1GB files

    while (!server_done)
    {
        WorkItem item;
        {
            pthread_mutex_lock(&queue_mutex);
            while (work_queue.empty() && !server_done)
                pthread_cond_wait(&queue_cond, &queue_mutex);

            if (server_done && work_queue.empty())
            {
                pthread_mutex_unlock(&queue_mutex);
                break;
            }
            item = work_queue.front();
            work_queue.pop();
            pthread_mutex_unlock(&queue_mutex);
        }

        // Use the SlimDataPacket structure
        SlimDataPacket &pkt = item.pkt;

        // ---- 2. DECOMPRESS INTO TEMPORARY BUFFER ---------------------------
        char decompressed_buffer[DATA_SIZE + 1];
        size_t decomp_len = sizeof(decompressed_buffer);

        // Only decompress if the compression flag is set in the header

        int ret = decompress_data(pkt.data, item.compressed_len,
                                  decompressed_buffer, decomp_len);
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
            size_t write_len = decomp_len; // or pkt.data_len after decompression
            outfile.seekp(pkt.chunk_offset, ios::beg);
            outfile.write(decompressed_buffer, (streamsize)write_len);
            if (outfile.fail())
            {
                cerr << "[WORKER] Write failed seq=" << pkt.seq_num << endl;
                outfile.clear();
            }

            expected_seq_num++;
            if (expected_seq_num % 500 == 0)
                save_checkpoint(current_filename, expected_seq_num);
            // 4. DRAIN THE POOL (Selective Repeat)
            while (true)
            {
                int idx = expected_seq_num % BUFFER_SIZE;
                PoolSlot &slot = pool[idx];

                if (!slot.occupied || slot.seq_num != expected_seq_num)
                    break;

                outfile.seekp(slot.chunk_offset, ios::beg);
                outfile.write(slot.data, slot.data_len);

                if (outfile.fail())
                {
                    cerr << "[WORKER] Write failed buffered seq="
                         << expected_seq_num << endl;
                    outfile.clear();
                    break;
                }

                bool is_end = (slot.type == 3);
                slot.occupied = false;
                expected_seq_num++;
                if (expected_seq_num % 500 == 0)
                    save_checkpoint(current_filename, expected_seq_num);

                if (is_end)
                {
                    outfile.flush();
                    outfile.close();
                    remove("resume.json");
                    cout << "[WORKER] Transfer complete: " << out_filepath << endl;
                    server_done = true;
                    goto cleanup;
                }
            }
            // END on in-order path
            if (pkt.type == 3)
            {
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
    delete[] pool;
    return nullptr;
}

int main()
{
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
    int buf_size = 64 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&buf_size, sizeof(buf_size));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&buf_size, sizeof(buf_size));

    // FIX: 1ms recv timeout — server must be responsive for ACK sending
    struct timeval tv = {0, 1000};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

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

    while (is_receiving)
    {
        char raw_buffer[sizeof(SlimDataPacket) + 64];
        int bytes_recv = recvfrom(sockfd, raw_buffer, sizeof(raw_buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (bytes_recv <= 0)
            continue;

        uint8_t p_type = (uint8_t)raw_buffer[0]; // Peek at type without deserializing full packet (type is at fixed offset)

        if (p_type == 2 && !start_received)
        {
            if (bytes_recv < (int)sizeof(StartPacket))
            {
                cerr << "[SERVER] Short StartPacket — ignoring" << endl;
                continue;
            }

            StartPacket sp;
            memcpy(&sp, raw_buffer, sizeof(StartPacket));
            deserialize_start_packet(&sp);
            pthread_mutex_lock(&init_mutex);
            shared_filename = string(sp.filename);
            shared_file_size = sp.file_size;
            start_received = true;
            pthread_mutex_unlock(&init_mutex);
            cout << "[SERVER] Connection established!" << endl;
            cout << "[SERVER] File: " << sp.filename
                 << " (" << sp.file_size << " bytes, "
                 << sp.total_chunks << " chunks)" << endl;

            ACKPacket start_ack;
            memset(&start_ack, 0, sizeof(start_ack));
            start_ack.type = 1;
            start_ack.ack_num = 0; // 0 = handshake ACK (not a data ACK)
            start_ack.bitmap = 0;

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
            // uint32_t received_crc = ntohl(pkt.crc32);
            deserialize_slim_packet(&pkt);
            // uint32_t received_crc = pkt.crc32;
            size_t compressed_len = pkt.data_len;

            if (compressed_len == 0 || compressed_len > (size_t)(DATA_SIZE + 1))
            {
                cerr << "[SERVER] Bad data_len=" << compressed_len
                     << " seq=" << pkt.seq_num << endl;
                continue;
            }
            //  1. Get length safely

            // ---- Validate data_len --------------------------------------------

            //  pkt.crc32 = 0; // Zero out CRC field for calculation (same as client did)

            // ---- Send ACK immediately after length check (before heavy work) --
            // FIX: ACK sent as small struct, not full Packet — reduces ACK latency
            // FIX: ACK sent BEFORE decode so the client's RTO doesn't expire
            //      while we decompress
            // ---- CRC check -------------------------------------------------------
            // [FIX Bug 1] crc32 sits in the MIDDLE of SlimDataPacket, not at the end.
            // Cannot exclude it by trimming sizeof(uint32_t) from the tail.
            // Instead: save the received value, zero the field, hash the full struct.
            uint32_t received_crc = pkt.crc32;
            pkt.crc32 = 0;
            uint32_t computed = calculate_crc32(
                reinterpret_cast<const unsigned char *>(&pkt),
                sizeof(SlimDataPacket));
            pkt.crc32 = received_crc; // restore for downstream use

            if (computed != pkt.crc32)
            {
                cerr << "[SERVER] CRC FAIL seq=" << pkt.seq_num
                     << " expected=0x" << hex << pkt.crc32
                     << " got=0x" << computed << dec << endl;
                continue;
            }

            // Convert header fields to host byte order for easier processing
            {
                ACKPacket small_ack;
                small_ack.type = 1;
                small_ack.ack_num = pkt.seq_num;
                small_ack.bitmap = (uint16_t)(1u << (pkt.seq_num % 16));
                small_ack.crc32 = calculate_crc32((unsigned char *)&small_ack, sizeof(small_ack) - 4);
                serialize_ack_packet(&small_ack);
                // serialize_packet(&small_ack);
                sendto(sockfd, (const char *)&small_ack, sizeof(small_ack), 0,
                       (struct sockaddr *)&client_addr, addr_len);
            }
            {
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
                // [FIX Bug 8] Don't set server_done here — it races with the worker
                // draining the queue. The worker sets server_done itself after writing
                // the final chunk and closing the file (goto cleanup path).
                // Just wake the worker so it processes the end-packet promptly.
                pthread_cond_signal(&queue_cond);
            }
        }
        // pkt.seq_num < expected_seq_num → duplicate, already processed, ignore
    }
    server_done = true;
    pthread_cond_signal(&queue_cond); // wake worker if it's waiting
    pthread_join(t_worker, nullptr);

    closesocket(sockfd);
    WSACleanup();
    return 0;
}
