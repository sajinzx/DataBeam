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
using namespace std;
#define BUFFER_SIZE 1024
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
    return (uint16_t)stoi(content.substr(s_start, s_end - s_start));
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
};
void *worker_thread(void *arg)
{
    // 1. PRE-ALLOCATED POOL: 1024 slots is enough for a 256-512 window.
    // Use SlimDataPacket as the base for the pool.
    SlimDataPacket *memory_pool = new SlimDataPacket[1024];
    bool slot_occupied[1024];
    memset(slot_occupied, false, sizeof(slot_occupied));

    ofstream outfile;
    string current_filename = "";
    uint32_t expected_seq_num = 1; // [CRITICAL] Must be 32-bit for 1GB files
    bool connection_init = false;

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
        size_t decomp_len = DATA_SIZE;

        // Only decompress if the compression flag is set in the header
        if (pkt.flags & 0x01)
        {
            int ret = decompress_data(pkt.data, item.compressed_len,
                                      decompressed_buffer, decomp_len);
            if (ret != 0)
                continue;
        }
        else
        {
            // Raw copy if not compressed
            memcpy(decompressed_buffer, pkt.data, item.compressed_len);
            decomp_len = item.compressed_len;
        }

        // ---- 3. IN-ORDER OR OUT-OF-ORDER LOGIC -----------------------------
        if (pkt.seq_num == expected_seq_num)
        {
            // Write directly to the correct offset
            // uint32_t Offset = (pkt.seq_num - 1) * DATA_SIZE;
            outfile.seekp(pkt.chunk_offset, ios::beg);
            outfile.write(decompressed_buffer, (streamsize)decomp_len);

            expected_seq_num++;

            // 4. DRAIN THE POOL (Selective Repeat)
            while (slot_occupied[expected_seq_num % 1024])
            {
                int idx = expected_seq_num % 1024;
                SlimDataPacket &bp = memory_pool[idx];
                // Offset = (pkt.seq_num - 1) * DATA_SIZE;
                //  Note: In a fully professional version, you'd store
                //  decompressed data in the pool. For simplicity here,
                //  we assume data in pool is ready to write.
                outfile.seekp(bp.chunk_offset, ios::beg);
                outfile.write(bp.data, bp.data_len);

                if (expected_seq_num % 1000 == 0)
                    save_checkpoint(current_filename, expected_seq_num);

                bool is_end = (bp.type == 3);
                slot_occupied[idx] = false;
                expected_seq_num++;

                if (is_end)
                {
                    server_done = true;
                    break;
                }
            }
        }
        else if (pkt.seq_num > expected_seq_num)
        {
            // Store out-of-order packet in the pool
            int idx = pkt.seq_num % 1024;
            if (!slot_occupied[idx])
            {
                // Copy the header and the decompressed data into the pool
                memory_pool[idx] = pkt;
                memcpy(memory_pool[idx].data, decompressed_buffer, decomp_len);
                memory_pool[idx].data_len = (uint16_t)decomp_len;
                slot_occupied[idx] = true;
            }
        }

        if (pkt.type == 3)
        {
            // End of file cleanup
            outfile.flush();
            outfile.close();
            remove("resume.json");
            server_done = true;
        }
    }

    delete[] memory_pool;
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

    uint16_t expected_seq_num = 1;
    bool is_receiving = true;
    bool connection_initialized = false;
    string current_filename = "";
    string out_filepath = ""; // FIX: single declaration, no shadowing

    // FIX: buffer stores DecodedPacket — already CRC-checked and decompressed
    // No duplicate work when draining
    DecodedPacket *fast_buffer[BUFFER_SIZE] = {nullptr};

    ofstream outfile;
    pthread_t t_worker;
    pthread_create(&t_worker, nullptr, worker_thread, nullptr);
    while (is_receiving)
    {
        char raw_buffer[2048];
        int bytes_recv = recvfrom(sockfd, raw_buffer, sizeof(raw_buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (bytes_recv <= 0)
            continue;

        uint8_t p_type = (uint8_t)raw_buffer[0]; // Peek at type without deserializing full packet (type is at fixed offset)
        if (p_type == 2)
        {
            if (!connection_initialized)
            {
                StartPacket *sp = (StartPacket *)raw_buffer;
                deserialize_start_packet(sp);
                current_filename = sp->filename;
                out_filepath = "received/recv_" + current_filename;
                outfile.open(out_filepath, ios::binary | ios::out | ios::trunc);
                if (!outfile.is_open())
                {
                    cerr << "[SERVER] Cannot create: " << out_filepath << endl;
                    continue;
                }
                connection_initialized = true;
            }
        }
        if (p_type == 0)
        {
            SlimDataPacket pkt;
            memcpy(&pkt, raw_buffer, bytes_recv);
            deserialize_slim_packet(&pkt);
            // 1. Get length safely
            uint16_t actual_len = pkt.data_len;
            // ---- Validate data_len --------------------------------------------
            size_t compressed_len = pkt.data_len;

            if (compressed_len == 0 || compressed_len > (size_t)(DATA_SIZE + 1))
            {
                cerr << "[SERVER] Bad data_len=" << compressed_len
                     << " seq=" << pkt.seq_num << endl;
                continue;
            }

            // ---- Send ACK immediately after length check (before heavy work) --
            // FIX: ACK sent as small struct, not full Packet — reduces ACK latency
            // FIX: ACK sent BEFORE decode so the client's RTO doesn't expire
            //      while we decompress
            // ---- CRC check — must pass before ACK ------------------------------------

            uint32_t computed = calculate_crc32((unsigned char *)pkt.data, actual_len);

            // 3. Compare against Big-Endian CRC from network
            if (computed != pkt.crc32)
            {
                cerr << "[SERVER] CRC FAIL" << endl;
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
        }
        // pkt.seq_num < expected_seq_num → duplicate, already processed, ignore
    }
    server_done = true;
    pthread_cond_signal(&queue_cond); // wake worker if it's waiting
    pthread_join(t_worker, nullptr);
    outfile.flush();
    outfile.close();
    closesocket(sockfd);
    WSACleanup();
    return 0;
}
