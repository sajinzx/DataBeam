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
#include <filesystem> // C++17
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
// Thread 1: Sender Thread
// ----------------------------------------------------------------------------
void *sender_thread(void *arg)
{
    while (!transfer_complete)
    {
        pthread_mutex_lock(&arq_mutex);
        bool can_send = (chunk_offset < (uint32_t)file_size && arq.can_send_packet());
        pthread_mutex_unlock(&arq_mutex);

        if (!can_send)
        {
            // Sleep(1);
            continue;
        }

        pthread_mutex_lock(&arq_mutex);
        // Re-check under lock (TOCTOU guard)
        if (!(chunk_offset < (uint32_t)file_size && arq.can_send_packet()))
        {
            pthread_mutex_unlock(&arq_mutex);
            continue;
        }

        uint32_t current_offset = chunk_offset;
        // [CHANGED] SR tracks next_seq_num internally; read it directly
        uint16_t seq = arq.get_next_seq_num();
        pthread_mutex_unlock(&arq_mutex);

        // Read file chunk outside the lock
        char chunk_data[DATA_SIZE];
        memset(chunk_data, 0, DATA_SIZE);
        size_t bytes_read = 0;

        if (!read_file_chunk(filename_str, current_offset, chunk_data, bytes_read))
        {
            cerr << " Error reading file at offset " << current_offset << endl;
            transfer_complete = true;
            break;
        }

        // Attempt compression
        char compressed_data[DATA_SIZE + 1];
        size_t compressed_len = sizeof(compressed_data);
        bool is_compressed = false;

        if (compress_data(chunk_data, bytes_read, compressed_data, compressed_len) == 0)
        {
            // New compress_data handles the raw fallback internally via marker byte.
            // Check the marker to know which path was taken.
            is_compressed = ((uint8_t)compressed_data[0] == 0x01);
        }
        else
        {
            // compress_data itself failed (Z_BUF_ERROR etc.) — send raw
            memcpy(compressed_data + 1, chunk_data, bytes_read);
            compressed_data[0] = 0x00; // raw marker
            compressed_len = bytes_read + 1;
            is_compressed = false;
        }

        // Build packet
        struct Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.seq_num = seq;
        pkt.ack_num = 0;
        pkt.type = (current_offset + bytes_read >= (uint32_t)file_size)
                       ? 3                        // END
                       : (is_compressed ? 5 : 0); // DATA
        strcpy(pkt.filename, filename.c_str());
        pkt.file_size = file_size;
        pkt.chunk_offset = current_offset;
        pkt.crc32 = calculate_crc32((unsigned char *)compressed_data, compressed_len);
        pkt.data_len = (uint16_t)compressed_len; // [CHANGED] Add data_len field for variable payload size
        memcpy(pkt.data, compressed_data, compressed_len);
        strcpy(pkt.username, "client_user");
        // [CHANGED] SR has no congestion window / EWMA RTT; omit those fields
        pkt.window_size = SR_WINDOW_SIZE;
        pkt.rtt_sample = 0;

        // Serialize a copy for sending
        struct Packet pkt_send = pkt;
        serialize_packet(&pkt_send);

        int bytes_sent = sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
                                (struct sockaddr *)&server_addr, addr_len);

        if (bytes_sent > 0)
        {
            pthread_mutex_lock(&arq_mutex);
            arq.record_sent_packet(pkt); // records pkt and sets send timestamp
            arq.increment_seq_num();     // [CHANGED] advance manually (no increment_seq_num in SR)
            chunk_offset += bytes_read;
            chunks_sent++;
            total_bytes_sent += bytes_read;
            // if (seq % 1000 == 1) // Print every 1000 packets to avoid flooding the console
            // {

            //     cout << " [" << arq.get_in_flight_count() << "/" << SR_WINDOW_SIZE
            //          << "] Seq=" << pkt.seq_num
            //          << " offset=" << current_offset
            //          << " bytes=" << bytes_read
            //          << (is_compressed ? " [COMPRESSED]" : " [UNCOMPRESSED]") << endl;
            // }
            pthread_mutex_unlock(&arq_mutex);
        }
        else
        {
            cerr << " sendto failed" << endl;
            transfer_complete = true;
            break;
        }
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// Thread 2: Receiver Thread
// ----------------------------------------------------------------------------
void *receiver_thread(void *arg)
{
    while (!transfer_complete)
    {
        struct Packet ack_pkt;
        memset(&ack_pkt, 0, sizeof(ack_pkt));

        int bytes_recv = recvfrom(sockfd, (char *)&ack_pkt, sizeof(ack_pkt), 0,
                                  (struct sockaddr *)&server_addr, &addr_len);

        if (bytes_recv > 0)
        {
            deserialize_packet(&ack_pkt);

            if (ack_pkt.type == 1) // ACK
            {
                pthread_mutex_lock(&arq_mutex);
                // [CHANGED] SR uses individual ACKs per seq_num (not cumulative)
                arq.handle_ack(ack_pkt.ack_num);
                acks_received++;

                // cout << " ACK for seq=" << ack_pkt.ack_num
                //     << " | in-flight=" <<   endl;
                if (arq.get_in_flight_count() > 1000)
                {
                    total_inflights++;
                }
                // Transfer done when all data sent and window fully drained
                if (chunk_offset >= (uint32_t)file_size && arq.get_in_flight_count() == 0)
                {
                    transfer_complete = true;
                }
                pthread_mutex_unlock(&arq_mutex);
            }
        }
        // Ignore WSAETIMEDOUT / WSAEWOULDBLOCK — just loop again
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
        uint16_t timed_out_seq = 0;

        pthread_mutex_lock(&arq_mutex);
        // [CHANGED] SR returns the seq_num of the first timed-out packet (0 = none)
        timed_out_seq = arq.check_for_timeout();
        pthread_mutex_unlock(&arq_mutex);

        if (timed_out_seq != 0)
        {
            Packet retransmit_pkt;
            bool ready = false;

            pthread_mutex_lock(&arq_mutex);
            // [CHANGED] prepare_retransmit resets the timer, increments retry count,
            //           and returns false if max retransmits exceeded
            retransmissions++;
            ready = arq.prepare_retransmit(timed_out_seq, retransmit_pkt);
            pthread_mutex_unlock(&arq_mutex);

            if (ready)
            {
                // cout << "  Timeout! SR retransmitting only seq=" << timed_out_seq
                //      << " (not full window)" << endl;

                struct Packet pkt_send = retransmit_pkt;
                serialize_packet(&pkt_send);
                sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
                       (struct sockaddr *)&server_addr, addr_len);
            }
            else
            {
                // Max retransmits exceeded — abort transfer
                cerr << " Max retransmits exceeded for seq=" << timed_out_seq
                     << ". Aborting." << endl;
                transfer_complete = true;
            }
        }

        Sleep(10); // Poll every 5ms
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
    tv.tv_usec = 300 * 1000;            // changed to 200ms to better accommodate SR's per-packet timeouts and avoid excessive looping on recvfrom
    int buffer_size = 32 * 1024 * 1024; // 16 MB
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
    cout << "\n Starting Multithreaded Selective Repeat Transmission...\n"
         << endl;

    auto start_time = chrono::high_resolution_clock::now();

    pthread_t t_sender, t_receiver, t_timeout, t_logger;
    pthread_create(&t_sender, nullptr, sender_thread, nullptr);
    pthread_create(&t_receiver, nullptr, receiver_thread, nullptr);
    pthread_create(&t_timeout, nullptr, timeout_thread, nullptr);
    // pthread_create(&t_logger, nullptr, logger_thread, nullptr);

    pthread_join(t_sender, nullptr);
    pthread_join(t_receiver, nullptr);
    pthread_join(t_timeout, nullptr);
    pthread_join(t_logger, nullptr);

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
    return 0;
}
