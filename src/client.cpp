// LinkFlow Phase 3: UDP Client with Go-Back-N, Compression & Congestion Control
// File: src/client.cpp
// Purpose: High-throughput file transfer with sliding window and AIMD using Pthreads

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
#include "./headers/arq.h"

using namespace std;

// ----------------------------------------------------------------------------
// Shared State (Protected by Mutex)
// ----------------------------------------------------------------------------
GoBackNARQ arq;
pthread_mutex_t arq_mutex = PTHREAD_MUTEX_INITIALIZER;

int sockfd;
struct sockaddr_in server_addr;
socklen_t addr_len;

const char *filename_str;
long file_size;
uint32_t chunk_offset = 0;
int total_chunks;
int chunks_sent = 0;
int acks_received = 0;
uint64_t total_bytes_sent = 0;

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
        bool can_send = (chunk_offset < file_size && arq.can_send_packet());
        pthread_mutex_unlock(&arq_mutex);

        if (!can_send)
        {
            Sleep(1); // Sleep 1ms to prevent busy-waiting if window is full
            continue;
        }

        // Lock again to verify and grab current stats
        pthread_mutex_lock(&arq_mutex);
        if (!(chunk_offset < file_size && arq.can_send_packet()))
        {
            pthread_mutex_unlock(&arq_mutex);
            continue;
        }
        
        uint32_t current_offset = chunk_offset;
        uint16_t seq = arq.get_next_seq_num();
        uint8_t win_sz = arq.get_window_size();
        uint16_t rtt = (uint16_t)arq.get_ewma_rtt();
        pthread_mutex_unlock(&arq_mutex);

        // Read and prepare packet (outside of mutex lock to maximize concurrency)
        char chunk_data[DATA_SIZE];
        memset(chunk_data, 0, DATA_SIZE);
        size_t bytes_read = 0;

        if (!read_file_chunk(filename_str, current_offset, chunk_data, bytes_read))
        {
            cerr << "❌ Error reading file at offset " << current_offset << endl;
            transfer_complete = true;
            break;
        }

        char compressed_data[DATA_SIZE];
        size_t compressed_len = DATA_SIZE;
        bool is_compressed = false;
        
        if (compress_data(chunk_data, bytes_read, compressed_data, compressed_len) == 0 && compressed_len < bytes_read)
        {
            is_compressed = true;
        }
        else
        {
            memcpy(compressed_data, chunk_data, bytes_read);
            compressed_len = bytes_read;
            is_compressed = false;
        }

        struct Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.seq_num = seq;
        pkt.ack_num = 0;
        
        if (current_offset + bytes_read >= file_size)
            pkt.type = 3; // END packet
        else
            pkt.type = is_compressed ? 5 : 0;

        strcpy(pkt.filename, filename_str);
        pkt.file_size = file_size;
        pkt.chunk_offset = current_offset;
        pkt.crc32 = calculate_crc32((unsigned char *)compressed_data, compressed_len);
        memcpy(pkt.data, compressed_data, compressed_len);
        strcpy(pkt.username, "client_user");
        pkt.window_size = win_sz;
        pkt.rtt_sample = rtt;

        struct Packet pkt_send = pkt;
        serialize_packet(&pkt_send);

        int bytes_sent = sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
                                (struct sockaddr *)&server_addr, addr_len);

        if (bytes_sent > 0)
        {
            pthread_mutex_lock(&arq_mutex);
            arq.record_sent_packet(pkt);
            arq.increment_seq_num();
            chunk_offset += bytes_read;
            chunks_sent++;
            total_bytes_sent += bytes_read;
            
            std::string comp_status = is_compressed ? " [COMPRESSED]" : " [UNCOMPRESSED]";
            cout << "📨 [" << arq.get_in_flight_count() << "/" << (int)arq.get_window_size()
                 << "] Seq=" << pkt.seq_num << " offset=" << current_offset
                 << " bytes=" << bytes_read << comp_status << endl;
            pthread_mutex_unlock(&arq_mutex);
        }
        else
        {
            cerr << "❌ sendto failed" << endl;
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
                cout << "✅ ACK for seq=" << ack_pkt.ack_num
                     << " (RTT sample: " << (int)arq.get_ewma_rtt() << "ms)" << endl;

                arq.handle_ack(ack_pkt.ack_num);
                acks_received++;
                
                // Check if transfer is totally done
                if (chunk_offset >= file_size && arq.get_in_flight_count() == 0)
                {
                    transfer_complete = true;
                }
                pthread_mutex_unlock(&arq_mutex);
            }
        }
        else if (WSAGetLastError() != WSAETIMEDOUT && WSAGetLastError() != WSAEWOULDBLOCK)
        {
            // Ignore timeout, loop again
        }
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// Thread 3: Timeout Thread
// ----------------------------------------------------------------------------
void *timeout_thread(void *arg)
{
    while (!transfer_complete)
    {
        Packet retransmit_pkt;
        bool has_timeout = false;

        pthread_mutex_lock(&arq_mutex);
        if (arq.check_for_timeout(retransmit_pkt))
        {
            has_timeout = true;
            arq.mark_loss();
            cout << "⏱️  Timeout! Retransmitting seq=" << retransmit_pkt.seq_num << endl;
        }
        pthread_mutex_unlock(&arq_mutex);

        if (has_timeout)
        {
            struct Packet pkt_send = retransmit_pkt;
            serialize_packet(&pkt_send);
            sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
                   (struct sockaddr *)&server_addr, addr_len);
        }

        Sleep(5); // Check timeouts every 5ms
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// Thread 4: Logger Thread
// ----------------------------------------------------------------------------
void *logger_thread(void *arg)
{
    while (!transfer_complete)
    {
        Sleep(1000); // 1 second interval
        if (transfer_complete) break; // Check again after sleep

        pthread_mutex_lock(&arq_mutex);
        double cwnd = arq.get_congestion_window();
        uint32_t rtt = arq.get_ewma_rtt();
        int in_flight = arq.get_in_flight_count();
        int acks = acks_received;
        int sent = chunks_sent;
        pthread_mutex_unlock(&arq_mutex);

        cout << "📊 [LOGGER] cwnd: " << fixed << setprecision(1) << cwnd 
             << " | RTT: " << rtt << "ms | InFlight: " << in_flight
             << " | ACKs: " << acks << "/" << sent << endl;
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// Main function
// ----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    cout << "📡 LinkFlow Phase 3 Client Starting (Pthread Architecture)..." << endl;

    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <filename>" << endl;
        return 1;
    }

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "❌ WSAStartup failed." << endl;
        return 1;
    }

    filename_str = argv[1];
    file_size = get_file_size(filename_str);

    if (file_size < 0)
    {
        cerr << "❌ Cannot open file: " << filename_str << endl;
        return 1;
    }

    total_chunks = (file_size + DATA_SIZE - 1) / DATA_SIZE;
    cout << "📁 File: " << filename_str << " (" << file_size << " bytes, " << total_chunks << " chunks)" << endl;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        cerr << "❌ Socket creation failed: " << strerror(errno) << endl;
        return 1;
    }
    
    // Set socket timeout to 50ms for non-blocking ACK reception
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50 * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    addr_len = sizeof(server_addr);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
    {
        cerr << "❌ Invalid address" << endl;
        close(sockfd);
        return 1;
    }

    cout << "🪟 Sliding Window Initialized. Mutex Ready." << endl;
    cout << "\n📤 Starting Multithreaded Transmission...\n" << endl;

    auto start_time = chrono::high_resolution_clock::now();

    pthread_t t_sender, t_receiver, t_timeout, t_logger;
    pthread_create(&t_sender, nullptr, sender_thread, nullptr);
    pthread_create(&t_receiver, nullptr, receiver_thread, nullptr);
    pthread_create(&t_timeout, nullptr, timeout_thread, nullptr);
    pthread_create(&t_logger, nullptr, logger_thread, nullptr);

    pthread_join(t_sender, nullptr);
    pthread_join(t_receiver, nullptr);
    pthread_join(t_timeout, nullptr);
    pthread_join(t_logger, nullptr);

    close(sockfd);
    WSACleanup();

    auto end_time = chrono::high_resolution_clock::now();
    double elapsed_sec = chrono::duration_cast<chrono::milliseconds>(end_time - start_time).count() / 1000.0;
    double throughput_mbps = (total_bytes_sent * 8.0) / (elapsed_sec * 1e6);

    cout << "\n✅ File transfer COMPLETE!" << endl;
    cout << "📊 Performance Summary:" << endl;
    cout << "   - Total chunks transmitted: " << chunks_sent << endl;
    cout << "   - Total bytes sent: " << total_bytes_sent << endl;
    cout << "   - ACKs received: " << acks_received << endl;
    cout << "   - Elapsed time: " << fixed << setprecision(2) << elapsed_sec << "s" << endl;
    cout << "   - Throughput: " << throughput_mbps << " Mbps" << endl;

    return 0;
}
