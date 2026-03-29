// LinkFlow Phase 3: UDP Client with Go-Back-N, Compression & Congestion Control
// File: src/client.cpp
// Purpose: High-throughput file transfer with sliding window and AIMD

#include <iostream>
#include <cstring>
#include <iomanip>
#include <unistd.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <fstream>
#include <chrono>
#include <zlib.h>
#include "./headers/packet.h"
#include "./headers/arq.h"

using namespace std;

const int RCVTIMEO_MS = 50; // Non-blocking receive timeout (50ms)

// Function to read a file and return its size
long get_file_size(const char *filename)
{
    ifstream file(filename, ios::binary | ios::ate);
    if (!file.is_open())
        return -1;
    return file.tellg();
}

// Function to read file chunk at given offset
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

int main(int argc, char *argv[])
{
    cout << "📡 LinkFlow Phase 3 Client Starting (Go-Back-N)..." << endl;

    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <filename>" << endl;
        return 1;
    }

    const char *filename = argv[1];
    long file_size = get_file_size(filename);

    if (file_size < 0)
    {
        cerr << "❌ Cannot open file: " << filename << endl;
        return 1;
    }

    cout << "📁 File: " << filename << " (" << file_size << " bytes)" << endl;

    // STEP 1: Create UDP Socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        cerr << "❌ Socket creation failed: " << strerror(errno) << endl;
        return 1;
    }
    cout << "✅ UDP socket created (fd=" << sockfd << ")" << endl;

    // Set socket timeout to 50ms for non-blocking ACK reception
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RCVTIMEO_MS * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    // STEP 2: Server Address Setup
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
    {
        cerr << "❌ Invalid address" << endl;
        close(sockfd);
        return 1;
    }
    cout << "🔗 Server address: 127.0.0.1:" << PORT << endl;

    // STEP 3: Initialize Go-Back-N ARQ
    GoBackNARQ arq;
    cout << "🪟 Sliding Window (Go-Back-N) initialized: N=" << (int)WINDOW_SIZE << endl;
    cout << "📦 Compression: zlib enabled" << endl;

    auto start_time = chrono::high_resolution_clock::now();
    uint32_t chunk_offset = 0;
    int total_chunks = (file_size + DATA_SIZE - 1) / DATA_SIZE;
    int chunks_sent = 0;
    int acks_received = 0;
    uint64_t total_bytes_sent = 0;

    cout << "\n📤 Starting Go-Back-N transmission (" << total_chunks << " chunks)...\n"
         << endl;

    while (chunk_offset < file_size || arq.get_in_flight_count() > 0)
    {
        // SEND: Fill window with new packets
        while (chunk_offset < file_size && arq.can_send_packet())
        {
            // Read chunk
            char chunk_data[DATA_SIZE];
            memset(chunk_data, 0, DATA_SIZE);
            size_t bytes_read = 0;

            if (!read_file_chunk(filename, chunk_offset, chunk_data, bytes_read))
            {
                cerr << "❌ Error reading file at offset " << chunk_offset << endl;
                close(sockfd);
                return 1;
            }

            // Compress data
            char compressed_data[DATA_SIZE];
            size_t compressed_len = DATA_SIZE;
            int compress_ret = compress_data(chunk_data, bytes_read,
                                             compressed_data, compressed_len);

            if (compress_ret != 0)
            {
                cout << "⚠️  Compression failed, using uncompressed" << endl;
                memcpy(compressed_data, chunk_data, bytes_read);
                compressed_len = bytes_read;
            }

            // Create packet
            struct Packet pkt;
            memset(&pkt, 0, sizeof(pkt));

            pkt.seq_num = arq.get_next_seq_num();
            pkt.ack_num = 0;
            pkt.type = (chunk_offset + bytes_read >= file_size) ? 3 : 0; // 3=END

            strcpy(pkt.filename, filename);
            pkt.file_size = file_size;
            pkt.chunk_offset = chunk_offset;

            // CRC32 of compressed data
            pkt.crc32 = calculate_crc32((unsigned char *)compressed_data, compressed_len);

            // Copy compressed payload
            memcpy(pkt.data, compressed_data, compressed_len);

            strcpy(pkt.username, "client_user");
            pkt.stream_id = 0;
            pkt.window_size = arq.get_window_size();
            pkt.rtt_sample = (uint16_t)arq.get_ewma_rtt();

            // Serialize
            struct Packet pkt_send = pkt;
            serialize_packet(&pkt_send);

            // Send
            int bytes_sent = sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
                                    (struct sockaddr *)&server_addr, addr_len);

            if (bytes_sent > 0)
            {
                cout << "📨 [" << arq.get_in_flight_count() + 1 << "/" << (int)arq.get_window_size()
                     << "] Seq=" << pkt.seq_num << " offset=" << chunk_offset
                     << " bytes=" << bytes_read << " (compressed: " << compressed_len << ")" << endl;

                arq.record_sent_packet(pkt);
                arq.increment_seq_num();
                chunk_offset += bytes_read;
                chunks_sent++;
                total_bytes_sent += bytes_read;
            }
            else
            {
                cerr << "❌ sendto failed" << endl;
                close(sockfd);
                return 1;
            }
        }

        // RECEIVE: Check for ACKs without blocking
        struct Packet ack_pkt;
        memset(&ack_pkt, 0, sizeof(ack_pkt));

        int bytes_recv = recvfrom(sockfd, (char *)&ack_pkt, sizeof(ack_pkt), 0,
                                  (struct sockaddr *)&server_addr, &addr_len);

        if (bytes_recv > 0)
        {
            deserialize_packet(&ack_pkt);

            if (ack_pkt.type == 1) // ACK
            {
                cout << "✅ ACK for seq=" << ack_pkt.ack_num
                     << " (RTT sample: " << (int)arq.get_ewma_rtt() << "ms)" << endl;

                arq.handle_ack(ack_pkt.ack_num);
                acks_received++;
            }
        }
        else if (WSAGetLastError() != WSAETIMEDOUT)
        {
            // Real error (not just timeout)
            // Ignore timeout, continue sending
        }

        // CHECK RETRANSMISSION TIMEOUT
        Packet retransmit_pkt;
        if (arq.check_for_timeout(retransmit_pkt))
        {
            cout << "⏱️  Timeout! Retransmitting seq=" << retransmit_pkt.seq_num << endl;
            struct Packet pkt_send = retransmit_pkt;
            serialize_packet(&pkt_send);

            sendto(sockfd, (const char *)&pkt_send, sizeof(pkt_send), 0,
                   (struct sockaddr *)&server_addr, addr_len);

            arq.mark_loss();
        }
    }

    close(sockfd);

    auto end_time = chrono::high_resolution_clock::now();
    double elapsed_sec = chrono::duration_cast<chrono::milliseconds>(
                             end_time - start_time)
                             .count() /
                         1000.0;

    double throughput_mbps = (total_bytes_sent * 8.0) / (elapsed_sec * 1e6);

    cout << "\n✅ File transfer COMPLETE!" << endl;
    cout << "📊 Performance Summary:" << endl;
    cout << "   - Total chunks transmitted: " << chunks_sent << endl;
    cout << "   - Total bytes sent: " << total_bytes_sent << endl;
    cout << "   - ACKs received: " << acks_received << endl;
    cout << "   - Elapsed time: " << fixed << setprecision(2) << elapsed_sec << "s" << endl;
    cout << "   - Throughput: " << throughput_mbps << " Mbps" << endl;
    cout << "   - Final cwnd: " << fixed << setprecision(1) << arq.get_congestion_window() << endl;
    cout << "   - Final RTT: " << (int)arq.get_ewma_rtt() << "ms" << endl;

    return 0;
}
