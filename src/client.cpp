// LinkFlow Phase 1.2: UDP Client Implementation
// File: src/client.cpp
// Purpose: Send packets to server and receive ACKs

#include <iostream>
#include <cstring>
#include <iomanip>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "packet.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << "🚀 LinkFlow Client Starting..." << endl;

    // STEP 2: Create UDP Socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        cerr << "❌ Socket creation failed: " << strerror(errno) << endl;
        return 1;
    }
    cout << "✅ UDP socket created (fd=" << sockfd << ")" << endl;

    // STEP 3: Server Address Setup
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);

    // Zero out structure
    memset(&server_addr, 0, sizeof(server_addr));

    // Fill server details
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT); // From packet.h

    // Convert IP address from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
    {
        cerr << "❌ Invalid address" << endl;
        close(sockfd);
        return 1;
    }
    cout << "✅ Server address configured: 127.0.0.1:" << PORT << endl;

    // STEP 4: Create & Fill FIRST Packet
    struct Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    // CORE FIELDS (Phase 1-2)
    pkt.seq_num = 1; // First packet
    pkt.ack_num = 0; // No ACK expected yet
    pkt.type = 0;    // Data packet (0=data, 1=ACK, 2=start, 3=end, 4=NAK)

    // ERROR DETECTION (Phase 2) - Dummy values for now
    pkt.crc32 = 0x12345678; // Placeholder CRC32
    pkt.parity = 1;         // Simple parity bit
    pkt.checksum = 0xABCD;  // Internet checksum placeholder

    // FILE TRANSFER (Phase 2)
    strcpy(pkt.filename, "test.txt"); // Test filename
    pkt.file_size = 1024;             // 1KB dummy file size
    pkt.chunk_offset = 0;             // First chunk at offset 0

    // PERFORMANCE (Phase 2.5-5)
    pkt.stream_id = 0;   // Primary stream
    pkt.window_size = 4; // Go-Back-N window size
    pkt.rtt_sample = 50; // 50ms RTT sample

    // SECURITY (Phase 7) - Zero initialized (not used in Phase 1.2)
    memset(pkt.hmac, 0, sizeof(pkt.hmac));
    memset(pkt.iv, 0, sizeof(pkt.iv));

    // ADVANCED (Phase 5+)
    pkt.fec_parity = 0; // No FEC yet
    pkt.bitmap = 0;     // No selective repeat yet

    // METADATA
    strcpy(pkt.username, "test_user"); // Test username

    // PAYLOAD
    strcpy(pkt.data, "Phase 1.2 Hello! This is the test payload data."); // Test message

    cout << "📦 Packet prepared:" << endl;
    cout << "   CORE FIELDS:" << endl;
    cout << "   - Sequence: " << pkt.seq_num << endl;
    cout << "   - ACK Number: " << pkt.ack_num << endl;
    cout << "   - Type: " << (int)pkt.type << " (DATA)" << endl;
    cout << "\n   ERROR DETECTION:" << endl;
    cout << "   - CRC32: 0x" << hex << pkt.crc32 << dec << endl;
    cout << "   - Parity: " << (int)pkt.parity << endl;
    cout << "   - Checksum: 0x" << hex << pkt.checksum << dec << endl;
    cout << "\n   FILE TRANSFER:" << endl;
    cout << "   - Filename: " << pkt.filename << endl;
    cout << "   - File Size: " << pkt.file_size << " bytes" << endl;
    cout << "   - Chunk Offset: " << pkt.chunk_offset << endl;
    cout << "\n   PERFORMANCE:" << endl;
    cout << "   - Stream ID: " << (int)pkt.stream_id << endl;
    cout << "   - Window Size: " << (int)pkt.window_size << endl;
    cout << "   - RTT Sample: " << pkt.rtt_sample << "ms" << endl;
    cout << "\n   METADATA:" << endl;
    cout << "   - Username: " << pkt.username << endl;
    cout << "\n   PAYLOAD:" << endl;
    cout << "   - Data: " << pkt.data << endl;
    cout << "\n   📏 Total Packet Size: " << sizeof(pkt) << " bytes" << endl;

    // STEP 5: Send Packet
    cout << "\n📤 Sending packet to server..." << endl;
    int bytes_sent = sendto(sockfd, &pkt, sizeof(pkt), 0,
                            (struct sockaddr *)&server_addr, addr_len);

    if (bytes_sent < 0)
    {
        cerr << "❌ sendto failed: " << strerror(errno) << endl;
        close(sockfd);
        return 1;
    }
    cout << "✅ Sent " << bytes_sent << " bytes to server" << endl;

    // STEP 5: Receive ACK
    cout << "\n⏳ Waiting for ACK from server..." << endl;
    struct Packet ack_pkt;
    memset(&ack_pkt, 0, sizeof(ack_pkt));

    int bytes_recv = recvfrom(sockfd, &ack_pkt, sizeof(ack_pkt), 0,
                              (struct sockaddr *)&server_addr, &addr_len);

    if (bytes_recv < 0)
    {
        cerr << "❌ recvfrom failed: " << strerror(errno) << endl;
        close(sockfd);
        return 1;
    }

    cout << "✅ ACK received (" << bytes_recv << " bytes):" << endl;
    cout << "   - ACK Number: " << ack_pkt.ack_num << endl;
    cout << "   - Type: " << ack_pkt.type << endl;

    // Verify ACK matches sent packet
    if (ack_pkt.ack_num == pkt.seq_num)
    {
        cout << "✅ ACK verification PASSED (seq=" << pkt.seq_num << ")" << endl;
    }
    else
    {
        cout << "⚠️  ACK mismatch: expected " << pkt.seq_num
             << ", got " << ack_pkt.ack_num << endl;
    }

    // STEP 6: Cleanup
    close(sockfd);
    cout << "\n🎉 Phase 1.2 COMPLETE!" << endl;
    cout << "📊 Summary:" << endl;
    cout << "   - Socket operations: SUCCESS" << endl;
    cout << "   - Packet transmission: SUCCESS" << endl;
    cout << "   - ACK reception: SUCCESS" << endl;

    return 0;
}
