// LinkFlow Phase 3: UDP Server (Advanced Receiver Features)
// File: src/server.cpp

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>

// Windows system + sockets
#include <winsock2.h>
#include <windows.h>

#include <ws2tcpip.h>

// File/stat support (Windows-compatible)
#include <sys/stat.h>

// Your project headers
#include "./headers/packet.h"
#include "./headers/arq.h"
#include "./headers/compress.h"
#include "./headers/crchw.h"
using namespace std;

// ----------------------------------------------------------------------------
// Utilities
// ----------------------------------------------------------------------------
void create_received_dir()
{
    struct stat st = {0};
    if (stat("received", &st) == -1)
    {
        mkdir("received");
    }
}

// ----------------------------------------------------------------------------
// Feature: Checkpoint Loading (resume.json)
// ----------------------------------------------------------------------------
void save_checkpoint(const string &filename, uint16_t expected_seq)
{
    ofstream out("resume.json");
    if (out.is_open())
    {
        out << "{\n  \"filename\": \"" << filename << "\",\n";
        out << "  \"expected_seq\": " << expected_seq << "\n}\n";
        out.close();
    }
}

uint16_t load_checkpoint(const string &target_filename)
{
    ifstream in("resume.json");
    if (!in.is_open())
        return 1;

    stringstream buffer;
    buffer << in.rdbuf();
    string content = buffer.str();

    size_t f_pos = content.find("\"filename\"");
    size_t s_pos = content.find("\"expected_seq\"");

    if (f_pos != string::npos && s_pos != string::npos)
    {
        size_t f_start = content.find("\"", f_pos + 10) + 1;
        size_t f_end = content.find("\"", f_start);
        string saved_file = content.substr(f_start, f_end - f_start);

        size_t s_start = content.find(":", s_pos) + 1;
        while (s_start < content.length() && isspace(content[s_start]))
            s_start++;
        size_t s_end = content.find(",", s_start);
        if (s_end == string::npos)
            s_end = content.find("}", s_start);
        while (s_end > s_start && isspace(content[s_end - 1]))
            s_end--;

        uint16_t seq = stoi(content.substr(s_start, s_end - s_start));

        if (saved_file == target_filename)
            return seq;
    }
    return 1;
}

// ----------------------------------------------------------------------------
// Feature: Rolling Hash Comparison (Delta Transfer)
// ----------------------------------------------------------------------------
vector<uint32_t> compute_file_hashes(const string &filepath)
{
    vector<uint32_t> hashes;
    ifstream file(filepath, ios::binary);
    if (!file.is_open())
        return hashes;

    char buffer[DATA_SIZE];
    while (file.read(buffer, DATA_SIZE) || file.gcount() > 0)
    {
        size_t bytes_read = file.gcount();
        uint32_t chunk_crc = calculate_crc32(reinterpret_cast<unsigned char *>(buffer), bytes_read);
        hashes.push_back(chunk_crc);
    }
    file.close();
    return hashes;
}

// ----------------------------------------------------------------------------
// Main Server
// ----------------------------------------------------------------------------
int main()
{
    cout << " LinkFlow Phase 4 Server Starting (Advanced Features)..." << endl;

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
        cerr << " Socket creation failed." << endl;
        return 1;
    }
    cout << " UDP socket created (fd=" << sockfd << ")" << endl;
    int buffer_size = 16 * 1024 * 1024; // 16 MB
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&buffer_size, sizeof(buffer_size));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&buffer_size, sizeof(buffer_size));
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
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
    map<uint16_t, Packet> receive_buffer;
    bool is_receiving = true;
    string current_filename = "";
    bool connection_initialized = false;
    ofstream outfile; // Declare outside the loop
    string out_filepath = "received/recv_" + current_filename;
    // Inside your metadata/initialization logic (when you get the filename)
    outfile.open(out_filepath, ios::binary | ios::trunc);
    if (!outfile.is_open())
    {
        cerr << "[SERVER] Fatal Error: Cannot create " << out_filepath << endl;
        return 1;
    }

    while (is_receiving)
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));

        int bytes_recv = recvfrom(sockfd, (char *)&pkt, sizeof(pkt), 0,
                                  (struct sockaddr *)&client_addr, &addr_len);

        if (bytes_recv > 0)
        {
            deserialize_packet(&pkt);

            // 1. Feature: Checkpoint Loading (resume.json)
            if (!connection_initialized || pkt.filename != current_filename)
            {
                current_filename = pkt.filename;
                string filepath = "received/recv_" + current_filename;

                uint16_t resume_seq = load_checkpoint(current_filename);
                if (resume_seq > 1)
                {
                    // cout << "\n Checkpoint loaded! Resuming transfer of " << current_filename << " from seq=" << resume_seq << endl;
                    expected_seq_num = resume_seq;

                    // 2. Feature: Rolling Hash Comparison
                    // cout << " Computing rolling hashes for delta transfer comparison..." << endl;
                    vector<uint32_t> hashes = compute_file_hashes(filepath);
                    // cout << "   -> Found " << hashes.size() << " existing chunk hashes in received/." << endl;
                }
                else
                {
                    expected_seq_num = 1;
                }
                connection_initialized = true;
            }

            size_t actual_compressed_len = pkt.data_len;

            // Sanity check — reject malformed packets before touching data
            bool crc_valid = false;

            if (actual_compressed_len == 0 || actual_compressed_len > (size_t)(DATA_SIZE + 1))
            {
                cerr << "[SERVER] Invalid data_len=" << actual_compressed_len
                     << " for seq=" << pkt.seq_num << " — dropping" << endl;
            }
            else
            {
                uint32_t computed_crc = calculate_crc32(
                    reinterpret_cast<const unsigned char *>(pkt.data),
                    actual_compressed_len);

                if (computed_crc == pkt.crc32)
                {
                    crc_valid = true;
                }
                else
                {
                    cerr << "[SERVER] CRC FAIL seq=" << pkt.seq_num
                         << " expected=0x" << hex << pkt.crc32
                         << " got=0x" << computed_crc << dec << endl;
                }
            }
            if (crc_valid)
            {
                // 3. Feature: Individual ACKs (Selective Repeat Support)
                Packet ack_pkt;
                memset(&ack_pkt, 0, sizeof(ack_pkt));
                ack_pkt.type = 1;              // ACK
                ack_pkt.ack_num = pkt.seq_num; // Individual ACK

                // Set Selective Repeat Bitmap
                ack_pkt.bitmap = (1 << (pkt.seq_num % 16));

                serialize_packet(&ack_pkt);

                sendto(sockfd, (const char *)&ack_pkt, sizeof(ack_pkt), 0,
                       (struct sockaddr *)&client_addr, addr_len);

                // cout << " Received seq=" << pkt.seq_num << " (Individual SR ACK Sent, Bitmap=" << ack_pkt.bitmap << ")" << endl;

                // File Reassembly Logic
                if (pkt.seq_num == expected_seq_num)
                {

                    // ---- Decompress (handles both raw and deflated via marker byte) ------------
                    char decompressed[DATA_SIZE];
                    size_t decompressed_len = sizeof(decompressed);

                    // actual_compressed_len must include the 1-byte marker prefix
                    int decomp_result = decompress_data(
                        pkt.data,
                        actual_compressed_len,
                        decompressed,
                        decompressed_len);

                    if (decomp_result != 0)
                    {
                        cerr << "[SERVER] Decompression failed seq=" << pkt.seq_num
                             << " err=" << decomp_result << endl;
                        continue; // SR ARQ will retransmit
                    }

                    // ---- Write to file ---------------------------------------------------------
                    {
                        // First packet ever → truncate (create fresh file)
                        // All subsequent    → append

                        // BUG FIX: write from decompressed buffer, not decomp_result (int)
                        // decompressed_len is set by decompress_data to the actual output size
                        outfile.write(decompressed, (streamsize)decompressed_len);

                        if (outfile.fail())
                        {
                            cerr << "[SERVER] File write failed at seq=" << pkt.seq_num << endl;
                        }
                    } // ofstream destructor closes the file here — no manual close() needed

                    expected_seq_num++;

                    // Save Checkpoint after successful write
                    save_checkpoint(current_filename, expected_seq_num);

                    // ---- Process buffered out-of-order packets (SR reordering) ----------------
                    while (receive_buffer.find(expected_seq_num) != receive_buffer.end())
                    {
                        Packet &buffered_pkt = receive_buffer[expected_seq_num];

                        // ----------------------------------------------------------------
                        // BUG FIX 1: Remove the CRC brute-force loop entirely.
                        // compressed length = total packet data - 1 marker byte.
                        // The actual payload length is derived from file geometry:
                        //   last chunk  → file_size - chunk_offset  (may be < DATA_SIZE)
                        //   other chunks → DATA_SIZE
                        // compress_data stores the marker byte at offset 0, so we pass
                        // the full data field; decompress_data reads the marker itself.
                        // ----------------------------------------------------------------
                        // Use data_len from packet directly — no geometry guessing needed
                        size_t buf_comp_len = buffered_pkt.data_len;

                        // Sanity check before CRC
                        if (buf_comp_len == 0 || buf_comp_len > DATA_SIZE + 1)
                        {
                            cerr << "[SERVER] Invalid data_len=" << buf_comp_len
                                 << " in buffered seq=" << expected_seq_num << " — dropping" << endl;
                            receive_buffer.erase(expected_seq_num);
                            break;
                        }

                        // CRC verification — verify BEFORE decompressing
                        uint32_t actual_crc = calculate_crc32(
                            reinterpret_cast<const unsigned char *>(buffered_pkt.data),
                            buf_comp_len);

                        if (actual_crc != buffered_pkt.crc32)
                        {
                            cerr << "[SERVER] CRC mismatch on buffered seq=" << expected_seq_num
                                 << " expected=0x" << hex << buffered_pkt.crc32
                                 << " got=0x" << actual_crc << dec << endl;

                            receive_buffer.erase(expected_seq_num);
                            break;
                        }

                        // ----------------------------------------------------------------
                        // Decompress — marker byte tells decompress_data which path to take
                        // BUG FIX 2: buffer sized DATA_SIZE + 1 for safety
                        // ----------------------------------------------------------------
                        char buf_decomp_data[DATA_SIZE + 1];
                        size_t buf_decomp_len = sizeof(buf_decomp_data);

                        int decomp_ret = decompress_data(
                            buffered_pkt.data,
                            buf_comp_len,
                            buf_decomp_data,
                            buf_decomp_len);

                        // BUG FIX 3: no silent fallback — drop and let SR retransmit
                        if (decomp_ret != 0)
                        {
                            cerr << "[SERVER] Decompression failed on buffered seq="
                                 << expected_seq_num
                                 << " err=" << decomp_ret << endl;

                            receive_buffer.erase(expected_seq_num);
                            break;
                        }

                        // ----------------------------------------------------------------
                        // BUG FIX 4: always clamp write_len to remaining file bytes,
                        // not just on type == 3
                        // ----------------------------------------------------------------
                        size_t remaining = buffered_pkt.file_size - buffered_pkt.chunk_offset;
                        size_t write_len = min(buf_decomp_len, remaining);

                        // ----------------------------------------------------------------
                        // Write to file
                        // ----------------------------------------------------------------
                        {

                            outfile.write(buf_decomp_data, (streamsize)write_len);

                            if (outfile.fail())
                            {
                                cerr << "[SERVER] Write failed for buffered seq="
                                     << expected_seq_num << endl;
                                break;
                            }
                        } // auto-close on scope exit

                        // ----------------------------------------------------------------
                        // Advance state
                        // ----------------------------------------------------------------
                        receive_buffer.erase(expected_seq_num);
                        expected_seq_num++;

                        save_checkpoint(current_filename, expected_seq_num);

                        if (buffered_pkt.type == 3)
                        {
                            is_receiving = false;
                            cout << "[SERVER] File transfer completed: " << out_filepath << endl;
                            remove("resume.json");
                            break; // END packet processed — stop draining
                        }
                    }

                    if (pkt.type == 3)
                    {
                        is_receiving = false;
                        cout << " File transfer completed successfully!" << endl;
                        remove("resume.json"); // clear checkpoint on completion
                    }
                }
                else if (pkt.seq_num > expected_seq_num)
                {
                    // Buffer out-of-order packets
                    receive_buffer[pkt.seq_num] = pkt;
                }
            }
            else
            {
                cout << " CRC Validation failed for seq=" << pkt.seq_num << endl;
            }
        }
    }

    close(sockfd);
    WSACleanup();
    return 0;
}
