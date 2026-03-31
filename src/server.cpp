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
    cout << " LinkFlow Phase 3 Server Starting (Advanced Features)..." << endl;

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
                    cout << "\n Checkpoint loaded! Resuming transfer of " << current_filename << " from seq=" << resume_seq << endl;
                    expected_seq_num = resume_seq;

                    // 2. Feature: Rolling Hash Comparison
                    cout << " Computing rolling hashes for delta transfer comparison..." << endl;
                    vector<uint32_t> hashes = compute_file_hashes(filepath);
                    cout << "   -> Found " << hashes.size() << " existing chunk hashes in received/." << endl;
                }
                else
                {
                    expected_seq_num = 1;
                }
                connection_initialized = true;
            }

            // CRC Validation
            uint32_t expected_crc = pkt.crc32;
            bool crc_valid = false;
            size_t actual_compressed_len = DATA_SIZE;

            for (size_t len = 0; len <= DATA_SIZE; len++)
            {
                if (calculate_crc32(reinterpret_cast<unsigned char *>(pkt.data), len) == expected_crc)
                {
                    crc_valid = true;
                    actual_compressed_len = len;
                    break;
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

                cout << " Received seq=" << pkt.seq_num << " (Individual SR ACK Sent, Bitmap=" << ack_pkt.bitmap << ")" << endl;

                // File Reassembly Logic
                if (pkt.seq_num == expected_seq_num)
                {
                    string out_filepath = "received/recv_" + current_filename;

                    char decompressed_data[DATA_SIZE];
                    size_t decompressed_len = DATA_SIZE;
                    int decomp_res = decompress_data(pkt.data, actual_compressed_len, decompressed_data, decompressed_len);

                    if (decomp_res != 0)
                    {
                        memcpy(decompressed_data, pkt.data, actual_compressed_len);
                        decompressed_len = actual_compressed_len;
                    }

                    size_t bytes_to_write = decompressed_len;
                    if (pkt.type == 3)
                    {
                        size_t remaining = pkt.file_size - pkt.chunk_offset;
                        if (remaining < decompressed_len)
                            bytes_to_write = remaining;
                    }

                    ofstream outfile;
                    if (pkt.seq_num == 1 && expected_seq_num == 1)
                    {
                        outfile.open(out_filepath, ios::binary | ios::trunc);
                    }
                    else
                    {
                        outfile.open(out_filepath, ios::binary | ios::app);
                    }

                    if (outfile.is_open())
                    {
                        outfile.write(decompressed_data, bytes_to_write);
                        outfile.close();
                    }

                    expected_seq_num++;

                    // Save Checkpoint after successful write
                    save_checkpoint(current_filename, expected_seq_num);

                    // Process Buffered Out-Of-Order Packets
                    while (receive_buffer.find(expected_seq_num) != receive_buffer.end())
                    {
                        Packet buffered_pkt = receive_buffer[expected_seq_num];

                        size_t buf_comp_len = DATA_SIZE;
                        for (size_t len = 0; len <= DATA_SIZE; len++)
                        {
                            if (calculate_crc32(reinterpret_cast<unsigned char *>(buffered_pkt.data), len) == buffered_pkt.crc32)
                            {
                                buf_comp_len = len;
                                break;
                            }
                        }

                        char buf_decomp_data[DATA_SIZE];
                        size_t buf_decomp_len = DATA_SIZE;
                        if (decompress_data(buffered_pkt.data, buf_comp_len, buf_decomp_data, buf_decomp_len) != 0)
                        {
                            memcpy(buf_decomp_data, buffered_pkt.data, buf_comp_len);
                            buf_decomp_len = buf_comp_len;
                        }

                        size_t write_len = buf_decomp_len;
                        if (buffered_pkt.type == 3)
                        {
                            size_t remaining = buffered_pkt.file_size - buffered_pkt.chunk_offset;
                            if (remaining < buf_decomp_len)
                                write_len = remaining;
                        }

                        outfile.open(out_filepath, ios::binary | ios::app);
                        if (outfile.is_open())
                        {
                            outfile.write(buf_decomp_data, write_len);
                            outfile.close();
                        }

                        receive_buffer.erase(expected_seq_num);
                        expected_seq_num++;

                        save_checkpoint(current_filename, expected_seq_num);

                        if (buffered_pkt.type == 3)
                        {
                            is_receiving = false;
                            cout << " File transfer completed successfully!" << endl;
                            remove("resume.json"); // clear checkpoint on completion
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
