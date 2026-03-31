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
#include "./headers/packet.h"
#include "./headers/arq.h"
#include "./headers/compress.h"
#include "./headers/crchw.h"
using namespace std;

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

// Helper — CRC check + decompress in one place, used for both paths
// Returns true on success, fills out decoded
static bool decode_packet(const Packet &pkt,
                          size_t compressed_len,
                          DecodedPacket &out)
{
    // CRC check
    uint32_t computed = calculate_crc32(
        reinterpret_cast<const unsigned char *>(pkt.data), compressed_len);
    if (computed != pkt.crc32)
    {
        cerr << "[SERVER] CRC FAIL seq=" << pkt.seq_num
             << " expected=0x" << hex << pkt.crc32
             << " got=0x" << computed << dec << endl;
        return false;
    }

    // Decompress
    out.data_len = sizeof(out.data);
    int ret = decompress_data(pkt.data, compressed_len,
                              out.data, out.data_len);
    if (ret != 0)
    {
        cerr << "[SERVER] Decomp failed seq=" << pkt.seq_num
             << " err=" << ret << endl;
        return false;
    }

    out.type = pkt.type;
    out.file_size = pkt.file_size;
    out.chunk_offset = pkt.chunk_offset;
    return true;
}

int main()
{
    cout << " LinkFlow Phase 4 Server Starting..." << endl;
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
    int buf_size = 32 * 1024 * 1024;
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
    DecodedPacket *fast_buffer[512] = {nullptr};

    ofstream outfile;

    while (is_receiving)
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));

        int bytes_recv = recvfrom(sockfd, (char *)&pkt, sizeof(pkt), 0,
                                  (struct sockaddr *)&client_addr, &addr_len);

        if (bytes_recv <= 0)
            continue; // timeout or error — loop again

        deserialize_packet(&pkt);

        // ---- New file / connection init ------------------------------------
        if (!connection_initialized || string(pkt.filename) != current_filename)
        {
            if (outfile.is_open())
            {
                outfile.flush();
                outfile.close();
            }

            current_filename = pkt.filename;
            out_filepath = "received/recv_" + current_filename; // FIX: assign outer

            outfile.open(out_filepath, ios::binary | ios::out | ios::trunc);
            if (!outfile.is_open())
            {
                cerr << "[SERVER] Cannot create: " << out_filepath << endl;
                return 1;
            }
            cout << "[SERVER] Opened: " << out_filepath << endl;

            uint16_t resume_seq = load_checkpoint(current_filename);
            expected_seq_num = (resume_seq > 1) ? resume_seq : 1;
            memset(fast_buffer, 0, sizeof(fast_buffer)); // Clear buffer on new file
            connection_initialized = true;
        }

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
        {
            Packet ack_pkt;
            memset(&ack_pkt, 0, sizeof(ack_pkt));
            ack_pkt.type = 1;
            ack_pkt.ack_num = pkt.seq_num;
            ack_pkt.bitmap = (uint16_t)(1u << (pkt.seq_num % 16));
            serialize_packet(&ack_pkt);
            sendto(sockfd, (const char *)&ack_pkt, sizeof(ack_pkt), 0,
                   (struct sockaddr *)&client_addr, addr_len);
        }

        // ---- Decode once — CRC + decompress --------------------------------
        // FIX: decode_packet does CRC + decompress exactly once per packet
        // Result goes into decoded. If it's out-of-order it goes into the
        // buffer as a DecodedPacket — no second CRC/decompress on drain.
        DecodedPacket decoded;
        if (!decode_packet(pkt, compressed_len, decoded))
            continue; // CRC fail or decomp fail — client will retransmit

        // ---- Buffer or write -----------------------------------------------
        if (pkt.seq_num == expected_seq_num)
        {
            // In-order — write immediately
            // FIX: clamp write_len to remaining file bytes (fixes file size bug)
            size_t remaining = (size_t)decoded.file_size - decoded.chunk_offset;
            size_t write_len = min(decoded.data_len, remaining);

            outfile.write(decoded.data, (streamsize)write_len);
            if (outfile.fail())
            {
                cerr << "[SERVER] Write failed seq=" << pkt.seq_num << endl;
                outfile.clear();
            }

            expected_seq_num++;
            save_checkpoint(current_filename, expected_seq_num);

            // ---- Drain buffer — NO decode work here, already done ----------
            while (fast_buffer[expected_seq_num % 512] != nullptr)
            {
                DecodedPacket &bp = *fast_buffer[expected_seq_num % 512];

                size_t bp_remaining = (size_t)bp.file_size - bp.chunk_offset;
                size_t bp_write_len = min(bp.data_len, bp_remaining);

                outfile.write(bp.data, (streamsize)bp_write_len);
                if (outfile.fail())
                {
                    cerr << "[SERVER] Write failed buffered seq="
                         << expected_seq_num << endl;
                    outfile.clear();
                    break;
                }

                bool is_end = (bp.type == 3);
                fast_buffer[expected_seq_num % 512] = nullptr;
                expected_seq_num++;
                save_checkpoint(current_filename, expected_seq_num);

                if (is_end)
                {
                    is_receiving = false;
                    connection_initialized = false;
                    outfile.flush();
                    outfile.close();
                    remove("resume.json");
                    cout << "[SERVER] Transfer complete: " << out_filepath << endl;
                    break;
                }
            }

            // END on in-order path
            if (decoded.type == 3 && is_receiving)
            {
                is_receiving = false;
                connection_initialized = false;
                outfile.flush();
                outfile.close();
                remove("resume.json");
                cout << "[SERVER] Transfer complete: " << out_filepath << endl;
            }
        }
        else if (pkt.seq_num > expected_seq_num)
        {
            // Out-of-order — store decoded result, not raw packet
            // FIX: buffer holds DecodedPacket — drain loop just writes, no decode
            if (fast_buffer[pkt.seq_num % 512] == nullptr)
            {
                fast_buffer[pkt.seq_num % 512] = new DecodedPacket(decoded);
            }
        }
        // pkt.seq_num < expected_seq_num → duplicate, already processed, ignore
    }

    outfile.flush();
    outfile.close();
    closesocket(sockfd);
    WSACleanup();
    return 0;
}
