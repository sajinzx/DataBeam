#ifndef ARQ_H
#define ARQ_H

#include <stdint.h>
#include <deque>
#include <chrono>
#include "packet.h"

using namespace std;

const uint8_t WINDOW_SIZE = 8;    // Go-Back-N window size
const double ALPHA_RTT = 0.125;   // EMA smoothing factor (1/8)
const double BETA_RTTVAR = 0.25;  // RTT variance smoothing factor
const int INITIAL_RTO = 500;      // Initial RTO: 500ms
const double AIMD_INCREASE = 1.0; // Additive Increase: +1 packet per RTT
const double AIMD_DECREASE = 0.5; // Multiplicative Decrease: * 0.5 on loss

// Structure to track sent packets
struct SentPacket
{
    Packet pkt;
    chrono::high_resolution_clock::time_point send_time;
    int retransmit_count;
};

// Go-Back-N ARQ Manager
class GoBackNARQ
{
private:
    uint16_t send_base;            // Oldest unacknowledged packet
    uint16_t next_seq_num;         // Next packet to send
    deque<SentPacket> sent_buffer; // Buffer of sent packets

    // RTT tracking
    uint32_t srtt_us;   // Smoothed RTT in microseconds
    uint32_t rttvar_us; // RTT variance in microseconds
    uint32_t rto_ms;    // Retransmission timeout in milliseconds

    // Congestion control (AIMD)
    double congestion_window; // cwnd: number of packets in flight
    double threshold;         // ssthresh: slow start threshold
    bool in_slow_start;       // Slow start state

public:
    GoBackNARQ();

    // Window management
    bool can_send_packet() const;
    uint16_t get_send_base() const { return send_base; }
    uint16_t get_next_seq_num() const { return next_seq_num; }
    uint8_t get_window_size() const;
    int get_in_flight_count() const { return sent_buffer.size(); }

    // Sending
    void record_sent_packet(const Packet &pkt);
    void increment_seq_num() { next_seq_num++; }

    // ACK handling
    void handle_ack(uint16_t ack_num);

    // Retransmission
    bool check_for_timeout(Packet &pkt_to_retransmit);
    void mark_loss();

    // RTT measurement
    void update_rtt(uint16_t seq_num);
    uint32_t get_rto_ms() const { return rto_ms; }
    double get_ewma_rtt() const { return srtt_us / 1000.0; }

    // Congestion window
    double get_congestion_window() const { return congestion_window; }
    void increase_window();
    void decrease_window();
};

// Compression utilities
int compress_data(const char *input, size_t input_len, char *output, size_t &output_len);
int decompress_data(const char *input, size_t input_len, char *output, size_t &output_len);

#endif
