// LinkFlow Phase 4: Selective Repeat (SR) ARQ Header
// File: src/headers/selectrepeat.h
// Purpose: Per-packet timeout tracking with ACK bitmap window management

#ifndef SELECTREPEAT_H
#define SELECTREPEAT_H

#include "packet.h"
#include <map>
#include <bitset>
#include <ctime>
#include <pthread.h>
#include <cstdint>
#include <cstring>

// Constants for Selective Repeat ARQ
#define SR_WINDOW_SIZE 4096     // Sliding window size
#define SR_PACKET_TIMEOUT_MS 50 // Individual packet timeout (ms)
#define SR_MAX_RETRANSMITS 200  // Max retransmit attempts per packet
#define ACK_BATCH_SIZE 30       // Server sends SACK every N in-order packets

// Structure to wrap Packet with timeout tracking for SR ARQ
struct WindowPacket
{
    SlimDataPacket pkt;   // The actual packet data
    timespec send_time;   // Send timestamp (CLOCK_MONOTONIC)
    bool is_acked;        // Has this packet been acknowledged?
    int retransmit_count; // Number of retransmission attempts

    // Constructor
    WindowPacket() : is_acked(false), retransmit_count(0)
    {
        memset(&pkt, 0, sizeof(SlimDataPacket));
        memset(&send_time, 0, sizeof(timespec));
    }
};

// Selective Repeat ARQ Manager with Per-Packet Timers
class SelectiveRepeatARQ
{
private:
    // Window variables
    uint32_t send_base;                     // Oldest unacked packet sequence
    uint32_t next_seq_num;                  // Next packet to send
    std::bitset<SR_WINDOW_SIZE> ack_bitmap; // ACK status: bit i = acked(base+i)?

    // Packet buffer: map from seq_num to WindowPacket — [FIX Bug 4] uint32_t key
    std::map<uint32_t, WindowPacket> window_buffer;

    // Thread synchronization
    mutable pthread_mutex_t window_mutex; // Protects window_buffer and state variables

    // RTT & Timeout (optional congestion control integration)
    uint32_t rto_ms; // Retransmission timeout in milliseconds

public:
    // Constructor & Destructor
    SelectiveRepeatARQ();
    ~SelectiveRepeatARQ();

    // === Window Management ===
    bool can_send_packet() const;
    uint32_t get_send_base() const { return send_base; }
    uint32_t get_next_seq_num() const { return next_seq_num; }
    void set_start_seq(uint32_t seq);
    void increment_seq_num() { next_seq_num++; }
    int get_in_flight_count() const;

    // === Packet Buffer Management ===
    // Record a packet as sent (store in window_buffer with current timestamp)
    void record_sent_packet(const SlimDataPacket &pkt);
    void record_sent_packet(const StartPacket &pkt);
    // Retrieve a packet by sequence number (for retransmission)
    bool get_packet_for_retransmit(uint32_t seq_num, SlimDataPacket &pkt_out);
    bool get_packet_for_retransmit(uint32_t seq_num, StartPacket &pkt_out);
    // === ACK Processing ===
    // Handle individual ACK for a specific packet (not cumulative)
    void handle_ack(uint32_t ack_num);

    // Hybrid SACK: slide the window to cum_ack in one shot.
    // Erases all buffered packets with seq < cum_ack, advances send_base,
    // and resets the ack_bitmap so the caller can re-populate it via
    // mark_packet_acked() for any bitmap-indicated out-of-order packets.
    void handle_cumulative_ack(uint32_t cum_ack);

    // Mark packet as acknowledged
    void mark_packet_acked(uint32_t seq_num);

    // Advance send_base when front of window is fully acked
    void advance_window();

    // === Timeout & Retransmission ===
    // Check if any packet in the window has timed out
    // Returns the sequence number of the first timed-out packet, or 0 if none
    uint32_t check_for_timeout();

    // Prepare packet for retransmission (updates send_time and retransmit_count)
    bool prepare_retransmit(uint32_t seq_num, SlimDataPacket &pkt_out);
    bool prepare_retransmit(uint32_t seq_num, StartPacket &pkt_out);
    // === Statistics & Debugging ===
    uint32_t get_window_size() const { return SR_WINDOW_SIZE; }
    uint8_t get_acked_count() const { return ack_bitmap.count(); }
    bool is_window_empty() const { return window_buffer.empty(); }
    bool is_packet_acked(uint32_t seq_num) const;

    // Print current window state (for debugging)
    void print_window_state() const;
};

#endif // SELECTREPEAT_H
