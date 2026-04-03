// LinkFlow Phase 4: Selective Repeat ARQ Implementation
// File: src/selectrepeat.cpp
// Purpose: Per-packet timeout tracking and ACK bitmap window management

#include "./headers/selectrepeat.h"
#include <iostream>
#include <cstring>
#include <cmath>

using namespace std;

// Constructor: Initialize SR ARQ state
SelectiveRepeatARQ::SelectiveRepeatARQ()
    : send_base(1), next_seq_num(1), rto_ms(SR_PACKET_TIMEOUT_MS), in_flight_count(0)
{
    pthread_mutex_init(&window_mutex, NULL);
    for (int i = 0; i < SR_WINDOW_SIZE; i++) {
        slot_occupied[i] = false;
    }
}

// Destructor: Clean up resources
SelectiveRepeatARQ::~SelectiveRepeatARQ()
{
    pthread_mutex_destroy(&window_mutex);
}

// Check if we can send another packet (window not full)
bool SelectiveRepeatARQ::can_send_packet() const
{
    // [FIX Bug 5] Don't use (next_seq_num - send_base) — it underflows on uint32 wrap.
    // in_flight_count is the authoritative in-flight count.
    return get_in_flight_count() < SR_WINDOW_SIZE;
}

// Get number of packets currently in flight
int SelectiveRepeatARQ::get_in_flight_count() const
{
    // O(1) atomic load — no mutex needed for just the count
    return in_flight_count.load(std::memory_order_relaxed);
}

// Set starting sequence number (for resuming transfers)
void SelectiveRepeatARQ::set_start_seq(uint32_t seq)
{
    pthread_mutex_lock(&window_mutex);
    send_base = seq;
    next_seq_num = seq;
    for (int i = 0; i < SR_WINDOW_SIZE; i++) {
        slot_occupied[i] = false;
    }
    in_flight_count.store(0, std::memory_order_relaxed);
    ack_bitmap.reset();
    pthread_mutex_unlock(&window_mutex);
}

// Record a packet as sent with timestamp
void SelectiveRepeatARQ::record_sent_packet(const SlimDataPacket &pkt)
{
    pthread_mutex_lock(&window_mutex);

    uint32_t idx = pkt.seq_num & (SR_WINDOW_SIZE - 1);
    WindowPacket &wp = window_buffer[idx];
    
    wp.pkt = pkt;
    wp.is_acked = false;
    wp.retransmit_count = 0;

    // Capture current time with CLOCK_MONOTONIC for precise RTT measurement
    clock_gettime(CLOCK_MONOTONIC, &wp.send_time);

    if (!slot_occupied[idx]) {
        slot_occupied[idx] = true;
        in_flight_count.fetch_add(1, std::memory_order_relaxed);
    }

    pthread_mutex_unlock(&window_mutex);
}

// Handle ACK for a specific packet (individual acknowledgment)
void SelectiveRepeatARQ::handle_ack(uint32_t ack_num)
{
    pthread_mutex_lock(&window_mutex);

    uint32_t idx = ack_num & (SR_WINDOW_SIZE - 1);
    if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == ack_num)
    {
        window_buffer[idx].is_acked = true;

        // Update ACK bitmap if packet is within current window
        if (ack_num >= send_base && ack_num < send_base + SR_WINDOW_SIZE)
        {
            int bitmap_idx = ack_num - send_base;
            ack_bitmap[bitmap_idx] = 1; // Mark as acked
        }
    }

    // Try to advance the window
    pthread_mutex_unlock(&window_mutex);
    advance_window();
}

// Hybrid SACK: slide the window to cum_ack in one bulk operation.
// All buffered packets with seq < cum_ack are implicitly acknowledged and freed.
// The ack_bitmap is reset because it is relative to send_base; the caller
// re-populates it via mark_packet_acked() for any SACK bitmap-indicated packets.
void SelectiveRepeatARQ::handle_cumulative_ack(uint32_t cum_ack)
{
    pthread_mutex_lock(&window_mutex);

    if (cum_ack <= send_base)
    {
        // Already past this point — duplicate/stale ACK, nothing to do
        pthread_mutex_unlock(&window_mutex);
        return;
    }

    // Mark slots covered by cumulative ACK as empty
    for (uint32_t s = send_base; s < cum_ack; s++) {
        uint32_t idx = s & (SR_WINDOW_SIZE - 1);
        if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num < cum_ack) {
            slot_occupied[idx] = false;
            in_flight_count.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    // Snap send_base forward and reset bitmap (now relative to new send_base)
    send_base = cum_ack;
    ack_bitmap.reset();

    pthread_mutex_unlock(&window_mutex);
}


// Mark a specific packet as acknowledged
void SelectiveRepeatARQ::mark_packet_acked(uint32_t seq_num)
{
    pthread_mutex_lock(&window_mutex);

    uint32_t idx = seq_num & (SR_WINDOW_SIZE - 1);
    if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == seq_num)
    {
        window_buffer[idx].is_acked = true;

        if (seq_num >= send_base && seq_num < send_base + SR_WINDOW_SIZE)
        {
            int bitmap_idx = seq_num - send_base;
            ack_bitmap[bitmap_idx] = 1;
        }
    }

    pthread_mutex_unlock(&window_mutex);
    advance_window();
}

// Advance window when front packet is acked
// Only moves send_base forward when packet at position 0 is acked
void SelectiveRepeatARQ::advance_window()
{
    pthread_mutex_lock(&window_mutex);

    // Keep advancing while the front of the window is acked
    while (true)
    {
        uint32_t idx = send_base & (SR_WINDOW_SIZE - 1);
        if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == send_base && window_buffer[idx].is_acked)
        {
            // Clear slot
            slot_occupied[idx] = false;
            in_flight_count.fetch_sub(1, std::memory_order_relaxed);
            
            // Slide window forward
            send_base++;

            // Shift ACK bitmap left
            ack_bitmap >>= 1;
            ack_bitmap[SR_WINDOW_SIZE - 1] = 0;
        }
        else {
            break;
        }
    }

    pthread_mutex_unlock(&window_mutex);
}

// Check for timeout on any packet in the window
// Returns sequence number of first timed-out packet, or 0 if none
uint32_t SelectiveRepeatARQ::check_for_timeout()
{
    pthread_mutex_lock(&window_mutex);

    timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (int count = 0; count < SR_WINDOW_SIZE; count++)
    {
        uint32_t seq_to_check = send_base + count;
        uint32_t idx = seq_to_check & (SR_WINDOW_SIZE - 1);

        if (!slot_occupied[idx]) continue;
        if (window_buffer[idx].pkt.seq_num != seq_to_check) continue;

        uint32_t seq_num = window_buffer[idx].pkt.seq_num;
        WindowPacket &wp = window_buffer[idx];

        // Skip already-acked packets
        if (wp.is_acked)
            continue;

        // Calculate elapsed time in milliseconds
        long elapsed_ms = (now.tv_sec - wp.send_time.tv_sec) * 1000 +
                          (now.tv_nsec - wp.send_time.tv_nsec) / 1000000;

        // Check if timeout exceeded
        if (elapsed_ms >= SR_PACKET_TIMEOUT_MS)
        {
            pthread_mutex_unlock(&window_mutex);
            return seq_num; // Found a timed-out packet
        }
    }

    pthread_mutex_unlock(&window_mutex);
    return 0; // No timeout
}

// Prepare packet for retransmission (reset timer, increment counter)
bool SelectiveRepeatARQ::prepare_retransmit(uint32_t seq_num, SlimDataPacket &pkt_out)
{
    pthread_mutex_lock(&window_mutex);

    uint32_t idx = seq_num & (SR_WINDOW_SIZE - 1);
    if (!slot_occupied[idx] || window_buffer[idx].pkt.seq_num != seq_num)
    {
        pthread_mutex_unlock(&window_mutex);
        return false;
    }

    WindowPacket &wp = window_buffer[idx];

    // Check maximum retransmit limit
    if (wp.retransmit_count >= SR_MAX_RETRANSMITS)
    {
        cout << "  Max retransmits reached for seq=" << seq_num << endl;
        pthread_mutex_unlock(&window_mutex);
        return false;
    }

    // Update retransmission state
    wp.retransmit_count++;
    clock_gettime(CLOCK_MONOTONIC, &wp.send_time); // Reset timer

    // Copy packet for sending
    pkt_out = wp.pkt;

    pthread_mutex_unlock(&window_mutex);
    return true;
}

// Retrieve packet data for retransmission
bool SelectiveRepeatARQ::get_packet_for_retransmit(uint32_t seq_num, SlimDataPacket &pkt_out)
{
    pthread_mutex_lock(&window_mutex);

    uint32_t idx = seq_num & (SR_WINDOW_SIZE - 1);
    if (!slot_occupied[idx] || window_buffer[idx].pkt.seq_num != seq_num)
    {
        pthread_mutex_unlock(&window_mutex);
        return false;
    }

    pkt_out = window_buffer[idx].pkt;

    pthread_mutex_unlock(&window_mutex);
    return true;
}

// Check if a packet has been acknowledged
bool SelectiveRepeatARQ::is_packet_acked(uint32_t seq_num) const
{
    pthread_mutex_lock(&window_mutex);

    bool acked = false;
    uint32_t idx = seq_num & (SR_WINDOW_SIZE - 1);
    if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == seq_num)
    {
        acked = window_buffer[idx].is_acked;
    }

    pthread_mutex_unlock(&window_mutex);
    return acked;
}

// Print current window state for debugging
void SelectiveRepeatARQ::print_window_state() const
{
    pthread_mutex_lock(&window_mutex);

    cout << " SR Window State:" << endl;
    cout << "   send_base=" << send_base << ", next_seq=" << next_seq_num << endl;
    cout << "   In-flight packets: ";
    for (int i = 0; i < SR_WINDOW_SIZE; i++)
    {
        if (slot_occupied[i]) {
            cout << "[" << window_buffer[i].pkt.seq_num << (window_buffer[i].is_acked ? "✓" : "✗") << "] ";
        }
    }
    cout << endl;

    pthread_mutex_unlock(&window_mutex);
}
