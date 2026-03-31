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
    : send_base(1), next_seq_num(1), rto_ms(SR_PACKET_TIMEOUT_MS)
{
    pthread_mutex_init(&window_mutex, NULL);
}

// Destructor: Clean up resources
SelectiveRepeatARQ::~SelectiveRepeatARQ()
{
    pthread_mutex_destroy(&window_mutex);
}

// Check if we can send another packet (window not full)
bool SelectiveRepeatARQ::can_send_packet() const
{
    int in_flight = next_seq_num - send_base;
    return in_flight < SR_WINDOW_SIZE;
}

// Get number of packets currently in flight
int SelectiveRepeatARQ::get_in_flight_count() const
{
    pthread_mutex_lock(&window_mutex);
    int count = window_buffer.size();
    pthread_mutex_unlock(&window_mutex);
    return count;
}

// Record a packet as sent with timestamp
void SelectiveRepeatARQ::record_sent_packet(const SlimDataPacket &pkt)
{
    pthread_mutex_lock(&window_mutex);

    WindowPacket wp;
    wp.pkt = pkt;
    wp.is_acked = false;
    wp.retransmit_count = 0;

    // Capture current time with CLOCK_MONOTONIC for precise RTT measurement
    clock_gettime(CLOCK_MONOTONIC, &wp.send_time);

    // Insert into window buffer (map will handle duplicates)
    window_buffer[pkt.seq_num] = wp;

    pthread_mutex_unlock(&window_mutex);
}

// Handle ACK for a specific packet (individual acknowledgment)
void SelectiveRepeatARQ::handle_ack(uint16_t ack_num)
{
    pthread_mutex_lock(&window_mutex);

    // Mark this packet as acknowledged
    if (window_buffer.find(ack_num) != window_buffer.end())
    {
        window_buffer[ack_num].is_acked = true;

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

// Mark a specific packet as acknowledged
void SelectiveRepeatARQ::mark_packet_acked(uint16_t seq_num)
{
    pthread_mutex_lock(&window_mutex);

    if (window_buffer.find(seq_num) != window_buffer.end())
    {
        window_buffer[seq_num].is_acked = true;

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
    while (!window_buffer.empty() &&
           window_buffer.find(send_base) != window_buffer.end() &&
           window_buffer[send_base].is_acked)
    {
        // Remove acknowledged packet from buffer
        window_buffer.erase(send_base);

        // Slide window forward
        send_base++;

        // Shift ACK bitmap left (drop leftmost bit, add new 0 on right)
        ack_bitmap >>= 1;
        ack_bitmap[SR_WINDOW_SIZE - 1] = 0; // New position is unacked
    }

    pthread_mutex_unlock(&window_mutex);
}

// Check for timeout on any packet in the window
// Returns sequence number of first timed-out packet, or 0 if none
uint16_t SelectiveRepeatARQ::check_for_timeout()
{
    pthread_mutex_lock(&window_mutex);

    timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (auto &entry : window_buffer)
    {
        uint16_t seq_num = entry.first;
        WindowPacket &wp = entry.second;

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
bool SelectiveRepeatARQ::prepare_retransmit(uint16_t seq_num, SlimDataPacket &pkt_out)
{
    pthread_mutex_lock(&window_mutex);

    if (window_buffer.find(seq_num) == window_buffer.end())
    {
        pthread_mutex_unlock(&window_mutex);
        return false;
    }

    WindowPacket &wp = window_buffer[seq_num];

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
bool SelectiveRepeatARQ::get_packet_for_retransmit(uint16_t seq_num, SlimDataPacket &pkt_out)
{
    pthread_mutex_lock(&window_mutex);

    if (window_buffer.find(seq_num) == window_buffer.end())
    {
        pthread_mutex_unlock(&window_mutex);
        return false;
    }

    pkt_out = window_buffer[seq_num].pkt;

    pthread_mutex_unlock(&window_mutex);
    return true;
}

// Check if a packet has been acknowledged
bool SelectiveRepeatARQ::is_packet_acked(uint16_t seq_num) const
{
    pthread_mutex_lock(&window_mutex);

    bool acked = false;
    if (window_buffer.find(seq_num) != window_buffer.end())
    {
        acked = window_buffer.at(seq_num).is_acked;
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
    cout << "   In-flight packets: " << window_buffer.size() << "/" << SR_WINDOW_SIZE << endl;
    cout << "   ACK bitmap: ";

    for (int i = SR_WINDOW_SIZE - 1; i >= 0; i--)
    {
        cout << (ack_bitmap[i] ? "1" : "0");
    }
    cout << " (MSB=base+" << (SR_WINDOW_SIZE - 1) << " LSB=base)" << endl;

    cout << "   Packets: ";
    for (auto &entry : window_buffer)
    {
        cout << "[" << entry.first << (entry.second.is_acked ? "✓" : "✗") << "] ";
    }
    cout << endl;

    pthread_mutex_unlock(&window_mutex);
}
