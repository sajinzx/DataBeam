// LinkFlow Phase 3: Go-Back-N ARQ with Congestion Control
// File: src/arq.cpp
// Purpose: Sliding window protocol with RTT tracking and AIMD

#include "headers/arq.h"
#include <zlib.h>
#include <cstring>
#include <iostream>
#include <cmath>

using namespace std;

// Constructor: Initialize ARQ state
GoBackNARQ::GoBackNARQ()
    : send_base(1), next_seq_num(1),
      srtt_us(DataBeam::GBN_INITIAL_RTO_MS * DataBeam::US_PER_MS), rttvar_us(DataBeam::GBN_INITIAL_RTO_MS * 500),
      rto_ms(DataBeam::GBN_INITIAL_RTO_MS), congestion_window(1.0), threshold(DataBeam::CC_INITIAL_THRESHOLD),
      in_slow_start(true)
{
}

// Check if we can send another packet (window not full)
bool GoBackNARQ::can_send_packet() const
{
    int in_flight = next_seq_num - send_base;
    return in_flight < (int)congestion_window && in_flight < (int)DataBeam::GBN_WINDOW_SIZE;
}

// Get actual window size (constrained by congestion window)
uint8_t GoBackNARQ::get_window_size() const
{
    return (uint8_t)min((double)DataBeam::GBN_WINDOW_SIZE, congestion_window);
}

// Record a packet as sent
void GoBackNARQ::record_sent_packet(const SlimDataPacket &pkt)
{
    SentPacket sp;
    sp.pkt = pkt;
    sp.send_time = chrono::high_resolution_clock::now();
    sp.retransmit_count = 0;
    sent_buffer.push_back(sp);
}

// Handle ACK: Remove acknowledged packets and manage congestion window
void GoBackNARQ::handle_ack(uint16_t ack_num)
{
    // Remove all packets up to (but not including) ack_num
    while (!sent_buffer.empty() && sent_buffer.front().pkt.seq_num < ack_num)
    {
        // Update RTT for this packet
        auto it = sent_buffer.begin();
        if (it->pkt.seq_num < ack_num)
        {
            auto now = chrono::high_resolution_clock::now();
            auto duration = chrono::duration_cast<chrono::microseconds>(
                now - it->send_time);
            uint32_t rtt_sample = duration.count();

            // Update SRTT and RTTVAR using RFC 6298
            if (srtt_us == 0)
            {
                srtt_us = rtt_sample;
                rttvar_us = rtt_sample / 2;
            }
            else
            {
                rttvar_us = (1 - DataBeam::BETA_RTTVAR) * rttvar_us +
                            DataBeam::BETA_RTTVAR * abs((int32_t)rtt_sample - (int32_t)srtt_us);
                srtt_us = (1 - DataBeam::ALPHA_RTT) * srtt_us + DataBeam::ALPHA_RTT * rtt_sample;
            }

            // Update RTO: SRTT + 4 * RTTVAR, with bounds [1ms, 60s]
            rto_ms = (srtt_us + 4 * rttvar_us) / DataBeam::US_PER_MS;
            if (rto_ms < 1)
                rto_ms = 1;
            if (rto_ms > DataBeam::GBN_MAX_RTO_MS)
                rto_ms = DataBeam::GBN_MAX_RTO_MS;
        }
        sent_buffer.pop_front();
    }

    // Congestion control: AIMD Additive Increase
    if (in_slow_start && congestion_window < threshold)
    {
        // Slow start: exponential increase
        congestion_window += 1.0;
    }
    else
    {
        // Congestion avoidance: additive increase
        in_slow_start = false;
        congestion_window += DataBeam::CC_AIMD_INCREASE / congestion_window;
    }

    if (congestion_window > (double)DataBeam::GBN_WINDOW_SIZE)
        congestion_window = (double)DataBeam::GBN_WINDOW_SIZE;
}

// Check for timeout and prepare packet for retransmission
bool GoBackNARQ::check_for_timeout(SlimDataPacket &pkt_to_retransmit)
{
    if (sent_buffer.empty())
        return false;

    auto now = chrono::high_resolution_clock::now();
    auto &oldest = sent_buffer.front();
    auto duration = chrono::duration_cast<chrono::milliseconds>(
        now - oldest.send_time);

    if (duration.count() >= (long)rto_ms)
    {
        pkt_to_retransmit = oldest.pkt;
        oldest.retransmit_count++;
        oldest.send_time = now; // Reset timer for retransmit
        return true;
    }

    return false;
}

// Mark packet loss and trigger Multiplicative Decrease
void GoBackNARQ::mark_loss()
{
    // AIMD Multiplicative Decrease
    threshold = congestion_window / 2;
    congestion_window = threshold;
    in_slow_start = false;

    if (congestion_window < 1.0)
        congestion_window = 1.0;

    cout << "⚠️  Packet loss detected! cwnd=" << congestion_window
         << " ssthresh=" << threshold << endl;
}

// RTT measurement (called when ACK received)
void GoBackNARQ::update_rtt(uint16_t seq_num)
{
    for (auto &sp : sent_buffer)
    {
        if (sp.pkt.seq_num == seq_num)
        {
            auto now = chrono::high_resolution_clock::now();
            auto duration = chrono::duration_cast<chrono::microseconds>(
                now - sp.send_time);
            uint32_t rtt_sample = duration.count();

            // RFC 6298 RTT calculation
            if (srtt_us == 0)
            {
                srtt_us = rtt_sample;
                rttvar_us = rtt_sample / 2;
            }
            else
            {
                rttvar_us = (1 - DataBeam::BETA_RTTVAR) * rttvar_us +
                            DataBeam::BETA_RTTVAR * abs((int32_t)rtt_sample - (int32_t)srtt_us);
                srtt_us = (1 - DataBeam::ALPHA_RTT) * srtt_us + DataBeam::ALPHA_RTT * rtt_sample;
            }

            rto_ms = (srtt_us + 4 * rttvar_us) / 1000;
            if (rto_ms < 1)
                rto_ms = 1;
            if (rto_ms > DataBeam::GBN_MAX_RTO_MS)
                rto_ms = DataBeam::GBN_MAX_RTO_MS;

            return;
        }
    }
}
