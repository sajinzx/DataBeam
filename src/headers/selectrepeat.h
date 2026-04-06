// LinkFlow Phase 4: Selective Repeat (SR) ARQ Header
// File: src/headers/selectrepeat.h
// Purpose: Per-packet timeout tracking with ACK bitmap window management

#ifndef SELECTREPEAT_H
#define SELECTREPEAT_H

#include "constants.h"
#include "packet.h"
#include <atomic>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <map>
#include <pthread.h>

// Server sends SACK every N in-order packets

// Structure to wrap Packet with timeout tracking for SR ARQ
struct WindowPacket {
  SlimDataPacket pkt;            // The actual packet data
  timespec send_time;            // Send timestamp (CLOCK_MONOTONIC)
  timespec last_retransmit_time; // Timestamp of last retransmit (for
                                 // fast-retransmit cooldown)
  bool is_acked;                 // Has this packet been acknowledged?
  int retransmit_count;          // Timeout-retransmit attempts (budget-limited)

  // Constructor
  WindowPacket() : is_acked(false), retransmit_count(0) {
    memset(&pkt, 0, sizeof(SlimDataPacket));
    memset(&send_time, 0, sizeof(timespec));
    memset(&last_retransmit_time, 0, sizeof(timespec));
  }
};

// Selective Repeat ARQ Manager with Per-Packet Timers
class SelectiveRepeatARQ {
private:
  // Window variables
  uint32_t send_base;    // Oldest unacked packet sequence
  uint32_t next_seq_num; // Next packet to send
  std::bitset<DataBeam::SR_WINDOW_SIZE>
      ack_bitmap; // ACK status: bit i = acked(base+i)?

  // Phase 6: Effective congestion window (virtual limit within fixed array)
  // Array size is always SR_WINDOW_SIZE (4096), but effective_cwnd limits
  // how many packets can actually be in flight.
  int32_t effective_cwnd;

  // Packet buffer: Pre-allocated circular array (O(1) access, zero heap churn)
  // Size is SR_WINDOW_SIZE (4096). Indexed by (seq_num & (SR_WINDOW_SIZE - 1)).
  WindowPacket window_buffer[DataBeam::SR_WINDOW_SIZE];
  bool slot_occupied[DataBeam::SR_WINDOW_SIZE]; // Tracks if a slot contains an
                                                // unacked packet
  std::atomic<int> in_flight_count; // O(1) tracking of buffered packets

  // Thread synchronization
  mutable pthread_mutex_t window_mutex; // Protects window state

  // RTT & Timeout (dynamically adjusted by timeout_thread)
  uint32_t rto_ms;     // Retransmission timeout in milliseconds
  int max_retransmits; // Dynamic max retransmit attempts (set by
                       // AdaptiveParams)

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
  int32_t get_effective_cwnd() const { return effective_cwnd; }

  // Phase 6: Dynamic cwnd — limits in-flight within the fixed 4096 array
  void set_effective_cwnd(int32_t cwnd);

  // Dynamic tuning setters — called by timeout_thread via LiveState
  void set_rto(int new_rto_ms) { rto_ms = (uint32_t)new_rto_ms; }
  void set_max_retransmits(int new_max) { max_retransmits = new_max; }

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
  // Phase 6: rtt_sample_out receives RTT of the acked base packet (μs), or -1
  void handle_cumulative_ack(uint32_t cum_ack,
                             int64_t *rtt_sample_us_out = nullptr);

  // Mark packet as acknowledged
  void mark_packet_acked(uint32_t seq_num);

  // Advance send_base when front of window is fully acked
  void advance_window();

  // === Timeout & Retransmission ===
  // Check if any packet in the window has timed out
  // Returns the sequence number of the first timed-out packet, or 0 if none
  uint32_t check_for_timeout();

  // Prepare packet for retransmission (updates send_time and retransmit_count)
  // Used by timeout_thread — increments retransmit_count, returns false when
  // budget exhausted.
  int prepare_retransmit(uint32_t seq_num, SlimDataPacket &pkt_out);
  int prepare_retransmit(uint32_t seq_num, StartPacket &pkt_out);

  // Fast retransmit (from receiver_thread): has cooldown guard, does NOT
  // increment retransmit_count. Returns false if the packet was retransmitted
  // too recently (within rto_ms/4), preventing the retransmit budget from being
  // burned by a flood of duplicate SACKs.
  bool try_fast_retransmit(uint32_t seq_num, SlimDataPacket &pkt_out);
  // === Statistics & Debugging ===
  uint32_t get_window_size() const { return DataBeam::SR_WINDOW_SIZE; }
  uint8_t get_acked_count() const { return ack_bitmap.count(); }
  bool is_window_empty() const { return get_in_flight_count() == 0; }
  bool is_packet_acked(uint32_t seq_num) const;
  void mark_range_acked(uint32_t base, const uint64_t *bitmap_chunks,
                        int num_chunks);
  // Print current window state (for debugging)
  void print_window_state() const;
};

#endif // SELECTREPEAT_H
