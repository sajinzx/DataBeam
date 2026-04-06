#include "./headers/selectrepeat.h"
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>

using namespace std;

// Constructor: Initialize SR ARQ state
SelectiveRepeatARQ::SelectiveRepeatARQ()
    : send_base(1), next_seq_num(1),
      effective_cwnd(DataBeam::SR_WINDOW_SIZE),
      rto_ms(DataBeam::SR_BASE_TIMEOUT_MS),
      max_retransmits(DataBeam::SR_MAX_RETRANSMITS), in_flight_count(0) {
  pthread_mutex_init(&window_mutex, NULL);
  for (int i = 0; i < DataBeam::SR_WINDOW_SIZE; i++) {
    slot_occupied[i] = false;
  }
}

// Destructor: Clean up resources
SelectiveRepeatARQ::~SelectiveRepeatARQ() {
  pthread_mutex_destroy(&window_mutex);
}

// Check if we can send another packet (window not full)
// FIXED — uses exact window range, not approximate count
bool SelectiveRepeatARQ::can_send_packet() const {
  pthread_mutex_lock(&window_mutex);
  // uint32 subtraction wraps correctly even across seq=0 boundary
  uint32_t in_use = next_seq_num - send_base;
  pthread_mutex_unlock(&window_mutex);
  // Phase 6: use effective_cwnd (dynamic) instead of compile-time SR_WINDOW_SIZE
  return in_use < (uint32_t)effective_cwnd;
}

// Phase 6: Dynamic cwnd setter — called by receiver thread after Vegas adjust
void SelectiveRepeatARQ::set_effective_cwnd(int32_t cwnd) {
  // Clamp to [CWND_MIN, SR_WINDOW_SIZE] — array size is the hard ceiling
  effective_cwnd = std::max((int32_t)DataBeam::CWND_MIN,
                           std::min(cwnd, (int32_t)DataBeam::SR_WINDOW_SIZE));
}

// Get number of packets currently in flight
int SelectiveRepeatARQ::get_in_flight_count() const {
  return in_flight_count.load(std::memory_order_relaxed);
}

// Set starting sequence number (for resuming transfers)
void SelectiveRepeatARQ::set_start_seq(uint32_t seq) {
  pthread_mutex_lock(&window_mutex);
  send_base = seq;
  next_seq_num = seq;
  for (int i = 0; i < DataBeam::SR_WINDOW_SIZE; i++) {
    slot_occupied[i] = false;
  }
  in_flight_count.store(0, std::memory_order_relaxed);
  ack_bitmap.reset();
  // effective_cwnd is NOT reset here — it's controlled by LiveState
  pthread_mutex_unlock(&window_mutex);
}

// Record a packet as sent with timestamp
void SelectiveRepeatARQ::record_sent_packet(const SlimDataPacket &pkt) {
  pthread_mutex_lock(&window_mutex);

  uint32_t idx = pkt.seq_num & (DataBeam::SR_WINDOW_SIZE - 1);

  // COLLISION GUARD: if slot occupied by a DIFFERENT seq, window overflow
  // This should never fire after the can_send_packet fixS
  // SELF-HEALING: if slot occupied by an OLD seq (stale), clear it.
  // This recovers if a previous window cycle was skipped by
  // handle_cumulative_ack.
  if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num != pkt.seq_num) {
    slot_occupied[idx] = false;
    in_flight_count.fetch_sub(1, std::memory_order_relaxed);
  }

  WindowPacket &wp = window_buffer[idx];
  wp.pkt = pkt;
  wp.is_acked = false;
  wp.retransmit_count = 0;
  clock_gettime(CLOCK_MONOTONIC, &wp.send_time);

  if (!slot_occupied[idx]) {
    slot_occupied[idx] = true;
    in_flight_count.fetch_add(1, std::memory_order_relaxed);
  }

  pthread_mutex_unlock(&window_mutex);
}

// Handle ACK for a specific packet (individual acknowledgment)
void SelectiveRepeatARQ::handle_ack(uint32_t ack_num) {
  pthread_mutex_lock(&window_mutex);

  uint32_t idx = ack_num & (DataBeam::SR_WINDOW_SIZE - 1);
  if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == ack_num) {
    window_buffer[idx].is_acked = true;

    // Update ACK bitmap if packet is within current window
    if (ack_num >= send_base &&
        ack_num < send_base + DataBeam::SR_WINDOW_SIZE) {
      int bitmap_idx = ack_num - send_base;
      ack_bitmap[bitmap_idx] = 1; // Mark as acked
    }
  }

  // Try to advance the window
  pthread_mutex_unlock(&window_mutex);
  advance_window();
}

// Hybrid SACK: slide the window to cum_ack in one bulk operation.
// All buffered packets with seq < cum_ack are implicitly acknowledged and
// freed. The ack_bitmap is reset because it is relative to send_base; the
// caller re-populates it via mark_packet_acked() for any SACK bitmap-indicated
// packets.
void SelectiveRepeatARQ::handle_cumulative_ack(uint32_t cum_ack,
                                               int64_t *rtt_sample_us_out) {
  pthread_mutex_lock(&window_mutex);

  if (cum_ack <= send_base) {
    // Already past this point — duplicate/stale ACK, nothing to do
    pthread_mutex_unlock(&window_mutex);
    if (rtt_sample_us_out) *rtt_sample_us_out = -1;
    return;
  }

  // Phase 6: Extract RTT sample from the packet at send_base before clearing
  if (rtt_sample_us_out) {
    uint32_t idx = send_base & (DataBeam::SR_WINDOW_SIZE - 1);
    if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == send_base) {
      timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      int64_t sent_us = (int64_t)window_buffer[idx].send_time.tv_sec * 1000000LL +
                        (int64_t)window_buffer[idx].send_time.tv_nsec / 1000LL;
      int64_t now_us = (int64_t)now.tv_sec * 1000000LL +
                       (int64_t)now.tv_nsec / 1000LL;
      *rtt_sample_us_out = now_us - sent_us;
    } else {
      *rtt_sample_us_out = -1;
    }
  }

  // Mark slots covered by cumulative ACK as empty
  for (uint32_t s = send_base; s < cum_ack; s++) {
    uint32_t idx = s & (DataBeam::SR_WINDOW_SIZE - 1);
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
void SelectiveRepeatARQ::mark_packet_acked(uint32_t seq_num) {
  pthread_mutex_lock(&window_mutex);

  uint32_t idx = seq_num & (DataBeam::SR_WINDOW_SIZE - 1);
  if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == seq_num) {
    window_buffer[idx].is_acked = true;

    if (seq_num >= send_base &&
        seq_num < send_base + DataBeam::SR_WINDOW_SIZE) {
      int bitmap_idx = seq_num - send_base;
      ack_bitmap[bitmap_idx] = 1;
    }
  }

  pthread_mutex_unlock(&window_mutex);
  advance_window();
}

// Advance window when front packet is acked
// Only moves send_base forward when packet at position 0 is acked
void SelectiveRepeatARQ::advance_window() {
  pthread_mutex_lock(&window_mutex);

  // Keep advancing while the front of the window is acked
  while (true) {
    uint32_t idx = send_base & (DataBeam::SR_WINDOW_SIZE - 1);
    if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == send_base &&
        window_buffer[idx].is_acked) {
      // Clear slot
      slot_occupied[idx] = false;
      in_flight_count.fetch_sub(1, std::memory_order_relaxed);

      // Slide window forward
      send_base++;

      // Shift ACK bitmap left
      ack_bitmap >>= 1;
      ack_bitmap[DataBeam::SR_WINDOW_SIZE - 1] = 0;
    } else {
      break;
    }
  }

  pthread_mutex_unlock(&window_mutex);
}

// Check for timeout on any packet in the window
// Returns sequence number of first timed-out packet, or 0 if none
uint32_t SelectiveRepeatARQ::check_for_timeout() {
  pthread_mutex_lock(&window_mutex);

  timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  // Only scan actually in-flight count, not the full window
  int in_flight = in_flight_count.load(std::memory_order_relaxed);
  if (in_flight == 0) {
    pthread_mutex_unlock(&window_mutex);
    return 0; // fast exit — nothing to check
  }

  int checked = 0;
  for (int count = 0; count < DataBeam::SR_WINDOW_SIZE && checked < in_flight;
       count++) {
    uint32_t seq_to_check = send_base + count;
    uint32_t idx = seq_to_check & (DataBeam::SR_WINDOW_SIZE - 1);

    if (!slot_occupied[idx])
      continue;
    if (window_buffer[idx].pkt.seq_num != seq_to_check)
      continue;

    checked++;
    WindowPacket &wp = window_buffer[idx];
    if (wp.is_acked)
      continue;

    long elapsed_ms =
        (now.tv_sec - wp.send_time.tv_sec) * DataBeam::MS_PER_SEC +
        (now.tv_nsec - wp.send_time.tv_nsec) / DataBeam::NS_PER_MS;

    if (elapsed_ms >= (long)rto_ms) {
      pthread_mutex_unlock(&window_mutex);
      return wp.pkt.seq_num;
    }
  }

  pthread_mutex_unlock(&window_mutex);
  return 0;
}

// Fast retransmit: cooldown guard so SACK floods don't burn the retransmit
// budget. Does NOT increment retransmit_count. Returns false if packet
// retransmitted too recently (within rto_ms/4), preventing thousands of SACKs
// from exhausting the retry budget.
bool SelectiveRepeatARQ::try_fast_retransmit(uint32_t seq_num,
                                             SlimDataPacket &pkt_out) {
  pthread_mutex_lock(&window_mutex);

  uint32_t idx = seq_num & (DataBeam::SR_WINDOW_SIZE - 1);
  if (!slot_occupied[idx] || window_buffer[idx].pkt.seq_num != seq_num) {
    pthread_mutex_unlock(&window_mutex);
    return false;
  }

  WindowPacket &wp = window_buffer[idx];
  if (wp.is_acked) {
    pthread_mutex_unlock(&window_mutex);
    return false;
  }

  // Cooldown check: skip if retransmitted within rto_ms/4 ago
  timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  long since_ms =
      (now.tv_sec - wp.last_retransmit_time.tv_sec) * DataBeam::MS_PER_SEC +
      (now.tv_nsec - wp.last_retransmit_time.tv_nsec) / DataBeam::NS_PER_MS;
  long cooldown_ms = (long)(rto_ms) / 4;
  if (cooldown_ms < 10)
    cooldown_ms = 10; // floor at 10ms
  if (since_ms < cooldown_ms) {
    pthread_mutex_unlock(&window_mutex);
    return false; // too soon — skip this fast retransmit
  }

  // OK to retransmit: update cooldown timestamp but NOT retransmit_count
  wp.last_retransmit_time = now;
  pkt_out = wp.pkt;

  pthread_mutex_unlock(&window_mutex);
  return true;
}
int SelectiveRepeatARQ::prepare_retransmit(uint32_t seq_num,
                                            SlimDataPacket &pkt_out) {
  pthread_mutex_lock(&window_mutex);

  uint32_t idx = seq_num & (DataBeam::SR_WINDOW_SIZE - 1);
  if (!slot_occupied[idx] || window_buffer[idx].pkt.seq_num != seq_num) {
    pthread_mutex_unlock(&window_mutex);
    return 0;
  }

  WindowPacket &wp = window_buffer[idx];
  if (wp.is_acked) {
    pthread_mutex_unlock(&window_mutex);
    return 0;
  }

  wp.retransmit_count++;
  if (wp.retransmit_count > max_retransmits) {
    pthread_mutex_unlock(&window_mutex);
    return -1;
  }

  timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  wp.send_time = now;
  wp.last_retransmit_time = now;
  
  pkt_out = wp.pkt;

  pthread_mutex_unlock(&window_mutex);
  return 1;
}

bool SelectiveRepeatARQ::get_packet_for_retransmit(uint32_t seq_num,
                                                   SlimDataPacket &pkt_out) {
  pthread_mutex_lock(&window_mutex);

  uint32_t idx = seq_num & (DataBeam::SR_WINDOW_SIZE - 1);
  if (!slot_occupied[idx] || window_buffer[idx].pkt.seq_num != seq_num) {
    pthread_mutex_unlock(&window_mutex);
    return false;
  }

  pkt_out = window_buffer[idx].pkt;

  pthread_mutex_unlock(&window_mutex);
  return true;
}

// Check if a packet has been acknowledged
bool SelectiveRepeatARQ::is_packet_acked(uint32_t seq_num) const {
  pthread_mutex_lock(&window_mutex);

  bool acked = false;
  uint32_t idx = seq_num & (DataBeam::SR_WINDOW_SIZE - 1);
  if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == seq_num) {
    acked = window_buffer[idx].is_acked;
  }

  pthread_mutex_unlock(&window_mutex);
  return acked;
}

// Print current window state for debugging
void SelectiveRepeatARQ::print_window_state() const {
  pthread_mutex_lock(&window_mutex);

  cout << " SR Window State:" << endl;
  cout << "   send_base=" << send_base << ", next_seq=" << next_seq_num << endl;
  cout << "   In-flight packets: ";
  for (int i = 0; i < DataBeam::SR_WINDOW_SIZE; i++) {
    if (slot_occupied[i]) {
      cout << "[" << window_buffer[i].pkt.seq_num
           << (window_buffer[i].is_acked ? "✓" : "✗") << "] ";
    }
  }
  cout << endl;

  pthread_mutex_unlock(&window_mutex);
}
// Mark a range of packets acked in one lock acquisition
void SelectiveRepeatARQ::mark_range_acked(uint32_t base,
                                          const uint64_t *bitmap_chunks,
                                          int num_chunks) {
  pthread_mutex_lock(&window_mutex);

  for (int ci = 0; ci < num_chunks; ci++) {
    uint64_t chunk = bitmap_chunks[ci];
    if (chunk == 0)
      continue;

    for (int bit = 0; bit < 64; bit++) {
      if (!(chunk & (1ULL << bit)))
        continue;

      uint32_t seq = base + (ci * 64) + bit;
      uint32_t idx = seq & (DataBeam::SR_WINDOW_SIZE - 1);

      if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == seq)
        window_buffer[idx].is_acked = true;
    }
  }

  // One advance_window pass covers everything
  while (true) {
    uint32_t idx = send_base & (DataBeam::SR_WINDOW_SIZE - 1);
    if (slot_occupied[idx] && window_buffer[idx].pkt.seq_num == send_base &&
        window_buffer[idx].is_acked) {
      slot_occupied[idx] = false;
      in_flight_count.fetch_sub(1, std::memory_order_relaxed);
      send_base++;
      ack_bitmap >>= 1;
      ack_bitmap[DataBeam::SR_WINDOW_SIZE - 1] = 0;
    } else
      break;
  }

  pthread_mutex_unlock(&window_mutex);
}
