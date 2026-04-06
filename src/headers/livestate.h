// =============================================================================
// livestate.h — Dynamic Runtime Parameters (Phase 6.1)
//
// Replaces the old AdaptiveParams with a full LiveState struct that updates
// every RTT cycle. Contains:
//   - Jacobson's RTT algorithm (SRTT + 4*RTTVAR)
//   - Vegas-style delay-based congestion control
//   - Dynamic cwnd, ack_batch, socket buffer sizing
//   - Exponential backoff on loss
// =============================================================================
#ifndef DATABEAM_LIVESTATE_H
#define DATABEAM_LIVESTATE_H

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iostream>

#include "constants.h"
#include "sysprofile.h"

namespace DataBeam {

struct LiveState {
  // ── RTT Tracking (Jacobson's Algorithm) ──────────────────────────────────
  std::atomic<int64_t> srtt_us{0};             // Smoothed RTT (μs)
  std::atomic<int64_t> rttvar_us{0};           // RTT variance (μs)
  std::atomic<int64_t> base_rtt_us{INT64_MAX}; // Minimum observed RTT (Vegas)
  std::atomic<int32_t> rto_ms{SR_BASE_TIMEOUT_MS};
  bool rtt_initialized{false};

  // ── Congestion Window ────────────────────────────────────────────────────
  std::atomic<int32_t> cwnd{SR_WINDOW_SIZE}; // effective window (packets)
  int32_t cwnd_max{SR_WINDOW_SIZE};          // compile-time array limit

  // ── Derived Parameters (recomputed each cycle) ───────────────────────────
  std::atomic<int32_t> ack_batch{SERVER_ACK_BATCH_SIZE};

  // ── Backoff state ────────────────────────────────────────────────────────
  std::atomic<int32_t> consecutive_timeouts{0};

  // ── Profile-derived (set once at startup) ────────────────────────────────
  uint32_t compressor_threads{CLIENT_COMPRESSOR_THREADS};
  uint32_t decompressor_threads{SERVER_DECOMPRESSOR_THREADS};
  uint32_t pool_slot_count{SERVER_RECV_BUFFER_SIZE};

  // ── Initialize from system profile (call once at startup) ────────────────
  void init_from_profile(const SystemProfile &profile) {
    compressor_threads = std::max(1u, profile.worker_threads);
    decompressor_threads = std::max(1u, profile.worker_threads);
    pool_slot_count = profile.pool_slot_count;
    cwnd.store((int32_t)profile.recommended_cwnd());
    cwnd_max = SR_WINDOW_SIZE; // array size limit
    recompute_derived();
  }

  // ── Initialize from network probe result ─────────────────────────────────
  void init_from_probe(uint64_t bandwidth_bps, int64_t rtt_us_val) {
    if (rtt_us_val <= 0 || bandwidth_bps == 0) return;

    // BDP = bandwidth (bytes/sec) * RTT (sec)
    double bdp_bytes =
        ((double)bandwidth_bps / 8.0) * ((double)rtt_us_val / 1e6);
    double bdp_packets = bdp_bytes / (double)PACKET_DATA_SIZE;

    // Safety margin: use 75% of measured BDP
    int32_t initial_cwnd = (int32_t)(bdp_packets * 0.75);
    initial_cwnd = std::clamp(initial_cwnd, (int32_t)CWND_MIN, cwnd_max);

    cwnd.store(initial_cwnd);
    base_rtt_us.store(rtt_us_val);
    srtt_us.store(rtt_us_val);
    rttvar_us.store(rtt_us_val / 4);
    rtt_initialized = true;

    recompute_derived();
  }

  // ── Jacobson's RTT update (call on each ACK with RTT sample) ─────────────
  void update_rtt(int64_t sample_us) {
    if (sample_us <= 0) return;

    if (!rtt_initialized) {
      srtt_us.store(sample_us);
      rttvar_us.store(sample_us / 2);
      base_rtt_us.store(sample_us);
      rtt_initialized = true;
    } else {
      // SRTT = (1 - 1/8) * SRTT + (1/8) * sample
      int64_t old_srtt = srtt_us.load();
      int64_t diff = sample_us - old_srtt;
      srtt_us.store(old_srtt + diff / 8);

      // RTTVAR = (1 - 1/4) * RTTVAR + (1/4) * |diff|
      int64_t old_var = rttvar_us.load();
      int64_t abs_diff = (diff < 0) ? -diff : diff;
      rttvar_us.store(old_var + (abs_diff - old_var) / 4);

      // Update base RTT (minimum observed)
      int64_t cur_base = base_rtt_us.load();
      if (sample_us < cur_base)
        base_rtt_us.store(sample_us);
    }

    // RTO = SRTT + 4 * RTTVAR, clamped
    int64_t new_rto_us = srtt_us.load() + 4 * rttvar_us.load();
    int32_t new_rto_ms = (int32_t)(new_rto_us / 1000);
    new_rto_ms = std::clamp(new_rto_ms, (int32_t)ADAPTIVE_MIN_RTO_MS,
                            (int32_t)ADAPTIVE_MAX_RTO_MS);
    rto_ms.store(new_rto_ms);
  }

  // ── Vegas congestion control (call periodically, e.g. every 100 ACKs) ────
  // Returns: +1 grew, -1 shrunk, 0 held steady
  int vegas_adjust() {
    if (!rtt_initialized) return 0;

    int64_t current_rtt = srtt_us.load();
    int64_t base = base_rtt_us.load();
    if (base <= 0 || current_rtt <= 0) return 0;

    double diff_ms = (double)(current_rtt - base) / 1000.0;
    int32_t cur_cwnd = cwnd.load();

    if (diff_ms < (double)VEGAS_ALPHA_MS / 2.0) {
      // Very clear path — grow aggressively (HighSpeed TCP style)
      int32_t increment = std::max(4, cur_cwnd / 64);
      int32_t new_cwnd = std::min(cur_cwnd + increment, cwnd_max);
      cwnd.store(new_cwnd);
      recompute_derived();
      return 1;
    } else if (diff_ms < (double)VEGAS_ALPHA_MS) {
      // Path clear — steady growth
      int32_t new_cwnd = std::min(cur_cwnd + 2, cwnd_max);
      cwnd.store(new_cwnd);
      recompute_derived();
      return 1;
    } 
    
    // DELAY-BASED SHRINKING DISABLED: Relying purely on Packet Loss (on_timeout) 
    // to gradually reduce window, per user request.
    return 0; // hold steady
  }

  // ── Timeout handler (exponential backoff + window halving) ───────────────
  std::atomic<int64_t> last_timeout_us{0};

  void on_timeout() {
    auto now_tp = std::chrono::high_resolution_clock::now();
    int64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                         now_tp.time_since_epoch()).count();
    
    int t = consecutive_timeouts.fetch_add(1) + 1;
    int new_rto = SR_BASE_TIMEOUT_MS * (1 << std::min(t, 5)); // cap at 32x
    rto_ms.store(std::min(new_rto, (int)ADAPTIVE_MAX_RTO_MS));

    int64_t last = last_timeout_us.load();
    int64_t current_rto_us = (int64_t)rto_ms.load() * 1000;

    // TCP Vegas/Reno principle: halving cwnd happens at most once per RTT/RTO.
    // If multiple packets from the same flight time out, do NOT compound the penalty.
    if (now_us - last < current_rto_us) {
      return; 
    }

    last_timeout_us.store(now_us);

    // Gradually reduce on packet loss (e.g. 20% reduction) instead of halving abruptly
    int32_t cur = cwnd.load();
    cwnd.store(std::max(cur - std::max(cur / 5, 10), (int32_t)CWND_MIN));
    recompute_derived();
  }

  // ── ACK handler (reset backoff) ──────────────────────────────────────────
  void on_ack() {
    if (consecutive_timeouts.load() > 0)
      consecutive_timeouts.store(0);
    // Don't reset RTO here — Jacobson's algorithm handles it via update_rtt()
  }

  // ── Max retransmits (budget-based) ───────────────────────────────────────
  int get_max_retransmits() const {
    int budget_ms = 10 * (int)MS_PER_SEC; // 10 seconds
    return std::max(10, budget_ms / rto_ms.load());
  }

  // ── Recompute derived parameters ─────────────────────────────────────────
  void recompute_derived() {
    int32_t w = cwnd.load();
    ack_batch.store(std::max(w / 16, 8));
  }

  void print() const {
    std::cout << "── LiveState ──" << std::endl;
    std::cout << "  SRTT:     " << srtt_us.load() / 1000.0 << " ms"
              << std::endl;
    std::cout << "  RTTVAR:   " << rttvar_us.load() / 1000.0 << " ms"
              << std::endl;
    std::cout << "  BaseRTT:  " << base_rtt_us.load() / 1000.0 << " ms"
              << std::endl;
    std::cout << "  RTO:      " << rto_ms.load() << " ms" << std::endl;
    std::cout << "  cwnd:     " << cwnd.load() << " packets" << std::endl;
    std::cout << "  ACK batch:" << ack_batch.load() << std::endl;
    std::cout << "───────────────" << std::endl;
  }
};

} // namespace DataBeam

#endif // DATABEAM_LIVESTATE_H
