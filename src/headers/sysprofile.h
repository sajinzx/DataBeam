// =============================================================================
// sysprofile.h — Hardware & System Profiling (Phase 6.1)
//
// Probes the local machine to set upper bounds of the pipeline:
//   - CPU topology: core count → worker thread allocation
//   - Memory pressure: available RAM → pool slot budget (10% rule, cap 1GB)
//   - Instruction set: AES-NI / AVX2 → cwnd recommendation
// =============================================================================
#ifndef DATABEAM_SYSPROFILE_H
#define DATABEAM_SYSPROFILE_H

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#elif defined(_MSC_VER)
#include <intrin.h>
#endif

#include "constants.h"

namespace DataBeam {

struct SystemProfile {
  uint32_t total_cores;
  uint32_t worker_threads; // total_cores - 2

  uint64_t available_ram_mb;
  uint32_t pool_slot_count; // power-of-2, for PoolSlot array

  bool has_aes_ni;
  bool has_avx2;

  // Recommended initial cwnd based on hardware capabilities
  uint32_t recommended_cwnd() const {
    if (!has_aes_ni)
      return 1024; // CPU-limited without hardware AES
    return SR_WINDOW_SIZE; // full speed
  }

  // Probe the local machine — call once at startup
  static SystemProfile probe() {
    SystemProfile p;

    // ── CPU Topology ──────────────────────────────────────────────────────
    p.total_cores = std::thread::hardware_concurrency();
    if (p.total_cores == 0)
      p.total_cores = 4; // fallback
    p.worker_threads = (p.total_cores > 2) ? (p.total_cores - 2) : 1;

    // ── Memory Pressure ───────────────────────────────────────────────────
#ifdef _WIN32
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
      p.available_ram_mb = (uint64_t)(mem.ullAvailPhys / (1024ULL * 1024ULL));
    } else {
      p.available_ram_mb = 4096; // fallback 4GB
    }
#else
    p.available_ram_mb = 4096; // fallback
#endif

    // 10% rule: pool budget = 10% of available RAM, capped at 1GB
    // Each PoolSlot is approximately sizeof(PoolSlot) ≈ 1420 bytes
    const uint64_t SLOT_SIZE_APPROX = 1500;
    uint64_t budget_bytes = std::min(p.available_ram_mb * 1024ULL * 1024ULL / 10,
                                     1024ULL * 1024ULL * 1024ULL);
    uint64_t slot_count = budget_bytes / SLOT_SIZE_APPROX;

    // Round down to nearest power of 2
    uint32_t pot = 4096; // minimum = SR_WINDOW_SIZE
    while ((uint64_t)pot * 2 <= slot_count && pot < 65536)
      pot *= 2;
    p.pool_slot_count = pot;

    // ── Instruction Set Detection (CPUID) ─────────────────────────────────
    p.has_aes_ni = false;
    p.has_avx2 = false;

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
#if defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
      p.has_aes_ni = (ecx & (1 << 25)) != 0;
    }
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
      p.has_avx2 = (ebx & (1 << 5)) != 0;
    }
#else
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    p.has_aes_ni = (cpuInfo[2] & (1 << 25)) != 0; // ECX bit 25

    __cpuidex(cpuInfo, 7, 0);
    p.has_avx2 = (cpuInfo[1] & (1 << 5)) != 0; // EBX bit 5
#endif
#endif

    return p;
  }

  void print() const {
    std::cout << "\n=== System Profile ===" << std::endl;
    std::cout << "  CPU Cores:        " << total_cores << std::endl;
    std::cout << "  Worker Threads:   " << worker_threads
              << " (cores - 2)" << std::endl;
    std::cout << "  Available RAM:    " << available_ram_mb << " MB"
              << std::endl;
    std::cout << "  Pool Slot Budget: " << pool_slot_count << " slots"
              << std::endl;
    std::cout << "  AES-NI:           " << (has_aes_ni ? "YES" : "NO")
              << std::endl;
    std::cout << "  AVX2:             " << (has_avx2 ? "YES" : "NO")
              << std::endl;
    std::cout << "  Initial cwnd:     " << recommended_cwnd() << std::endl;
    std::cout << "======================\n" << std::endl;
  }
};

} // namespace DataBeam

#endif // DATABEAM_SYSPROFILE_H
