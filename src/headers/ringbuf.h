// =============================================================================
// ringbuf.h — Single-producer single-consumer lock-free ring buffer
// Safe for one writer thread + one reader thread with no mutex.
// For multi-producer use the mutex variant below.
// =============================================================================
#pragma once
#include <atomic>
#include <cstddef>

template <typename T, size_t CAP>
struct RingBuf
{
    static_assert((CAP & (CAP - 1)) == 0, "CAP must be power of 2");

    T slots[CAP];
    std::atomic<size_t> head{0}; // writer advances
    std::atomic<size_t> tail{0}; // reader advances

    // Push — called by ONE producer thread only
    // Returns false if full (back-pressure)
    bool push(const T &item) noexcept
    {
        size_t h = head.load(std::memory_order_relaxed);
        size_t next = (h + 1) & (CAP - 1);
        if (next == tail.load(std::memory_order_acquire))
            return false; // full
        slots[h] = item;
        head.store(next, std::memory_order_release);
        return true;
    }

    // Pop — called by ONE consumer thread only
    bool pop(T &item) noexcept
    {
        size_t t = tail.load(std::memory_order_relaxed);
        if (t == head.load(std::memory_order_acquire))
            return false; // empty
        item = slots[t];
        tail.store((t + 1) & (CAP - 1), std::memory_order_release);
        return true;
    }

    size_t size() const noexcept
    {
        size_t h = head.load(std::memory_order_acquire);
        size_t t = tail.load(std::memory_order_acquire);
        return (h - t) & (CAP - 1);
    }

    bool empty() const noexcept { return size() == 0; }
};

// Multi-producer variant — used when multiple compressor threads push to ready
// Uses a simple spinlock for the push side only
#include <pthread.h>
template <typename T, size_t CAP>
struct MPRingBuf
{
    T slots[CAP];
    std::atomic<size_t> head{0};
    std::atomic<size_t> tail{0};
    pthread_mutex_t push_mutex = PTHREAD_MUTEX_INITIALIZER;

    bool push(const T &item) noexcept
    {
        pthread_mutex_lock(&push_mutex);
        size_t h = head.load(std::memory_order_relaxed);
        size_t next = (h + 1) & (CAP - 1);
        if (next == tail.load(std::memory_order_acquire))
        {
            pthread_mutex_unlock(&push_mutex);
            return false;
        }
        slots[h] = item;
        head.store(next, std::memory_order_release);
        pthread_mutex_unlock(&push_mutex);
        return true;
    }

    bool pop(T &item) noexcept
    {
        size_t t = tail.load(std::memory_order_relaxed);
        if (t == head.load(std::memory_order_acquire))
            return false;
        item = slots[t];
        tail.store((t + 1) & (CAP - 1), std::memory_order_release);
        return true;
    }

    size_t size() const noexcept
    {
        size_t h = head.load(std::memory_order_acquire);
        size_t t = tail.load(std::memory_order_acquire);
        return (h - t) & (CAP - 1);
    }

    bool empty() const noexcept { return size() == 0; }
};
