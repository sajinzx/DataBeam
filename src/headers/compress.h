// =============================================================================
// compress.h — Optimised compression using zlib internals + heuristics
// Strategy: small data → Z_RLE, compressible → Z_DEFAULT, else store raw
// =============================================================================
#pragma once
#include <zlib.h>
#include <cstddef>
#include <cstring>
#include <cstdint>

// =============================================================================
// Entropy estimator — samples up to 256 bytes to decide if data is worth
// compressing. Skips compression entirely for already-compressed data
// (images, pre-zipped buffers, encrypted payloads) saving wasted CPU.
// Returns true if data is likely compressible.
// =============================================================================
static inline bool is_compressible(const char *data, size_t len) noexcept
{
    // Too small to bother — compression header overhead exceeds any gain
    if (len < 64)
        return false;

    // Sample up to 256 bytes evenly spread across the buffer
    uint32_t freq[256] = {};
    size_t step = (len < 256) ? 1 : len / 256;
    size_t samples = 0;

    for (size_t i = 0; i < len; i += step, ++samples)
        freq[(uint8_t)data[i]]++;

    // Shannon entropy approximation — count distinct byte values seen
    // High cardinality with uniform distribution = low compressibility
    uint32_t distinct = 0;
    for (int i = 0; i < 256; ++i)
        if (freq[i])
            ++distinct;

    // Heuristic thresholds (tuned empirically):
    //   < 64  distinct values  → text/structured data  → compress
    //   64–200                 → mixed                 → compress
    //   > 200 distinct values  → binary/encrypted      → skip
    return distinct <= 200;
}

// =============================================================================
// compress_data — replaces your compress2(..., 6) call
//
// Strategy selection:
//   len <  256 B  → Z_BEST_SPEED  (level 1) — latency beats ratio at this size
//   len <   4 KB  → Z_RLE         (level 1, RLE strategy) — fast, good for
//                                  repetitive protocol headers
//   len >= 4 KB   → Z_DEFAULT_COMPRESSION (level 6, deflate) — best ratio
//                   for large file chunks
//
// Compressibility check:  if the entropy sampler flags the data as
//   incompressible, the raw bytes are copied into output with a 1-byte
//   header (0x00) so the caller can detect "not compressed" without
//   re-attempting decompression and failing.
//
// Returns 0 on success (same as your original).
// output_len is updated to the actual compressed (or copied) byte count.
// =============================================================================
inline int compress_data(const char *input,
                         size_t input_len,
                         char *output,
                         size_t &output_len) noexcept
{
    // --- Guard: output buffer must have room for at least input + 1 byte ----
    if (output_len < input_len + 1)
        return Z_BUF_ERROR;

    // --- Entropy check: skip compression for already-compressed data --------
    if (!is_compressible(input, input_len))
    {
        // Store raw: 1-byte marker (0x00) + original data
        output[0] = 0x00;
        memcpy(output + 1, input, input_len);
        output_len = input_len + 1;
        return 0; // caller sees success; packet type flag tells receiver
    }

    // --- Pick strategy based on chunk size ----------------------------------
    int level = Z_DEFAULT_COMPRESSION; // 6
    int strategy = Z_DEFAULT_STRATEGY;

    if (input_len < 256)
    {
        level = Z_BEST_SPEED; // level 1 — minimise latency
        strategy = Z_DEFAULT_STRATEGY;
    }
    else if (input_len < 4096)
    {
        level = 1;
        strategy = Z_RLE; // fast RLE for small structured data
    }
    // else: keep level 6, Z_DEFAULT_STRATEGY for large chunks

    // --- Use raw deflate via deflateInit2 (skips 2-byte zlib header +
    //     4-byte Adler-32 trailer — saves 6 bytes per packet) ----------------
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    // +1 byte marker for "compressed" flag (0x01)
    zs.next_in = (Bytef *)input;
    zs.avail_in = (uInt)input_len;
    zs.next_out = (Bytef *)(output + 1); // leave room for marker byte
    zs.avail_out = (uInt)(output_len - 1);

    // windowBits = -15 → raw deflate (no zlib wrapper, no Adler-32)
    int ret = deflateInit2(&zs, level, Z_DEFLATED,
                           -15, // raw deflate, no header
                           8,   // memory level (1–9, 8 is default)
                           strategy);
    if (ret != Z_OK)
        return ret;

    ret = deflate(&zs, Z_FINISH);
    deflateEnd(&zs);

    if (ret != Z_STREAM_END)
        return (ret == Z_OK) ? Z_BUF_ERROR : ret;

    size_t compressed_size = zs.total_out + 1; // +1 for marker byte

    // --- Expansion check: if compression grew the data, store raw instead ---
    if (compressed_size >= input_len + 1)
    {
        output[0] = 0x00; // raw marker
        memcpy(output + 1, input, input_len);
        output_len = input_len + 1;
        return 0;
    }

    output[0] = 0x01; // compressed marker
    output_len = compressed_size;
    return 0;
}

// =============================================================================
// decompress_data — replaces your uncompress() call
//
// Reads the 1-byte marker written by compress_data:
//   0x00 → data was stored raw, memcpy it out
//   0x01 → raw deflate stream, inflate it
//
// Returns 0 on success (same as your original).
// =============================================================================
inline int decompress_data(const char *input,
                           size_t input_len,
                           char *output,
                           size_t &output_len) noexcept
{
    if (input_len < 2)
        return Z_DATA_ERROR;

    uint8_t marker = (uint8_t)input[0];

    // --- Raw / uncompressed passthrough -------------------------------------
    if (marker == 0x00)
    {
        size_t data_len = input_len - 1;
        if (data_len > output_len)
            return Z_BUF_ERROR;
        memcpy(output, input + 1, data_len);
        output_len = data_len;
        return 0;
    }

    // --- Raw deflate inflation ----------------------------------------------
    if (marker != 0x01)
        return Z_DATA_ERROR; // unknown marker — corrupt packet

    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    zs.next_in = (Bytef *)(input + 1); // skip marker byte
    zs.avail_in = (uInt)(input_len - 1);
    zs.next_out = (Bytef *)output;
    zs.avail_out = (uInt)output_len;

    // windowBits = -15 → raw inflate (matches raw deflate above)
    int ret = inflateInit2(&zs, -15);
    if (ret != Z_OK)
        return ret;

    ret = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);

    if (ret != Z_STREAM_END)
        return Z_DATA_ERROR;

    output_len = zs.total_out;
    return 0;
}
