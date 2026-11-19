// Log-structured record store on a raw flash partition (SPEC 5).
// Plain C with no ESP-IDF dependency, so it can be tested on the host (test/host).
//
// Records are only ever appended. An edit writes a new version, a delete writes a tombstone, and an
// in-memory index points at the newest version of each key. Garbage collection copies the live records
// out of the segment with the least live data and then erases it. Every record carries a CRC, so a write
// cut short by power loss is detected and ignored at the next mount.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LS_SEG_SIZE   65536u  // erase unit used by the store (16 flash sectors)
#define LS_SECTOR     4096u   // flash erase sector
#define LS_SEG_HDR    16u
#define LS_REC_HDR    40u
#define LS_MAX_PAYLOAD (LS_SEG_SIZE - LS_SEG_HDR - LS_REC_HDR)
#define LS_RESERVE_SEGS 3u    // segments' worth of space never promised to live data (GC headroom)
#define LS_RECENT_N   32

enum { LS_KIND_USER = 1, LS_KIND_FOLDER = 2, LS_KIND_CIPHER = 3, LS_KIND_TEST = 4 };
enum { LS_OP_PUT = 1, LS_OP_DEL = 2 };

enum {
    LS_OK = 0,
    LS_ERR_IO = -1,
    LS_ERR_NOMEM = -2,
    LS_ERR_NOSPACE = -3,
    LS_ERR_TOOBIG = -4,
    LS_ERR_NOTFOUND = -5,
    LS_ERR_ARG = -6,
};

typedef struct {
    int (*read)(void *ctx, uint32_t off, void *buf, uint32_t len);         // 0 on success
    int (*write)(void *ctx, uint32_t off, const void *buf, uint32_t len);  // NOR: can only clear bits
    int (*erase)(void *ctx, uint32_t off, uint32_t len);                   // LS_SECTOR aligned
    uint32_t (*now)(void *ctx);                                            // unix seconds, for history
    void *ctx;
    uint32_t size;  // bytes, multiple of LS_SEG_SIZE
} ls_flash_t;

typedef struct {
    uint8_t kind, deleted;
    uint16_t stale;  // older PUT records of this key still physically present (tombstones not counted)
    uint8_t id[16];
    uint32_t off;    // absolute offset of the newest record
    uint32_t len;    // payload length
    uint32_t seq;
    uint32_t time;
} ls_entry_t;

typedef struct {
    uint32_t seq, time;
    uint8_t kind, op;
    uint8_t id[16];
} ls_change_t;

typedef struct {
    uint32_t capacity;      // bytes of records the store promises to hold
    uint32_t live_bytes;    // newest versions (incl. tombstones still needed)
    uint32_t stale_bytes;   // old versions and dead tombstones, reclaimable by GC
    uint32_t free_bytes;    // capacity - live_bytes
    uint16_t segs_total, segs_free, segs_used;
    uint32_t count[5];      // live keys per kind
    uint32_t gc_runs;       // since mount
    uint32_t torn_records;  // detected at mount (power loss during a write)
    uint32_t mount_ms_hint; // unused by the store; for the caller
} ls_stats_t;

typedef struct ls_store ls_store_t;

// Scans the flash, rebuilds the index and repairs half-erased segments. Never loses committed records.
int ls_mount(ls_store_t **out, const ls_flash_t *flash);
void ls_unmount(ls_store_t *ls);
int ls_format(ls_store_t *ls);  // erase everything

// Size a payload of len bytes takes on flash (header + padding). Use it for capacity checks.
uint32_t ls_record_size(uint32_t len);
bool ls_fits(ls_store_t *ls, uint32_t extra_record_bytes);

int ls_put(ls_store_t *ls, uint8_t kind, const uint8_t id[16], const void *data, uint32_t len);
int ls_del(ls_store_t *ls, uint8_t kind, const uint8_t id[16]);
bool ls_exists(ls_store_t *ls, uint8_t kind, const uint8_t id[16]);
// *data is malloc'd (caller frees) and NUL-terminated for convenience
int ls_get(ls_store_t *ls, uint8_t kind, const uint8_t id[16], char **data, uint32_t *len);

// Visits the newest version of every live key of one kind. data is valid only during the call.
typedef int (*ls_visit_cb)(uint8_t kind, const uint8_t id[16], const char *data, uint32_t len, void *ctx);
int ls_foreach(ls_store_t *ls, uint8_t kind, ls_visit_cb cb, void *ctx);

void ls_get_stats(ls_store_t *ls, ls_stats_t *st);
// Most recent changes, newest first. Returns how many were written to out.
int ls_recent(ls_store_t *ls, ls_change_t *out, int max);
