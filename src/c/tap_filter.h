/*
 * tap_filter.h - stateful VT500 / ECMA-48 stream filter for the meow
 * read-only analysis tap.
 *
 * The filter consumes raw PTY bytes in arbitrary chunks and produces clean,
 * newline-terminated UTF-8 text lines. All parser state lives in tap_state_t,
 * so escape sequences and multi-byte characters may be split anywhere across
 * chunk boundaries.
 *
 * It is never placed inline with terminal display output: the PTY host writes
 * raw bytes to stdout and hands copies to this filter on a worker thread.
 *
 * Portable C11; depends only on <stddef.h> and <stdint.h>.
 */
#ifndef MEOW_TAP_FILTER_H
#define MEOW_TAP_FILTER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Longest line kept, in bytes. Longer lines are truncated on a character
 * boundary. */
#define TAP_LINE_MAX 4096u

/* A line carrying more than this many invalid/binary bytes is dropped. */
#define TAP_BAD_MAX 3u

/* An OSC/DCS/APC/PM/SOS string longer than this is treated as unterminated
 * and abandoned, so a stray introducer cannot swallow the stream forever. */
#define TAP_STRING_MAX 65536u

typedef enum tap_mode {
    TAP_GROUND = 0,    /* plain text */
    TAP_ESCAPE,        /* after ESC */
    TAP_ESC_INTER,     /* ESC + intermediate bytes (e.g. ESC ( B) */
    TAP_CSI,           /* ESC [ ... final */
    TAP_OSC,           /* ESC ] ... BEL | ST */
    TAP_STRING,        /* DCS / SOS / PM / APC ... ST */
    TAP_STRING_ESC     /* ESC seen inside OSC/STRING (possible ST) */
} tap_mode_t;

typedef struct tap_stats {
    uint64_t lines_emitted;
    uint64_t dropped_binary;  /* lines dropped as binary / non-UTF-8 */
    uint64_t dropped_secret;  /* password / passphrase prompts suppressed */
    uint64_t dropped_nospace; /* lines lost because the output buffer was full */
} tap_stats_t;

typedef struct tap_state {
    tap_stats_t stats;

    uint32_t line_len;   /* bytes buffered in line[] */
    uint32_t line_bad;   /* invalid/binary bytes seen on this line */
    uint32_t csi_param;  /* parameter currently being accumulated */
    uint32_t csi_first;  /* value of the first parameter */
    uint32_t str_len;    /* bytes consumed by the current OSC/STRING */

    uint8_t mode;           /* tap_mode_t */
    uint8_t alt_screen;     /* 1 between ?1049h and ?1049l */
    uint8_t pending_cr;     /* CR seen; rewind on next text, emit on LF */
    uint8_t line_truncated; /* line[] hit TAP_LINE_MAX */

    uint8_t csi_private; /* private marker byte ('?', '>', ...) or 0 */
    uint8_t csi_seen;    /* at least one byte consumed after "ESC [" */
    uint8_t csi_inter;   /* intermediate byte present */
    uint8_t csi_invalid; /* malformed sequence; ignore on dispatch */
    uint8_t csi_nparams; /* parameters completed so far (saturating) */
    uint8_t csi_alt_hit; /* a parameter was 47, 1047 or 1049 */
    uint8_t str_is_osc;  /* current string is an OSC (BEL terminates it) */

    uint8_t u8_need; /* UTF-8 continuation bytes still expected */
    uint8_t u8_have; /* bytes collected in u8_buf */
    uint8_t u8_lo;   /* valid range for the next continuation byte */
    uint8_t u8_hi;
    uint8_t u8_buf[4];

    uint8_t line[TAP_LINE_MAX];
} tap_state_t;

/* Layout facts for foreign callers that allocate the state themselves. */
size_t tap_state_size(void);
size_t tap_state_align(void);
size_t tap_line_max(void);

/* Reset *st to its initial state (GROUND, main screen, empty line). */
void tap_init(tap_state_t *st);

/*
 * Feed in_len raw bytes. Completed clean lines are written to out, each
 * terminated by '\n'. Returns the number of bytes written.
 *
 * Callers should size out_cap generously (e.g. 2 * in_len + TAP_LINE_MAX + 2,
 * since CSI n C cursor-forward sequences expand to spaces). Any line that
 * does not fit in out_cap is dropped whole and counted in dropped_nospace.
 */
size_t tap_feed(tap_state_t *st, const uint8_t *in, size_t in_len,
                uint8_t *out, size_t out_cap);

/*
 * Emit the buffered partial line, if any (same filters as tap_feed). Call at
 * end of stream. Needs out_cap >= TAP_LINE_MAX + 1 to be lossless.
 */
size_t tap_flush(tap_state_t *st, uint8_t *out, size_t out_cap);

void tap_get_stats(const tap_state_t *st, tap_stats_t *out);
int tap_in_alt_screen(const tap_state_t *st);

#ifdef __cplusplus
}
#endif

#endif /* MEOW_TAP_FILTER_H */
