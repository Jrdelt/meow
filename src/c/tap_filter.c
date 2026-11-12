/*
 * tap_filter.c - stateful VT500 / ECMA-48 stream filter. See tap_filter.h.
 */
#include "tap_filter.h"

typedef struct tap_out {
    uint8_t *buf;
    size_t cap;
    size_t len;
} tap_out_t;

static void tap_step(tap_state_t *st, uint8_t b, tap_out_t *out);

/* ------------------------------------------------------------------ */
/* Line buffer                                                         */
/* ------------------------------------------------------------------ */

static void line_reset(tap_state_t *st)
{
    st->line_len = 0;
    st->line_bad = 0;
    st->line_truncated = 0;
    st->pending_cr = 0;
}

/* Append one whole character (1-4 bytes). Never splits a character. */
static void line_push(tap_state_t *st, const uint8_t *bytes, uint32_t n)
{
    uint32_t i;

    if (st->alt_screen) {
        return;
    }
    if (st->pending_cr) {
        /* Bare CR followed by text: the line is being overwritten. */
        line_reset(st);
    }
    if (st->line_truncated) {
        return;
    }
    if (st->line_len + n > TAP_LINE_MAX) {
        st->line_truncated = 1;
        return;
    }
    for (i = 0; i < n; i++) {
        st->line[st->line_len++] = bytes[i];
    }
}

/* Backspace: remove the last whole character. */
static void line_pop(tap_state_t *st)
{
    if (st->alt_screen || st->pending_cr) {
        return;
    }
    while (st->line_len > 0) {
        st->line_len--;
        if ((st->line[st->line_len] & 0xC0u) != 0x80u) {
            break; /* removed a lead byte or an ASCII byte */
        }
    }
}

static void line_mark_bad(tap_state_t *st)
{
    if (st->alt_screen) {
        return;
    }
    if (st->pending_cr) {
        line_reset(st);
    }
    st->line_bad++;
}

static uint8_t ascii_lower(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

static int contains_ci(const uint8_t *hay, uint32_t n, const char *needle)
{
    uint32_t m = 0;
    uint32_t i;
    uint32_t j;

    while (needle[m] != '\0') {
        m++;
    }
    if (m == 0 || m > n) {
        return 0;
    }
    for (i = 0; i + m <= n; i++) {
        for (j = 0; j < m; j++) {
            if (ascii_lower(hay[i + j]) != (uint8_t)needle[j]) {
                break;
            }
        }
        if (j == m) {
            return 1;
        }
    }
    return 0;
}

/*
 * Interactive secret prompt: mentions a password/passphrase and ends with
 * ':' (sudo, su, ssh, ssh-keygen, openssl, ...). Requiring the trailing
 * colon keeps ordinary output that merely mentions passwords.
 */
static int is_secret_prompt(const uint8_t *line, uint32_t len)
{
    if (len == 0 || line[len - 1] != ':') {
        return 0;
    }
    return contains_ci(line, len, "password") ||
           contains_ci(line, len, "passphrase") ||
           contains_ci(line, len, "pass phrase") ||
           contains_ci(line, len, "passcode");
}

static void line_emit(tap_state_t *st, tap_out_t *out)
{
    uint32_t len = st->line_len;
    uint32_t bad = st->line_bad;
    uint32_t i;

    line_reset(st); /* clears counters only; line[] bytes stay readable */
    if (st->alt_screen) {
        return;
    }
    if (bad > TAP_BAD_MAX) {
        st->stats.dropped_binary++;
        return;
    }
    while (len > 0 && (st->line[len - 1] == ' ' || st->line[len - 1] == '\t')) {
        len--;
    }
    if (len == 0) {
        return;
    }
    if (is_secret_prompt(st->line, len)) {
        st->stats.dropped_secret++;
        return;
    }
    if (out->cap - out->len < (size_t)len + 1u) {
        st->stats.dropped_nospace++;
        return;
    }
    for (i = 0; i < len; i++) {
        out->buf[out->len++] = st->line[i];
    }
    out->buf[out->len++] = '\n';
    st->stats.lines_emitted++;
}

static void set_alt_screen(tap_state_t *st, uint8_t on)
{
    if (st->alt_screen != on) {
        line_reset(st);
        st->alt_screen = on;
    }
}

/* ------------------------------------------------------------------ */
/* C0 controls                                                         */
/* ------------------------------------------------------------------ */

static void c0_execute(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    switch (b) {
    case 0x1B: /* ESC */
        st->mode = TAP_ESCAPE;
        break;
    case 0x0A: /* LF */
        line_emit(st, out);
        break;
    case 0x0D: /* CR: decided by the next byte (LF = newline, text = rewind) */
        st->pending_cr = 1;
        break;
    case 0x08: /* BS */
        line_pop(st);
        break;
    case 0x09: /* HT */
        line_push(st, &b, 1);
        break;
    case 0x07: /* BEL */
    case 0x0B: /* VT */
    case 0x0C: /* FF */
    case 0x0E: /* SO */
    case 0x0F: /* SI */
        break;
    default: /* NUL and other controls do not occur in text output */
        line_mark_bad(st);
        break;
    }
}

/* C0 handling shared by the ESCAPE / ESC_INTER / CSI states: VT500 executes
 * controls in the middle of a sequence; CAN and SUB abort it. */
static void c0_in_sequence(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    if (b == 0x18 || b == 0x1A) {
        st->mode = TAP_GROUND;
    } else {
        c0_execute(st, b, out);
    }
}

/* ------------------------------------------------------------------ */
/* GROUND: text + UTF-8 validation                                     */
/* ------------------------------------------------------------------ */

static void utf8_begin(tap_state_t *st, uint8_t lead, uint8_t need,
                       uint8_t lo, uint8_t hi)
{
    st->u8_buf[0] = lead;
    st->u8_have = 1;
    st->u8_need = need;
    st->u8_lo = lo;
    st->u8_hi = hi;
}

static void ground(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    if (st->u8_need) {
        if (b >= st->u8_lo && b <= st->u8_hi) {
            st->u8_buf[st->u8_have++] = b;
            st->u8_need--;
            st->u8_lo = 0x80;
            st->u8_hi = 0xBF;
            if (st->u8_need == 0) {
                /* U+0080..U+009F are C1 controls: drop, do not print. */
                if (!(st->u8_have == 2 && st->u8_buf[0] == 0xC2 &&
                      st->u8_buf[1] < 0xA0)) {
                    line_push(st, st->u8_buf, st->u8_have);
                }
            }
            return;
        }
        /* Truncated sequence: count it, then treat b as a fresh byte. */
        st->u8_need = 0;
        line_mark_bad(st);
    }

    if (b < 0x20) {
        c0_execute(st, b, out);
    } else if (b < 0x7F) {
        line_push(st, &b, 1);
    } else if (b == 0x7F) {
        /* DEL: ignored */
    } else if (b >= 0xC2 && b <= 0xDF) {
        utf8_begin(st, b, 1, 0x80, 0xBF);
    } else if (b == 0xE0) {
        utf8_begin(st, b, 2, 0xA0, 0xBF); /* reject overlong */
    } else if (b == 0xED) {
        utf8_begin(st, b, 2, 0x80, 0x9F); /* reject surrogates */
    } else if (b >= 0xE1 && b <= 0xEF) {
        utf8_begin(st, b, 2, 0x80, 0xBF);
    } else if (b == 0xF0) {
        utf8_begin(st, b, 3, 0x90, 0xBF); /* reject overlong */
    } else if (b >= 0xF1 && b <= 0xF3) {
        utf8_begin(st, b, 3, 0x80, 0xBF);
    } else if (b == 0xF4) {
        utf8_begin(st, b, 3, 0x80, 0x8F); /* reject > U+10FFFF */
    } else {
        line_mark_bad(st); /* stray continuation, 0xC0/0xC1, 0xF5..0xFF */
    }
}

/* ------------------------------------------------------------------ */
/* Escape sequences                                                    */
/* ------------------------------------------------------------------ */

static void string_begin(tap_state_t *st, uint8_t is_osc)
{
    st->mode = is_osc ? TAP_OSC : TAP_STRING;
    st->str_is_osc = is_osc;
    st->str_len = 0;
}

static void escape(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    if (b < 0x20) {
        c0_in_sequence(st, b, out);
    } else if (b == '[') {
        st->mode = TAP_CSI;
        st->csi_param = 0;
        st->csi_first = 0;
        st->csi_private = 0;
        st->csi_seen = 0;
        st->csi_inter = 0;
        st->csi_invalid = 0;
        st->csi_nparams = 0;
        st->csi_alt_hit = 0;
    } else if (b == ']') {
        string_begin(st, 1);
    } else if (b == 'P' || b == 'X' || b == '^' || b == '_') {
        string_begin(st, 0);
    } else if (b <= 0x2F) {
        st->mode = TAP_ESC_INTER;
    } else if (b == 'c') {
        /* RIS: full reset returns to the main screen. */
        st->mode = TAP_GROUND;
        set_alt_screen(st, 0);
    } else if (b <= 0x7E) {
        st->mode = TAP_GROUND; /* two-byte escape, e.g. ESC 7 / ESC = */
    } else if (b == 0x7F) {
        /* ignored */
    } else {
        st->mode = TAP_GROUND;
        ground(st, b, out);
    }
}

static void esc_inter(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    if (b < 0x20) {
        c0_in_sequence(st, b, out);
    } else if (b <= 0x2F || b == 0x7F) {
        /* more intermediates */
    } else if (b <= 0x7E) {
        st->mode = TAP_GROUND;
    } else {
        st->mode = TAP_GROUND;
        ground(st, b, out);
    }
}

static void csi_param_end(tap_state_t *st)
{
    uint32_t v = st->csi_param;

    if (st->csi_nparams == 0) {
        st->csi_first = v;
    }
    if (v == 47 || v == 1047 || v == 1049) {
        st->csi_alt_hit = 1;
    }
    if (st->csi_nparams < 255) {
        st->csi_nparams++;
    }
    st->csi_param = 0;
}

static void csi_dispatch(tap_state_t *st, uint8_t final)
{
    if (st->csi_inter || st->csi_invalid) {
        return;
    }
    if (st->csi_private == '?') {
        /* DECSET / DECRST: alternate screen buffer (smcup / rmcup). */
        if (st->csi_alt_hit && (final == 'h' || final == 'l')) {
            set_alt_screen(st, final == 'h' ? 1 : 0);
        }
        return;
    }
    if (st->csi_private != 0) {
        return;
    }
    if (final == 'K' && st->csi_first == 2) {
        line_reset(st); /* EL 2: erase whole line (spinner redraw) */
    } else if (final == 'G' && st->csi_first <= 1) {
        st->pending_cr = 1; /* CHA 1: cursor to column 1, same as bare CR */
    }
}

static void csi(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    if (b < 0x20) {
        c0_in_sequence(st, b, out);
        return;
    }
    if (b >= '0' && b <= '9') {
        if (st->csi_param < 100000u) {
            st->csi_param = st->csi_param * 10u + (uint32_t)(b - '0');
        }
    } else if (b == ';' || b == ':') {
        csi_param_end(st);
    } else if (b >= 0x3C && b <= 0x3F) {
        if (st->csi_seen) {
            st->csi_invalid = 1;
        } else {
            st->csi_private = b;
        }
    } else if (b <= 0x2F) {
        st->csi_inter = 1;
    } else if (b <= 0x7E) {
        csi_param_end(st);
        st->mode = TAP_GROUND;
        csi_dispatch(st, b);
        return;
    } else if (b == 0x7F) {
        /* ignored */
    } else {
        st->mode = TAP_GROUND;
        ground(st, b, out);
        return;
    }
    st->csi_seen = 1;
}

static void string_body(tap_state_t *st, uint8_t b)
{
    if (b == 0x1B) {
        st->mode = TAP_STRING_ESC;
    } else if (b == 0x18 || b == 0x1A || (b == 0x07 && st->str_is_osc)) {
        st->mode = TAP_GROUND;
    } else if (++st->str_len > TAP_STRING_MAX) {
        st->mode = TAP_GROUND; /* unterminated: give up on it */
    }
}

static void string_esc(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    if (b == '\\') {
        st->mode = TAP_GROUND; /* ST */
    } else {
        /* The ESC ended the string and starts a new sequence. */
        st->mode = TAP_ESCAPE;
        tap_step(st, b, out);
    }
}

static void tap_step(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    switch (st->mode) {
    case TAP_ESCAPE:
        escape(st, b, out);
        break;
    case TAP_ESC_INTER:
        esc_inter(st, b, out);
        break;
    case TAP_CSI:
        csi(st, b, out);
        break;
    case TAP_OSC:
    case TAP_STRING:
        string_body(st, b);
        break;
    case TAP_STRING_ESC:
        string_esc(st, b, out);
        break;
    case TAP_GROUND:
    default:
        ground(st, b, out);
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

size_t tap_state_size(void)
{
    return sizeof(tap_state_t);
}

size_t tap_state_align(void)
{
    return _Alignof(tap_state_t);
}

size_t tap_line_max(void)
{
    return TAP_LINE_MAX;
}

void tap_init(tap_state_t *st)
{
    uint8_t *p = (uint8_t *)st;
    size_t i;

    if (st == NULL) {
        return;
    }
    for (i = 0; i < sizeof(*st); i++) {
        p[i] = 0;
    }
    st->mode = TAP_GROUND;
}

size_t tap_feed(tap_state_t *st, const uint8_t *in, size_t in_len,
                uint8_t *out, size_t out_cap)
{
    tap_out_t o;
    size_t i;

    if (st == NULL || in == NULL) {
        return 0;
    }
    o.buf = out;
    o.cap = (out != NULL) ? out_cap : 0;
    o.len = 0;
    for (i = 0; i < in_len; i++) {
        tap_step(st, in[i], &o);
    }
    return o.len;
}

size_t tap_flush(tap_state_t *st, uint8_t *out, size_t out_cap)
{
    tap_out_t o;

    if (st == NULL) {
        return 0;
    }
    o.buf = out;
    o.cap = (out != NULL) ? out_cap : 0;
    o.len = 0;
    if (st->u8_need) {
        st->u8_need = 0;
        line_mark_bad(st);
    }
    line_emit(st, &o);
    return o.len;
}

void tap_get_stats(const tap_state_t *st, tap_stats_t *out)
{
    if (st != NULL && out != NULL) {
        *out = st->stats;
    }
}

int tap_in_alt_screen(const tap_state_t *st)
{
    return (st != NULL && st->alt_screen) ? 1 : 0;
}
