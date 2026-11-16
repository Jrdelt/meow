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
    if (st->alt_screen || st->pending_cr || st->line_truncated) {
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
    if (st->line_bad < 255u) {
        st->line_bad++;
    }
}

static uint8_t ascii_lower(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

static int equals_ci(const uint8_t *s, uint32_t n, const char *lit)
{
    uint32_t i = 0;

    while (lit[i] != '\0') {
        if (i >= n || ascii_lower(s[i]) != (uint8_t)lit[i]) {
            return 0;
        }
        i++;
    }
    return i == n;
}

static int ends_with_ci(const uint8_t *s, uint32_t n, const char *suffix)
{
    uint32_t m = 0;

    while (suffix[m] != '\0') {
        m++;
    }
    if (m == 0 || m > n) {
        return 0;
    }
    return equals_ci(s + (n - m), m, suffix);
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

static int is_secret_prefix(const uint8_t *prefix, uint32_t plen)
{
    return equals_ci(prefix, plen, "password:") ||
           equals_ci(prefix, plen, "passphrase:") ||
           equals_ci(prefix, plen, "pass phrase:") ||
           equals_ci(prefix, plen, "passcode:") ||
           equals_ci(prefix, plen, "token:") ||
           equals_ci(prefix, plen, "secret:") ||
           ends_with_ci(prefix, plen, "'s password:") ||
           ends_with_ci(prefix, plen, "enter password:") ||
           ends_with_ci(prefix, plen, "enter passphrase:") ||
           ends_with_ci(prefix, plen, "enter pass phrase:") ||
           ends_with_ci(prefix, plen, "enter pem pass phrase:") ||
           ends_with_ci(prefix, plen, "enter passcode:") ||
           ends_with_ci(prefix, plen, "enter token:") ||
           ends_with_ci(prefix, plen, "enter secret:") ||
           ends_with_ci(prefix, plen, "api key:") ||
           ends_with_ci(prefix, plen, "api-key:") ||
           ends_with_ci(prefix, plen, "secret key:") ||
           ends_with_ci(prefix, plen, "client secret:") ||
           ends_with_ci(prefix, plen, "access token:") ||
           ends_with_ci(prefix, plen, "bearer token:") ||
           ends_with_ci(prefix, plen, "auth token:") ||
           ends_with_ci(prefix, plen, "refresh token:") ||
           contains_ci(prefix, plen, "[sudo] password") ||
           contains_ci(prefix, plen, "password for ") ||
           contains_ci(prefix, plen, "passphrase for ") ||
           contains_ci(prefix, plen, "pass phrase for ");
}

/*
 * Interactive secret prompt: mentions a password/passphrase and ends with
 * ':' (sudo, su, ssh, ssh-keygen, openssl, ...), or contains an interactive
 * secret prompt prefix ending at ':' followed by echoed input on the same line.
 */
static int is_secret_prompt(const uint8_t *line, uint32_t len)
{
    uint32_t start = 0;
    const uint8_t *trimmed;
    uint32_t tlen;
    uint32_t colon;

    while (start < len && (line[start] == ' ' || line[start] == '\t')) {
        start++;
    }
    if (start >= len) {
        return 0;
    }
    trimmed = line + start;
    tlen = len - start;

    if (trimmed[tlen - 1] == ':') {
        if (contains_ci(trimmed, tlen, "password") ||
            contains_ci(trimmed, tlen, "passphrase") ||
            contains_ci(trimmed, tlen, "pass phrase") ||
            contains_ci(trimmed, tlen, "passcode") ||
            contains_ci(trimmed, tlen, "api key") ||
            contains_ci(trimmed, tlen, "api-key") ||
            contains_ci(trimmed, tlen, "secret key") ||
            contains_ci(trimmed, tlen, "client secret") ||
            contains_ci(trimmed, tlen, "access token") ||
            contains_ci(trimmed, tlen, "bearer token") ||
            contains_ci(trimmed, tlen, "auth token") ||
            ends_with_ci(trimmed, tlen, "token:") ||
            equals_ci(trimmed, tlen, "secret:")) {
            return 1;
        }
    }
    for (colon = 0; colon < tlen; colon++) {
        if (trimmed[colon] == ':' && is_secret_prefix(trimmed, colon + 1u)) {
            return 1;
        }
    }
    return 0;
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
        st->last_cup_row = 0;
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
        st->last_cup_row = 0;
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
 * controls in the middle of a sequence; CAN, SUB and LF end an incomplete
 * sequence so it cannot bleed into the next line. */
static void c0_in_sequence(tap_state_t *st, uint8_t b, tap_out_t *out)
{
    if (b == 0x18u || b == 0x1Au) {
        st->mode = TAP_GROUND;
    } else {
        c0_execute(st, b, out);
        if (b == 0x0Au) {
            st->mode = TAP_GROUND;
        }
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
        st->csi_second = 0;
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
        st->last_cup_row = 0;
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
    } else if (st->csi_nparams == 1) {
        st->csi_second = v;
    }
    if (v == 47 || v == 1047 || v == 1049) {
        st->csi_alt_hit = 1;
    }
    if (st->csi_nparams < 255) {
        st->csi_nparams++;
    }
    st->csi_param = 0;
}

static void csi_dispatch(tap_state_t *st, uint8_t final, tap_out_t *out)
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
    if (final == 'K' && (st->csi_first == 2 || (st->csi_first == 0 && st->pending_cr))) {
        line_reset(st); /* EL 2 or CR + EL 0: erase whole line (spinner redraw) */
    } else if (final == 'G' && st->csi_first <= 1) {
        st->pending_cr = 1; /* CHA 1: cursor to column 1, same as bare CR */
    } else if ((final == 'E' || final == 'F') && !st->alt_screen) {
        /* CNL / CPL: Windows ConPTY and TUIs jump to the next/previous row. */
        st->last_cup_row = 0;
        line_emit(st, out);
    } else if ((final == 'H' || final == 'f') && !st->alt_screen) {
        /* CUP / HVP: Windows ConPTY often repositions between rows via CSI r;c H. */
        uint32_t row = (st->csi_first == 0) ? 1u : st->csi_first;
        uint32_t col = (st->csi_nparams < 2 || st->csi_second == 0) ? 1u : st->csi_second;
        if ((st->last_cup_row != 0 && row != st->last_cup_row) ||
            (st->last_cup_row == 0 && st->line_len > 0)) {
            line_emit(st, out);
        } else if (col <= 1u) {
            st->pending_cr = 1;
        }
        st->last_cup_row = row;
    } else if (final == 'C' && !st->alt_screen) {
        /* CUF (CSI <n> C): Windows ConPTY translates runs of spaces into cursor-forward. */
        uint32_t n = (st->csi_first == 0) ? 1u : st->csi_first;
        const uint8_t sp = ' ';
        if (n > 256u) {
            n = 256u;
        }
        while (n-- > 0) {
            line_push(st, &sp, 1);
        }
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
        csi_dispatch(st, b, out);
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
