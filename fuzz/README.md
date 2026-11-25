# Fuzzing meow

Fuzzing means feeding a program large amounts of random and mutated input to
find crashes. meow reads text that other people's machines produced, so these
fuzz targets feed that kind of input to its parsers and its C terminal filter,
to find panics, hangs and memory errors before anyone else does.

| Target | What it fuzzes |
|---|---|
| `parse_text` | `meow add`: format detection, then the Nmap XML, JSONL (katana, feroxbuster), git diff or log parser |
| `nmap_xml` | The Nmap XML parser, with names trusted and untrusted, and the open-port reader used by recon |
| `terminal_lines` | The line parser fed one terminal line at a time, as the live tap does |
| `tap_filter` | The C11 ECMA-48 filter that turns raw terminal bytes into lines, fed in chunks of every size. It also checks that every line is a single line, and that no line is lost for want of buffer room |

## Run it

You need nightly Rust and cargo-fuzz:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

Then, from the repository root, run one target for a minute:

```sh
mkdir -p fuzz/corpus/tap_filter && cp fuzz/seeds/tap_filter/* fuzz/corpus/tap_filter/
CC=clang CFLAGS=-fsanitize=address,fuzzer-no-link \
  cargo +nightly fuzz run tap_filter fuzz/corpus/tap_filter -- -max_total_time=60
```

`CC=clang CFLAGS=-fsanitize=address,fuzzer-no-link` builds the C filter with
AddressSanitizer (a compiler feature that catches memory errors) and coverage
instrumentation. An out-of-bounds read or write
in C then stops the run like a Rust panic does, and the fuzzer can see which
paths through the C code an input reaches. (In a two-minute run that lifted
`tap_filter` from 145 covered edges to 641.)

A crash leaves its input in `fuzz/artifacts/<target>/`. Replay it with:

```sh
cargo +nightly fuzz run tap_filter fuzz/artifacts/tap_filter/crash-<hash>
```

Fix the bug, then add a unit test with that input next to the code it broke.

## In CI

`.github/workflows/fuzz.yml` runs every target for 5 minutes each week, and on
demand from **Actions → fuzz → Run workflow** with a time of your choice. A
crash fails the run and uploads the input.

`fuzz/seeds/` holds small, hand-written starting inputs (documentation
addresses only). `fuzz/corpus/` and `fuzz/artifacts/` are local and not
committed.
