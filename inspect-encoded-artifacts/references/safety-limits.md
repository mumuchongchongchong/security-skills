# Safety limits

## Defaults

| Limit | Default | Purpose |
|---|---:|---|
| `max_depth` | 4 | Bound nested transformations |
| `max_input_bytes` | 1 MiB | Bound explicitly supplied input reads |
| `max_output_bytes` | 2 MiB | Bound each decoded or decompressed output |
| `max_candidates` | 100 | Bound decoder fan-out |
| `max_preview_chars` | 1000 | Bound redacted previews |
| `max_decompression_ratio` | 100 | Bound Gzip/Zlib expansion |

CLI arguments may lower these values but may not exceed the compiled defaults or disable them. Treat a zero, negative, or oversized value as an error.

## Limit handling

- Read at most `max_input_bytes + 1` bytes from the one explicitly named input file.
- Keep decoded bytes in memory and write only the report to standard output.
- Use bounded streaming-style Zlib operations for both Gzip and Zlib data.
- Stop a transformation that would exceed its output or decompression-ratio allowance.
- Stop creating candidates at `max_candidates`.
- Stop recursion at `max_depth`.
- Record every triggered limit and list the unfinished work in `incomplete_analysis`.
- Prefer `INCONCLUSIVE` risk status when limits or parse errors leave relevant content unexamined.

Never disable limits, make network requests, open decoded paths, extract archives, or execute content to "complete" an analysis.
