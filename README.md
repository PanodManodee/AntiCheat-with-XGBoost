# dos-cheat

Network-level cheat detection for an Unreal Engine 5 shooter (Lyra-based "CheatNet").
Recorded matches contain both the server's raw UDP traffic (`.pcap`) and a server-side
ground-truth log (`.bin`/`.csv`) that records every packet, player event and injected
cheat (DOS, LagSwitch, FixedDelay, Aimbot, Wallhack, HitRedirection).

The project has two halves:

1. **Feature extraction** – decode the UE5 wire protocol from the pcaps and align every
   packet with the ground truth, producing labelled per-packet / per-bunch / per-event
   CSVs (`parse_pcap.py`).
2. **Modelling** – sliding-window aggregation per player and a multi-label XGBoost
   classifier (`TKL_ServerOnly_model*.ipynb`, see `TKL_code_explanation1.txt`).

---

## Repository layout

| Path | Purpose |
|---|---|
| `parse_pcap.py` | **Main pipeline.** pcap → decoded packets joined to ground truth, with player identity and cheat labels. |
| `pcap_adaptor.py` | Offline UE5 packet decoder (handler prefix, handshake, packet header, packet info, bunch headers). Usable standalone. |
| `truth_loader.py` | Finds and loads the ground-truth trace that sits next to a pcap (`.bin` or `.csv`) and flattens it. |
| `client/` | Vendored UE5 Python network client (bit reader, `NetConnection`, `StatelessConnect` handler) used by the decoder. |
| `data_parse.py` | Older batch flattener: every `Server/*.bin` → `parsed_files/parse_<Session>_<Match>`. |
| `TKL_ServerOnly_model2.ipynb` | Current XGBoost model (windowing, actor resolution, multi-label targets, diagnostics). |
| `TKL_code_explanation1.txt`, `To_be_fixed.txt` | Walkthrough of the model notebook and its known open issues. |
| `main.py`, `find_cheat.py`, `pcap_stream.py`, `Anti-cheat Model.ipynb`, `TKL_ServerOnly_model1.ipynb` | Early exploration scripts/notebooks. |

Not tracked in git (see `.gitignore`): `dataset/`, `ParserProtobufLogs/`, all `*.csv` outputs.

## Setup

Python 3.14 (any recent 3.x should work).

```bash
python -m venv .venv
source .venv/bin/activate
pip install pandas numpy scapy protobuf     # pipeline
pip install xgboost scikit-learn matplotlib # notebooks
```

Optional, for reading `.bin` traces directly (otherwise the `.csv` traces are used):

```bash
git clone https://github.com/Lyra-FullGame/ParserProtobufLogs
```

Place it at the repository root so `from ParserProtobufLogs.parser_utils import RingBufferParser` works.

## Dataset

```
dataset/
  Session_<N>/<Match>/
    metadata.yml                       # clients, server, cheats enabled, start/end time
    Server/
      capture_server_<ts>.pcap         # raw UDP capture on the server (port 7777)
      trace_server_<ts>.bin            # ground truth, protobuf RingBufferLog
      trace_server_<ts>.csv            # same log exported to CSV
    Clients/
      <name>_match_<n>_merged.{bin,csv} # client-side traces
```

Sessions 1–4 have server pcaps with traces. `Session_Specific_Context` pcaps have no trace
(they are processed with `join_method = no_truth`).

## Usage

### Map pcaps onto the ground truth

```bash
# one match
python parse_pcap.py dataset/Session_2/Match3/Server/capture_server_2026.02.26-12.36.06.pcap

# a whole session (directories are scanned recursively), custom output name
python parse_pcap.py dataset/Session_2 --output out/session2.csv
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `--output` | `pcap_mapped.csv` | Packet CSV; `<stem>_bunches.csv` and `<stem>_events.csv` are written beside it. |
| `--truth-source` | `auto` | `bin` (ParserProtobufLogs), `csv` (pandas only) or `auto` (`.bin` if parseable, else `.csv`). |
| `--truth` | – | Explicit trace file; only with a single pcap. |
| `--seq-window-s` | `2.0` | Max time difference for an exact sequence-number match. |
| `--match-window-ms` | `50` | Window for the nearest-time fallback match. |
| `--server-port` | `7777` | UDP port that identifies server traffic. |
| `--no-bunches` / `--no-events` | – | Skip the bunch / event CSV. |

Each match takes about 2 minutes and up to ~5 GB RAM. Per match, the run prints join
statistics, decode errors and the wire-vs-truth bunch agreement as a sanity check.

### Decode pcaps only (no ground truth)

```bash
python pcap_adaptor.py dataset/Session_1 --output pcap_adaptor_out.csv
```

## Outputs

**`<out>.csv` – one row per UDP packet**

- `wire_*` – decoded from the pcap: sequence/acked sequence, jitter clock, server frame time,
  bunch count, channels, handshake fields, decode errors.
- `client_addr`, `address_id`, `player_id`, `player_name`, `player_map_method` – who the
  packet belongs to. `player_map_method` is `exact` (registered ip:port), `ip_only` (only one
  player ever used that IP) or `none` (ambiguous).
- `cheat_active`, `cheat_types` – cheats this packet's player is running at that moment;
  `cheat_target_active`, `cheat_target_types` – cheats aimed at this player.
- `bin_*` – matched ground-truth packet row: notification seq/acked seq, jitter, ids, and
  features from the trace's bunch log (RPC names, control messages, actor classes, client
  movement location/velocity, invalid move timestamps).
- `join_method` (`seq`, `time`, `handshake`, `unmatched`, `no_truth`), `join_delta_ms`,
  `wire_bin_bunch_count_diff` (incoming packets only; ~0 when decoding is aligned).

**`<out>_bunches.csv` – one row per decoded bunch**, with channel index/name, reliable/open/close
flags, close reason, partial flags, channel sequence and payload size, plus parent-packet context.

**`<out>_events.csv` – one row per ground-truth event** (movement, weapon, health, cheat,
phase, new_address, new_player) with the resolved actor (`actor_player_id`, `actor_name`,
`actor_addr`) and the same cheat label columns.

## How it works

1. **Decoding** (`pcap_adaptor.py`): UDP payloads to/from the server port are sorted by time
   and decoded per client connection. The decoder handles the StatelessConnect handler
   prefix, then the packet header (seq/ack/history). It then reads the packet info:
   jitter clock, the frame-time flag, and the frame-time byte, which only server→client
   packets carry. Finally it parses the bunch headers.
2. **Ground truth** (`truth_loader.py`): `capture_<x>.pcap` → `trace_<x>.bin|.csv` in the
   same folder (falls back to a `*_merged` trace with the same timestamp). Nested records are
   flattened to dotted columns (`notification.seq`, `weapon.target_id`, …); field-name
   differences between the two export formats are normalised.
3. **Identity**: `new_address` events map address id → `ip:port`; `new_player` events map
   `ip:port` → player id (time-aware).
4. **Join**: exact (client, direction, seq), nearest in time; then nearest unused row of the same
   client and direction within the time window.
5. **Labels**: cheat events come in start/stop pairs (`cheat.start` True / False); unpaired
   starts last `cheat.dur` seconds.

## Known caveats

- On server→client packets, `wire_acked_seq` (last client seq the server received) and
  `bin_notif_acked_seq` (server's own last-acked out-seq) are different quantities by design.
- The `.bin` reader in ParserProtobufLogs truncates sub-second duration fields
  (`weapon.time`, `movement.ts_client`) to 0; the `.csv` traces keep them.
- The `.csv` traces lack `cheat.in_`, `weapon.cartridge_id` and `new_player.update_ip_port`.
- Players sharing an IP who never registered their exact ip:port get no `player_id`.
- Truth bunch logs exist only for client→server packets.
- Open modelling issues are listed in `To_be_fixed.txt`.
