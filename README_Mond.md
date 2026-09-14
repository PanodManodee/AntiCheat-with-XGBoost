Quick usage of python files

usage: pcap_adaptor.py [-h] [--output OUTPUT] [--server-port SERVER_PORT] [input ...]

Decode UE5 packets from a .pcap using the UE5 network implementation.

positional arguments:
input pcap file(s) or directory/glob to scan

options:
-h, --help show this help message and exit
--output OUTPUT output CSV path (default: pcap_adaptor_out.csv)
--server-port SERVER_PORT
UDP server port used to identify flows (default: 7777)

usage: parse_pcap.py [-h] [--output OUTPUT] [--server-port SERVER_PORT] [--truth TRUTH] [--match-window-ms MATCH_WINDOW_MS] [--no-bunches] [--no-events] inputs [inputs ...]

Map pcap packet fields onto the .bin-derived ground-truth CSV.

positional arguments:
inputs pcap file(s), directories (recursively scanned) or glob patterns

options:
-h, --help show this help message and exit
--output OUTPUT output packet CSV (default: pcap_mapped.csv)
--server-port SERVER_PORT
UDP server port identifying the flows (default: 7777)
--truth TRUTH ground-truth CSV (default: /home/panodmanodee/projects/python/dos-cheat/parsed_all_packets.csv)
--match-window-ms MATCH_WINDOW_MS
time-window used for the fallback join (default: 50.0)
--no-bunches skip the bunch-level output CSV
--no-events skip the event-label output CSV
