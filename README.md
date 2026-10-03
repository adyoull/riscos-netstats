# NetStats for RISC OS

Network statistics for RISC OS that work with the
[RISC OS Developments TCP/IP stack](https://www.riscosdev.com/projects/network/)
(Internet 7.x, OpenBSD based) as well as the older Acorn/ROOL Internet 5 stack.

- **Monitor**: download and upload rates, totals since start-up, five-minute graph
- **Interfaces**: type, link state and duplex, speed, MTU, MAC, IPv4/IPv6 addresses,
  per-direction rate, bytes, packets, errors and drops
- **Protocols**: TCP, UDP and IP counters with the change per second
- **Connections**: open TCP/UDP sockets (from the stack's `inetstat -an`, run in a TaskWindow)
- Current rates under the icon bar icon; bits/s or bytes/s; settings and window
  positions saved in Choices

Written because SockStatsLite (Chris Williams) stops working on the ROD stack: it reads
`_tcpstat` via `Socket_InternalLookup`, which ROD no longer publishes. NetStats uses
`Socket_Sysctl` instead (`net.route.0.0.iflist`, `net.inet.tcp/udp/ip.stats`), the same calls
ROD's `inetstat` makes. See `appsrc/!Help,fff` for details.

## Download

See [Releases](../../releases): unzip `NetStats-<version>.zip` on RISC OS (filetypes are kept)
and run `!NetStats`. Needs RISC OS 3.5 or later; tested on a Raspberry Pi with the ROD stack.

## Building

The program is BBC BASIC; `src/RunImage.bas` is the text source (no line numbers).

    ./make.sh              # tokenise, draw the sprites, zip with RISC OS filetypes -> build/
    tests/run_tests.sh     # unit tests under Matrix Brandy (sbrandy)

- `tools/tokenise.py` – text to tokenised BASIC (&FFB)
- `tools/mksprites.py` – draws `!Sprites` (32bpp with mask)
- `tools/rozip.py` – zip keeping RISC OS filetypes (`name,xxx` files)
- `tests/make_fixtures.py` – sysctl replies in both stacks' struct layouts

Files named `name,xxx` carry their RISC OS filetype (`,feb` Obey, `,fff` Text).

## Credits

Inspired by SockStats and SockStatsLite by Chris Williams.
Parts of this program were written with the help of an AI assistant.

## Licence

MIT – see `LICENSE`.
