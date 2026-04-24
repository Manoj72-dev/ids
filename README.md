# CIDS

Custom Intrusion Detection System (CIDS) is a final-year project implemented in C. The system captures live network traffic with `libpcap`, parses packet headers, evaluates traffic against a rule set, and generates alerts for suspicious or monitored events.

## Abstract

The aim of this project is to demonstrate how a lightweight host-side intrusion detection system can be designed and implemented from first principles. CIDS monitors live traffic on a chosen network interface, extracts protocol metadata, compares that metadata against custom detection rules, and stores alerts for later review. The project focuses on core IDS concepts such as packet capture, protocol analysis, rule-based detection, alert logging, daemon execution, and configurable runtime behavior.

## Project Objectives

- Build a working packet capture tool in C using `libpcap`
- Parse common network protocols and extract useful metadata
- Design and implement a rule-based detection engine
- Provide foreground and daemon modes for monitoring
- Store alerts and operational logs on disk
- Support user configuration through CLI options and a config file
- Demonstrate testing, documentation, and modular software design

## Features

- Live packet capture on a selected interface
- Foreground monitoring and background daemon mode
- Packet parsing for Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, and ICMPv6
- Custom rule engine with:
- exact IP matching
- CIDR subnet matching
- exact ports and port ranges
- directional `->` and bidirectional `<>` matching
- TCP flag checks
- ICMP type matching
- ARP opcode matching
- threshold-based alerting by source IP
- Config-file defaults with CLI overrides
- Alert log read/clear operations
- Unit tests for rules, CLI parsing, and config loading

## System Architecture

The system is divided into small modules so each part has a clear responsibility.

- `src/main.c`: entry point and high-level control flow
- `src/cli.c`: parses arguments and validates user actions
- `src/config.c`: loads default runtime values from `config/cids.conf`
- `src/capture.c`: opens the network interface, captures packets, parses headers, and invokes rule evaluation
- `src/rules.c`: loads rule files and evaluates packets against detection rules
- `src/alerts.c`: writes alerts to disk and reads/clears stored alerts
- `src/daemon.c`: starts, stops, and tracks the background daemon process

### High-Level Workflow

```text
User Input / Config
        |
        v
  CLI + Validation
        |
        v
  Packet Capture (libpcap)
        |
        v
  Protocol Parsing
        |
        v
  Rule Evaluation
        |
        v
  Alert Generation
        |
        v
  Log Storage / User Review
```

## Project Layout

- `src/`: source code
- `include/`: header files
- `config/cids.conf`: runtime defaults
- `rules/cids.rules`: default detection rules
- `logs/alerts.log`: generated alerts
- `logs/cids.log`: daemon runtime log
- `tests/`: unit tests and test fixtures
- `build/`: compiled output

## Requirements

- `gcc`
- `make`
- `libpcap` development package

On Debian-based systems:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
```

## Build Instructions

Compile the project:

```bash
make
```

The executable is created at `build/cids`.

Clean generated binaries:

```bash
make clean
```

## Test Instructions

Run the full automated test suite:

```bash
make test
```

Available individual test targets:

- `make test-rules`
- `make test-cli`
- `make test-config`

## Usage

Show help:

```bash
./build/cids -h
```

List available interfaces:

```bash
./build/cids -l
```

Capture 25 packets on `eth0` with verbose output:

```bash
./build/cids -i eth0 -n 25 -v
```

Capture continuously using a BPF filter:

```bash
./build/cids -i eth0 -n 0 -p "tcp port 80"
```

Load a custom rules file:

```bash
./build/cids -i eth0 -f tests/rules_test.rules
```

Run the IDS as a daemon:

```bash
./build/cids -i eth0 --daemon --log-packets
```

Check daemon status:

```bash
./build/cids --status
```

Stop the daemon:

```bash
./build/cids --stop
```

Read stored alerts:

```bash
./build/cids -r
```

Clear stored alerts:

```bash
./build/cids -c
```

## Configuration

Defaults are loaded from `config/cids.conf` before CLI arguments are parsed. Command-line options override config values.

Example configuration:

```ini
interface=
protocol=
packet_count=100
verbose=false
log_packets=false
rule_file=rules/cids.rules
```

## Rule Format

The rule format used by CIDS is:

```text
action protocol src_ip src_port direction dst_ip dst_port (option:value; option:value;)
```

Example:

```text
alert tcp 192.168.1.0/24 any -> any 80 (msg:"HTTP request"; severity:medium; sid:2001; flags:S;)
```

Supported options:

- `msg`
- `severity`
- `flags`
- `icmp_type`
- `arp_opcode`
- `threshold`
- `sid`

Supported protocol keywords:

- `any`
- `ip`
- `tcp`
- `udp`
- `icmp`
- `icmp6`
- `icmpv6`
- `arp`

## Logs and Runtime Files

- Alerts are appended to `logs/alerts.log`
- Daemon output is written to `logs/cids.log`
- The daemon PID is stored in `logs/cids.pid`
- The daemon log rotates to `logs/cids.log.1` when it reaches 5 MB

## Demonstration Scenario

One simple demo flow for a project presentation:

1. Build the project with `make`
2. Show the available interfaces with `./build/cids -l`
3. Start monitoring on a chosen interface with verbose mode enabled
4. Generate traffic such as a ping, web request, or SSH connection attempt
5. Show the resulting terminal output and alert log entries
6. Explain which rule matched and why

Example commands:

```bash
./build/cids -i eth0 -v -n 0
ping -c 2 8.8.8.8
curl http://example.com
./build/cids -r
```

## Expected Outcomes

When traffic matches a rule, the system should:

- decode the packet metadata
- evaluate the packet against loaded rules
- generate an alert message
- append the alert to `logs/alerts.log`
- optionally print packet details in verbose mode

## Limitations

This project is functional, but it is intentionally lightweight. Current limitations include:

- no deep payload inspection
- no offline `.pcap` replay mode
- no advanced signature syntax such as rule includes or suppression lists
- thresholding is simple and based only on source IP counters
- limited automated coverage for real packet capture and daemon lifecycle behavior
- no database or remote alert forwarding

## Future Improvements

Possible extensions for future work:

- add offline `.pcap` analysis mode
- support payload/content matching
- add more advanced rule syntax and rule grouping
- add richer logging formats such as JSON
- provide dashboard or web-based alert visualization
- improve alert correlation and scanning detection logic
- package the project for easier deployment

## Academic Value

This project demonstrates:

- network programming concepts
- systems programming in C
- modular software architecture
- rule-based detection logic
- process management and daemonization
- testing and documentation practices

These areas make it suitable as a final-year project focused on cybersecurity, networks, or systems development.

## Notes

- Live capture may require root privileges or suitable Linux capabilities
- The `-p` option accepts a `libpcap` BPF filter expression
- The default runtime rule file is `rules/cids.rules`
