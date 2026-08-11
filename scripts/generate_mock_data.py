#!/usr/bin/env python3
"""Generate deterministic AWSVPCFlow-shaped records with anomaly scenarios."""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def record(
    when: datetime,
    *,
    src: str,
    dst: str,
    src_port: int,
    dst_port: int,
    action: str,
    bytes_count: int,
    packets: int,
    log_status: str = "OK",
    direction: str = "ingress",
    protocol: int = 6,
    region: str = "us-east-1",
    traffic_path: str = "1",
    traffic_type: str = "IPv4",
    instance: str = "i-0a11ce00000000001",
    interface: str = "eni-0a11ce0000000001",
    subnet: str = "subnet-0a11ce00000001",
    vpc: str = "vpc-0a11ce000000001",
    pkt_dst_service: str = "",
    pkt_src_service: str = "",
) -> dict[str, Any]:
    start = when - timedelta(seconds=55)
    return {
        "TimeGenerated": iso(when),
        "AccountId": "123456789012",
        "Action": action,
        "AzId": f"{region}a",
        "Bytes": bytes_count,
        "DstAddr": dst,
        "DstPort": dst_port,
        "End": iso(when),
        "FlowDirection": direction,
        "InstanceId": instance,
        "InterfaceId": interface,
        "LogStatus": log_status,
        "Packets": packets,
        "PktDstAddr": dst,
        "PktDstAwsService": pkt_dst_service,
        "PktSrcAddr": src,
        "PktSrcAwsService": pkt_src_service,
        "Protocol": protocol,
        "Region": region,
        "SrcAddr": src,
        "SrcPort": src_port,
        "Start": iso(start),
        "SubnetId": subnet,
        "TcpFlags": 2 if protocol == 6 else 0,
        "TrafficPath": traffic_path,
        "TrafficType": traffic_type,
        "Version": 5,
        "VpcId": vpc,
    }


def generate(seed: int, now: datetime) -> tuple[list[dict[str, Any]], Counter[str]]:
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    scenarios: Counter[str] = Counter()

    def add(scenario: str, **kwargs: Any) -> None:
        rows.append(record(**kwargs))
        scenarios[scenario] += 1

    internal_hosts = [f"10.20.{subnet}.{host}" for subnet in range(1, 4) for host in range(10, 31)]
    public_clients = [f"198.51.100.{host}" for host in range(10, 60)]

    for _ in range(320):
        when = now - timedelta(seconds=rng.randint(0, 24 * 3600))
        direction = rng.choice(["ingress", "egress"])
        if direction == "ingress":
            src, dst = rng.choice(public_clients), rng.choice(internal_hosts)
            dst_port = rng.choice([80, 443, 443, 443])
        else:
            src, dst = rng.choice(internal_hosts), rng.choice(
                ["13.107.42.14", "52.95.110.1", "151.101.1.69"]
            )
            dst_port = rng.choice([443, 443, 80])
        add(
            "normal",
            when=when,
            src=src,
            dst=dst,
            src_port=rng.randint(1024, 65535),
            dst_port=dst_port,
            action="ACCEPT",
            bytes_count=rng.randint(500, 250_000),
            packets=rng.randint(5, 300),
            direction=direction,
        )

    scanner = "203.0.113.45"
    scan_target = "10.20.1.15"
    for offset, port in enumerate(range(20, 100)):
        add(
            "port_scan",
            when=now - timedelta(minutes=15, seconds=offset),
            src=scanner,
            dst=scan_target,
            src_port=41000 + offset,
            dst_port=port,
            action="REJECT",
            bytes_count=60,
            packets=1,
        )

    brute_source = "198.51.100.250"
    for offset in range(55):
        add(
            "ssh_bruteforce",
            when=now - timedelta(minutes=35, seconds=offset * 8),
            src=brute_source,
            dst="10.20.2.22",
            src_port=50000 + offset,
            dst_port=22,
            action="REJECT" if offset < 52 else "ACCEPT",
            bytes_count=120 if offset < 52 else 5_000,
            packets=2 if offset < 52 else 25,
        )

    for offset in range(12):
        add(
            "high_volume_egress",
            when=now - timedelta(minutes=65, seconds=offset * 30),
            src="10.20.3.25",
            dst="203.0.113.200",
            src_port=55000 + offset,
            dst_port=443,
            action="ACCEPT",
            bytes_count=750_000_000 + offset * 25_000_000,
            packets=450_000 + offset * 5_000,
            direction="egress",
            traffic_path="8",
            instance="i-0badc0ffee0000001",
            interface="eni-0badc0ffee000001",
            subnet="subnet-0a11ce00000003",
        )

    for offset in range(70):
        add(
            "dns_spike",
            when=now - timedelta(minutes=120, seconds=offset * 3),
            src="10.20.1.29",
            dst="8.8.8.8",
            src_port=30000 + offset,
            dst_port=53,
            action="ACCEPT",
            bytes_count=rng.randint(70, 220),
            packets=1,
            direction="egress",
            protocol=17,
        )

    for offset in range(18):
        add(
            "lateral_movement",
            when=now - timedelta(minutes=45, seconds=offset * 20),
            src="10.20.1.50",
            dst=f"10.20.2.{30 + offset}",
            src_port=47000 + offset,
            dst_port=rng.choice([22, 3389, 445]),
            action="ACCEPT",
            bytes_count=rng.randint(2_000, 90_000),
            packets=rng.randint(20, 500),
            direction="egress",
        )

    for offset, status in enumerate(["NODATA"] * 5 + ["SKIPDATA"] * 7):
        add(
            "collection_health",
            when=now - timedelta(hours=3, minutes=offset),
            src="-",
            dst="-",
            src_port=0,
            dst_port=0,
            action="-",
            bytes_count=0,
            packets=0,
            log_status=status,
            protocol=0,
        )

    for offset in range(10):
        add(
            "ipv6",
            when=now - timedelta(hours=4, minutes=offset),
            src=f"2001:db8:1::{offset + 1}",
            dst="2606:4700:4700::1111",
            src_port=60000 + offset,
            dst_port=443,
            action="ACCEPT",
            bytes_count=rng.randint(1_000, 50_000),
            packets=rng.randint(10, 100),
            direction="egress",
            traffic_type="IPv6",
        )

    rows.sort(key=lambda item: item["TimeGenerated"])
    return rows, scenarios


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="mock-data.json")
    parser.add_argument("--manifest", default=".mock-manifest.json")
    parser.add_argument("--seed", type=int, default=20260811)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows, scenarios = generate(args.seed, datetime.now(timezone.utc))
    Path(args.output).write_text(
        json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    manifest = {
        "generatedAt": iso(datetime.now(timezone.utc)),
        "seed": args.seed,
        "records": len(rows),
        "scenarios": dict(sorted(scenarios.items())),
    }
    Path(args.manifest).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
