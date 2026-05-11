"""
network_monitor.py - Network Activity Monitor
===============================================
Two modes:
  - Mock mode (local testing): Extracts network info from API hook logs
  - VM mode (future): Integrates with FakeNet-NG for full PCAP capture

Usage:
    monitor = NetworkMonitor(mode="mock")
    report = monitor.analyze(api_report_path)
    monitor.save_report("reports/raw/network_activity.json")
"""

import os
import json
import time
import re


class NetworkMonitor:
    """Monitors network activity via API hooks or FakeNet-NG."""

    # APIs that indicate network activity
    NET_APIS = {
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "closesocket", "shutdown",
        "gethostbyname", "getaddrinfo", "freeaddrinfo",
        "WSAStartup", "WSACleanup", "WSASocketW",
        "InternetOpenW", "InternetOpenA",
        "InternetConnectW", "InternetConnectA",
        "HttpOpenRequestW", "HttpOpenRequestA",
        "HttpSendRequestW", "HttpSendRequestA",
        "InternetReadFile",
        "URLDownloadToFileW", "URLDownloadToFileA",
    }

    # Well-known suspicious ports
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default",
        5555: "Common RAT",
        8080: "HTTP alternate (C2)",
        8443: "HTTPS alternate (C2)",
        1337: "Common backdoor",
        31337: "Back Orifice",
        6667: "IRC (botnet C2)",
        6697: "IRC SSL",
    }

    def __init__(self, mode="mock"):
        """
        Args:
            mode: "mock" (parse API hooks) or "vm" (use FakeNet-NG)
        """
        self.mode = mode
        self.report_data = {}

    def _load_api_calls(self, api_report_path):
        """Load API calls from the collector report."""
        if not os.path.exists(api_report_path):
            print(f"[NET_MON] WARNING: API report not found: {api_report_path}")
            return []

        with open(api_report_path) as f:
            report = json.load(f)

        calls = []
        for proc in report.get("behavior", {}).get("processes", []):
            for c in proc.get("calls", []):
                calls.append(c)

        return calls

    def _extract_ip_port(self, args_dict):
        """Try to extract IP and port from API call arguments."""
        ip = None
        port = None

        # The hook logs connect() as: {"address": "127.0.0.1:8080"}
        # Parse the combined "ip:port" format first
        for key, value in args_dict.items():
            val_str = str(value)

            # Check for "IP:PORT" combined format (most common from our hooks)
            ip_port_match = re.match(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', val_str)
            if ip_port_match:
                ip = ip_port_match.group(1)
                port = int(ip_port_match.group(2))
                return ip, port

            # Check for standalone IP addresses
            ip_match = re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', val_str)
            if ip_match:
                ip = ip_match.group(1)

            # Check for port in named fields
            if "port" in key.lower():
                try:
                    port = int(val_str)
                except (ValueError, TypeError):
                    pass

        return ip, port

    def _extract_hostname(self, args_dict):
        """Extract hostname from DNS-related API arguments."""
        for key, value in args_dict.items():
            val_str = str(value)
            # Our hooks use these argument names
            if key.lower() in ("name", "hostname", "lpszservername",
                               "nodename", "lpszurl", "pnodename",
                               "pname", "host", "server"):
                return val_str
        # Fallback: check all values for domain-like patterns
        for key, value in args_dict.items():
            val_str = str(value)
            if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', val_str):
                return val_str
        return None

    def _analyze_mock(self, calls):
        """Analyze network behavior from API hook data (mock mode)."""
        connections = []
        dns_queries = []
        http_requests = []
        sockets_created = 0
        net_api_calls = []
        send_recv_data = []  # Track data transfer

        for c in calls:
            api = c.get("api", "")
            args = c.get("arguments", {})
            cat = c.get("category", "")

            if api not in self.NET_APIS and cat != "NET":
                continue

            net_api_calls.append({
                "api": api,
                "time": c.get("time", 0),
                "args": args,
            })

            # Socket creation
            if api in ("socket", "WSASocketW"):
                sockets_created += 1

            # Connection attempts
            elif api == "connect":
                ip, port = self._extract_ip_port(args)
                conn = {
                    "api": api,
                    "ip": ip or "unknown",
                    "port": port,
                    "time": c.get("time", 0),
                    "result": c.get("return", ""),
                }
                if port and port in self.SUSPICIOUS_PORTS:
                    conn["suspicious"] = self.SUSPICIOUS_PORTS[port]
                connections.append(conn)

            # DNS queries
            elif api in ("gethostbyname", "getaddrinfo"):
                hostname = self._extract_hostname(args)
                if hostname:
                    dns_queries.append({
                        "api": api,
                        "hostname": hostname,
                        "time": c.get("time", 0),
                    })

            # Data transfer
            elif api in ("send", "sendto"):
                data_len = args.get("len", 0)
                send_recv_data.append({
                    "direction": "outbound",
                    "bytes": data_len,
                    "time": c.get("time", 0),
                })

            elif api in ("recv", "recvfrom"):
                data_len = args.get("len", 0)
                send_recv_data.append({
                    "direction": "inbound",
                    "bytes": data_len,
                    "time": c.get("time", 0),
                })

            # HTTP requests (WinINet)
            elif api in ("HttpOpenRequestW", "HttpOpenRequestA",
                         "InternetConnectW", "InternetConnectA"):
                hostname = self._extract_hostname(args)
                http_requests.append({
                    "api": api,
                    "target": hostname or "unknown",
                    "time": c.get("time", 0),
                })

            # URL downloads
            elif api in ("URLDownloadToFileW", "URLDownloadToFileA"):
                url = None
                filepath = None
                for k, v in args.items():
                    if "url" in k.lower():
                        url = str(v)
                    if "file" in k.lower():
                        filepath = str(v)
                http_requests.append({
                    "api": api,
                    "url": url or "unknown",
                    "download_path": filepath,
                    "time": c.get("time", 0),
                })

            # WSASend/WSARecv (alternative data transfer)
            elif api == "WSASend":
                total_bytes = args.get("totalBytes", 0)
                send_recv_data.append({
                    "direction": "outbound",
                    "bytes": total_bytes if isinstance(total_bytes, int) else 0,
                    "time": c.get("time", 0),
                })

            elif api == "WSARecv":
                buf_count = args.get("bufferCount", 0)
                send_recv_data.append({
                    "direction": "inbound",
                    "bytes": buf_count if isinstance(buf_count, int) else 0,
                    "time": c.get("time", 0),
                })

            # Bind — server behavior
            elif api == "bind":
                ip, port = self._extract_ip_port(args)
                connections.append({
                    "api": api,
                    "ip": ip or "0.0.0.0",
                    "port": port,
                    "time": c.get("time", 0),
                    "result": c.get("return", ""),
                    "type": "bind",
                })

            # Listen — server behavior
            elif api == "listen":
                connections.append({
                    "api": api,
                    "ip": None,
                    "port": None,
                    "time": c.get("time", 0),
                    "result": c.get("return", ""),
                    "type": "listen",
                    "backlog": args.get("backlog", 0),
                })

            # Accept — incoming connections
            elif api == "accept":
                ip, port = self._extract_ip_port(args)
                connections.append({
                    "api": api,
                    "ip": ip,
                    "port": port,
                    "time": c.get("time", 0),
                    "result": c.get("return", ""),
                    "type": "accept",
                })

        # Detect connections without DNS (hardcoded IPs = suspicious)
        resolved_ips = set()
        for q in dns_queries:
            resolved_ips.add(q["hostname"])

        connections_without_dns = []
        for conn in connections:
            ip = conn.get("ip", "")
            if ip and ip != "unknown" and ip not in ("127.0.0.1", "0.0.0.0"):
                has_dns = False
                for q in dns_queries:
                    if q["hostname"] == ip:
                        has_dns = True
                        break
                if not has_dns:
                    connections_without_dns.append(ip)

        # Calculate data transfer totals
        total_sent = sum(d["bytes"] for d in send_recv_data
                         if d["direction"] == "outbound" and isinstance(d["bytes"], int))
        total_recv = sum(d["bytes"] for d in send_recv_data
                         if d["direction"] == "inbound" and isinstance(d["bytes"], int))

        return {
            "mode": "mock",
            "connections": connections,
            "dns_queries": dns_queries,
            "http_requests": http_requests,
            "data_transfer": {
                "total_bytes_sent": total_sent,
                "total_bytes_received": total_recv,
                "transfers": send_recv_data,
            },
            "sockets_created": sockets_created,
            "total_net_api_calls": len(net_api_calls),
            "connections_without_dns": connections_without_dns,
            "suspicious_ports": [
                c for c in connections if c.get("suspicious")
            ],
        }

    def _analyze_fakenet(self, pcap_path=None, fakenet_log=None):
        """Analyze network from FakeNet-NG output (VM mode)."""
        # Placeholder for FakeNet-NG integration
        print("[NET_MON] FakeNet-NG mode: not yet implemented")
        print("[NET_MON] Will parse PCAP and FakeNet JSON logs when in VM")

        result = {
            "mode": "fakenet",
            "connections": [],
            "dns_queries": [],
            "http_requests": [],
            "pcap_file": pcap_path,
            "note": "FakeNet-NG integration pending (requires VM deployment)",
        }

        # Parse FakeNet JSON log if available
        if fakenet_log and os.path.exists(fakenet_log):
            try:
                with open(fakenet_log) as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            # FakeNet-NG log parsing would go here
                        except json.JSONDecodeError:
                            pass
            except (OSError, PermissionError):
                pass

        return result

    def analyze(self, api_report_path, pcap_path=None, fakenet_log=None):
        """Run network analysis."""
        print(f"[NET_MON] Analyzing network activity (mode: {self.mode})...")

        if self.mode == "mock":
            calls = self._load_api_calls(api_report_path)
            self.report_data = self._analyze_mock(calls)
        else:
            self.report_data = self._analyze_fakenet(pcap_path, fakenet_log)

        return self.report_data

    def generate_report(self):
        """Generate the network activity report."""
        data = self.report_data

        summary = {
            "total_connections": len(data.get("connections", [])),
            "total_dns_queries": len(data.get("dns_queries", [])),
            "total_http_requests": len(data.get("http_requests", [])),
            "sockets_created": data.get("sockets_created", 0),
            "connections_without_dns": data.get("connections_without_dns", []),
            "suspicious_ports_used": [
                c.get("suspicious") for c in data.get("suspicious_ports", [])
            ],
            "c2_risk": "HIGH" if data.get("connections_without_dns") else
                       "MEDIUM" if data.get("suspicious_ports") else "LOW",
        }

        data["summary"] = summary

        return {
            "component": "network_activity",
            "version": "1.0",
            "timestamp": time.time(),
            "data": data,
        }

    def save_report(self, output_path):
        """Save the report to a JSON file."""
        report = self.generate_report()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        s = report["data"]["summary"]
        print(f"[NET_MON] Report saved: {output_path}")
        print(f"[NET_MON]   Connections:    {s['total_connections']}")
        print(f"[NET_MON]   DNS queries:    {s['total_dns_queries']}")
        print(f"[NET_MON]   HTTP requests:  {s['total_http_requests']}")
        print(f"[NET_MON]   C2 risk level:  {s['c2_risk']}")

        if s["connections_without_dns"]:
            print(f"[NET_MON]   WARNING: Connections without DNS: "
                  f"{s['connections_without_dns']}")

        return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Network Monitor")
    parser.add_argument("--api-report",
                        default="sandbox/reports/test_report.json")
    parser.add_argument("--mode", choices=["mock", "vm"], default="mock")
    parser.add_argument("--output",
                        default="sandbox/reports/raw/network_activity.json")
    args = parser.parse_args()

    monitor = NetworkMonitor(mode=args.mode)
    monitor.analyze(args.api_report)
    monitor.save_report(args.output)
