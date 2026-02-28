"""
Temel ag zafiyet tarayici.

Ozellikler:
- Hedef IP veya CIDR araliginda acik portlari tarar
- python-nmap mevcutsa servis tespiti yapar
- nmap yoksa soket tabanli taramaya geri doner
- Yaygin guvensiz servisler icin temel risk ipuclari uretir
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import socket
import time
from typing import Iterable, List, Optional, Tuple


DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080
]

SERVICE_PORT_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "ms-wbt-server",
    8080: "http-alt",
}

RISK_HINTS = {
    21: "FTP genelde duz metindir; SFTP/FTPS tercih edin.",
    23: "Telnet duz metindir; kapatin veya SSH ile degistirin.",
    25: "SMTP disari acik; relay kisitlarini ve kimlik dogrulamayi kontrol edin.",
    53: "DNS disari acik; recursion ve zone transferlerini kisitlayin.",
    80: "HTTP disari acik; TLS kullanin ve web sunucuyu guncel tutun.",
    110: "POP3 duz metindir; POP3S/IMAPS tercih edin.",
    139: "NetBIOS/SMB eski; kullanilmiyorsa kisitlayin veya kapatin.",
    143: "IMAP duz metindir; IMAPS tercih edin.",
    445: "SMB disari acik; yamalayin ve ag erisimini kisitlayin.",
    3306: "Veritabani disari acik; erisimi kisitlayin ve kimlik dogrulamayi zorlayin.",
    3389: "RDP disari acik; erisimi kisitlayin ve mumkunse MFA kullanin.",
    8080: "Alternatif HTTP disari acik; kimlik dogrulama ve yamalari kontrol edin.",
}


class ScanResult:
    def __init__(self, host: str) -> None:
        self.host = host
        self.open_ports: List[Tuple[int, str, Optional[str]]] = []
        self.hints: List[str] = []


def parse_ports(port_spec: str) -> List[int]:
    ports: List[int] = []
    parts = [p.strip() for p in port_spec.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    unique = sorted(set(p for p in ports if 1 <= p <= 65535))
    return unique


def iter_targets(target: str) -> Iterable[str]:
    network = ipaddress.ip_network(target, strict=False)
    for ip in network.hosts():
        yield str(ip)


def socket_scan_host(host: str, ports: List[int], timeout: float) -> ScanResult:
    result = ScanResult(host)

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            status = sock.connect_ex((host, port))
            if status == 0:
                service = SERVICE_PORT_MAP.get(port, "unknown")
                banner = _try_banner(sock)
                result.open_ports.append((port, service, banner))
                hint = RISK_HINTS.get(port)
                if hint:
                    result.hints.append(hint)
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

    return result


def _try_banner(sock: socket.socket) -> Optional[str]:
    try:
        sock.settimeout(1.0)
        sock.sendall(b"\r\n")
        data = sock.recv(128)
        if data:
            banner = data.decode(errors="ignore").strip()
            return banner if banner else None
    except OSError:
        return None
    return None


def nmap_scan_hosts(
    targets: List[str],
    ports: List[int],
    timeout: float,
) -> List[ScanResult]:
    try:
        import nmap  # type: ignore
    except Exception:
        raise RuntimeError("python-nmap kurulu degil")

    scanner = nmap.PortScanner()
    port_arg = ",".join(str(p) for p in ports)
    results: List[ScanResult] = []

    for host in targets:
        try:
            scanner.scan(hosts=host, arguments=f"-sS -sV -Pn -T4 -p {port_arg}")
        except Exception as exc:
            raise RuntimeError(f"nmap taramasi basarisiz: {exc}")

        if host not in scanner.all_hosts():
            continue

        host_state = scanner[host].state()
        if host_state != "up":
            continue

        result = ScanResult(host)
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                port_data = scanner[host][proto][port]
                if port_data.get("state") != "open":
                    continue
                service = port_data.get("name") or SERVICE_PORT_MAP.get(port, "unknown")
                product = port_data.get("product") or ""
                version = port_data.get("version") or ""
                extra = port_data.get("extrainfo") or ""
                banner_parts = [p for p in [product, version, extra] if p]
                banner = " ".join(banner_parts) if banner_parts else None
                result.open_ports.append((int(port), service, banner))
                hint = RISK_HINTS.get(int(port))
                if hint:
                    result.hints.append(hint)

        results.append(result)

    time.sleep(timeout)
    return results


def print_report(results: List[ScanResult]) -> None:
    print("\n=== Tarama Raporu ===")
    if not results:
        print("Yanit veren host bulunamadi.")
        return

    for res in results:
        print(f"\nHost: {res.host}")
        if not res.open_ports:
            print("  Secilen aralikta acik port bulunamadi.")
            continue

        print("  Acik portlar:")
        for port, service, banner in res.open_ports:
            if banner:
                print(f"    - {port}/tcp {service} ({banner})")
            else:
                print(f"    - {port}/tcp {service}")

        if res.hints:
            print("  Risk ipuclari:")
            for hint in sorted(set(res.hints)):
                print(f"    - {hint}")


def scan_with_threads(
    targets: List[str],
    ports: List[int],
    timeout: float,
    workers: int,
) -> List[ScanResult]:
    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(socket_scan_host, host, ports, timeout) for host in targets]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Temel ag zafiyet tarayici (egitim amacli)."
    )
    parser.add_argument(
        "target",
        help="Hedef IP veya CIDR araligi (ornek: 192.168.1.0/24)",
    )
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Port listesi veya araligi (ornek: 22,80,443 veya 1-1024)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Soket zaman asimi (saniye)",
    )
    parser.add_argument(
        "--use-nmap",
        action="store_true",
        help="Mevcutsa servis tespiti icin nmap kullan",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Ayni anda calisacak is parcacigi sayisi",
    )

    args = parser.parse_args()
    ports = parse_ports(args.ports)
    targets = list(iter_targets(args.target))
    workers = max(1, args.workers)

    print("Tarama basliyor...")
    print(f"Hedef sayisi: {len(targets)}")
    print(f"Port sayisi: {len(ports)}")

    results: List[ScanResult] = []

    if args.use_nmap:
        try:
            results = nmap_scan_hosts(targets, ports, args.timeout)
        except RuntimeError as exc:
            print(f"Nmap kullanilamadi: {exc}")
            print("Soket tabanli taramaya geri donuluyor.")

    if not results:
        results = scan_with_threads(targets, ports, args.timeout, workers)

    print_report(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
