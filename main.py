import argparse
import asyncio
import ipaddress
import json
import os
import socket
import sys
from pathlib import Path

from scanner.diff import compute_diff, load_previous_scan, save_scan
from scanner.engine import scan_ports
from scanner.report_md import save_markdown_report

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 27017
]

# Códigos ANSI para formateo en terminal
RISK_COLORS = {
    "CRÍTICO": "\033[1;91m",  # Rojo brillante (Negrita)
    "ALTO": "\033[1;31m",     # Rojo (Negrita)
    "MEDIO": "\033[1;33m",    # Amarillo (Negrita)
    "BAJO": "\033[1;32m",     # Verde (Negrita)
    "INFO": "\033[1;36m",     # Cian (Negrita)
}

BANNER_COLOR = "\033[38;5;244m"  # Gris suave para banners
REC_COLOR = "\033[38;5;250m"     # Gris claro para recomendaciones
HEADER_COLOR = "\033[1;35m"      # Magenta para títulos de sección
RESET_COLOR = "\033[0m"
COPYRIGHT_TEXT = "© 2026 keybyitaliano"


def supports_color() -> bool:
    """Verifica si el entorno de ejecución soporta colores ANSI."""
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() or os.environ.get("WT_SESSION") is not None or os.name == "nt"


def colorize_risk(level: str, enabled: bool) -> str:
    if not enabled:
        return level
    code = RISK_COLORS.get(level, "")
    return f"{code}{level}{RESET_COLOR}" if code else level


def parse_ports(raw: str) -> list[int]:
    ports: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f"Rango de puertos inválido: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Puerto fuera de rango (1-65535): {p}")
            ports.add(p)
    return sorted(ports)


def is_local_or_private(host: str) -> bool:
    if host.lower() in {"localhost", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved_ip)
            return ip.is_loopback or ip.is_private
        except OSError:
            return False


def print_report(target: str, results: list[dict], diff: dict, use_color: bool) -> None:
    header_title = f"\n=== Port Sentinel | Objetivo: {target} ==="
    if use_color:
        print(f"{HEADER_COLOR}{header_title}{RESET_COLOR}")
        print(f"{BANNER_COLOR}{COPYRIGHT_TEXT}{RESET_COLOR}\n")
    else:
        print(header_title)
        print(f"{COPYRIGHT_TEXT}\n")

    if not results:
        print("No se detectaron puertos abiertos que coincidan con el filtro.")
    else:
        print(f"{'PUERTO':<8} {'SERVICIO':<12} {'RIESGO':<10} {'BANNER / TLS'}")
        print("-" * 76)
        for item in results:
            detail_txt = item.get("tls_info") or item.get("banner") or "-"
            if use_color and detail_txt != "-":
                detail_display = f"{BANNER_COLOR}{detail_txt}{RESET_COLOR}"
            else:
                detail_display = detail_txt

            risk_display = colorize_risk(item["risk_level"], use_color)

            # Ancho de formato ajustado considerando secuencias ANSI
            print(f"{item['port']:<8} {item['service']:<12} {risk_display:<19} {detail_display}")

            rec_txt = item["recommendation"]
            if use_color:
                print(f"   ↳ {REC_COLOR}{rec_txt}{RESET_COLOR}")
            else:
                print(f"   ↳ {rec_txt}")

    diff_header = "\n--- Comparación con escaneo anterior (Diff) ---"
    if use_color:
        print(f"{HEADER_COLOR}{diff_header}{RESET_COLOR}")
    else:
        print(diff_header)

    if not diff["has_baseline"]:
        print("Primer escaneo guardado para este objetivo. La próxima ejecución mostrará cambios.")
    else:
        print(f"Baseline anterior: {diff.get('previous_scan_at')}")

        new_p = diff["new_ports"]
        closed_p = diff["closed_ports"]

        if use_color:
            new_str = f"\033[1;32m{new_p}\033[0m" if new_p else "Ninguno"
            closed_str = f"\033[1;31m{closed_p}\033[0m" if closed_p else "Ninguno"
        else:
            new_str = str(new_p) if new_p else "Ninguno"
            closed_str = str(closed_p) if closed_p else "Ninguno"

        print(f"Puertos nuevos abiertos: {new_str}")
        print(f"Puertos cerrados:        {closed_str}")

        if diff["changed_banners"]:
            for cb in diff["changed_banners"]:
                print(f"Banner cambiado en {cb['port']}: '{cb['old']}' -> '{cb['new']}'")
        else:
            print("Cambios de banner:       Ninguno")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Escáner de puertos asíncrono con banners, TLS, evaluación de riesgo y modo diff."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="IP o hostname (por defecto: 127.0.0.1)",
    )
    parser.add_argument(
        "-p", "--ports",
        help="Puertos o rangos separados por coma (ej. 22,80,443 o 1-1024). Por defecto: puertos comunes."
    )
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout por conexión en segundos")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Conexiones simultáneas máximas")
    parser.add_argument("--no-banner", action="store_true", help="Desactiva la lectura de banners")
    parser.add_argument("--only-risks", action="store_true", help="Muestra solo puertos con riesgo MEDIO, ALTO o CRÍTICO")
    parser.add_argument("--md", action="store_true", help="Guarda también un reporte en formato Markdown en reports/")
    parser.add_argument("--json", action="store_true", help="Imprime salida en formato JSON")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirma autorización explícita para escanear objetivos fuera de localhost/red privada."
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.target == "127.0.0.1" and not args.json:
        print("[INFO] Sin objetivo indicado: usando localhost (127.0.0.1) por defecto.")

    if not is_local_or_private(args.target) and not args.i_have_authorization:
        print(
            "[AVISO ÉTICO] Por seguridad, este escáner solo permite objetivos locales o privados por defecto.\n"
            "Si tienes autorización explícita para escanear este objetivo, vuelve a ejecutar con:\n"
            f"  python main.py {args.target} --i-have-authorization",
            file=sys.stderr,
        )
        return 1

    try:
        ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    reports_dir = Path("reports")
    previous = load_previous_scan(reports_dir, args.target)

    port_objs = asyncio.run(
        scan_ports(
            host=args.target,
            ports=ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            fetch_banner=not args.no_banner,
        )
    )
    all_results = [p.to_dict() for p in port_objs]
    diff = compute_diff(previous, all_results)
    saved_json = save_scan(reports_dir, args.target, all_results)

    displayed_results = (
        [r for r in all_results if r["risk_level"] in {"MEDIO", "ALTO", "CRÍTICO"}]
        if args.only_risks
        else all_results
    )

    saved_md: Path | None = None
    if args.md:
        saved_md = save_markdown_report(reports_dir, args.target, displayed_results, diff)

    if args.json:
        print(
            json.dumps(
                {
                    "target": args.target,
                    "results": displayed_results,
                    "diff": diff,
                    "saved_json": str(saved_json),
                    "saved_md": str(saved_md) if saved_md else None,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print_report(args.target, displayed_results, diff, use_color=supports_color())
        print(f"\nJSON guardado en: {saved_json}")
        if saved_md:
            print(f"Markdown guardado en: {saved_md}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())