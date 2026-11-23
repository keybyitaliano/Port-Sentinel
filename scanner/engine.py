import asyncio
from dataclasses import asdict, dataclass
from scanner.banners import grab_banner
from scanner.risk import evaluate_risk
from scanner.tls_info import inspect_tls


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str | None
    tls_info: str | None
    risk_level: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


async def _scan_single_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
    fetch_banner: bool,
) -> PortResult | None:
    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            return None

        banner: str | None = None
        if fetch_banner:
            banner = await grab_banner(reader, writer, port, timeout=min(timeout, 1.5))

        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

        tls_info = await inspect_tls(host, port, timeout=min(timeout, 2.0))
        risk_level, service, recommendation = evaluate_risk(port, banner)

        return PortResult(
            port=port,
            state="open",
            service=service,
            banner=banner,
            tls_info=tls_info,
            risk_level=risk_level,
            recommendation=recommendation,
        )


async def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    concurrency: int = 100,
    fetch_banner: bool = True,
) -> list[PortResult]:
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        _scan_single_port(host, port, timeout, semaphore, fetch_banner)
        for port in ports
    ]
    results = await asyncio.gather(*tasks)
    open_ports = [r for r in results if r is not None]
    open_ports.sort(key=lambda item: item.port)
    return open_ports