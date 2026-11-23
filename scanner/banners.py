import asyncio

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    27017: "MongoDB",
}


async def grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
    timeout: float = 1.5,
) -> str | None:
    try:
        # En protocolos HTTP pedimos una cabecera mínima; en otros esperamos saludo inicial
        if port in (80, 8080, 8000, 8888):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if not data:
            return None

        cleaned = data.decode("utf-8", errors="replace").strip()
        first_line = cleaned.splitlines()[0] if cleaned.splitlines() else ""
        return first_line[:120] if first_line else None
    except (asyncio.TimeoutError, OSError):
        return None