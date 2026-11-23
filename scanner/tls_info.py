import asyncio
import datetime
import ssl


async def inspect_tls(host: str, port: int, timeout: float = 1.5) -> str | None:
    if port not in (443, 8443):
        return None

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        conn = asyncio.open_connection(host, port, ssl=context, server_hostname=host)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
        tls_version = ssl_obj.version() if ssl_obj else None

        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

        parts: list[str] = []
        if tls_version:
            parts.append(tls_version)

        if cert and cert.get("notAfter"):
            not_after_raw = cert["notAfter"]
            try:
                exp_dt = datetime.datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z")
                parts.append(f"vence {exp_dt.strftime('%Y-%m-%d')}")
            except ValueError:
                parts.append(f"vence {not_after_raw}")

        return f"TLS ({', '.join(parts)})" if parts else "TLS activo"
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None