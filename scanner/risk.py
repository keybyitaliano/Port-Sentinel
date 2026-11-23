from scanner.banners import COMMON_SERVICES

HIGH_RISK_PORTS = {
    21: ("ALTO", "FTP sin cifrar; credenciales y datos viajan en texto plano."),
    23: ("CRÍTICO", "Telnet es inseguro y no cifra el tráfico; usar SSH en su lugar."),
    3389: ("ALTO", "RDP expuesto aumenta el riesgo de fuerza bruta y exploits; restringir por VPN/IP."),
    6379: ("CRÍTICO", "Redis sin autenticación puede permitir acceso o ejecución remota; aislar en red privada."),
    27017: ("CRÍTICO", "MongoDB expuesto sin auth es objetivo frecuente; exigir autenticación y limitar red."),
}

MEDIUM_RISK_PORTS = {
    22: ("MEDIO", "Verificar autenticación por clave SSH, deshabilitar root directo y limitar intentos."),
    80: ("MEDIO", "Revisar si debe redirigir a HTTPS y comprobar encabezados de seguridad HTTP."),
    443: ("BAJO", "Auditar versión TLS, certificado vigente y encabezados como HSTS."),
    3306: ("MEDIO", "Base de datos en red: restringir origen de conexiones y usar contraseñas robustas."),
    5432: ("MEDIO", "Base de datos en red: revisar `pg_hba.conf`, TLS y permisos de roles."),
    8080: ("MEDIO", "Puerto HTTP alternativo: verificar que no exponga paneles administrativos sin protección."),
}


def evaluate_risk(port: int, banner: str | None) -> tuple[str, str, str]:
    service = COMMON_SERVICES.get(port, "Desconocido")

    if banner:
        upper_banner = banner.upper()
        if "SSH" in upper_banner and service == "Desconocido":
            service = "SSH"
        elif "HTTP/" in upper_banner and service == "Desconocido":
            service = "HTTP"
        elif "REDIS" in upper_banner and service == "Desconocido":
            service = "Redis"

    if port in HIGH_RISK_PORTS:
        level, rec = HIGH_RISK_PORTS[port]
        return level, service, rec

    if port in MEDIUM_RISK_PORTS:
        level, rec = MEDIUM_RISK_PORTS[port]
        return level, service, rec

    return "INFO", service, "Revisar si el servicio es necesario y mantiene actualizaciones de seguridad."