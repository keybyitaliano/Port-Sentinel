from datetime import datetime, timezone
from pathlib import Path


def save_markdown_report(
    reports_dir: Path,
    target: str,
    results: list[dict],
    diff: dict,
) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in target)
    path = reports_dir / f"{safe_name}.md"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Reporte Port Sentinel — `{target}`",
        "",
        f"- **Fecha:** {now_str}",
        f"- **Puertos abiertos detectados:** {len(results)}",
        "",
        "## Puertos abiertos",
        "",
    ]

    if not results:
        lines.append("No se detectaron puertos abiertos en el rango escaneado.")
    else:
        lines.extend([
            "| Puerto | Servicio | Riesgo | Detalle / Banner | Recomendación |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for item in results:
            detail = item.get("tls_info") or item.get("banner") or "-"
            detail = detail.replace("|", "\\|")
            rec = item.get("recommendation", "-").replace("|", "\\|")
            lines.append(
                f"| `{item['port']}` | {item['service']} | **{item['risk_level']}** | {detail} | {rec} |"
            )

    lines.extend(["", "## Comparación con escaneo anterior (Diff)", ""])
    if not diff.get("has_baseline"):
        lines.append("Primer escaneo registrado para este objetivo.")
    else:
        lines.append(f"- **Baseline anterior:** `{diff.get('previous_scan_at')}`")
        lines.append(f"- **Puertos nuevos abiertos:** `{diff.get('new_ports') or 'Ninguno'}`")
        lines.append(f"- **Puertos cerrados:** `{diff.get('closed_ports') or 'Ninguno'}`")
        changed = diff.get("changed_banners") or []
        if changed:
            for cb in changed:
                lines.append(f"- **Banner cambiado en `{cb['port']}`:** `{cb['old']}` → `{cb['new']}`")
        else:
            lines.append("- **Cambios de banner:** Ninguno")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path