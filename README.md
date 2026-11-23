# Port Sentinel

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

Escáner de puertos asíncrono en Python enfocado en **contexto de riesgo**, **lectura ligera de banners**, **inspección básica TLS** y **detección de cambios entre escaneos (`diff`)**, construido únicamente con la librería estándar de Python.

## Requisitos
- **Python 3.10+**
- No requiere dependencias externas (utiliza únicamente la librería estándar de Python).
---

## Características principales

* **Ejecución cómoda por defecto:** si no pasas un objetivo, escanea `127.0.0.1` automáticamente; también acepta IPs, rangos de puertos y opciones por línea de comandos.
* **Escaneo concurrente con `asyncio`:** gestiona conexiones simultáneas y *timeouts* de forma asíncrona sin dependencias externas.
* **Banner grabbing e inspección TLS:** lee respuestas iniciales o cabeceras HTTP simples y, en puertos TLS/HTTPS (`443`, `8443`), extrae la versión del protocolo y la fecha de vencimiento del certificado.
* **Evaluación de riesgo y recomendaciones:** clasifica la exposición (`CRÍTICO`, `ALTO`, `MEDIO`, `BAJO`, `INFO`), aplica colores ANSI en consola cuando el terminal lo soporta y añade una recomendación práctica por puerto.
* **Filtro de riesgos (`--only-risks`):** muestra únicamente los puertos con nivel `MEDIO`, `ALTO` o `CRÍTICO`.
* **Modo diff y guardado de reportes:** guarda cada escaneo por objetivo en `reports/` (JSON) y compara frente a la ejecución previa para detectar puertos nuevos abiertos, puertos cerrados o cambios de banner; además permite exportar a Markdown con `--md`.
* **Guardia ética por defecto:** restringe el escaneo a `localhost` o redes privadas salvo que indiques explícitamente `--i-have-authorization`.

---

## Estructura del proyecto

```text
port-sentinel/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── main.py
├── scanner/
│   ├── __init__.py
│   ├── engine.py
│   ├── banners.py
│   ├── tls_info.py
│   ├── risk.py
│   ├── diff.py
│   └── report_md.py
└── reports/
```

---

## Requisitos e instalación

* **Python 3.10+** (no requiere librerías ni dependencias externas).

```bash
git clone https://github.com/TU-USUARIO/port-sentinel.git
cd port-sentinel
```

---

## Uso

```bash
# Escaneo rápido en localhost (127.0.0.1) con puertos comunes
python main.py

# Escanear un rango específico ajustando timeout y concurrencia
python main.py 127.0.0.1 -p 1-1024 -t 0.8 -c 150

# Mostrar solo puertos con riesgo MEDIO, ALTO o CRÍTICO
python main.py --only-risks

# Guardar reporte adicional en Markdown en la carpeta reports/
python main.py --md

# Imprimir salida directamente en formato JSON
python main.py --json

# Escanear un objetivo externo tras confirmar autorización explícita
python main.py objetivo.ejemplo.com --i-have-authorization
```

---

## Gestión de archivos y carpetas locales

* **`scanner/__pycache__/` (`*.pyc`):** archivos de *bytecode* compilados automáticamente por Python para optimizar importaciones futuras. Se omiten del control de versiones a través de `.gitignore`.
* **`reports/`:** almacena el historial de escaneos en JSON (y en Markdown si activas `--md`) para calcular las diferencias (`diff`) entre ejecuciones.

---

## Licencia

Este proyecto está distribuido bajo la licencia **MIT**. Consulta el archivo [`LICENSE`](LICENSE) para obtener más detalles.

---

## Aviso de uso ético

Esta herramienta ha sido desarrollada exclusivamente con fines educativos, de aprendizaje y de auditoría defensiva en entornos propios o debidamente autorizados. Utilízala únicamente sobre sistemas de tu propiedad o en los que cuentes con autorización explícita y por escrito.

© 2026 Agustín — Todos los derechos reservados.
