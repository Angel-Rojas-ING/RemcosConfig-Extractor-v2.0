---

## RemcosConfig Extractor v2.0

Herramienta CLI para extraer y descifrar la configuración embebida en muestras de Remcos RAT.

```
  ____                               ____             __ _
 |  _ \ ___ _ __ ___   ___ ___  ___ / ___|___  _ __  / _(_) __ _
 | |_) / _ \ '_ ` _ \ / __/ _ \/ __| |   / _ \| '_ \| |_| |/ _` |
 |  _ <  __/ | | | | | (_| (_) \__ \ |__| (_) | | | |  _| | (_| |
 |_| \_\___|_| |_| |_|\___\___/|___/\____\___/|_| |_|_| |_|\__, |
                                                             |___/
                          E X T R A C T O R   v2.0
```

### Capacidades

- Extrae y descifra configuración RC4 desde recursos RCDATA/SETTINGS del PE
- Parsea C2 en formato `host:port:password`
- Calcula hashes (SHA-256, MD5, SHA-1) de cada muestra
- Detecta packers (UPX, Themida, VMProtect, entropía alta)
- Detecta versión de Remcos (v1.x - v4.x)
- Mapea ~45 campos de configuración organizados por categoría
- Muestra flags como `[ON]`/`[OFF]` con colores
- Interfaz CLI con colores, marcos y banner ASCII Art
- Exporta a CSV y JSON
- Soporte batch con resumen consolidado y barra de progreso

### Requisitos

```bash
pip install pefile colorama
```

### Uso

```bash
# Extraer configuración de una muestra
python remcosconfg-extract.py muestra.exe

# Exportar a CSV y JSON
python remcosconfg-extract.py muestra.exe --csv iocs.csv --json config.json

# Batch (múltiples muestras)
python remcosconfg-extract.py *.exe --csv campana.csv

# Sin colores (para logs/pipelines)
python remcosconfg-extract.py muestra.exe --no-color --no-banner
```

### Ejemplo de Salida

```
  +========================================================================+
  | SAMPLE INFO                                                            |
  +------------------------------------------------------------------------+
  |  File      : FrameTrac32.exe                                           |
  |  SHA-256   : 9f84bbd8179674ee35fd...                                   |
  |  Packer    : None detected                                             |
  |  Remcos    : v4.x                                                      |
  +========================================================================+

  +------------------------------------------------------------------------+
  | NETWORK                                                                |
  +------------------------------------------------------------------------+
  |  [C2 #1]  192.159.99.19:1122  (password: (none))                      |
  |  Connect Interval (s) : 1                                              |
  |  TLS Enabled           [OFF]                                           |
  +------------------------------------------------------------------------+

  +------------------------------------------------------------------------+
  | SURVEILLANCE                                                           |
  +------------------------------------------------------------------------+
  |  Keylogger             [ON]                                            |
  |  Screenshots           [ON]                                            |
  |  Audio Capture         [ON]                                            |
  |  Clipboard Monitor     [OFF]                                           |
  +------------------------------------------------------------------------+
```

---
