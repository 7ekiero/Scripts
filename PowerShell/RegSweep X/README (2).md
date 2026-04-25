# RegSweep-X

**Framework forense de recolección de registro y eventos para Windows 10/11**

> Desarrollado para análisis post-incidente y threat hunting. Sin dependencias externas. Solo PowerShell 5.1 y .NET Base Class Library.

---

## Descripción

RegSweep-X es un script de PowerShell diseñado para recolección forense rápida en sistemas Windows comprometidos o bajo sospecha. Extrae artefactos de alto valor del registro de Windows y del visor de eventos, los cruza con logs de instalación del sistema y genera un reporte estructurado listo para el analista.

Toda la lógica se ejecuta localmente. No hay llamadas a red, no se instalan módulos, no se modifica el sistema investigado.

---

## Características

| Vector | Fuente | Artefacto |
|--------|--------|-----------|
| BAM/DAM | `HKLM\...\bam\State\UserSettings` | Ejecución de binarios por SID con timestamp FILETIME |
| LSA/SSP | `HKLM\...\Control\Lsa` | Paquetes de autenticación — detección de credential theft |
| IFEO | `HKLM\...\Image File Execution Options` | Hijacking de ejecución (T1546.012) |
| RDP Saliente | `HKCU\...\Terminal Server Client` | Historial de conexiones remotas por usuario |
| USB/USBSTOR | `HKLM\...\Enum\USBSTOR` + `setupapi.dev.log` | Dispositivos conectados con timestamp de primera instalación |
| Eventos | Security / System / PS Operational | ClearLog, servicios sospechosos, ScriptBlock malicioso |

---

## Requisitos

- Windows 10 / Windows 11
- PowerShell 5.1 o superior
- **Consola elevada como Administrador** (obligatorio)
- Sin módulos adicionales. Sin conexión a red.

---

## Uso

```powershell
# Ejecución estándar
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\RegSweep-X.ps1"

# Modo verbose completo (recomendado en análisis activo)
.\RegSweep-X.ps1 -ConsoleLevel DEBUG

# Directorio de salida personalizado
.\RegSweep-X.ps1 -OutputRoot "D:\Evidencias"

# Capturar objeto de retorno para inspección en pipeline
$r = .\RegSweep-X.ps1
$r.Data['BAM'] | Where-Object LastRunUTC | Sort-Object LastRunUTC -Descending | Format-Table
explorer $r.OutputDir
```

---

## Parámetros

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `-OutputRoot` | `[string]` | `$env:TEMP` | Directorio raíz donde se crea la carpeta de salida |
| `-ConsoleLevel` | `[string]` | `INFO` | Nivel mínimo de log en consola: `DEBUG` / `INFO` / `WARN` / `ERROR` |

---

## Salida

El script crea un directorio con el formato `RegSweepX_<HOSTNAME>_<YYYYMMDD_HHmmss>` dentro de `OutputRoot`. Contiene tres archivos:

```
RegSweepX_7EKIERO_20260425_013813\
├── RegSweepX.log            # Log completo de la sesión (todos los niveles)
├── RegSweepX_Results.json   # Datos estructurados — todos los vectores
└── RegSweepX_Report.md      # Reporte Markdown para el analista
```

El objeto devuelto por el script expone las rutas directamente:

```powershell
$r.OutputDir     # Ruta del directorio de salida
$r.LogFile       # Ruta del .log
$r.JsonFile      # Ruta del .json
$r.MarkdownFile  # Ruta del .md
$r.Data          # Hashtable con todos los artefactos recolectados
$r.Metadata      # PSCustomObject con metadatos de la sesión
```

---

## Vectores de detección

### BAM/DAM
El Background Activity Moderator almacena evidencia de ejecución de binarios por SID de usuario, con timestamps en formato FILETIME. El script parsea los 8 bytes a `DateTime UTC` mediante `BitConverter` y `FromFileTimeUtc()` sin dependencias externas.

### LSA / SSP
Extrae los valores `Authentication Packages`, `Security Packages` y `Notification Packages` de la clave LSA. Cada paquete se compara contra una lista de valores conocidos de Windows. Los paquetes no estándar se marcan en el reporte y generan entradas `WARN` en el log — indicador de posible credential theft (T1556.002).

### IFEO Hijacking
Itera `Image File Execution Options` buscando exclusivamente los valores `Debugger` y `MonitorProcess`. Cualquier resultado es sospechoso por definición (T1546.012).

### RDP Saliente
Recorre el historial MRU y la lista de Servers del cliente RDP para el usuario actual (HKCU) y para todos los perfiles adicionales de `C:\Users\*`. Usa una estrategia de tres capas para acceder a perfiles de otros usuarios: HKCU directo → HKU si el hive está activo → `reg.exe load` para hives offline. Antes del `unload` fuerza un GC para liberar handles de .NET y evitar que el hive quede bloqueado.

### USB / USBSTOR
Enumera únicamente clases `Disk&` (almacenamiento masivo). Para cada dispositivo con serial real, busca el timestamp de primera instalación en `setupapi.dev.log` usando `StreamReader` línea a línea — nunca carga el archivo completo en memoria. El log puede superar los 50 MB; el buffer de 64 KB y la detección automática de BOM (UTF-16 LE / UTF-8) garantizan lecturas correctas en cualquier build.

### Eventos
- **EID 1102 / 104**: Borrado de log de Seguridad y Sistema (anti-forense, T1070.001)
- **EID 7045**: Servicios creados con rutas en `temp`, `appdata`, `powershell` o `cmd.exe` (T1543.003)
- **EID 4104**: Script Block Logging — filtra los últimos 30 días y busca `base64`, `downloadstring`, `invoke-expression`, `-enc`, `iex` en memoria sobre los eventos ya recuperados (T1059.001)

---

## Notas de seguridad operacional

- El script verifica privilegios de Administrador en la primera instrucción. Si no está elevado, lanza `Write-Error` y `throw` y detiene la ejecución. No hay intento de bypass de UAC.
- Todos los accesos al registro usan `ErrorAction Stop` dentro de bloques `try/catch`. Un error en una clave individual no detiene la recolección del resto.
- Los hives montados con `reg.exe load` se desmontan siempre en el bloque `finally`, incluso si hay error en la recolección.
- El `StreamReader` del setupapi se cierra en `finally` independientemente del resultado.
- `Set-StrictMode -Version Latest` activo en todo el script.

---

## Falsos positivos conocidos

| Vector | Valor | Explicación |
|--------|-------|-------------|
| LSA | `""` (string vacío) | Artefacto de `REG_MULTI_SZ` con entrada vacía. Inofensivo. |
| LSA | `scecli` | Security Configuration Engine de Windows. Legítimo en la mayoría de sistemas. |
| USB | Serial `ABCDEF0123456789AB` | Serial genérico de placeholder presente en algunas instalaciones virtuales. |

Para suprimir estos avisos, añade los valores correspondientes al array `$knownDefaults` dentro de `Get-SweepLSA`.

---

## Estructura del código

```
RegSweep-X.ps1
├── Region 1  Assert-AdminPrivilege
├── Region 2  New-SweepOutputDirectory
├── Region 3  Write-SweepLog
├── Region 4  Export-SweepJson
├── Region 5  Vectores de recolección
│   ├── Get-SweepBAM
│   ├── Get-SweepLSA
│   ├── Get-SweepIFEO
│   ├── _Get-RDPFromHive  (helper interno)
│   ├── Get-SweepRDP
│   ├── _Get-SetupApiTimestamp  (helper interno)
│   ├── _Get-USBFriendlyName   (helper interno)
│   ├── Get-SweepUSB
│   └── Get-SweepEvents
├── Region 6  Export-SweepMarkdown
│   ├── _ConvertTo-MarkdownTable  (helper interno)
│   └── _New-MdSection            (helper interno)
└── Region 7  Main
```

---

## Referencias MITRE ATT&CK

| Técnica | ID | Vector cubierto |
|---------|----|-----------------|
| Boot or Logon Autostart – IFEO | T1546.012 | Get-SweepIFEO |
| Modify Authentication Process – SSP | T1556.002 | Get-SweepLSA |
| Create or Modify System Process – Windows Service | T1543.003 | Get-SweepEvents (7045) |
| Command and Scripting – PowerShell | T1059.001 | Get-SweepEvents (4104) |
| Indicator Removal – Clear Windows Event Logs | T1070.001 | Get-SweepEvents (1102/104) |
| Remote Services – RDP | T1021.001 | Get-SweepRDP |

---

## Licencia

Uso interno en operaciones de respuesta ante incidentes. No redistribuir sin autorización.
