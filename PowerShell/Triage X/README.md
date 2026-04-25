# Triage-X

**Triage Rapido de Respuesta ante Incidentes para Endpoints Windows**  
`v0.1.0` · PowerShell 5.1+ · Windows 10/11 · Sin dependencias externas

Triage-X es un script de PowerShell autocontenido para la recoleccion rapida de datos forenses durante la fase inicial de una respuesta ante incidentes. Funciona exclusivamente con APIs nativas de Windows y cmdlets integrados: sin modulos de terceros, sin llamadas de red, sin instalador. Copialo en el endpoint, ejecutalo como Administrador y recoge los datos.

La salida es un reporte Markdown estructurado optimizado para revision humana, junto con un artefacto JSON para ingestion en SIEM o procesamiento automatizado. El tiempo de ejecucion en un equipo tipico con ~250 procesos es inferior a 60 segundos.

---

## Capacidades

| Modulo | Que recopila |
| --- | --- |
| **Analisis de Procesos** | Arbol de procesos completo con PPIDs, rutas de ejecutables, hashes SHA-256 completos (64 caracteres) y verificacion de firma Authenticode. Detecta masquerading de binarios del sistema fuera de rutas canonicas. Procesos PPL (lsass, csrss, smss) manejados sin falsos positivos. |
| **Correlacion de Red** | Enumeracion de sockets TCP/UDP correlacionada con el snapshot de procesos. Clasificacion RFC 1918 sin resolucion DNS (sin DNS leak). Detecta LOLBins con conexiones publicas activas. Resultados deduplicados por PID en el resumen. |
| **Auditoria de Persistencia** | Run keys de registro (HKLM/HKCU + WOW6432Node), deteccion de hijacking de Winlogon, Tareas Programadas fuera de \Microsoft\Windows\, servicios anomalos y WMI Event Subscriptions (ActiveScriptEventConsumer, CommandLineEventConsumer). Lista blanca de rutas legitimas conocidas (Defender, servicios de gaming, instaladores de usuario). |
| **Forense de Actividad de Usuario** | Timeline de metadatos Prefetch, decodificacion UserAssist (ROT13 + estructura binaria USERASSISTENTRY), artefactos LNK de archivos recientes, analisis del Log de Seguridad (4624/4625 con deteccion de rafagas de brute-force), analisis del historial de PowerShell por usuario con matching de palabras clave IOC. |
| **Contexto del Sistema** | Build del OS, inventario de hotfixes, enumeracion del grupo Administradores locales (por SID, independiente del idioma), estado de productos de seguridad via SecurityCenter2, configuracion de adaptadores de red. |

**Restricciones de diseno aplicadas en todo el script:**
- Sin resolucion DNS durante la recoleccion: evita alertar a infraestructura controlada por el atacante
- Sin dependencias de modulos externos (solo `#Requires -Version 5.1`)
- Modelo de datos `PSCustomObject` en todo el script: pipeable, filtrable, serializable
- Salida dual: Markdown legible por humanos + JSON legible por maquinas
- Codificacion UTF-8 con BOM para compatibilidad total con PowerShell 5.1

---

## Cobertura MITRE ATT&CK

| Modulo Triage-X | ID Tecnica | Nombre de la Tecnica |
| --- | --- | --- |
| Analisis de Procesos | T1036.005 | Masquerading: Coincidir Nombre o Ubicacion Legitima |
| Analisis de Procesos | T1055 | Inyeccion de Proceso (procesos sin firma, PIDs sin ruta accesible) |
| Analisis de Procesos | T1553.002 | Subvertir Controles de Confianza: Firma de Codigo |
| Correlacion de Red | T1071 | Protocolo de Capa de Aplicacion (LOLBins con IPs publicas) |
| Correlacion de Red | T1048 | Exfiltracion por Protocolo Alternativo |
| Correlacion de Red | T1078 | Cuentas Validas (movimiento lateral via red) |
| Persistencia - Registro | T1547.001 | Inicio Automatico: Run Keys de Registro |
| Persistencia - Registro | T1547.004 | Inicio Automatico: Winlogon Helper DLL |
| Persistencia - Tareas | T1053.005 | Tarea Programada |
| Persistencia - Servicios | T1543.003 | Crear o Modificar Proceso del Sistema: Servicio Windows |
| Persistencia - WMI | T1546.003 | Ejecucion Activada por Evento: WMI Event Subscription |
| Actividad Usuario - Prefetch | T1204.002 | Ejecucion por Usuario: Archivo Malicioso |
| Actividad Usuario - UserAssist | T1204.002 | Ejecucion por Usuario: Archivo Malicioso |
| Actividad Usuario - Log de Eventos | T1110 | Brute Force (deteccion de rafagas de 4625) |
| Actividad Usuario - Historial PS | T1059.001 | Interprete de Scripts: PowerShell |
| Actividad Usuario - Archivos Recientes | T1566 | Phishing (artefactos de acceso a documentos) |

> La cobertura refleja capacidad de deteccion, no prevencion. Triage-X es un recolector forense, no un EDR.

---

## Requisitos

- **OS:** Windows 10 / Windows 11 (workstation o LTSC). Ediciones Server soportadas con matices: el namespace WMI SecurityCenter2 no existe en Server Core ni en Controladores de Dominio sin rol de Experiencia de Escritorio.
- **PowerShell:** 5.1 (Desktop) o 7.x. Validado en PS 5.1.26100 (Windows 11 26100).
- **Privilegios:** Administrador local requerido. Win32_Process.CommandLine, el Log de Seguridad, las suscripciones WMI y el Prefetch son inaccesibles sin elevacion.
- **Politica de Ejecucion:** Lanzar con `-ExecutionPolicy Bypass` si el entorno restringe la ejecucion de scripts. El script no modifica la politica del sistema.

---

## Uso

### Ejecucion estandar

Abrir un prompt de PowerShell elevado:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Triage-X.ps1
```

Si se lanza sin privilegios de Administrador, la ejecucion se detiene inmediatamente con un mensaje descriptivo. No se realiza ninguna elevacion automatica ni bypass de UAC.

### Ubicacion de la salida

Todo el output se escribe en un directorio con timestamp bajo %TEMP%:

```
C:\Users\<Analista>\AppData\Local\Temp\
+-- TriageX_Report_HOSTNAME_AAAAMMDD_HHmmss\
    +-- Triage-Report.md     # Reporte principal
    +-- triage_raw.json      # Datos crudos para SIEM / Elastic
```

Un log de sesion se escribe en paralelo:

```
C:\Users\<Analista>\AppData\Local\Temp\TriageX_HOSTNAME_AAAAMMDD_HHmmss.log
```

### Visualizar el reporte Markdown

El archivo .md se renderiza correctamente en GitHub/GitLab, VS Code (Ctrl+Shift+V), Obsidian (secciones colapsables con details soportadas de forma nativa) o cualquier extension de navegador para Markdown.

---

## Estructura del Reporte

```
Triage-X Report - HOSTNAME
|
+-- 1. Resumen de Hallazgos     <- Indicador de riesgo + conteo de HIGH por modulo
+-- 2. Contexto del Sistema     <- OS, hotfixes, admins locales, AV, adaptadores
+-- 3. Detecciones de Alto Riesgo <- Tabla consolidada, red deduplicada por PID
+-- 4. Detalle Completo por Modulo
    +-- 4.1 Procesos            <- Ordenados High-primero, SHA-256 completo
    +-- 4.2 Conexiones de Red   <- TCP/UDP, flag IP publica, correlacion de proceso
    +-- 4.3 Persistencia        <- Bloques de comando para entradas HIGH
    +-- 4.4 Actividad de Usuario <- Prefetch / UserAssist / Logs / Historial PS
```

### Niveles de alerta

| Nivel | Significado |
| --- | --- |
| [!] HIGH | Indicador directo de compromiso o anomalia de alta confianza. Requiere revision del analista. |
| [~] Medium | Hallazgo notable que requiere contexto: puede ser benigno segun el entorno. |
| [+] Low | Recopilado por completitud. Sin anomalia detectada contra los conjuntos de reglas integrados. |

### Interpretacion de hallazgos clave

**Analisis de Procesos - IsSuspicious: True**
Se activa cuando: la firma Authenticode es invalida o inexistente (excluyendo binarios MSIX/AppX conocidos de Windows); la ruta del ejecutable coincide con directorios de staging (Temp, AppData sin firma, Downloads, Public); o un binario sensible del sistema se ejecuta fuera de su ruta canonica. Los procesos protegidos por PPL (smss, csrss, lsass, wininit) quedan excluidos de las alertas de ruta por diseno: su inaccesibilidad la impone el kernel, no es un IoC.

**Red - IP publica + proceso inesperado**
Los LOLBins (notepad.exe, rundll32.exe, mshta.exe, certutil.exe) no tienen razon legitima para iniciar TCP saliente a IPs publicas. El puerto 443 desde un proceso que no es un navegador sugiere beaconing HTTPS (C2); puertos altos no estandar (4444, 8888, etc.) sugieren C2 sin cifrar o reverse shells. La tabla de resumen agrupa las conexiones por PID para evitar ruido de clientes P2P.

**Persistencia - Consumidores WMI**
Cualquier entrada bajo WMI\ActiveScriptConsumer o WMI\CommandLineConsumer es critica independientemente del nivel de alerta. Las suscripciones WMI legitimas de herramientas de gestion enterprise deben estar inventariadas y ser conocidas. Los consumidores desconocidos deben tratarse como persistencia confirmada hasta que se demuestre lo contrario.

**Historial de PowerShell - alertas HIGH**
El archivo ConsoleHost_history.txt persiste entre sesiones y no se ve afectado por Clear-History: PSReadLine escribe en disco de forma independiente al buffer de historia en memoria. Las coincidencias de palabras clave incluyen numeros de linea para contexto preciso.

**Eventos de Seguridad - rafagas de 4625**
Los eventos de logon fallido se agrupan en buckets de 60 segundos. Cinco o mas fallos en el mismo minuto activan una alerta Medium. Rafagas de tipo de logon 3 (Network) indican spray SMB/RDP; rafagas de tipo 10 (RemoteInteractive) indican ataque directo contra RDP.

---

## Diseno de Seguridad y Privacidad

**Sin llamadas de red externas**
La clasificacion de IPs (publica vs. privada) se calcula localmente mediante aritmetica de rangos RFC 1918 sobre la representacion uint32 de cada direccion. Sin consultas DNS, sin HTTP, sin LDAP a hosts externos. Las consultas DNS inversas generarian trafico visible para los resolutores controlados por el atacante, lo que podria quemar la investigacion.

**Sin dependencias externas**
Toda la funcionalidad usa cmdlets integrados de PowerShell, CIM/WMI, ADSI y tipos del .NET BCL presentes en una instalacion predeterminada de Windows. Sin Install-Module, sin conectividad a internet, sin exposicion a la cadena de suministro. Funciona en entornos air-gapped.

**Huella minima**
El script escribe exclusivamente en %TEMP%. No modifica claves de registro, servicios, tareas programadas ni ninguna configuracion del sistema. No instala ningun agente ni crea ninguna persistencia.

---

## Extender Triage-X

Cada modulo Invoke-Collect* sigue un contrato consistente:

- Devuelve PSCustomObject[] con campos AlertLevel y AlertReasons
- Usa Write-TriageLog para salida dual a consola y archivo
- Maneja errores por elemento con Try-Catch para evitar fallos en cascada
- Acepta parametros opcionales para correlacion entre modulos

Para anadir un nuevo modulo de recoleccion: implementa Invoke-Collect*, aniadelo al bloque $CollectedData en Main y anade una seccion a New-TriageReport usando New-MdTable.

---

## Aviso Legal

Triage-X esta concebido para uso por parte de respondedores de incidentes autorizados, ingenieros de seguridad y administradores de sistemas en equipos que sean de su propiedad o para los que dispongan de autorizacion escrita explicita. El uso no autorizado contra sistemas que no poseas o para los que no tengas permiso puede infringir la legislacion aplicable. Los autores no asumen ninguna responsabilidad por un uso indebido.
