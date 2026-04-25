#Requires -Version 5.1
<#
.SYNOPSIS
    Triage-X - Incident Response Triage Tool
.DESCRIPTION
    Skeleton base para recoleccion forense en endpoints Windows.
    Modulos de coleccion a implementar sobre esta estructura.
.NOTES
    Author  : IR Engineer
    Version : 0.1.0-alpha
    Requires: Administrator privileges, PowerShell 5.1+
#>

# ============================================================
#region  AUTO-ELEVATION
# ============================================================
$CurrentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Warning "[-] Privilegios insuficientes. Intentando re-lanzar como Administrator..."
    try {
        $PSArgs = @{
            FilePath     = 'powershell.exe'
            ArgumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            Verb         = 'RunAs'
        }
        Start-Process @PSArgs
    }
    catch {
        Write-Error "[!] No se pudo elevar el proceso. Abortando. Error: $($_.Exception.Message)"
    }
    exit 1
}
#endregion

# ============================================================
#region  CONFIGURACION DE ENTORNO
# ============================================================

# Forzar UTF-8 en todos los streams de salida
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding            = [Text.Encoding]::UTF8

# Detener ejecucion ante errores no controlados (excepto donde se capture explicitamente)
$ErrorActionPreference = 'Stop'

# Detectar soporte ANSI real. $host.Name es siempre 'ConsoleHost' en PS5.1 incluso en ISE/pipes.
# SupportsVirtualTerminal es el check correcto para saber si el host renderiza secuencias ANSI.
$Script:AnsiSupported = (
    [bool]$env:WT_SESSION -or
    ($env:TERM_PROGRAM -eq 'vscode') -or
    ($host.UI.SupportsVirtualTerminal -eq $true)
)

# Paleta ANSI - se usa solo si el terminal lo soporta; en caso contrario, strings vacios
if ($Script:AnsiSupported) {
    # [char]27 = ESC — compatible con PS 5.1. El literal `e solo existe en PS 6+
    $Esc = [char]27
    $Script:Colors = @{
        Reset   = "$Esc[0m"
        Bold    = "$Esc[1m"
        Green   = "$Esc[92m"
        Yellow  = "$Esc[93m"
        Red     = "$Esc[91m"
        Cyan    = "$Esc[96m"
        Magenta = "$Esc[95m"
        Gray    = "$Esc[90m"
    }
} else {
    # Degradacion gracia en consolas sin soporte ANSI (ej: ISE, cmd legacy)
    $Script:Colors = @{
        Reset = ''; Bold = ''; Green = ''; Yellow = ''
        Red   = ''; Cyan  = ''; Magenta = ''; Gray = ''
    }
}
#endregion

# ============================================================
#region  CONSTANTES GLOBALES
# ============================================================
$Script:Config = [PSCustomObject]@{
    Version    = '0.1.0-alpha'
    ToolName   = 'Triage-X'
    StartTime  = Get-Date
    Hostname   = $env:COMPUTERNAME
    # Log en %TEMP% con timestamp para evitar colisiones entre ejecuciones
    LogFile    = Join-Path $env:TEMP ("TriageX_{0}_{1}.log" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    ReportDir  = Join-Path $env:TEMP ("TriageX_Report_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
#endregion

# ============================================================
#region  SISTEMA DE LOGGING DUAL
# ============================================================

<#
.SYNOPSIS
    Escribe un mensaje en consola (con color ANSI) y en el log file simultaneamente.
.PARAMETER Message
    Texto del mensaje.
.PARAMETER Level
    INFO | WARN | ERROR | SECTION. Controla prefijo y color.
#>
function Write-TriageLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ERROR','SECTION')]
        [string]$Level = 'INFO'
    )

    $C = $Script:Colors
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Mapeado nivel -> prefijo visual + color
    $Map = @{
        INFO    = @{ Prefix = '[+]'; Color = $C.Green  }
        WARN    = @{ Prefix = '[!]'; Color = $C.Yellow }
        ERROR   = @{ Prefix = '[-]'; Color = $C.Red    }
        SECTION = @{ Prefix = '[*]'; Color = $C.Cyan   }
    }

    $Prefix = $Map[$Level].Prefix
    $Color  = $Map[$Level].Color

    # Salida consola con ANSI
    $ConsoleLine = "{0}{1} {2}{3} {4}{5}" -f $Color, $Prefix, $C.Gray, $Timestamp, $C.Reset, $Message
    Write-Host $ConsoleLine

    # Salida log plano (sin secuencias ANSI)
    $LogLine = "{0} {1} {2}" -f $Timestamp, $Prefix, $Message
    try {
        Add-Content -Path $Script:Config.LogFile -Value $LogLine -Encoding UTF8
    }
    catch {
        # Fallo silencioso en log para no interrumpir el flujo principal
        Write-Warning "No se pudo escribir en log: $($_.Exception.Message)"
    }
}
#endregion

# ============================================================
#region  BANNER
# ============================================================
function Show-Banner {
    $C = $Script:Colors
    $Banner = @"
$($C.Magenta)$($C.Bold)
  ######  ####  #  ###    ###   ####  ####     #  #
     #    #  #  #  #  #  #  #  #     #         # #
     #    ###   #  ###   #  #  # ##  ###         #
     #    #  #  #  #  #  #  #  #  #  #          # #
     #    #  #  #  #  #   ###   ###  ####       #  #
$($C.Reset)$($C.Gray)  Incident Response Triage Tool  |  v$($Script:Config.Version)  |  $($Script:Config.Hostname)
  ---------------------------------------------------------$($C.Reset)
"@
    Write-Host $Banner
}
#endregion

# ============================================================
#region  INICIALIZACION
# ============================================================
function Initialize-Environment {
    Write-TriageLog "Inicializando entorno de triage..." -Level SECTION

    # Crear directorio de reporte
    try {
        New-Item -ItemType Directory -Path $Script:Config.ReportDir -Force | Out-Null
        Write-TriageLog "Directorio de reporte: $($Script:Config.ReportDir)"
    }
    catch {
        Write-TriageLog "Fallo al crear directorio de reporte: $($_.Exception.Message)" -Level ERROR
        throw
    }

    # Snapshot del contexto de ejecucion para metadatos del reporte
    $Script:TriageContext = [PSCustomObject]@{
        Analyst      = $env:USERNAME
        Hostname     = $Script:Config.Hostname
        OS           = (Get-CimInstance Win32_OperatingSystem).Caption
        PSVersion    = $PSVersionTable.PSVersion.ToString()
        StartTime    = $Script:Config.StartTime
        LogFile      = $Script:Config.LogFile
        ReportDir    = $Script:Config.ReportDir
    }

    Write-TriageLog "Entorno listo. OS: $($Script:TriageContext.OS) | PS: $($Script:TriageContext.PSVersion)"
}
#endregion

# ── HELPERS DE PERSISTENCIA (scope de script, definidos una vez) ──────────────
function Get-ExecutableFromCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $Command = $Command.Trim()
    if ($Command -match '^"([^"]+\.exe)"')             { return $Matches[1] }
    if ($Command -match '^([^\s]+\.exe)')              { return $Matches[1] }
    if ($Command -match '^"?([^"]+\.(ps1|vbs|js|bat|cmd|hta))"?') { return $Matches[1] }
    return $null
}

function Get-SignatureInfo {
    param([string]$Path)
    $Default = @{ Status = 'N/A'; Issuer = 'N/A' }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Default }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
        return @{ Status = 'FileNotFound'; Issuer = 'N/A' }
    }
    try {
        $Sig    = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $Issuer = if ($Sig.SignerCertificate) {
            $Sig.SignerCertificate.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        } else { 'None' }
        return @{ Status = $Sig.Status.ToString(); Issuer = $Issuer }
    }
    catch { return @{ Status = "Error: $($_.Exception.Message)"; Issuer = 'N/A' } }
}

function Get-PersistenceAlertReasons {
    param([string]$Command, [string]$ExePath, [string]$SigStatus)
    $Reasons  = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($Command)) { return $Reasons }
    $CmdLower = $Command.ToLower()
    $HighPatterns = @{
        'powershell.*-e(nc|ncodedcommand)'   = 'PowerShell con EncodedCommand'
        'powershell.*-w(indowstyle)?\s+hid' = 'PowerShell con ventana oculta'
        'powershell.*-nop(rofile)?'          = 'PowerShell -NoProfile'
        'cmd(\.exe)?\s+/c'                 = 'cmd.exe /c (ejecucion encadenada)'
        'mshta(\.exe)?'                     = 'mshta.exe (HTA LOLBin)'
        'wscript(\.exe)?|cscript(\.exe)?'  = 'Script host (wscript/cscript)'
        'regsvr32.*scrobj'                   = 'regsvr32 + scrobj.dll (Squiblydoo)'
        'rundll32.*javascript'               = 'rundll32 ejecutando JavaScript'
        'certutil.*(decode|-urlcache)'       = 'certutil como downloader'
        'bitsadmin.*/transfer'              = 'BITSAdmin como downloader'
        '\bIEX\b|\bInvoke-Expression\b'  = 'Invoke-Expression'
        'frombase64string'                   = 'Decodificacion base64 en runtime'
    }
    foreach ($Pat in $HighPatterns.Keys) {
        if ($CmdLower -match $Pat) { $Reasons.Add($HighPatterns[$Pat]) }
    }
    $SuspPaths = @('\btemp\b','appdata','\\downloads\\','\\desktop\\',
                   'users\\public','programdata','\\windows\\fonts\\')
    $ExeLower  = $ExePath.ToLower()
    foreach ($Pat in $SuspPaths) {
        if ($ExeLower -match $Pat) { $Reasons.Add("Ruta sospechosa: $ExePath"); break }
    }
    if ($SigStatus -notin @('Valid','N/A','FileNotFound')) {
        $Reasons.Add("Sin firma valida: $SigStatus")
    }
    return $Reasons
}

function New-PersistenceEntry {
    param(
        [string]$Type, [string]$Name, [string]$Command,
        [string]$ExePath, [hashtable]$SigInfo,
        [System.Collections.Generic.List[string]]$AlertReasons
    )
    return [PSCustomObject]@{
        Type            = $Type
        Name            = $Name
        Command         = if ($Command) { $Command } else { '[Vacio]' }
        Path            = if ($ExePath) { $ExePath } else { '[No resuelto]' }
        SignatureStatus = $SigInfo.Status
        SignatureIssuer = $SigInfo.Issuer
        AlertLevel      = if ($AlertReasons.Count -gt 0) { 'High' } else { 'Low' }
        AlertReasons    = $AlertReasons -join ' | '
    }
}

# ── HELPERS DE ACTIVIDAD (scope de script, definidos una vez) ─────────────────
function ConvertFrom-Rot13 {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $Chars = $Text.ToCharArray()
    for ($i = 0; $i -lt $Chars.Length; $i++) {
        $c = [int]$Chars[$i]
        if    ($c -ge 65 -and $c -le 90)  { $Chars[$i] = [char](65 + (($c - 65 + 13) % 26)) }
        elseif($c -ge 97 -and $c -le 122) { $Chars[$i] = [char](97 + (($c - 97 + 13) % 26)) }
    }
    return [string]::new($Chars)
}

function New-ActivityEntry {
    param(
        [string]$Category, [string]$User, [string]$Action,
        [string]$Timestamp, [string]$AlertLevel = 'Low', [string]$AlertReasons = ''
    )
    return [PSCustomObject]@{
        Category     = $Category
        User         = $User
        Action       = $Action
        Timestamp    = $Timestamp
        AlertLevel   = $AlertLevel
        AlertReasons = $AlertReasons
    }
}

# ============================================================
#region  MODULOS DE RECOLECCION (placeholders)
# ============================================================

# Cada funcion Invoke-Collect* debe retornar un [PSCustomObject] o [array of PSCustomObject]
# con los datos forenses recopilados. El resultado se agrega al reporte final.

function Invoke-CollectProcesses {
    Write-TriageLog "Modulo: Recoleccion de procesos iniciada" -Level SECTION

    # Rutas canonicas de binarios del sistema. Normalizadas a lowercase para comparacion
    # case-insensitive sin overhead de -ieq en cada iteracion.
    $LegitSystemPaths = @(
        "$env:SystemRoot\system32"      # C:\Windows\System32
        "$env:SystemRoot\syswow64"      # C:\Windows\SysWOW64 (procesos 32b en 64b)
        "$env:SystemRoot"               # C:\Windows (explorer.exe vive aqui)
    ) | ForEach-Object { $_.ToLower().TrimEnd('\') }

    # Procesos "lolbins de identidad": nombres que atacantes suplantan fuera de su ruta legitima.
    # Lista reducida a los de mayor abuso segun MITRE T1036.005
    $SensitiveBinaries = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @('svchost.exe','lsass.exe','explorer.exe','services.exe','winlogon.exe',
      'csrss.exe','smss.exe','wininit.exe','taskhost.exe','taskhostw.exe'
    ) | ForEach-Object { [void]$SensitiveBinaries.Add($_) }

    # Procesos PPL (Protected Process Light) — corren en session 0 sin ruta accesible
    # incluso como Admin. Es comportamiento esperado del kernel, no un IoC.
    $PPLProcesses = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @('smss.exe','csrss.exe','wininit.exe','lsass.exe','services.exe',
      'winlogon.exe','svchost.exe'
    ) | ForEach-Object { [void]$PPLProcesses.Add($_) }

    # Binarios MSIX/AppX de Windows que no llevan firma Authenticode convencional.
    # Get-AuthenticodeSignature devuelve NotSigned en ellos aunque sean legitimos del OS.
    # Confirmado limpio via: sfc /scannow (sin infraccion de integridad).
    $AppXUnsignedBinaries = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @('SecHealthUI.exe','SecHealthSystray.exe','SecurityHealthHost.exe',
      'SecurityHealthService.exe','PhoneExperienceHost.exe','YourPhone.exe',
      'MicrosoftEdge.exe','MicrosoftEdgeCP.exe','HxOutlook.exe',
      'HxTsr.exe','WinStore.App.exe','ZuneMusic.exe','ZuneVideo.exe'
    ) | ForEach-Object { [void]$AppXUnsignedBinaries.Add($_) }

    # Patrones de rutas sospechosas (living-off-the-land tipico, staging desde userland)
    $SuspiciousPathPatterns = @(
        '\btemp\b', 'appdata', 'programdata', 'users\\public',
        '\\downloads\\', '\\desktop\\', '\brecycle\b', '\\windows\\fonts\\'
    )

    # Una sola query CIM para todos los procesos: minimiza roundtrips WMI
    Write-TriageLog "Consultando Win32_Process via CIM..."
    $RawProcesses = Get-CimInstance -ClassName Win32_Process `
                        -Property ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,Description

    $TotalCount   = $RawProcesses.Count
    $ProcessedIdx = 0
    $Results      = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-TriageLog "Analizando $TotalCount procesos (firmas + hashes)..."

    foreach ($Proc in $RawProcesses) {
        $ProcessedIdx++

        # Progreso cada 25 procesos para no saturar el log
        if ($ProcessedIdx % 25 -eq 0) {
            Write-TriageLog "  Progreso: $ProcessedIdx / $TotalCount" -Level INFO
        }

        # Inicializar campos opcionales con valores seguros por defecto
        $SHA256          = 'N/A'
        $SigStatus       = 'N/A'
        $SigIssuer       = 'N/A'
        $AlertLevel      = 'Low'
        $AlertReasons    = [System.Collections.Generic.List[string]]::new()
        $PathNormalized  = ''

        try {
            # ── BLOQUE POR PROCESO: acceso denegado / proceso efimero no deben abortar el bucle ──
            $ExePath = $Proc.ExecutablePath

            if (-not [string]::IsNullOrWhiteSpace($ExePath) -and (Test-Path -LiteralPath $ExePath -PathType Leaf)) {

                $PathNormalized = $ExePath.ToLower().TrimEnd('\')

                # ── FIRMA DIGITAL ──────────────────────────────────────────────────────────────
                # Get-AuthenticodeSignature es una llamada costosa; solo se hace si el archivo existe
                Write-TriageLog "Verificando firma: $($Proc.Name) (PID $($Proc.ProcessId))" -Level INFO
                try {
                    $Sig       = Get-AuthenticodeSignature -LiteralPath $ExePath -ErrorAction Stop
                    $SigStatus = $Sig.Status.ToString()       # Valid | NotSigned | HashMismatch | etc.
                    $SigIssuer = if ($Sig.SignerCertificate) {
                        $Sig.SignerCertificate.GetNameInfo(
                            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false
                        )
                    } else { 'None' }
                }
                catch {
                    $SigStatus = "Error: $($_.Exception.Message)"
                }

                # ── HASH SHA256 ───────────────────────────────────────────────────────────────
                # Usar FileStream con buffer para evitar leer el archivo completo en memoria
                # especialmente relevante para DLLs/ejecutables grandes
                try {
                    $SHA256 = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256 -ErrorAction Stop).Hash
                }
                catch {
                    $SHA256 = "Error: $($_.Exception.Message)"
                }

                # ── LOGICA DE ALERTAS ─────────────────────────────────────────────────────────

                # Regla 1: Firma invalida o ausente.
                # Excepcion: binarios MSIX/AppX del OS no tienen firma Authenticode accesible.
                # Su integridad se verifica via SFC/Component Store, no via Authenticode.
                if ($SigStatus -ne 'Valid' -and -not $AppXUnsignedBinaries.Contains($Proc.Name)) {
                    $AlertReasons.Add("Firma no valida: $SigStatus")
                }

                # Regla 2: Ejecucion desde ruta sospechosa.
                # Para AppData/AppLocal: solo alertar si la firma TAMBIEN es invalida.
                # Discord, Spotify, Teams y similares viven legitimamente en AppData firmados.
                $CombinedPattern = $SuspiciousPathPatterns -join '|'
                if ($PathNormalized -match $CombinedPattern) {
                    $IsAppDataPath = ($PathNormalized -match 'appdata|applocal')
                    if ($IsAppDataPath -and $SigStatus -eq 'Valid') {
                        # Firmado + AppData = instalador de usuario legitimo, no alertar
                    } else {
                        $AlertReasons.Add("Ruta sospechosa: $ExePath")
                    }
                }

                # Regla 3: Binario sensible fuera de su ruta canonica (masquerading)
                if ($SensitiveBinaries.Contains($Proc.Name)) {
                    $ProcDir   = [System.IO.Path]::GetDirectoryName($PathNormalized).TrimEnd('\')
                    $IsLegit   = $LegitSystemPaths -contains $ProcDir
                    if (-not $IsLegit) {
                        $AlertReasons.Add("Binario del sistema fuera de ruta canonica: $ExePath")
                    }
                }

            } else {
                # Proceso sin ruta ejecutable (System, Idle, Protected)
                $SigStatus = 'NoPath'
                $SHA256    = 'NoPath'

                # Para procesos PPL conocidos, la ausencia de ruta es comportamiento normal del kernel.
                # Solo alertar si el nombre sensible NO esta en la lista PPL (posible masquerading).
                if ($SensitiveBinaries.Contains($Proc.Name) -and
                    -not $PPLProcesses.Contains($Proc.Name) -and
                    $Proc.ProcessId -gt 4) {
                    $AlertReasons.Add("Proceso sensible sin ruta accesible (posible proteccion o inyeccion)")
                } elseif ($SensitiveBinaries.Contains($Proc.Name) -and $PPLProcesses.Contains($Proc.Name)) {
                    # PPL esperado — registrar en SignatureStatus para visibilidad sin alertar
                    $SigStatus = 'PPL-Protected'
                    $SHA256    = 'PPL-Protected'
                }
            }

            # Consolidar AlertLevel desde la lista de razones acumuladas
            # Se podria extender a 'Medium' anadiendo reglas de peso parcial
            if ($AlertReasons.Count -gt 0) {
                $AlertLevel = 'High'
            }

            $Results.Add([PSCustomObject]@{
                PID             = $Proc.ProcessId
                PPID            = $Proc.ParentProcessId
                Name            = $Proc.Name
                Company         = $SigIssuer
                Path            = if ($ExePath) { $ExePath } else { '[Inaccesible]' }
                CommandLine     = if ($Proc.CommandLine) { $Proc.CommandLine } else { '[Protegido]' }
                SignatureStatus = $SigStatus
                SHA256          = $SHA256
                AlertLevel      = $AlertLevel
                # IsSuspicious como bool para filtrado rapido downstream (ej: Where-Object)
                IsSuspicious    = ($AlertLevel -eq 'High')
                AlertReasons    = $AlertReasons -join ' | '
            })
        }
        catch {
            # Proceso desaparecio en mid-flight (race condition) o acceso denegado total
            Write-TriageLog "Proceso PID $($Proc.ProcessId) ($($Proc.Name)) inaccessible: $($_.Exception.Message)" -Level WARN

            $Results.Add([PSCustomObject]@{
                PID             = $Proc.ProcessId
                PPID            = $Proc.ParentProcessId
                Name            = $Proc.Name
                Company         = 'N/A'
                Path            = '[Error de acceso]'
                CommandLine     = '[Error de acceso]'
                SignatureStatus = 'Error'
                SHA256          = 'Error'
                AlertLevel      = 'Unknown'
                IsSuspicious    = $false
                AlertReasons    = $_.Exception.Message
            })
        }
    }

    $HighCount = ($Results | Where-Object { $_.AlertLevel -eq 'High' }).Count
    Write-TriageLog "Recoleccion de procesos completada. Total: $($Results.Count) | High: $HighCount"

    # Retornar como array estatico; el List[T] ya esta ordenado por iteracion
    return $Results.ToArray()
}

function Invoke-CollectNetworkConnections {
    [CmdletBinding()]
    param(
        # Resultados previos de Invoke-CollectProcesses para correlacion directa.
        # Opcional: si es $null, la correlacion de IsSuspicious no se aplica.
        [PSCustomObject[]]$ProcessResults = $null
    )

    Write-TriageLog "Modulo: Recoleccion de conexiones de red iniciada" -Level SECTION

    # ── HELPER: Clasificacion RFC 1918 / RFC 5735 sin DNS ────────────────────────────────────
    # Parseo manual via [System.Net.IPAddress] + aritmetica de mascara.
    # Cubre: 10/8, 172.16/12, 192.168/16, 127/8 (loopback), 169.254/16 (link-local), ::1 (IPv6 loopback)
    # Sin llamadas a resolver DNS — cumple restriccion anti-DNS-leak.
    function Test-IsPrivateIP {
        param([string]$IPString)

        if ([string]::IsNullOrWhiteSpace($IPString) -or
            $IPString -eq '0.0.0.0' -or $IPString -eq '::') { return $true }

        try {
            $IP = [System.Net.IPAddress]::Parse($IPString)

            # IPv6: solo loopback es "privado" para nuestros fines forenses
            if ($IP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                return ($IP.IsIPv6LinkLocal -or $IP.Equals([System.Net.IPAddress]::IPv6Loopback))
            }

            # Convertir a uint32 para comparacion de rangos por mascara
            $Bytes  = $IP.GetAddressBytes()
            # GetAddressBytes() devuelve big-endian; BitConverter espera little-endian en x86
            [array]::Reverse($Bytes)
            $IntIP  = [System.BitConverter]::ToUInt32($Bytes, 0)

            # Rangos privados como limites uint32 pre-calculados (evita recalculo por iteracion)
            # 10.0.0.0/8       : 167772160  - 184549375
            # 172.16.0.0/12    : 2886729728 - 2887778303
            # 192.168.0.0/16   : 3232235520 - 3232301055
            # 127.0.0.0/8      : 2130706432 - 2147483647
            # 169.254.0.0/16   : 2851995648 - 2852061183
            return (
                ($IntIP -ge 167772160  -and $IntIP -le 184549375)  -or
                ($IntIP -ge 2886729728 -and $IntIP -le 2887778303) -or
                ($IntIP -ge 3232235520 -and $IntIP -le 3232301055) -or
                ($IntIP -ge 2130706432 -and $IntIP -le 2147483647) -or
                ($IntIP -ge 2851995648 -and $IntIP -le 2852061183)
            )
        }
        catch {
            # IP no parseable (ej: '*') se trata como privada para no generar falsos positivos
            return $true
        }
    }

    # ── INDICES DE CORRELACION ────────────────────────────────────────────────────────────────
    # Construir lookup PID -> proceso una sola vez. Dictionary<int,PSCustomObject> O(1) vs Where-Object O(n)
    $ProcByPID = [System.Collections.Generic.Dictionary[int,PSCustomObject]]::new()
    if ($null -ne $ProcessResults) {
        foreach ($P in $ProcessResults) {
            if (-not $ProcByPID.ContainsKey([int]$P.PID)) {
                $ProcByPID[[int]$P.PID] = $P
            }
        }
        Write-TriageLog "Indice de correlacion PID construido: $($ProcByPID.Count) entradas"
    } else {
        Write-TriageLog "Sin datos de procesos previos; correlacion IsSuspicious deshabilitada" -Level WARN
    }

    # Procesos que no deberian tener conexiones salientes a IPs publicas — ruido conocido alto riesgo
    $UnexpectedNetworkProcs = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @('notepad.exe','mspaint.exe','calc.exe','wordpad.exe','rundll32.exe',
      'regsvr32.exe','mshta.exe','wscript.exe','cscript.exe','certutil.exe',
      'bitsadmin.exe','msiexec.exe','installutil.exe'
    ) | ForEach-Object { [void]$UnexpectedNetworkProcs.Add($_) }

    # Puertos de sistema estandar — usados para filtrar Listen/Bound de bajo interes
    $CommonSystemPorts = [System.Collections.Generic.HashSet[int]]::new()
    # Expansion separada: el operador + sobre rangos tiene precedencia incorrecta en PS 5.1
    @(135,139,445,80,443,53,67,68,123,389,636,3268,3269,88,464) +
    (49152..49200) |
        ForEach-Object { [void]$CommonSystemPorts.Add([int]$_) }

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ── RECOLECCION TCP ───────────────────────────────────────────────────────────────────────
    Write-TriageLog "Analizando conexiones TCP establecidas..."
    try {
        $TcpConns = Get-NetTCPConnection -ErrorAction Stop
    }
    catch {
        Write-TriageLog "Error obteniendo conexiones TCP: $($_.Exception.Message)" -Level ERROR
        $TcpConns = @()
    }

    Write-TriageLog "Correlacionando PIDs con sockets TCP ($($TcpConns.Count) entradas)..."

    foreach ($Conn in $TcpConns) {
        try {
            $State = $Conn.State.ToString()  # Established, Listen, TimeWait, CloseWait, etc.

            # Filtrar Listen/Bound en puertos estandar de sistema — reduccion de ruido
            if ($State -in @('Listen','Bound')) {
                if ($CommonSystemPorts.Contains([int]$Conn.LocalPort)) { continue }
                # Listen en puerto no estandar: se incluye con alerta potencial
            }

            $ConnPID    = [int]$Conn.OwningProcess
            $RemoteIP   = $Conn.RemoteAddress
            $IsPublic   = -not (Test-IsPrivateIP -IPString $RemoteIP)

            # Correlacion con modulo de procesos
            $ProcEntry  = $null
            $ProcName   = 'Unknown'
            $ProcIsSusp = $false
            $ProcSig    = 'N/A'

            if ($ProcByPID.ContainsKey($ConnPID)) {
                $ProcEntry  = $ProcByPID[$ConnPID]
                $ProcName   = $ProcEntry.Name
                $ProcIsSusp = [bool]$ProcEntry.IsSuspicious
                $ProcSig    = $ProcEntry.SignatureStatus
            } else {
                # PID no encontrado en snapshot previo (proceso efimero o sistema)
                try {
                    $ProcName = (Get-Process -Id $ConnPID -ErrorAction Stop).Name
                }
                catch { $ProcName = "PID_$ConnPID" }
            }

            # ── ALERTAS DE RED ────────────────────────────────────────────────────────────────
            $AlertReasons = [System.Collections.Generic.List[string]]::new()
            $AlertLevel   = 'Low'

            # R1: Proceso previamente marcado como sospechoso
            if ($ProcIsSusp) {
                $AlertReasons.Add("Proceso origen marcado IsSuspicious por modulo de procesos")
            }

            # R2: Conexion ESTABLECIDA a IP publica desde binario de alto riesgo
            if ($IsPublic -and $State -eq 'Established' -and $UnexpectedNetworkProcs.Contains($ProcName)) {
                $AlertReasons.Add("Binario inusual con conexion saliente a IP publica: $ProcName -> $RemoteIP")
            }

            # R3: Proceso sin firma valida con conexion a IP publica
            if ($IsPublic -and $State -eq 'Established' -and
                $ProcSig -notin @('Valid','N/A','NoPath')) {
                $AlertReasons.Add("Proceso sin firma valida conectado a IP publica ($RemoteIP)")
            }

            # R4: Puerto de destino inusual en conexiones establecidas (no 80/443/8080/8443)
            if ($State -eq 'Established' -and $IsPublic) {
                # Common outbound ports incl. Steam SDR (27015-27030), QUIC (443 UDP), gaming
                $CommonOutPorts = @(80, 443, 8080, 8443, 21, 22, 25, 587, 993, 995,
                    27015, 27016, 27017, 27018, 27019, 27020, 27036,  # Steam
                    3478, 3479, 3480,  # PSN / various gaming
                    8081, 8082, 8888,   # Local proxies / browser extensions
                    6667, 6697         # IRC legacy
                )
                if ([int]$Conn.RemotePort -notin $CommonOutPorts) {
                    $AlertReasons.Add("Puerto remoto no estandar en conexion publica: $($Conn.RemotePort)")
                }
            }

            if ($AlertReasons.Count -gt 0) { $AlertLevel = 'High' }

            $Results.Add([PSCustomObject]@{
                Protocol      = 'TCP'
                LocalAddress  = $Conn.LocalAddress
                LocalPort     = $Conn.LocalPort
                RemoteAddress = $RemoteIP
                RemotePort    = $Conn.RemotePort
                State         = $State
                PID           = $ConnPID
                ProcessName   = $ProcName
                IsPublicIP    = $IsPublic
                AlertLevel    = $AlertLevel
                AlertReasons  = $AlertReasons -join ' | '
                # Timestamp del snapshot - util para correlacion temporal en el reporte
                CapturedAt    = (Get-Date -Format 'o')
            })
        }
        catch {
            # Conexion efimera: desaparecio entre Get-NetTCPConnection y el procesamiento
            Write-TriageLog "Conexion TCP efimera ignorada: $($_.Exception.Message)" -Level WARN
        }
    }

    # ── RECOLECCION UDP ───────────────────────────────────────────────────────────────────────
    # UDP es connectionless: no hay State ni RemoteAddress en la mayoria de endpoints.
    # Se incluyen solo los que escuchan en puertos no estandar (potencial C2 UDP / tunneling)
    Write-TriageLog "Analizando endpoints UDP (puertos no estandar)..."
    try {
        $UdpEndpoints = Get-NetUDPEndpoint -ErrorAction Stop
    }
    catch {
        Write-TriageLog "Error obteniendo endpoints UDP: $($_.Exception.Message)" -Level WARN
        $UdpEndpoints = @()
    }

    $CommonUdpPorts = [System.Collections.Generic.HashSet[int]]::new()
    @(53, 67, 68, 123, 137, 138, 161, 500, 4500, 5353, 5355) |
        ForEach-Object { [void]$CommonUdpPorts.Add([int]$_) }

    foreach ($Ep in $UdpEndpoints) {
        try {
            # Filtrar puertos UDP conocidos del sistema
            if ($CommonUdpPorts.Contains([int]$Ep.LocalPort)) { continue }

            $EpPID      = [int]$Ep.OwningProcess
            $ProcName   = 'Unknown'
            $ProcIsSusp = $false

            if ($ProcByPID.ContainsKey($EpPID)) {
                $ProcName   = $ProcByPID[$EpPID].Name
                $ProcIsSusp = [bool]$ProcByPID[$EpPID].IsSuspicious
            } else {
                try { $ProcName = (Get-Process -Id $EpPID -ErrorAction Stop).Name }
                catch { $ProcName = "PID_$EpPID" }
            }

            $AlertReasons = [System.Collections.Generic.List[string]]::new()
            $AlertReasons.Add("Endpoint UDP activo en puerto no estandar: $($Ep.LocalPort)")
            if ($ProcIsSusp) { $AlertReasons.Add("Proceso origen IsSuspicious") }

            $Results.Add([PSCustomObject]@{
                Protocol      = 'UDP'
                LocalAddress  = $Ep.LocalAddress
                LocalPort     = $Ep.LocalPort
                RemoteAddress = 'N/A'
                RemotePort    = 'N/A'
                State         = 'Listen'
                PID           = $EpPID
                ProcessName   = $ProcName
                IsPublicIP    = $false
                AlertLevel    = if ($ProcIsSusp) { 'High' } else { 'Medium' }
                AlertReasons  = $AlertReasons -join ' | '
                CapturedAt    = (Get-Date -Format 'o')
            })
        }
        catch {
            Write-TriageLog "Endpoint UDP efimero ignorado: $($_.Exception.Message)" -Level WARN
        }
    }

    $HighCount = ($Results | Where-Object { $_.AlertLevel -eq 'High' }).Count
    Write-TriageLog "Recoleccion de red completada. Total: $($Results.Count) | High: $HighCount"

    return $Results.ToArray()
}

function Invoke-CollectPersistenceMechanisms {

    Write-TriageLog "Modulo: Recoleccion de mecanismos de persistencia iniciada" -Level SECTION

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ═══════════════════════════════════════════════════════════════
    #  FASE 1 — REGISTRY RUN KEYS
    # ═══════════════════════════════════════════════════════════════
    Write-TriageLog "Escaneando llaves de registro (Run / RunOnce / Winlogon)..."

    $RunKeyPaths = @(
        # Maquina (todos los usuarios) — vector mas comun de persistencia
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        # Usuario actual — persistencia de baja integridad, frecuente en adware/spyware
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        # WOW6432Node — clave de 32 bits en sistemas de 64 bits, a menudo ignorada por defensores
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($KeyPath in $RunKeyPaths) {
        try {
            if (-not (Test-Path -LiteralPath $KeyPath -ErrorAction SilentlyContinue)) { continue }
            $Key    = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
            $Hive   = if ($KeyPath -like 'HKLM:*') { 'HKLM' } else { 'HKCU' }

            foreach ($ValueName in $Key.GetValueNames()) {
                try {
                    $Command = $Key.GetValue($ValueName)
                    $ExePath = Get-ExecutableFromCommand -Command $Command
                    $SigInfo = Get-SignatureInfo -Path $ExePath
                    $Reasons = Get-PersistenceAlertReasons -Command $Command -ExePath "$ExePath" -SigStatus $SigInfo.Status
                    # Run key en AppData con firma valida = instalador de usuario conocido (Discord, Spotify...)
                    # Eliminar la razon de ruta sospechosa si la firma es valida
                    if ($SigInfo.Status -eq 'Valid') {
                        $Reasons = [System.Collections.Generic.List[string]]($Reasons | Where-Object { $_ -notmatch '^Ruta sospechosa' })
                    }

                    $Results.Add((New-PersistenceEntry `
                        -Type    "Registry\Run [$Hive]" `
                        -Name    $ValueName `
                        -Command $Command `
                        -ExePath $ExePath `
                        -SigInfo $SigInfo `
                        -AlertReasons $Reasons))
                }
                catch {
                    Write-TriageLog "Error leyendo valor '$ValueName' en $KeyPath : $($_.Exception.Message)" -Level WARN
                }
            }
        }
        catch {
            Write-TriageLog "Clave de registro inaccesible: $KeyPath - $($_.Exception.Message)" -Level WARN
        }
    }

    # ── Winlogon Shell / Userinit ─────────────────────────────────────────────────────────────
    # Hijacking de Winlogon (T1547.004): reemplazar Shell o Userinit con payload propio
    $WinlogonPath    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $WinlogonChecks  = @{
        'Shell'    = 'explorer.exe'          # valor canonico
        'Userinit' = 'C:\Windows\system32\userinit.exe,'
    }

    try {
        $WLKey = Get-Item -LiteralPath $WinlogonPath -ErrorAction Stop
        foreach ($ValName in $WinlogonChecks.Keys) {
            try {
                $CurrentVal  = $WLKey.GetValue($ValName)
                $ExpectedVal = $WinlogonChecks[$ValName]
                # Alerta si el valor difiere del canonico (podria haber valores extra separados por coma)
                $IsModified  = ($CurrentVal.Trim() -ne $ExpectedVal.Trim())
                $Reasons     = [System.Collections.Generic.List[string]]::new()
                if ($IsModified) {
                    $Reasons.Add("Valor Winlogon\$ValName modificado. Esperado: '$ExpectedVal' | Actual: '$CurrentVal'")
                }
                $ExePath = Get-ExecutableFromCommand -Command $CurrentVal
                $SigInfo = Get-SignatureInfo -Path $ExePath

                $Results.Add((New-PersistenceEntry `
                    -Type    'Registry\Winlogon' `
                    -Name    $ValName `
                    -Command $CurrentVal `
                    -ExePath $ExePath `
                    -SigInfo $SigInfo `
                    -AlertReasons $Reasons))
            }
            catch {
                Write-TriageLog "Error leyendo Winlogon\$ValName : $($_.Exception.Message)" -Level WARN
            }
        }
    }
    catch {
        Write-TriageLog "Clave Winlogon inaccesible: $($_.Exception.Message)" -Level WARN
    }

    # ═══════════════════════════════════════════════════════════════
    #  FASE 2 — SCHEDULED TASKS
    # ═══════════════════════════════════════════════════════════════
    Write-TriageLog "Auditando tareas programadas (excluyendo \Microsoft\Windows\)..."

    try {
        # Get-ScheduledTask devuelve objetos ricos; TaskPath filtra el namespace de MS
        $Tasks = Get-ScheduledTask -ErrorAction Stop |
                 Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' }

        Write-TriageLog "Tareas no-Microsoft encontradas: $($Tasks.Count)"

        foreach ($Task in $Tasks) {
            try {
                # Una tarea puede tener multiples acciones; se analiza cada una
                foreach ($Action in $Task.Actions) {
                    $Command = ''
                    $ExePath = $null

                    # CimInstance de tipo MSFT_TaskExecAction tiene Execute + Arguments
                    if ($Action.CimClass.CimClassName -eq 'MSFT_TaskExecAction') {
                        $ExePath = $Action.Execute
                        $Command = "$($Action.Execute) $($Action.Arguments)".Trim()
                    } else {
                        # Otros tipos de accion (ComHandler, etc.) — serializar como string
                        $Command = $Action.ToString()
                    }

                    $SigInfo = Get-SignatureInfo -Path $ExePath
                    $Reasons = Get-PersistenceAlertReasons -Command $Command -ExePath "$ExePath" -SigStatus $SigInfo.Status

                    # Tareas deshabilitadas siguen siendo IOC si tienen comandos sospechosos
                    $StateNote = if ($Task.State -eq 'Disabled') { ' [DISABLED]' } else { '' }

                    $Results.Add((New-PersistenceEntry `
                        -Type    "ScheduledTask$StateNote" `
                        -Name    "$($Task.TaskPath)$($Task.TaskName)" `
                        -Command $Command `
                        -ExePath $ExePath `
                        -SigInfo $SigInfo `
                        -AlertReasons $Reasons))
                }
            }
            catch {
                Write-TriageLog "Error procesando tarea '$($Task.TaskName)': $($_.Exception.Message)" -Level WARN
            }
        }
    }
    catch {
        Write-TriageLog "Error enumerando tareas programadas: $($_.Exception.Message)" -Level ERROR
    }

    # ═══════════════════════════════════════════════════════════════
    #  FASE 3 — SERVICIOS
    # ═══════════════════════════════════════════════════════════════
    Write-TriageLog "Auditando servicios no-Microsoft con rutas sospechosas..."

    try {
        # Traer solo servicios con PathName (excluye drivers sin ruta de usuario)
        $Services = Get-CimInstance -ClassName Win32_Service `
                        -Property Name,DisplayName,PathName,StartMode,State,Description `
                        -ErrorAction Stop |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_.PathName) }

        # Rutas de servicios legitimos del sistema — cualquier servicio fuera de estas es candidato
        $LegitServiceRoots = @(
            "$env:SystemRoot\system32"
            "$env:SystemRoot\syswow64"
            "$env:SystemRoot\Microsoft.NET"
            "$env:SystemRoot\servicing"
            "$env:ProgramFiles"
            "${env:ProgramFiles(x86)}"
            # Defender, MRT y componentes de seguridad viven en ProgramData desde Win10 1703
            "$env:ProgramData\Microsoft\Windows Defender"
            "$env:ProgramData\Microsoft\Windows Defender\Platform"
            "$env:ProgramData\Microsoft\Windows Malicious Software Removal Tool"
            # Battle.net, Blizzard y similares usan ProgramData legitimamente
            "$env:ProgramData\Battle.net"
            "$env:ProgramData\Battle.net_components"
        ) | ForEach-Object { $_.ToLower() }

        foreach ($Svc in $Services) {
            try {
                $Command = $Svc.PathName
                $ExePath = Get-ExecutableFromCommand -Command $Command
                if ([string]::IsNullOrWhiteSpace($ExePath)) { continue }

                $ExeLower   = $ExePath.ToLower()
                $SigInfo    = Get-SignatureInfo -Path $ExePath
                $ReasonsRaw = Get-PersistenceAlertReasons -Command $Command -ExePath $ExePath -SigStatus $SigInfo.Status
                # Garantizar que $Reasons sea siempre List[string] — la funcion puede retornar null en edge cases
                $Reasons    = [System.Collections.Generic.List[string]]::new()
                if ($null -ne $ReasonsRaw) { foreach ($R in $ReasonsRaw) { $Reasons.Add([string]$R) } }

                # Verificar si el servicio corre desde fuera de las raices legitimas
                $IsLegitRoot = $false
                foreach ($Root in $LegitServiceRoots) {
                    if ($ExeLower.StartsWith($Root)) { $IsLegitRoot = $true; break }
                }
                if (-not $IsLegitRoot) {
                    $Reasons.Add("Servicio ejecutandose fuera de rutas de sistema estandar: $ExePath")
                }

                # Si la ruta es legitima, eliminar las alertas de "Ruta sospechosa"
                # que Get-PersistenceAlertReasons pudo haber generado por programdata/appdata
                if ($IsLegitRoot) {
                    $Reasons = [System.Collections.Generic.List[string]](
                        $Reasons | Where-Object { $_ -notmatch '^Ruta sospechosa' }
                    )
                }

                # Solo registrar si hay razones de alerta O si la firma es invalida
                # Evita poblar el reporte con miles de servicios legitimos de terceros
                if ($Reasons.Count -gt 0 -or $SigInfo.Status -notin @('Valid','N/A')) {
                    $Results.Add((New-PersistenceEntry `
                        -Type    "Service [$($Svc.StartMode)]" `
                        -Name    $Svc.Name `
                        -Command $Command `
                        -ExePath $ExePath `
                        -SigInfo $SigInfo `
                        -AlertReasons $Reasons))
                }
            }
            catch {
                Write-TriageLog "Error procesando servicio '$($Svc.Name)': $($_.Exception.Message)" -Level WARN
            }
        }
    }
    catch {
        Write-TriageLog "Error enumerando servicios: $($_.Exception.Message)" -Level ERROR
    }

    # ═══════════════════════════════════════════════════════════════
    #  FASE 4 — WMI EVENT SUBSCRIPTIONS (persistencia fileless)
    # ═══════════════════════════════════════════════════════════════
    # T1546.003: atacantes usan el tridente Filter + Consumer + Binding para persistencia
    # sin tocar disco. Siempre alta criticidad cuando se detectan consumers activos.
    Write-TriageLog "Buscando WMI Event Subscriptions (persistencia fileless)..."

    # ActiveScriptEventConsumer: ejecuta VBScript/JScript directamente en memoria
    try {
        $ScriptConsumers = Get-CimInstance -Namespace 'root\subscription' `
                               -ClassName  'ActiveScriptEventConsumer' `
                               -ErrorAction Stop

        foreach ($Consumer in $ScriptConsumers) {
            $Reasons = [System.Collections.Generic.List[string]]::new()
            $Reasons.Add("WMI ActiveScriptEventConsumer detectado - persistencia fileless critica (T1546.003)")

            $ScriptBody = if ($Consumer.ScriptText) {
                $Consumer.ScriptText.Substring(0, [Math]::Min(512, $Consumer.ScriptText.Length))
            } else { '[Vacio]' }

            # Analizar el texto del script en busca de patrones de alto riesgo
            $HighRiskScriptPatterns = @('powershell','cmd','wscript','shell','http','base64','frombase64')
            foreach ($Pat in $HighRiskScriptPatterns) {
                if ($ScriptBody -match $Pat) {
                    $Reasons.Add("Script contiene patron de alto riesgo: '$Pat'")
                }
            }

            $Results.Add([PSCustomObject]@{
                Type            = 'WMI\ActiveScriptConsumer'
                Name            = $Consumer.Name
                Command         = $ScriptBody
                Path            = '[In-Memory / Fileless]'
                SignatureStatus = 'N/A'
                SignatureIssuer = 'N/A'
                AlertLevel      = 'High'
                AlertReasons    = $Reasons -join ' | '
            })
        }
    }
    catch {
        Write-TriageLog "Error consultando WMI ActiveScriptEventConsumer: $($_.Exception.Message)" -Level WARN
    }

    # CommandLineEventConsumer: ejecuta un proceso arbitrario via WMI en respuesta a eventos
    try {
        $CmdConsumers = Get-CimInstance -Namespace 'root\subscription' `
                            -ClassName  'CommandLineEventConsumer' `
                            -ErrorAction Stop

        foreach ($Consumer in $CmdConsumers) {
            $Command = $Consumer.CommandLineTemplate
            $ExePath = Get-ExecutableFromCommand -Command $Command
            $SigInfo = Get-SignatureInfo -Path $ExePath
            $Reasons = Get-PersistenceAlertReasons -Command $Command -ExePath "$ExePath" -SigStatus $SigInfo.Status
            $Reasons.Insert(0, "WMI CommandLineEventConsumer detectado (T1546.003)")

            $Results.Add((New-PersistenceEntry `
                -Type    'WMI\CommandLineConsumer' `
                -Name    $Consumer.Name `
                -Command $Command `
                -ExePath $ExePath `
                -SigInfo $SigInfo `
                -AlertReasons $Reasons))
        }
    }
    catch {
        Write-TriageLog "Error consultando WMI CommandLineEventConsumer: $($_.Exception.Message)" -Level WARN
    }

    # Correlacion Filter <-> Consumer via __FilterToConsumerBinding
    # Registrar bindings huerfanos (consumer sin filter o viceversa) — IOC de limpieza incompleta
    try {
        $Bindings = Get-CimInstance -Namespace 'root\subscription' `
                        -ClassName  '__FilterToConsumerBinding' `
                        -ErrorAction Stop

        if ($Bindings.Count -gt 0) {
            Write-TriageLog "WMI Bindings activos encontrados: $($Bindings.Count) - ver entradas WMI en reporte" -Level WARN
        }
    }
    catch {
        Write-TriageLog "Error consultando WMI Bindings: $($_.Exception.Message)" -Level WARN
    }

    $HighCount = ($Results | Where-Object { $_.AlertLevel -eq 'High' }).Count
    Write-TriageLog "Recoleccion de persistencia completada. Total: $($Results.Count) | High: $HighCount"

    return $Results.ToArray()
}

function Invoke-CollectUserActivity {

    Write-TriageLog "Modulo: Recoleccion de actividad de usuario iniciada" -Level SECTION

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()


    # Palabras clave de alto riesgo — compiladas como regex OR una sola vez para reutilizar
    # en multiples fases (historial PS, archivos recientes, UserAssist)
    $HighRiskPattern = 'mimikatz|cobaltstrike|lsadump|psexec|invoke-mimikatz|' +
                       'downloadstring|encodedcommand|\s-enc\s|\s-e\s|' +
                       'hidden|bypass|amsiutils|disable.*defender|' +
                       'sekurlsa|dcsync|hashdump|meterpreter|shellcode|' +
                       'net\.webclient|iex\s*\(|invoke-expression'

    # ═══════════════════════════════════════════════════════════════
    #  FASE 1 — PREFETCH METADATA
    # ═══════════════════════════════════════════════════════════════
    # Parseo binario completo de .pf requiere conocer el formato MAM (Win10+) o sin comprimir
    # (Win7/8). Aqui extraemos la timeline de filesystem (CreationTime = primera ejecucion,
    # LastWriteTime = ultima ejecucion) que ya es forense-util sin parsear el binario.
    Write-TriageLog "Analizando artefactos Prefetch..."

    $PrefetchPath = Join-Path $env:SystemRoot 'Prefetch'

    try {
        if (Test-Path -LiteralPath $PrefetchPath -PathType Container) {
            $PfFiles = Get-ChildItem -LiteralPath $PrefetchPath -Filter '*.pf' -ErrorAction Stop

            Write-TriageLog "Archivos Prefetch encontrados: $($PfFiles.Count)"

            foreach ($Pf in $PfFiles) {
                try {
                    # Nombre del .pf: EJECUTABLE-XXXXXXXX.pf  (hash de ruta en hex)
                    # Extraer solo el nombre del ejecutable (antes del guion + hash)
                    $ExeName = if ($Pf.BaseName -match '^(.+)-[0-9A-F]{8}$') {
                        $Matches[1]
                    } else { $Pf.BaseName }

                    $AlertLevel   = 'Low'
                    $AlertReasons = ''

                    # Alerta si el nombre del ejecutable prefetcheado coincide con herramientas
                    # de ataque conocidas (ej: mimikatz.exe tendra MIMIKATZ-XXXXXXXX.pf)
                    if ($ExeName -imatch $HighRiskPattern) {
                        $AlertLevel   = 'High'
                        $AlertReasons = "Ejecutable sospechoso en Prefetch: $ExeName"
                    }

                    $Results.Add((New-ActivityEntry `
                        -Category    'Prefetch' `
                        -User        'SYSTEM' `
                        -Action      "Ejecutado: $ExeName | Ruta hash: $($Pf.BaseName.Split('-')[-1])" `
                        -Timestamp   $Pf.LastWriteTime.ToString('o') `
                        -AlertLevel  $AlertLevel `
                        -AlertReasons $AlertReasons))
                }
                catch {
                    Write-TriageLog "Error procesando Prefetch '$($Pf.Name)': $($_.Exception.Message)" -Level WARN
                }
            }
        } else {
            Write-TriageLog "Directorio Prefetch no accesible o no existe (puede estar deshabilitado)" -Level WARN
        }
    }
    catch {
        Write-TriageLog "Error accediendo a Prefetch: $($_.Exception.Message)" -Level WARN
    }

    # ═══════════════════════════════════════════════════════════════
    #  FASE 2 — USERASSIST (ROT13 decode)
    # ═══════════════════════════════════════════════════════════════
    # UserAssist trackea ejecuciones desde Explorer (GUI). Claves bajo GUIDs especificos,
    # cada valor codificado en ROT13. El payload binario incluye contador y timestamp FILETIME
    # pero aqui nos centramos en el nombre decodificado (el artefacto de mayor valor forense).
    Write-TriageLog "Decodificando UserAssist (ROT13)..."

    $UserAssistBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'

    try {
        if (Test-Path -LiteralPath $UserAssistBase -ErrorAction SilentlyContinue) {
            # Cada subkey es un GUID que agrupa diferentes tipos de ejecucion
            $GuidKeys = Get-ChildItem -LiteralPath $UserAssistBase -ErrorAction Stop

            foreach ($GuidKey in $GuidKeys) {
                try {
                    $CountSubkey = Join-Path $GuidKey.PSPath 'Count'
                    if (-not (Test-Path -LiteralPath $CountSubkey -ErrorAction SilentlyContinue)) { continue }

                    $CountKey = Get-Item -LiteralPath $CountSubkey -ErrorAction Stop

                    foreach ($ValueName in $CountKey.GetValueNames()) {
                        try {
                            # Ignorar la entrada de metadata UEME_CTLSESSION
                            if ($ValueName -eq 'UEME_CTLSESSION') { continue }

                            $Decoded = ConvertFrom-Rot13 -Text $ValueName

                            # El valor binario de UserAssist es una estructura USERASSISTENTRY
                            # (session, count, focus, time en FILETIME). Extraer solo el contador
                            # y el timestamp si el formato es el esperado (72 bytes en Win10+)
                            $RawBytes  = $CountKey.GetValue($ValueName)
                            $RunCount  = 'N/A'
                            $Timestamp = 'N/A'

                            if ($RawBytes -is [byte[]] -and $RawBytes.Length -ge 72) {
                                # Offset 4: session count (int32 LE)
                                $RunCount = [System.BitConverter]::ToInt32($RawBytes, 4)
                                # Offset 60: last execution time como FILETIME (int64 LE)
                                $FileTime = [System.BitConverter]::ToInt64($RawBytes, 60)
                                if ($FileTime -gt 0) {
                                    $Timestamp = [DateTime]::FromFileTimeUtc($FileTime).ToString('o')
                                }
                            }

                            $AlertLevel   = 'Low'
                            $AlertReasons = ''
                            if ($Decoded -imatch $HighRiskPattern) {
                                $AlertLevel   = 'High'
                                $AlertReasons = "Herramienta de ataque detectada en UserAssist: $Decoded"
                            }

                            $Results.Add((New-ActivityEntry `
                                -Category    'UserAssist' `
                                -User        $env:USERNAME `
                                -Action      "Ejecutado (x$RunCount): $Decoded" `
                                -Timestamp   $Timestamp `
                                -AlertLevel  $AlertLevel `
                                -AlertReasons $AlertReasons))
                        }
                        catch {
                            Write-TriageLog "Error decodificando valor UserAssist '$ValueName': $($_.Exception.Message)" -Level WARN
                        }
                    }
                }
                catch {
                    Write-TriageLog "Error en subkey UserAssist '$($GuidKey.Name)': $($_.Exception.Message)" -Level WARN
                }
            }
        }
    }
    catch {
        Write-TriageLog "Error accediendo a UserAssist: $($_.Exception.Message)" -Level WARN
    }

    # ═══════════════════════════════════════════════════════════════
    #  FASE 3 — RECENT FILES (.lnk)
    # ═══════════════════════════════════════════════════════════════
    # Los .lnk de Recent revelan acceso a ficheros aunque el fichero original haya sido borrado.
    # No parseamos el formato LNK binario (requeriria COM/Shell32) — nos basta nombre y timestamps
    # del propio .lnk que el Shell mantiene sincronizados con la fecha de apertura.
    Write-TriageLog "Extrayendo artefactos de archivos recientes (.lnk)..."

    # Enumerar todos los perfiles de usuario bajo HKLM para cubrir todos los usuarios, no solo SYSTEM
    $UserProfiles = @()
    try {
        $UserProfiles = Get-CimInstance -ClassName Win32_UserProfile `
                            -Filter "Special=False" -ErrorAction Stop |
                        Where-Object { Test-Path -LiteralPath $_.LocalPath -ErrorAction SilentlyContinue }
    }
    catch {
        # Fallback: al menos el perfil del usuario que ejecuta el script
        $UserProfiles = @([PSCustomObject]@{ LocalPath = $env:USERPROFILE; SID = 'CurrentUser' })
        Write-TriageLog "Fallback a perfil actual para archivos recientes" -Level WARN
    }

    foreach ($Profile in $UserProfiles) {
        $RecentPath = Join-Path $Profile.LocalPath 'AppData\Roaming\Microsoft\Windows\Recent'
        $ProfileUser = Split-Path $Profile.LocalPath -Leaf

        if (-not (Test-Path -LiteralPath $RecentPath -ErrorAction SilentlyContinue)) { continue }

        try {
            $LnkFiles = Get-ChildItem -LiteralPath $RecentPath -Filter '*.lnk' -ErrorAction Stop |
                        Sort-Object LastWriteTime -Descending

            foreach ($Lnk in $LnkFiles) {
                try {
                    # BaseName del .lnk = nombre del fichero accedido (sin extension .lnk)
                    $FileName     = $Lnk.BaseName
                    $AlertLevel   = 'Low'
                    $AlertReasons = ''

                    if ($FileName -imatch $HighRiskPattern) {
                        $AlertLevel   = 'High'
                        $AlertReasons = "Nombre de archivo reciente contiene patron sospechoso: $FileName"
                    }

                    $Results.Add((New-ActivityEntry `
                        -Category    'RecentFiles' `
                        -User        $ProfileUser `
                        -Action      "Archivo accedido: $FileName" `
                        -Timestamp   $Lnk.LastWriteTime.ToString('o') `
                        -AlertLevel  $AlertLevel `
                        -AlertReasons $AlertReasons))
                }
                catch {
                    Write-TriageLog "Error procesando .lnk '$($Lnk.Name)': $($_.Exception.Message)" -Level WARN
                }
            }
        }
        catch {
            Write-TriageLog "Error enumerando Recent de '$ProfileUser': $($_.Exception.Message)" -Level WARN
        }
    }

    # ═══════════════════════════════════════════════════════════════
    #  FASE 4 — SECURITY EVENT LOG (4624 / 4625)
    # ═══════════════════════════════════════════════════════════════
    Write-TriageLog "Filtrando eventos de seguridad (4624/4625)..."

    try {
        # Get-WinEvent con FilterHashtable es significativamente mas rapido que Get-EventLog
        # ya que el filtrado ocurre en el proveedor ETW, no en PS
        $LogonEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id      = @(4624, 4625)
        } -MaxEvents 100 -ErrorAction Stop

        Write-TriageLog "Eventos de logon obtenidos: $($LogonEvents.Count)"

        # Deteccion de picos de 4625: agrupar por ventana de 60 segundos
        # Un brute-force tipico genera decenas de 4625 en segundos
        $FailedLogons = $LogonEvents | Where-Object { $_.Id -eq 4625 }

        # Agrupar en buckets de 60s para deteccion de spray/brute
        $BruteMap = [System.Collections.Generic.Dictionary[string, int]]::new()
        foreach ($Ev in $FailedLogons) {
            # Bucket = minuto exacto (truncar segundos)
            $Bucket = $Ev.TimeCreated.ToString('yyyy-MM-dd HH:mm')
            if (-not $BruteMap.ContainsKey($Bucket)) { $BruteMap[$Bucket] = 0 }
            $BruteMap[$Bucket]++
        }
        # Umbral: 5+ fallos en 60s = anomalia significativa
        $BruteThreshold = 5
        $BrucketAlerts  = $BruteMap.GetEnumerator() | Where-Object { $_.Value -ge $BruteThreshold }

        foreach ($Ba in $BrucketAlerts) {
            $Results.Add((New-ActivityEntry `
                -Category    'SecurityLog' `
                -User        'Multiple' `
                -Action      "Pico de fallos de logon: $($Ba.Value) intentos fallidos (4625) en el minuto $($Ba.Key)" `
                -Timestamp   $Ba.Key `
                -AlertLevel  'Medium' `
                -AlertReasons "Posible brute-force o password spray: $($Ba.Value) eventos 4625 en 60 segundos"))
        }

        # Registrar los eventos individualmente (los ultimos 100, mixtos 4624+4625)
        foreach ($Ev in $LogonEvents) {
            try {
                # Parsear propiedades del XML del evento para extraer cuenta y origen
                # XPath sobre el XML del evento es mas robusto que confiar en Message localizado
                [xml]$EvXml    = $Ev.ToXml()
                $EventData     = $EvXml.Event.EventData.Data

                # Helper inline para extraer valor por nombre del campo XML
                $GetField = { param($Name)
                    ($EventData | Where-Object { $_.Name -eq $Name }).'#text'
                }

                $AccountName  = & $GetField 'TargetUserName'
                $LogonType    = & $GetField 'LogonType'     # 2=Interactive, 3=Network, 10=RemoteInteractive
                $SourceIP     = & $GetField 'IpAddress'
                $WorkStation  = & $GetField 'WorkstationName'

                $LogonTypeMap = @{
                    '2'  = 'Interactive'
                    '3'  = 'Network'
                    '4'  = 'Batch'
                    '5'  = 'Service'
                    '7'  = 'Unlock'
                    '8'  = 'NetworkCleartext'
                    '9'  = 'NewCredentials'
                    '10' = 'RemoteInteractive (RDP)'
                    '11' = 'CachedInteractive'
                }
                $LogonTypeStr = if ($LogonTypeMap.ContainsKey($LogonType)) {
                    $LogonTypeMap[$LogonType] } else { "Type $LogonType" }

                $Status       = if ($Ev.Id -eq 4624) { 'Logon OK' } else { 'Logon FAIL' }
                $AlertLevel   = 'Low'
                $AlertReasons = ''

                # Alertas de logon: RDP o NetworkCleartext exitosos son de interes forense
                if ($Ev.Id -eq 4624 -and $LogonType -in @('10','8')) {
                    $AlertLevel   = 'Medium'
                    $AlertReasons = "Logon exitoso de tipo $LogonTypeStr desde $SourceIP"
                }

                $Results.Add((New-ActivityEntry `
                    -Category    "SecurityLog\$Status" `
                    -User        $AccountName `
                    -Action      "$Status | Tipo: $LogonTypeStr | Origen: $SourceIP | Host: $WorkStation" `
                    -Timestamp   $Ev.TimeCreated.ToString('o') `
                    -AlertLevel  $AlertLevel `
                    -AlertReasons $AlertReasons))
            }
            catch {
                Write-TriageLog "Error parseando evento $($Ev.Id) @ $($Ev.TimeCreated): $($_.Exception.Message)" -Level WARN
            }
        }
    }
    catch {
        Write-TriageLog "Error accediendo al log de seguridad (requiere admin): $($_.Exception.Message)" -Level WARN
    }

    # ═══════════════════════════════════════════════════════════════
    #  FASE 5 — POWERSHELL HISTORY
    # ═══════════════════════════════════════════════════════════════
    # ConsoleHost_history.txt persiste entre sesiones. PSReadLine lo gestiona por usuario.
    # En entornos de ataque, contiene comandos de reconocimiento, lateral movement y ejecucion.
    Write-TriageLog "Analizando historial de PowerShell por usuario..."

    foreach ($Profile in $UserProfiles) {
        $ProfileUser  = Split-Path $Profile.LocalPath -Leaf
        $HistoryPaths = @(
            # PS 5.1 — PSReadLine default path
            (Join-Path $Profile.LocalPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
            # PS 7+ cambia el directorio de AppData\Roaming a una ruta nueva pero mantiene el nombre
            (Join-Path $Profile.LocalPath 'AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt')
        )

        foreach ($HistPath in $HistoryPaths) {
            if (-not (Test-Path -LiteralPath $HistPath -PathType Leaf -ErrorAction SilentlyContinue)) { continue }

            try {
                # Leer con StreamReader para archivos grandes sin cargar todo en memoria
                $Reader   = [System.IO.StreamReader]::new($HistPath, [System.Text.Encoding]::UTF8)
                $LineNum  = 0

                while ($null -ne ($Line = $Reader.ReadLine())) {
                    $LineNum++
                    $Line = $Line.Trim()
                    if ([string]::IsNullOrEmpty($Line)) { continue }

                    $AlertLevel   = 'Low'
                    $AlertReasons = ''

                    if ($Line -imatch $HighRiskPattern) {
                        $AlertLevel   = 'High'
                        # Capturar que patron especifico disparo la alerta
                        $Matched = [regex]::Match($Line, $HighRiskPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                        $AlertReasons = "Patron de ataque en historial PS (linea $LineNum): '$($Matched.Value)'"
                    }

                    # Solo registrar lineas de alto riesgo Y una muestra de las normales
                    # para no inundar el reporte con todo el historial (puede tener miles de lineas)
                    if ($AlertLevel -eq 'High' -or $LineNum % 50 -eq 0) {
                        $Results.Add((New-ActivityEntry `
                            -Category    'PSHistory' `
                            -User        $ProfileUser `
                            -Action      $Line `
                            -Timestamp   (Get-Item -LiteralPath $HistPath).LastWriteTime.ToString('o') `
                            -AlertLevel  $AlertLevel `
                            -AlertReasons $AlertReasons))
                    }
                }
                $Reader.Close()
                $Reader.Dispose()

                Write-TriageLog "Historial PS de '$ProfileUser': $LineNum lineas analizadas"
            }
            catch {
                Write-TriageLog "Error leyendo historial PS de '$ProfileUser': $($_.Exception.Message)" -Level WARN
            }
        }
    }

    $HighCount   = ($Results | Where-Object { $_.AlertLevel -eq 'High'   }).Count
    $MediumCount = ($Results | Where-Object { $_.AlertLevel -eq 'Medium' }).Count
    Write-TriageLog "Recoleccion de actividad completada. Total: $($Results.Count) | High: $HighCount | Medium: $MediumCount"

    return $Results.ToArray()
}

function Invoke-CollectSystemInfo {

    Write-TriageLog "Modulo: Recoleccion de informacion de sistema iniciada" -Level SECTION

    # ── OS & BUILD ────────────────────────────────────────────────────────────────────────────
    Write-TriageLog "Obteniendo detalles de OS y build..."

    $OS       = $null
    $OSDetail = [PSCustomObject]@{
        Caption          = 'N/A'; Version        = 'N/A'; BuildNumber    = 'N/A'
        Architecture     = 'N/A'; InstallDate    = 'N/A'; LastBootTime   = 'N/A'
        RegisteredUser   = 'N/A'; Organization   = 'N/A'; SystemDrive    = 'N/A'
        TotalVisibleRAM  = 'N/A'; FreePhysicalRAM = 'N/A'
    }

    try {
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $OSDetail = [PSCustomObject]@{
            Caption          = $OS.Caption
            Version          = $OS.Version
            BuildNumber      = $OS.BuildNumber
            Architecture     = $OS.OSArchitecture
            # InstallDate viene como DateTime desde CIM — formatear ISO 8601
            InstallDate      = $OS.InstallDate.ToString('o')
            LastBootTime     = $OS.LastBootUpTime.ToString('o')
            RegisteredUser   = $OS.RegisteredUser
            Organization     = $OS.Organization
            SystemDrive      = $OS.SystemDrive
            TotalVisibleRAM  = "$([math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)) GB"
            FreePhysicalRAM  = "$([math]::Round($OS.FreePhysicalMemory  / 1MB, 2)) GB"
        }
    }
    catch {
        Write-TriageLog "Error obteniendo Win32_OperatingSystem: $($_.Exception.Message)" -Level WARN
    }

    # Datos del BIOS y hardware — util para correlacionar con inventario de activos
    $ComputerSystem = $null
    try {
        $CS             = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $ComputerSystem = [PSCustomObject]@{
            Manufacturer = $CS.Manufacturer
            Model        = $CS.Model
            Domain       = $CS.Domain
            PartOfDomain = $CS.PartOfDomain
            DNSHostName  = $CS.DNSHostName
            CurrentUser  = $CS.UserName
        }
    }
    catch {
        Write-TriageLog "Error obteniendo Win32_ComputerSystem: $($_.Exception.Message)" -Level WARN
        $ComputerSystem = [PSCustomObject]@{
            Manufacturer = 'N/A'; Model = 'N/A'; Domain = 'N/A'
            PartOfDomain = 'N/A'; DNSHostName = 'N/A'; CurrentUser = 'N/A'
        }
    }

    # ── HOTFIXES (ultimos 10 KBs) ────────────────────────────────────────────────────────────
    Write-TriageLog "Enumerando hotfixes instalados (ultimos 10)..."

    $Hotfixes = @()
    try {
        $Hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop |
                    Sort-Object InstalledOn -Descending |
                    Select-Object -First 10 |
                    ForEach-Object {
                        [PSCustomObject]@{
                            HotFixID    = $_.HotFixID
                            Description = $_.Description
                            InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { 'N/A' }
                            InstalledBy = $_.InstalledBy
                        }
                    }
    }
    catch {
        Write-TriageLog "Error obteniendo hotfixes: $($_.Exception.Message)" -Level WARN
    }

    # ── LOCAL ADMINISTRATORS ──────────────────────────────────────────────────────────────────
    # Enumerar via ADSI LocalGroup es mas robusto que net.exe — funciona offline y sin WMI
    Write-TriageLog "Enumerando miembros del grupo Administradores locales..."

    $LocalAdmins = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Resolver SID S-1-5-32-544 a nombre local (independiente del idioma del OS).
        # ADSI WinNT:// no acepta SIDs directamente — necesita el nombre del grupo.
        $AdminSID    = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $AdminName   = $AdminSID.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $AdminGroup  = [ADSI]"WinNT://./$AdminName,group"
        $Members     = @($AdminGroup.psbase.Invoke('Members'))

        foreach ($Member in $Members) {
            try {
                $MemberName = $Member.GetType().InvokeMember('Name', 'GetProperty', $null, $Member, $null)
                $MemberPath = $Member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $Member, $null)
                # ADsPath formato: WinNT://DOMAIN/Username — extraer origen
                $Origin     = if ($MemberPath -match 'WinNT://([^/]+)/') { $Matches[1] } else { 'Unknown' }

                $LocalAdmins.Add([PSCustomObject]@{
                    Name   = $MemberName
                    Origin = $Origin
                    Path   = $MemberPath
                })
            }
            catch {
                Write-TriageLog "Error leyendo miembro del grupo Admins: $($_.Exception.Message)" -Level WARN
            }
        }
    }
    catch {
        Write-TriageLog "Error enumerando grupo Administradores: $($_.Exception.Message)" -Level WARN
    }

    # ── ANTIVIRUS / SECURITY CENTER ───────────────────────────────────────────────────────────
    # SecurityCenter2 solo disponible en workstations (no en Server Core/DC sin rol)
    Write-TriageLog "Detectando productos de seguridad (SecurityCenter2)..."

    $AVProducts = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $AVRaw = Get-CimInstance -Namespace 'root\SecurityCenter2' `
                     -ClassName 'AntiVirusProduct' -ErrorAction Stop

        foreach ($AV in $AVRaw) {
            # productState es un DWORD que codifica estado en nibbles:
            # Bytes: [0x00][Estado Real-time][Estado Definiciones][Unused]
            # Estado real-time: 0x10 = ON, 0x00 = OFF
            # Definiciones:     0x00 = UpToDate, 0x10 = OutOfDate
            $State           = $AV.productState
            $RealTimeHex     = ($State -band 0x00F000) -shr 12
            $DefStatusHex    = ($State -band 0x000F00) -shr 8
            $RealTimeEnabled = ($RealTimeHex -eq 1)
            $DefsUpToDate    = ($DefStatusHex -ne 1)

            $AVProducts.Add([PSCustomObject]@{
                Name             = $AV.displayName
                PathToExe        = $AV.pathToSignedProductExe
                RealTimeEnabled  = $RealTimeEnabled
                DefinitionsOK    = $DefsUpToDate
                ProductStateRaw  = '0x{0:X6}' -f $State
                Timestamp        = $AV.timestamp
            })
        }
    }
    catch {
        # En Server editions SecurityCenter2 no existe — no es un error critico
        Write-TriageLog "SecurityCenter2 no disponible (normal en Server editions): $($_.Exception.Message)" -Level WARN
    }

    # ── NETWORK ADAPTERS ─────────────────────────────────────────────────────────────────────
    Write-TriageLog "Recopilando configuracion de adaptadores de red..."

    $Adapters = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Solo adaptadores activos con IP asignada — filtra loopback y tuneles
        $NetConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
                          -Filter 'IPEnabled=True' -ErrorAction Stop

        foreach ($Adapter in $NetConfigs) {
            $Adapters.Add([PSCustomObject]@{
                Description  = $Adapter.Description
                MACAddress   = $Adapter.MACAddress
                IPAddresses  = $Adapter.IPAddress  -join ', '
                SubnetMasks  = $Adapter.IPSubnet   -join ', '
                Gateways     = $Adapter.DefaultIPGateway -join ', '
                DNS          = $Adapter.DNSServerSearchOrder -join ', '
                DHCPEnabled  = $Adapter.DHCPEnabled
                DHCPServer   = $Adapter.DHCPServer
            })
        }
    }
    catch {
        Write-TriageLog "Error obteniendo adaptadores de red: $($_.Exception.Message)" -Level WARN
    }

    Write-TriageLog "Recoleccion de sistema completada."

    return [PSCustomObject]@{
        OS              = $OSDetail
        ComputerSystem  = $ComputerSystem
        Hotfixes        = $Hotfixes
        LocalAdmins     = $LocalAdmins.ToArray()
        AVProducts      = $AVProducts.ToArray()
        NetworkAdapters = $Adapters.ToArray()
    }
}
#endregion

# ============================================================
#region  GENERACION DE REPORTE
# ============================================================
function New-TriageReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$CollectedData
    )

    Write-TriageLog "Generando reporte dual (Markdown + JSON)..." -Level SECTION

    $EndTime   = Get-Date
    $Duration  = [math]::Round(($EndTime - $Script:Config.StartTime).TotalSeconds, 2)
    $MdPath    = Join-Path $Script:Config.ReportDir 'Triage-Report.md'
    $JsonPath  = Join-Path $Script:Config.ReportDir 'triage_raw.json'

    # ── HELPER: Contador de High por modulo ──────────────────────────────────────────────────
    function Get-HighCount {
        param([object[]]$Items)
        if ($null -eq $Items) { return 0 }
        return @($Items | Where-Object { $_.AlertLevel -eq 'High' }).Count
    }

    # ── HELPER: Sanitizar celdas de tabla Markdown ───────────────────────────────────────────
    # Los pipe | y saltos de linea rompen el parser de tablas MD
    function Format-MdCell {
        param([object]$Value, [int]$MaxLen = 80)
        if ($null -eq $Value) { return '-' }
        $Str = "$Value" -replace '\|', '|' -replace "`r`n|`n|`r", ' '
        if ($Str.Length -gt $MaxLen) { return $Str.Substring(0, $MaxLen - 1) + '...' }
        if ([string]::IsNullOrWhiteSpace($Str)) { return '-' }
        return $Str
    }

    # ── HELPER: Fila de tabla con badge de alerta ────────────────────────────────────────────
    function Get-AlertBadge {
        param([string]$Level)
        switch ($Level) {
            'High'    { return '[!] **HIGH**' }
            'Medium'  { return '[~] Medium'   }
            'Unknown' { return '[?] Unknown'  }
            default   { return '[+] Low'      }
        }
    }

    # ── HELPER: Tabla Markdown generica desde array de PSCustomObject ─────────────────────────
    # Genera cabecera + separador + filas automaticamente a partir de las propiedades del objeto
    function New-MdTable {
        param(
            [PSCustomObject[]]$Items,
            [string[]]$Columns,           # propiedades a incluir (en orden)
            [string[]]$Headers = $null,   # cabeceras alternativas (mismo orden que Columns)
            [int]$MaxRows     = 500,
            [int]$CellMaxLen  = 80
        )
        if ($null -eq $Items -or $Items.Count -eq 0) {
            return "_No se encontraron entradas._`n"
        }
        $Hdr = if ($Headers) { $Headers } else { $Columns }
        $Sb  = [System.Text.StringBuilder]::new()

        # Cabecera
        [void]$Sb.Append('| ')
        [void]$Sb.Append($Hdr -join ' | ')
        [void]$Sb.AppendLine(' |')

        # Separador
        [void]$Sb.Append('|')
        foreach ($H in $Hdr) { [void]$Sb.Append(' --- |') }
        [void]$Sb.AppendLine()

        # Filas (limitadas a MaxRows para no generar MD gigante)
        $Count = 0
        foreach ($Row in $Items) {
            if ($Count -ge $MaxRows) {
                [void]$Sb.AppendLine("| _... $($Items.Count - $MaxRows) entradas adicionales omitidas_ |")
                break
            }
            [void]$Sb.Append('| ')
            $Cells = foreach ($Col in $Columns) {
                Format-MdCell -Value $Row.$Col -MaxLen $CellMaxLen
            }
            [void]$Sb.Append($Cells -join ' | ')
            [void]$Sb.AppendLine(' |')
            $Count++
        }
        return $Sb.ToString()
    }

    # ── CONTADORES PARA EXECUTIVE SUMMARY ────────────────────────────────────────────────────
    $HighProc  = Get-HighCount -Items $CollectedData.Processes
    $HighNet   = Get-HighCount -Items $CollectedData.NetworkConnections
    $HighPers  = Get-HighCount -Items $CollectedData.PersistenceMechanisms
    $HighAct   = Get-HighCount -Items $CollectedData.UserActivity
    $TotalHigh = $HighProc + $HighNet + $HighPers + $HighAct

    # ── CONSTRUCCION DEL MARKDOWN ────────────────────────────────────────────────────────────
    $Md = [System.Text.StringBuilder]::new(65536)  # Pre-alloc ~64KB

    # ─────────────────────────────────────────────────────────────
    #  HEADER
    # ─────────────────────────────────────────────────────────────
    [void]$Md.AppendLine("# [TRIAGE-X] Report - ``$($Script:Config.Hostname)``")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("| Campo | Valor |")
    [void]$Md.AppendLine("| --- | --- |")
    [void]$Md.AppendLine("| **Herramienta** | Triage-X $($Script:Config.Version) |")
    [void]$Md.AppendLine("| **Analista** | $($Script:TriageContext.Analyst) |")
    [void]$Md.AppendLine("| **Hostname** | $($Script:Config.Hostname) |")
    [void]$Md.AppendLine("| **Inicio** | $($Script:Config.StartTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC |")
    [void]$Md.AppendLine("| **Fin** | $($EndTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC |")
    [void]$Md.AppendLine("| **Duracion** | ${Duration}s |")
    [void]$Md.AppendLine("| **Log** | ``$($Script:Config.LogFile)`` |")
    [void]$Md.AppendLine("| **Raw JSON** | ``$JsonPath`` |")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("---")
    [void]$Md.AppendLine()

    # ─────────────────────────────────────────────────────────────
    #  SECCION 1 — EXECUTIVE SUMMARY
    # ─────────────────────────────────────────────────────────────
    [void]$Md.AppendLine("## 1. Summary of Findings")
    [void]$Md.AppendLine()

    # Semaforo visual basado en total de alertas High
    $RiskLabel = switch ($TotalHigh) {
        { $_ -eq 0 }             { '[BAJO]  **BAJO** - Sin alertas de alta criticidad detectadas.' }
        { $_ -ge 1 -and $_ -le 4 } { '[MEDIO] **MEDIO** - Se requiere revision de los hallazgos.' }
        default                   { '[ALTO]  **ALTO** - Hallazgos criticos detectados. Accion inmediata recomendada.' }
    }
    [void]$Md.AppendLine("> $RiskLabel")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("| Modulo | Total Entradas | Alertas HIGH |")
    [void]$Md.AppendLine("| --- | --- | --- |")
    [void]$Md.AppendLine("| [01] Procesos | $(@($CollectedData.Processes).Count) | **$HighProc** |")
    [void]$Md.AppendLine("| [02] Conexiones de Red | $(@($CollectedData.NetworkConnections).Count) | **$HighNet** |")
    [void]$Md.AppendLine("| [03] Persistencia | $(@($CollectedData.PersistenceMechanisms).Count) | **$HighPers** |")
    [void]$Md.AppendLine("| [04] Actividad de Usuario | $(@($CollectedData.UserActivity).Count) | **$HighAct** |")
    [void]$Md.AppendLine("| **TOTAL** | - | **$TotalHigh** |")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("---")
    [void]$Md.AppendLine()

    # ─────────────────────────────────────────────────────────────
    #  SECCION 2 — SYSTEM CONTEXT
    # ─────────────────────────────────────────────────────────────
    [void]$Md.AppendLine("## 2. System Context")
    [void]$Md.AppendLine()

    $SI = $CollectedData.SystemInfo

    if ($null -ne $SI) {

        # OS
        [void]$Md.AppendLine("### 2.1 Operating System")
        [void]$Md.AppendLine()
        [void]$Md.AppendLine("| Campo | Valor |")
        [void]$Md.AppendLine("| --- | --- |")
        if ($SI.OS) {
            foreach ($Prop in @('Caption','Version','BuildNumber','Architecture','InstallDate','LastBootTime','TotalVisibleRAM','FreePhysicalRAM')) {
                [void]$Md.AppendLine("| $Prop | ``$(Format-MdCell $SI.OS.$Prop)`` |")
            }
        }
        if ($SI.ComputerSystem) {
            [void]$Md.AppendLine("| Manufacturer | $(Format-MdCell $SI.ComputerSystem.Manufacturer) |")
            [void]$Md.AppendLine("| Model | $(Format-MdCell $SI.ComputerSystem.Model) |")
            [void]$Md.AppendLine("| Domain | ``$(Format-MdCell $SI.ComputerSystem.Domain)`` (PartOfDomain: $($SI.ComputerSystem.PartOfDomain)) |")
            [void]$Md.AppendLine("| Current User | ``$(Format-MdCell $SI.ComputerSystem.CurrentUser)`` |")
        }
        [void]$Md.AppendLine()

        # Hotfixes
        [void]$Md.AppendLine("### 2.2 Hotfixes Recientes (ultimos 10)")
        [void]$Md.AppendLine()
        [void]$Md.Append((New-MdTable -Items $SI.Hotfixes `
            -Columns @('HotFixID','Description','InstalledOn','InstalledBy') `
            -Headers @('KB', 'Descripcion', 'Instalado', 'Por')))
        [void]$Md.AppendLine()

        # Administradores locales
        [void]$Md.AppendLine("### 2.3 Administradores Locales")
        [void]$Md.AppendLine()
        [void]$Md.Append((New-MdTable -Items $SI.LocalAdmins `
            -Columns @('Name','Origin','Path') `
            -Headers @('Cuenta', 'Origen', 'ADsPath')))
        [void]$Md.AppendLine()

        # Antivirus
        [void]$Md.AppendLine("### 2.4 Productos de Seguridad")
        [void]$Md.AppendLine()
        if ($SI.AVProducts -and $SI.AVProducts.Count -gt 0) {
            [void]$Md.Append((New-MdTable -Items $SI.AVProducts `
                -Columns @('Name','RealTimeEnabled','DefinitionsOK','ProductStateRaw','PathToExe') `
                -Headers @('Producto', 'RT Activo', 'Defs OK', 'State (hex)', 'Ejecutable')))
        } else {
            [void]$Md.AppendLine("> [!] No se detectaron productos antivirus via SecurityCenter2.")
            [void]$Md.AppendLine("> Puede ser normal en Server editions o en entornos con AV enterprise.")
            [void]$Md.AppendLine()
        }
        [void]$Md.AppendLine()

        # Adaptadores de red
        [void]$Md.AppendLine("### 2.5 Adaptadores de Red")
        [void]$Md.AppendLine()
        [void]$Md.Append((New-MdTable -Items $SI.NetworkAdapters `
            -Columns @('Description','MACAddress','IPAddresses','Gateways','DNS','DHCPEnabled') `
            -Headers @('Adaptador', 'MAC', 'IPs', 'Gateways', 'DNS', 'DHCP')))

    } else {
        [void]$Md.AppendLine("_Modulo SystemInfo no disponible._")
    }

    [void]$Md.AppendLine()
    [void]$Md.AppendLine("---")
    [void]$Md.AppendLine()

    # ─────────────────────────────────────────────────────────────
    #  SECCION 3 — HIGH RISK DETECTIONS (consolidado)
    # ─────────────────────────────────────────────────────────────
    [void]$Md.AppendLine("## 3. High Risk Detections")
    [void]$Md.AppendLine()

    if ($TotalHigh -eq 0) {
        [void]$Md.AppendLine("> [OK] No se detectaron hallazgos de alta criticidad en ninguno de los modulos.")
        [void]$Md.AppendLine()
    } else {
        [void]$Md.AppendLine("> Los siguientes hallazgos requieren revision prioritaria.")
        [void]$Md.AppendLine()

        # Consolidar todas las entradas High de todos los modulos en una tabla unica
        $AllHighFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

        $ModuleMap = @{
            'Proceso'    = $CollectedData.Processes
            'Red'        = $CollectedData.NetworkConnections
            'Persistencia' = $CollectedData.PersistenceMechanisms
            'Actividad'  = $CollectedData.UserActivity
        }

        foreach ($ModName in $ModuleMap.Keys) {
            $Items = $ModuleMap[$ModName]
            if ($null -eq $Items) { continue }
            $HighItems = @($Items | Where-Object { $_.AlertLevel -eq 'High' })

            # Red: agrupar por PID para evitar 30 filas identicas del mismo proceso
            if ($ModName -eq 'Red' -and $HighItems.Count -gt 0) {
                $NetGroups = $HighItems | Group-Object { "$($_.PID)/$($_.ProcessName)" }
                foreach ($Grp in $NetGroups) {
                    $Sample   = $Grp.Group[0]
                    $Identity = "PID $($Sample.PID) / $($Sample.ProcessName) ($($Grp.Count) conexiones)"
                    $AllHighFindings.Add([PSCustomObject]@{
                        Modulo    = $ModName
                        Identidad = (Format-MdCell $Identity 70)
                        Razones   = (Format-MdCell $Sample.AlertReasons 100)
                    })
                }
                continue
            }

            foreach ($Item in $HighItems) {
                $Identity = if ($Item.Name)        { $Item.Name }
                            elseif ($Item.PID)      { "PID $($Item.PID) / $($Item.ProcessName)" }
                            elseif ($Item.Action)   { $Item.Action }
                            else                    { '-' }

                $AllHighFindings.Add([PSCustomObject]@{
                    Modulo    = $ModName
                    Identidad = (Format-MdCell $Identity 60)
                    Razones   = (Format-MdCell $Item.AlertReasons 100)
                })
            }
        }

        [void]$Md.AppendLine("| Modulo | Identidad | Razones |")
        [void]$Md.AppendLine("| --- | --- | --- |")
        foreach ($F in $AllHighFindings) {
            [void]$Md.AppendLine("| [!] **$($F.Modulo)** | ``$($F.Identidad)`` | $($F.Razones) |")
        }
        [void]$Md.AppendLine()
    }

    [void]$Md.AppendLine("---")
    [void]$Md.AppendLine()

    # ─────────────────────────────────────────────────────────────
    #  SECCION 4 — FULL MODULE DETAILS
    # ─────────────────────────────────────────────────────────────
    [void]$Md.AppendLine("## 4. Full Module Details")
    [void]$Md.AppendLine()

    # ── 4.1 PROCESOS ─────────────────────────────────────────────
    [void]$Md.AppendLine("### 4.1 Procesos")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("<details><summary>Expandir tabla de procesos ($(@($CollectedData.Processes).Count) entradas)</summary>")
    [void]$Md.AppendLine()

    if ($CollectedData.Processes) {
        # Primero los High, luego el resto
        $SortedProcs = @($CollectedData.Processes | Sort-Object { if ($_.AlertLevel -eq 'High') { 0 } else { 1 } }, Name)
        [void]$Md.AppendLine("| Alert | PID | PPID | Nombre | Firma | SHA256 | Razones |")
        [void]$Md.AppendLine("| --- | --- | --- | --- | --- | --- | --- |")
        $ProcCount = 0
        foreach ($P in $SortedProcs) {
            if ($ProcCount -ge 300) {
                [void]$Md.AppendLine("| _... $($SortedProcs.Count - 300) filas omitidas_ | | | | | | |")
                break
            }
            $Badge  = Get-AlertBadge $P.AlertLevel
            $Hash   = if ($P.SHA256 -and $P.SHA256.Length -eq 64) { "``$($P.SHA256)``" } else { Format-MdCell $P.SHA256 20 }
            [void]$Md.AppendLine("| $Badge | $($P.PID) | $($P.PPID) | ``$(Format-MdCell $P.Name)`` | $(Format-MdCell $P.SignatureStatus) | $Hash | $(Format-MdCell $P.AlertReasons 80) |")
            $ProcCount++
        }
    }
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("</details>")
    [void]$Md.AppendLine()

    # ── 4.2 RED ──────────────────────────────────────────────────
    [void]$Md.AppendLine("### 4.2 Conexiones de Red")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("<details><summary>Expandir tabla de red ($(@($CollectedData.NetworkConnections).Count) entradas)</summary>")
    [void]$Md.AppendLine()

    if ($CollectedData.NetworkConnections) {
        $SortedNet = @($CollectedData.NetworkConnections | Sort-Object { if ($_.AlertLevel -eq 'High') { 0 } else { 1 } })
        [void]$Md.AppendLine("| Alert | Proto | Local | Puerto L | Remoto | Puerto R | Estado | Proceso | IP Publica |")
        [void]$Md.AppendLine("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        foreach ($C in $SortedNet) {
            $Badge = Get-AlertBadge $C.AlertLevel
            [void]$Md.AppendLine("| $Badge | $($C.Protocol) | ``$($C.LocalAddress)`` | $($C.LocalPort) | ``$(Format-MdCell $C.RemoteAddress)`` | $($C.RemotePort) | $($C.State) | ``$(Format-MdCell $C.ProcessName)`` | $($C.IsPublicIP) |")
        }
    }
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("</details>")
    [void]$Md.AppendLine()

    # ── 4.3 PERSISTENCIA ─────────────────────────────────────────
    [void]$Md.AppendLine("### 4.3 Mecanismos de Persistencia")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("<details><summary>Expandir tabla de persistencia ($(@($CollectedData.PersistenceMechanisms).Count) entradas)</summary>")
    [void]$Md.AppendLine()

    if ($CollectedData.PersistenceMechanisms) {
        $SortedPers = @($CollectedData.PersistenceMechanisms | Sort-Object { if ($_.AlertLevel -eq 'High') { 0 } else { 1 } })
        [void]$Md.AppendLine("| Alert | Tipo | Nombre | Firma | Razones |")
        [void]$Md.AppendLine("| --- | --- | --- | --- | --- |")
        foreach ($Pe in $SortedPers) {
            $Badge = Get-AlertBadge $Pe.AlertLevel
            [void]$Md.AppendLine("| $Badge | $(Format-MdCell $Pe.Type) | ``$(Format-MdCell $Pe.Name 50)`` | $(Format-MdCell $Pe.SignatureStatus) | $(Format-MdCell $Pe.AlertReasons 90) |")
        }
        [void]$Md.AppendLine()

        # Bloque de detalle de comandos para los High — en code block para legibilidad
        $HighPers = @($SortedPers | Where-Object { $_.AlertLevel -eq 'High' })
        if ($HighPers.Count -gt 0) {
            [void]$Md.AppendLine("#### Comandos de entradas HIGH")
            [void]$Md.AppendLine()
            foreach ($Pe in $HighPers) {
                [void]$Md.AppendLine("**``$($Pe.Name)``** (`$($Pe.Type)`)")
                [void]$Md.AppendLine('```')
                $CmdClean = $Pe.Command -replace "`r`n|`n", ' '
                [void]$Md.AppendLine($CmdClean)
                [void]$Md.AppendLine('```')
                [void]$Md.AppendLine()
            }
        }
    }
    [void]$Md.AppendLine("</details>")
    [void]$Md.AppendLine()

    # ── 4.4 ACTIVIDAD DE USUARIO ─────────────────────────────────
    [void]$Md.AppendLine("### 4.4 Actividad de Usuario")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("<details><summary>Expandir tabla de actividad ($(@($CollectedData.UserActivity).Count) entradas)</summary>")
    [void]$Md.AppendLine()

    if ($CollectedData.UserActivity) {
        $SortedAct = @($CollectedData.UserActivity | Sort-Object { if ($_.AlertLevel -eq 'High') { 0 } elseif ($_.AlertLevel -eq 'Medium') { 1 } else { 2 } }, Timestamp -Descending)
        [void]$Md.AppendLine("| Alert | Categoria | Usuario | Timestamp | Accion |")
        [void]$Md.AppendLine("| --- | --- | --- | --- | --- |")
        $ActCount = 0
        foreach ($A in $SortedAct) {
            if ($ActCount -ge 200) {
                [void]$Md.AppendLine("| _... $($SortedAct.Count - 200) filas omitidas_ | | | | |")
                break
            }
            $Badge = Get-AlertBadge $A.AlertLevel
            [void]$Md.AppendLine("| $Badge | $(Format-MdCell $A.Category) | ``$(Format-MdCell $A.User)`` | $(Format-MdCell $A.Timestamp 20) | $(Format-MdCell $A.Action 70) |")
            $ActCount++
        }
    }
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("</details>")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("---")
    [void]$Md.AppendLine()
    [void]$Md.AppendLine("_Generado por Triage-X $($Script:Config.Version) - $($EndTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC_")

    # ── ESCRITURA A DISCO ─────────────────────────────────────────────────────────────────────
    # StreamWriter con UTF8 sin BOM — maxima compatibilidad con herramientas Unix y SIEMs
    $Sw = $null
    try {
        $Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        $Sw        = [System.IO.StreamWriter]::new($MdPath, $false, $Utf8NoBom)
        $Sw.Write($Md.ToString())
    }
    finally {
        # Garantizar cierre aunque haya excepcion — evita bloqueo del archivo
        if ($null -ne $Sw) { $Sw.Close(); $Sw.Dispose() }
    }

    Write-TriageLog "Reporte Markdown: $MdPath"

    # ── JSON RAW DATA ─────────────────────────────────────────────────────────────────────────
    $SwJson = $null
    try {
        $RawReport = [PSCustomObject]@{
            Metadata  = $Script:TriageContext
            EndTime   = $EndTime.ToString('o')
            Duration  = "${Duration}s"
            Findings  = $CollectedData
        }
        $Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        $SwJson    = [System.IO.StreamWriter]::new($JsonPath, $false, $Utf8NoBom)
        $SwJson.Write(($RawReport | ConvertTo-Json -Depth 12 -Compress:$false))
    }
    finally {
        if ($null -ne $SwJson) { $SwJson.Close(); $SwJson.Dispose() }
    }

    Write-TriageLog "Raw JSON: $JsonPath"

    return [PSCustomObject]@{
        MarkdownReport = $MdPath
        JsonRaw        = $JsonPath
    }
}
#endregion

# ============================================================
#region  MAIN
# ============================================================
function Main {
    Show-Banner

    try {
        # --- FASE 1: Inicializacion ---
        Initialize-Environment

        # --- FASE 2: Recoleccion ---
        Write-TriageLog "Iniciando recoleccion forense..." -Level SECTION

        # Red necesita el snapshot de procesos para correlacion PID -> IsSuspicious
        $ProcResults = Invoke-CollectProcesses
        $NetResults  = Invoke-CollectNetworkConnections -ProcessResults $ProcResults

        $CollectedData = [PSCustomObject]@{
            Processes             = $ProcResults
            NetworkConnections    = $NetResults
            PersistenceMechanisms = Invoke-CollectPersistenceMechanisms
            UserActivity          = Invoke-CollectUserActivity
            SystemInfo            = Invoke-CollectSystemInfo
        }

        # --- FASE 3: Reporte ---
        $Report = New-TriageReport -CollectedData $CollectedData

        Write-TriageLog "Triage completado." -Level SECTION
        Write-TriageLog "  Markdown : $($Report.MarkdownReport)"
        Write-TriageLog "  JSON Raw : $($Report.JsonRaw)"
        Write-TriageLog "  Log      : $($Script:Config.LogFile)"
        Write-TriageLog "Duracion total: $([math]::Round(((Get-Date) - $Script:Config.StartTime).TotalSeconds, 2))s"
    }
    catch {
        Write-TriageLog "Error critico en ejecucion principal: $($_.Exception.Message)" -Level ERROR
        Write-TriageLog "StackTrace: $($_.ScriptStackTrace)" -Level ERROR
        exit 1
    }
}

# Entry point
Main
#endregion
