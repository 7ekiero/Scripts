#Requires -Version 5.1
<#
.SYNOPSIS
    RegSweep-X — Forensic Registry & Event Collection Framework
    Versión completa: Fases 1-4 ensambladas.

.DESCRIPTION
    Recolección forense para Windows 10/11. Sin dependencias externas.
    Solo cmdlets integrados y .NET Base Class Library.

    Vectores cubiertos:
      1. BAM/DAM     — Evidencia de ejecución de binarios por SID
      2. LSA/SSP     — Paquetes de autenticación (detección de credential theft)
      3. IFEO        — Image File Execution Options hijacking (T1546.012)
      4. RDP         — Historial de conexiones salientes (movimiento lateral)
      5. USB/USBSTOR — Dispositivos de almacenamiento + timeline setupapi
      6. Events      — Borrado de logs, servicios sospechosos, ScriptBlock malicioso

    Salida: directorio RegSweepX_<HOST>_<TIMESTAMP> bajo $OutputRoot con:
      - RegSweepX.log             (log completo de la sesion)
      - RegSweepX_Results.json    (datos estructurados)
      - RegSweepX_Report.md       (reporte Markdown para el analista)

.PARAMETER OutputRoot
    Directorio padre donde se creara la carpeta de salida. Por defecto $env:TEMP.

.PARAMETER ConsoleLevel
    Nivel minimo de log mostrado en consola: DEBUG | INFO | WARN | ERROR.
    El archivo .log siempre recibe todos los niveles.

.EXAMPLE
    # Ejecucion estandar (requiere consola elevada)
    .\RegSweep-X.ps1

.EXAMPLE
    # Modo verbose completo
    .\RegSweep-X.ps1 -ConsoleLevel DEBUG

.EXAMPLE
    # Capturar el objeto de retorno para inspeccion posterior
    $result = .\RegSweep-X.ps1
    $result.Data['USB'] | Format-Table -AutoSize
    explorer $result.OutputDir

.NOTES
    Version  : 1.0.0
    Autor    : IR Senior Engineer
    Requiere : Windows 10/11, PowerShell 5.1+, privilegios de Administrador
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$OutputRoot = $env:TEMP,

    [Parameter()]
    [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
    [string]$ConsoleLevel = 'INFO'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
# REGION 1 - CONTROL DE PRIVILEGIOS
# =============================================================================
#region Privilege Check

function Assert-AdminPrivilege {
    <#
    .SYNOPSIS
        Verifica privilegios de Administrador. Detiene ejecucion si no esta elevado.
        Sin bypass de UAC.
    #>
    [CmdletBinding()]
    param()

    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        $msg = '[RegSweep-X] ACCESO DENEGADO - Se requieren privilegios de Administrador. ' +
               'Ejecuta la consola como Administrador y vuelve a lanzar el script.'
        Write-Error -Message $msg -Category PermissionDenied -ErrorAction Stop
        throw $msg
    }

    Write-Verbose '[Assert-AdminPrivilege] Privilegios de Administrador confirmados.'
}

#endregion

# =============================================================================
# REGION 2 - ESTRUCTURA DE DIRECTORIOS
# =============================================================================
#region Directory Setup

function New-SweepOutputDirectory {
    <#
    .SYNOPSIS
        Crea el directorio de salida unico: RegSweepX_<HOSTNAME>_<YYYYMMDD_HHmmss>
    .OUTPUTS
        [string] Ruta absoluta del directorio creado.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Root
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $hostname  = $env:COMPUTERNAME.ToUpper()
    $dirName   = 'RegSweepX_{0}_{1}' -f $hostname, $timestamp
    $fullPath  = Join-Path -Path $Root -ChildPath $dirName

    if ($PSCmdlet.ShouldProcess($fullPath, 'Crear directorio de salida')) {
        $null = New-Item -Path $fullPath -ItemType Directory -Force
    }

    return $fullPath
}

#endregion

# =============================================================================
# REGION 3 - MOTOR DE LOGGING
# =============================================================================
#region Logging Engine

$Script:LevelColors = @{ DEBUG = 'Cyan'; INFO = 'White'; WARN = 'Yellow'; ERROR = 'Red' }
$Script:LevelOrder  = @{ DEBUG = 0; INFO = 1; WARN = 2; ERROR = 3 }
$Script:LogFilePath = $null   # Se asigna en Main tras crear el directorio

function Write-SweepLog {
    <#
    .SYNOPSIS
        Escribe simultaneamente en consola (filtrado por ConsoleLevel) y en archivo .log
        (siempre). Nunca falla en silencio: si el disco falla, avisa por consola.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO',

        [Parameter()]
        [string]$Component = 'RegSweep-X'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $entry     = '[{0}] [{1,-5}] [{2}] {3}' -f $timestamp, $Level, $Component, $Message

    if ($Script:LogFilePath) {
        try   { Add-Content -Path $Script:LogFilePath -Value $entry -Encoding UTF8 }
        catch { Write-Warning "Write-SweepLog: No se pudo escribir en '$Script:LogFilePath'. $_" }
    }

    if ($Script:LevelOrder[$Level] -ge $Script:LevelOrder[$ConsoleLevel]) {
        Write-Host $entry -ForegroundColor $Script:LevelColors[$Level]
    }
}

#endregion

# =============================================================================
# REGION 4 - MOTOR DE EXPORTACION JSON
# =============================================================================
#region Export JSON

function Export-SweepJson {
    <#
    .SYNOPSIS
        Serializa $CollectedData a RegSweepX_Results.json con ConvertTo-Json -Depth 10.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [hashtable]$Data,
        [Parameter(Mandatory)] [string]$OutputDir,
        [Parameter()]          [switch]$Compress
    )

    $jsonFile = Join-Path -Path $OutputDir -ChildPath 'RegSweepX_Results.json'
    Write-SweepLog -Message "Exportando JSON -> '$jsonFile'" -Level INFO -Component 'Export-Json'

    try {
        $params = @{ InputObject = $Data; Depth = 10 }
        if ($Compress) { $params['Compress'] = $true }
        $jsonContent = ConvertTo-Json @params

        if ($PSCmdlet.ShouldProcess($jsonFile, 'Escribir archivo JSON')) {
            [System.IO.File]::WriteAllText($jsonFile, $jsonContent, [System.Text.Encoding]::UTF8)
        }
        Write-SweepLog -Message 'JSON exportado correctamente.' -Level INFO -Component 'Export-Json'
    }
    catch {
        Write-SweepLog -Message "ERROR al exportar JSON: $_" -Level ERROR -Component 'Export-Json'
        throw
    }

    return $jsonFile
}

#endregion

# =============================================================================
# REGION 5 - VECTORES DE RECOLECCION (FASES 2, 3 y 4)
# =============================================================================
#region Collection Vectors

# -----------------------------------------------------------------------------
# VECTOR 1 - BAM/DAM
# -----------------------------------------------------------------------------
function Get-SweepBAM {
    <#
    .SYNOPSIS
        Extrae artefactos BAM/DAM. Evidencia de ejecucion por SID con timestamp FILETIME.
    .OUTPUTS
        [PSCustomObject[]] SID | ExecutablePath | LastRunUTC | TimestampRaw | Source
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $bamRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'

    Write-SweepLog -Message 'Iniciando recoleccion BAM/DAM.' -Level INFO -Component 'Get-SweepBAM'

    if (-not (Test-Path $bamRoot)) {
        Write-SweepLog -Message "Ruta BAM no encontrada: '$bamRoot'. Puede ser build antigua (pre-1709)." `
                       -Level WARN -Component 'Get-SweepBAM'
        return $results.ToArray()
    }

    try   { $sidKeys = Get-ChildItem -Path $bamRoot -ErrorAction Stop }
    catch {
        Write-SweepLog -Message "Error enumerando subclaves BAM: $_" -Level ERROR -Component 'Get-SweepBAM'
        return $results.ToArray()
    }

    foreach ($sidKey in $sidKeys) {
        $sid = $sidKey.PSChildName

        try   { $values = Get-ItemProperty -Path $sidKey.PSPath -ErrorAction Stop }
        catch {
            Write-SweepLog -Message "Error leyendo SID '$sid': $_" -Level DEBUG -Component 'Get-SweepBAM'
            continue
        }

        foreach ($valueName in $values.PSObject.Properties.Name) {
            if ($valueName -match '^PS(Path|ParentPath|ChildName|Provider|Drive)$') { continue }

            $rawData = $values.$valueName

            if ($rawData -isnot [byte[]]) {
                Write-SweepLog -Message "Valor '$valueName' no es binario ($($rawData.GetType().Name)). Omitido." `
                               -Level DEBUG -Component 'Get-SweepBAM'
                continue
            }

            $lastRunUTC   = $null
            $timestampRaw = ($rawData | ForEach-Object { $_.ToString('X2') }) -join ' '

            try {
                if ($rawData.Length -ge 8) {
                    $fileTimeLong = [System.BitConverter]::ToInt64($rawData[0..7], 0)
                    if ($fileTimeLong -gt 0) {
                        $lastRunUTC = [System.DateTime]::FromFileTimeUtc($fileTimeLong)
                    }
                }
            }
            catch {
                Write-SweepLog -Message "Error parseando FILETIME para '$valueName': $_" `
                               -Level DEBUG -Component 'Get-SweepBAM'
            }

            $results.Add([PSCustomObject]@{
                SID            = $sid
                ExecutablePath = $valueName
                LastRunUTC     = $lastRunUTC
                TimestampRaw   = $timestampRaw
                Source         = $sidKey.PSPath
            })
        }
    }

    Write-SweepLog -Message "BAM/DAM: $($results.Count) entradas recolectadas." -Level INFO -Component 'Get-SweepBAM'
    return $results.ToArray()
}


# -----------------------------------------------------------------------------
# VECTOR 2 - LSA / SSP
# -----------------------------------------------------------------------------
function Get-SweepLSA {
    <#
    .SYNOPSIS
        Extrae paquetes de autenticacion LSA. Cualquier paquete no estandar =
        indicador critico de persistencia o credential theft (T1556.002).
    .OUTPUTS
        [PSCustomObject[]] ValueName | Package | IsKnownDefault | Source
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    $knownDefaults = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    @(
        'msv1_0','kerberos','wdigest','tspkg','pku2u','cloudap',
        'negoexts','schannel','negotiate','ntlm','lsasrv',
        'rassfm','msnsspc','msapsspc',''
    ) | ForEach-Object { $null = $knownDefaults.Add($_) }

    $targetValues = @('Authentication Packages', 'Security Packages', 'Notification Packages')

    Write-SweepLog -Message 'Iniciando recoleccion LSA/SSP.' -Level INFO -Component 'Get-SweepLSA'

    if (-not (Test-Path $lsaPath)) {
        Write-SweepLog -Message "Ruta LSA no encontrada: '$lsaPath'." -Level ERROR -Component 'Get-SweepLSA'
        return $results.ToArray()
    }

    foreach ($valueName in $targetValues) {
        try   { $raw = Get-ItemPropertyValue -Path $lsaPath -Name $valueName -ErrorAction Stop }
        catch {
            Write-SweepLog -Message "Valor LSA '$valueName' no encontrado: $_" `
                           -Level DEBUG -Component 'Get-SweepLSA'
            continue
        }

        $packages = @($raw) | Where-Object { $_ -ne $null } |
                    ForEach-Object { $_.Trim() } |
                    Where-Object   { $_ -ne '' }

        foreach ($pkg in $packages) {
            $isKnown = $knownDefaults.Contains($pkg)

            if (-not $isKnown) {
                Write-SweepLog -Message "[!] Paquete LSA NO ESTANDAR -> '$pkg' en '$valueName'." `
                               -Level WARN -Component 'Get-SweepLSA'
            }

            $results.Add([PSCustomObject]@{
                ValueName      = $valueName
                Package        = $pkg
                IsKnownDefault = $isKnown
                Source         = "$lsaPath\$valueName"
            })
        }
    }

    Write-SweepLog -Message "LSA/SSP: $($results.Count) paquetes recolectados." -Level INFO -Component 'Get-SweepLSA'
    return $results.ToArray()
}


# -----------------------------------------------------------------------------
# VECTOR 3 - IFEO Hijacking
# -----------------------------------------------------------------------------
function Get-SweepIFEO {
    <#
    .SYNOPSIS
        Busca entradas IFEO con 'Debugger' o 'MonitorProcess' (T1546.012).
        Cualquier resultado es sospechoso por definicion.
    .OUTPUTS
        [PSCustomObject[]] ImageName | ValueName | HandlerPath | Source
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $results         = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ifeoRoot        = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $suspiciousValues = @('Debugger', 'MonitorProcess')

    Write-SweepLog -Message 'Iniciando recoleccion IFEO.' -Level INFO -Component 'Get-SweepIFEO'

    if (-not (Test-Path $ifeoRoot)) {
        Write-SweepLog -Message "Ruta IFEO no encontrada: '$ifeoRoot'." -Level WARN -Component 'Get-SweepIFEO'
        return $results.ToArray()
    }

    try   { $imageKeys = Get-ChildItem -Path $ifeoRoot -ErrorAction Stop }
    catch {
        Write-SweepLog -Message "Error enumerando IFEO: $_" -Level ERROR -Component 'Get-SweepIFEO'
        return $results.ToArray()
    }

    foreach ($imageKey in $imageKeys) {
        $imageName = $imageKey.PSChildName

        foreach ($valueName in $suspiciousValues) {
            try   { $handler = Get-ItemPropertyValue -Path $imageKey.PSPath -Name $valueName -ErrorAction Stop }
            catch {
                Write-SweepLog -Message "IFEO '$imageName': '$valueName' no presente." `
                               -Level DEBUG -Component 'Get-SweepIFEO'
                continue
            }

            Write-SweepLog -Message "[!] IFEO hijack -> '$imageName' :: $valueName = '$handler'" `
                           -Level WARN -Component 'Get-SweepIFEO'

            $results.Add([PSCustomObject]@{
                ImageName   = $imageName
                ValueName   = $valueName
                HandlerPath = $handler
                Source      = $imageKey.PSPath
            })
        }
    }

    Write-SweepLog -Message "IFEO: $($results.Count) entradas sospechosas encontradas." -Level INFO -Component 'Get-SweepIFEO'
    return $results.ToArray()
}


# -----------------------------------------------------------------------------
# VECTOR 4 - RDP Saliente
# -----------------------------------------------------------------------------

function _Get-RDPFromHive {
    <#
    .SYNOPSIS
        Helper interno. Extrae artefactos RDP de un PSDrive de registro dado.
        No llamar directamente - usar Get-SweepRDP.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$HiveDrive,
        [Parameter(Mandatory)] [string]$UserIdentifier
    )

    $rdpResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $tsRoot     = "${HiveDrive}:\Software\Microsoft\Terminal Server Client"

    if (-not (Test-Path $tsRoot)) {
        Write-SweepLog -Message "RDP: ruta TS Client no encontrada para '$UserIdentifier'." `
                       -Level DEBUG -Component 'Get-SweepRDP'
        return $rdpResults.ToArray()
    }

    # MRU (Default\MRU0..MRUn)
    $defaultPath = "$tsRoot\Default"
    if (Test-Path $defaultPath) {
        try {
            $mruProps = Get-ItemProperty -Path $defaultPath -ErrorAction Stop
            foreach ($prop in $mruProps.PSObject.Properties) {
                if ($prop.Name -match '^PS')      { continue }
                if ($prop.Name -match '^MRU\d+$') {
                    $rdpResults.Add([PSCustomObject]@{
                        User         = $UserIdentifier
                        RecordType   = 'MRU'
                        HostOrIP     = $prop.Value
                        MRUPosition  = $prop.Name
                        UsernameHint = $null
                        Source       = $defaultPath
                    })
                }
            }
        }
        catch {
            Write-SweepLog -Message "RDP MRU error para '$UserIdentifier': $_" -Level DEBUG -Component 'Get-SweepRDP'
        }
    }

    # Servers (<hostname>\UsernameHint)
    $serversPath = "$tsRoot\Servers"
    if (Test-Path $serversPath) {
        try {
            $serverKeys = Get-ChildItem -Path $serversPath -ErrorAction Stop
            foreach ($srvKey in $serverKeys) {
                $hostname     = $srvKey.PSChildName
                $usernameHint = $null
                try {
                    $usernameHint = Get-ItemPropertyValue -Path $srvKey.PSPath `
                                                          -Name 'UsernameHint' -ErrorAction Stop
                }
                catch {
                    Write-SweepLog -Message "RDP: sin UsernameHint para '$hostname'." `
                                   -Level DEBUG -Component 'Get-SweepRDP'
                }

                $rdpResults.Add([PSCustomObject]@{
                    User         = $UserIdentifier
                    RecordType   = 'Server'
                    HostOrIP     = $hostname
                    MRUPosition  = $null
                    UsernameHint = $usernameHint
                    Source       = $srvKey.PSPath
                })
            }
        }
        catch {
            Write-SweepLog -Message "RDP Servers error para '$UserIdentifier': $_" -Level DEBUG -Component 'Get-SweepRDP'
        }
    }

    return $rdpResults.ToArray()
}


function Get-SweepRDP {
    <#
    .SYNOPSIS
        Extrae historial de conexiones RDP salientes para todos los usuarios.
        Estrategia de tres capas: HKCU -> HKU (hive activo) -> reg.exe load (hive offline).
    .OUTPUTS
        [PSCustomObject[]] User | RecordType | HostOrIP | MRUPosition | UsernameHint | Source
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-SweepLog -Message 'Iniciando recoleccion RDP saliente.' -Level INFO -Component 'Get-SweepRDP'

    # A. Usuario actual (HKCU)
    Write-SweepLog -Message "RDP: procesando usuario actual '$env:USERNAME' via HKCU." `
                   -Level DEBUG -Component 'Get-SweepRDP'
    try {
        $null = New-PSDrive -Name 'HKCU_RDP' -PSProvider Registry -Root 'HKCU:\' -Scope Local -ErrorAction Stop
        _Get-RDPFromHive -HiveDrive 'HKCU_RDP' -UserIdentifier $env:USERNAME |
            ForEach-Object { $results.Add($_) }
    }
    catch {
        Write-SweepLog -Message "Error leyendo HKCU para RDP: $_" -Level WARN -Component 'Get-SweepRDP'
    }
    finally {
        if (Get-PSDrive -Name 'HKCU_RDP' -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name 'HKCU_RDP' -Force -ErrorAction SilentlyContinue
        }
    }

    # B. Otros usuarios
    $usersRoot = 'C:\Users'
    if (-not (Test-Path $usersRoot)) {
        Write-SweepLog -Message "RDP: '$usersRoot' no encontrado. Omitiendo perfiles adicionales." `
                       -Level WARN -Component 'Get-SweepRDP'
        return $results.ToArray()
    }

    try {
        $userProfiles = Get-ChildItem -Path $usersRoot -Directory -ErrorAction Stop |
                        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    }
    catch {
        Write-SweepLog -Message "Error enumerando perfiles en '$usersRoot': $_" -Level WARN -Component 'Get-SweepRDP'
        return $results.ToArray()
    }

    # Asegurar PSDrive HKU
    if (-not (Get-PSDrive -Name 'HKU' -ErrorAction SilentlyContinue)) {
        try {
            $null = New-PSDrive -Name 'HKU' -PSProvider Registry -Root 'HKEY_USERS' -Scope Script -ErrorAction Stop
        }
        catch {
            Write-SweepLog -Message "RDP: no se pudo montar HKU: $_. Continuando solo con HKCU." `
                           -Level WARN -Component 'Get-SweepRDP'
            return $results.ToArray()
        }
    }

    foreach ($profile in $userProfiles) {
        if ($profile.Name -ieq $env:USERNAME) { continue }

        $ntUserDat   = Join-Path $profile.FullName 'NTUSER.DAT'
        $driveName   = 'REGSWEEP_' + ($profile.Name -replace '[^A-Za-z0-9]', '_')
        $hiveMounted = $false

        if (-not (Test-Path $ntUserDat)) {
            Write-SweepLog -Message "RDP: NTUSER.DAT no encontrado para '$($profile.Name)'." `
                           -Level DEBUG -Component 'Get-SweepRDP'
            continue
        }

        # Intento 1: hive ya montado por el SO en HKU
        $sidLoaded = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue |
                     Where-Object {
                         $_.PSChildName -notmatch '_Classes$' -and
                         (Test-Path "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders") -and
                         ((Get-ItemPropertyValue "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" `
                                                 -Name 'Desktop' -ErrorAction SilentlyContinue) -like "*$($profile.Name)*")
                     } | Select-Object -First 1 -ExpandProperty PSChildName

        if ($sidLoaded) {
            Write-SweepLog -Message "RDP: '$($profile.Name)' (SID $sidLoaded) ya en HKU." `
                           -Level DEBUG -Component 'Get-SweepRDP'
            try {
                $null = New-PSDrive -Name $driveName -PSProvider Registry `
                                    -Root "HKEY_USERS\$sidLoaded" -Scope Local -ErrorAction Stop
                _Get-RDPFromHive -HiveDrive $driveName -UserIdentifier $profile.Name |
                    ForEach-Object { $results.Add($_) }
            }
            catch {
                Write-SweepLog -Message "RDP: error leyendo HKU\$sidLoaded para '$($profile.Name)': $_" `
                               -Level DEBUG -Component 'Get-SweepRDP'
            }
            finally {
                if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
                    Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
                }
            }
            continue
        }

        # Intento 2: reg.exe load (hive offline)
        try {
            Write-SweepLog -Message "RDP: montando hive offline para '$($profile.Name)'." `
                           -Level DEBUG -Component 'Get-SweepRDP'

            $regLoadOutput = & reg.exe load "HKU\$driveName" $ntUserDat 2>&1
            if ($LASTEXITCODE -ne 0) { throw "reg.exe load fallo (exit $LASTEXITCODE): $regLoadOutput" }
            $hiveMounted = $true

            $null = New-PSDrive -Name $driveName -PSProvider Registry `
                                -Root "HKEY_USERS\$driveName" -Scope Local -ErrorAction Stop

            _Get-RDPFromHive -HiveDrive $driveName -UserIdentifier $profile.Name |
                ForEach-Object { $results.Add($_) }
        }
        catch {
            Write-SweepLog -Message "RDP: no se pudo procesar '$($profile.Name)': $_" `
                           -Level WARN -Component 'Get-SweepRDP'
        }
        finally {
            if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
                Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            }
            if ($hiveMounted) {
                # Forzar GC para liberar handles .NET antes del unload
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()

                $regUnloadOutput = & reg.exe unload "HKU\$driveName" 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Write-SweepLog -Message "RDP: unload fallo para '$($profile.Name)' (exit $LASTEXITCODE): $regUnloadOutput" `
                                   -Level WARN -Component 'Get-SweepRDP'
                }
                else {
                    Write-SweepLog -Message "RDP: hive '$($profile.Name)' desmontado." `
                                   -Level DEBUG -Component 'Get-SweepRDP'
                }
            }
        }
    }

    Write-SweepLog -Message "RDP: $($results.Count) entradas totales recolectadas." -Level INFO -Component 'Get-SweepRDP'
    return $results.ToArray()
}


# -----------------------------------------------------------------------------
# VECTOR 5 - USB & Storage
# -----------------------------------------------------------------------------

function _Get-SetupApiTimestamp {
    <#
    .SYNOPSIS
        Busca el timestamp de primera instalacion de un Device ID en setupapi.dev.log.
        Usa StreamReader linea a linea: nunca carga el archivo completo en memoria.
        Detecta BOM automaticamente (UTF-16 LE en Win10/11, UTF-8 en builds antiguas).
    #>
    [CmdletBinding()]
    [OutputType([nullable[datetime]])]
    param(
        [Parameter(Mandatory)] [string]$LogPath,
        [Parameter(Mandatory)] [string]$DeviceId
    )

    $reader = $null
    try {
        $reader = [System.IO.StreamReader]::new(
            $LogPath,
            [System.Text.Encoding]::Unicode,
            $true,    # detectBOM
            65536     # buffer 64 KB
        )

        $devicePattern = [System.Text.RegularExpressions.Regex]::new(
            [System.Text.RegularExpressions.Regex]::Escape($DeviceId),
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        # Patron: ">>> Section start 2024/03/15 14:32:11.456"
        $timestampPattern = [System.Text.RegularExpressions.Regex]::new(
            '>>>\s+Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )

        $prevLineMatched = $false

        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()

            if ($prevLineMatched) {
                $tsMatch = $timestampPattern.Match($line)
                if ($tsMatch.Success) {
                    $dateStr = $tsMatch.Groups[1].Value
                    try {
                        return [datetime]::ParseExact(
                            $dateStr, 'yyyy/MM/dd HH:mm:ss',
                            [System.Globalization.CultureInfo]::InvariantCulture
                        )
                    }
                    catch {
                        Write-SweepLog -Message "SetupAPI: error parseando fecha '$dateStr': $_" `
                                       -Level DEBUG -Component '_Get-SetupApiTimestamp'
                        return $null
                    }
                }
                $prevLineMatched = $false
            }

            if ($devicePattern.IsMatch($line)) { $prevLineMatched = $true }
        }
    }
    catch { throw }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }

    return $null
}


function _Get-USBFriendlyName {
    <#
    .SYNOPSIS
        Recupera FriendlyName desde Windows Portable Devices cruzando por serial.
        Best-effort: devuelve $null si no encuentra nada.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]$SerialNumber
    )

    $wpdRoot = 'HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices'
    if (-not (Test-Path $wpdRoot)) { return $null }

    try {
        $matchKey = Get-ChildItem -Path $wpdRoot -ErrorAction Stop |
                    Where-Object { $_.PSChildName -like "*$SerialNumber*" } |
                    Select-Object -First 1

        if ($null -eq $matchKey) { return $null }

        return Get-ItemPropertyValue -Path $matchKey.PSPath -Name 'FriendlyName' -ErrorAction Stop
    }
    catch {
        Write-SweepLog -Message "WPD FriendlyName: error para '$SerialNumber': $_" `
                       -Level DEBUG -Component '_Get-USBFriendlyName'
        return $null
    }
}


function Get-SweepUSB {
    <#
    .SYNOPSIS
        Enumera dispositivos USB de almacenamiento masivo (USBSTOR) con:
        Vendor/Product/Revision/Serial (Registro), FirstSeenUTC (setupapi, StreamReader),
        FriendlyName (WPD, best-effort), ParentIdPrefix (para correlacion futura).
    .OUTPUTS
        [PSCustomObject[]] Vendor|Product|Revision|SerialNumber|SerialRaw|HasRealSerial|
                           ParentIdPrefix|FriendlyName|FirstSeenUTC|SetupApiFound|Source
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $results     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $usbStorRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    $setupApiLog = 'C:\Windows\INF\setupapi.dev.log'

    Write-SweepLog -Message 'Iniciando recoleccion USB/USBSTOR.' -Level INFO -Component 'Get-SweepUSB'

    if (-not (Test-Path $usbStorRoot)) {
        Write-SweepLog -Message 'USBSTOR: ruta no encontrada. Sin historial USB.' `
                       -Level WARN -Component 'Get-SweepUSB'
        return $results.ToArray()
    }

    $setupApiAvailable = $false
    if (Test-Path $setupApiLog) {
        $logSizeMB = [math]::Round((Get-Item $setupApiLog).Length / 1MB, 1)
        Write-SweepLog -Message "setupapi.dev.log encontrado (${logSizeMB} MB). Usando StreamReader." `
                       -Level INFO -Component 'Get-SweepUSB'
        $setupApiAvailable = $true
    }
    else {
        Write-SweepLog -Message 'setupapi.dev.log no accesible. FirstSeenUTC quedara null.' `
                       -Level WARN -Component 'Get-SweepUSB'
    }

    try   { $deviceClasses = Get-ChildItem -Path $usbStorRoot -ErrorAction Stop }
    catch {
        Write-SweepLog -Message "USBSTOR: error enumerando clases: $_" -Level ERROR -Component 'Get-SweepUSB'
        return $results.ToArray()
    }

    foreach ($classKey in $deviceClasses) {
        # Solo clases Disk& (almacenamiento masivo). CdRom&, Other& se descartan.
        if ($classKey.PSChildName -notmatch '^Disk&') {
            Write-SweepLog -Message "USBSTOR: clase '$($classKey.PSChildName)' no es storage. Omitida." `
                           -Level DEBUG -Component 'Get-SweepUSB'
            continue
        }

        $vendor = $product = $revision = $null
        if ($classKey.PSChildName -match 'Ven_(?<v>[^&]+)&Prod_(?<p>[^&]+)&Rev_(?<r>.+)$') {
            $vendor   = $Matches['v'].Trim()
            $product  = $Matches['p'].Trim()
            $revision = $Matches['r'].Trim()
        }

        try   { $instanceKeys = Get-ChildItem -Path $classKey.PSPath -ErrorAction Stop }
        catch {
            Write-SweepLog -Message "USBSTOR: error enumerando instancias de '$($classKey.PSChildName)': $_" `
                           -Level DEBUG -Component 'Get-SweepUSB'
            continue
        }

        foreach ($instanceKey in $instanceKeys) {
            $serialRaw     = $instanceKey.PSChildName
            $serialNumber  = $serialRaw -replace '&\d+$', ''
            $hasRealSerial = $serialNumber -notmatch '^&'

            if (-not $hasRealSerial) {
                Write-SweepLog -Message "USBSTOR: '$vendor $product' sin serial real (ID: '$serialRaw')." `
                               -Level DEBUG -Component 'Get-SweepUSB'
            }

            $parentIdPrefix = $null
            try {
                $parentIdPrefix = Get-ItemPropertyValue -Path $instanceKey.PSPath `
                                                        -Name 'ParentIdPrefix' -ErrorAction Stop
            }
            catch {
                Write-SweepLog -Message "USBSTOR: ParentIdPrefix no disponible para '$serialRaw'." `
                               -Level DEBUG -Component 'Get-SweepUSB'
            }

            $friendlyName = $null
            if ($hasRealSerial) { $friendlyName = _Get-USBFriendlyName -SerialNumber $serialNumber }
            if ($null -eq $friendlyName) {
                try {
                    $friendlyName = Get-ItemPropertyValue -Path $instanceKey.PSPath `
                                                          -Name 'FriendlyName' -ErrorAction Stop
                }
                catch { }
            }

            $firstSeenUTC  = $null
            $setupApiFound = $false
            if ($setupApiAvailable -and $hasRealSerial) {
                try {
                    $firstSeenUTC  = _Get-SetupApiTimestamp -LogPath $setupApiLog -DeviceId $serialNumber
                    $setupApiFound = $null -ne $firstSeenUTC
                }
                catch {
                    Write-SweepLog -Message "USBSTOR: error setupapi para '$serialNumber': $_" `
                                   -Level WARN -Component 'Get-SweepUSB'
                }
            }

            if ($setupApiAvailable -and -not $setupApiFound) {
                Write-SweepLog -Message "USBSTOR: '$serialNumber' no encontrado en setupapi." `
                               -Level DEBUG -Component 'Get-SweepUSB'
            }

            $results.Add([PSCustomObject]@{
                Vendor         = $vendor
                Product        = $product
                Revision       = $revision
                SerialNumber   = $serialNumber
                SerialRaw      = $serialRaw
                HasRealSerial  = $hasRealSerial
                ParentIdPrefix = $parentIdPrefix
                FriendlyName   = $friendlyName
                FirstSeenUTC   = $firstSeenUTC
                SetupApiFound  = $setupApiFound
                Source         = $instanceKey.PSPath
            })

            Write-SweepLog -Message ("USB: [{0}] {1} {2} | Serial: {3} | FirstSeen: {4}" -f
                $vendor, $product, $revision, $serialNumber,
                $(if ($firstSeenUTC) { $firstSeenUTC.ToString('o') } else { 'N/A' })
            ) -Level DEBUG -Component 'Get-SweepUSB'
        }
    }

    Write-SweepLog -Message "USB: $($results.Count) dispositivo(s) recolectados." `
                   -Level INFO -Component 'Get-SweepUSB'
    return $results.ToArray()
}


# -----------------------------------------------------------------------------
# VECTOR 6 - Event Log Sweeper
# -----------------------------------------------------------------------------
function Get-SweepEvents {
    <#
    .SYNOPSIS
        Extrae eventos de alto valor forense usando -FilterHashtable / -FilterXPath.
        Detecciones: ClearLog (1102/104), SuspiciousService (7045), ScriptBlock (4104).
    .OUTPUTS
        [PSCustomObject[]] DetectionType|EventId|LogName|TimeCreatedUTC|Message|ExtraField1|ExtraField2
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        # Ventana de tiempo para ScriptBlock Logging en ms. 2592000000 = 30 dias.
        [Parameter()]
        [long]$ScriptBlockTimeDiffMs = 2592000000L
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-SweepLog -Message 'Iniciando recoleccion de eventos.' -Level INFO -Component 'Get-SweepEvents'

    # DETECCION 1: Borrado de logs (Security 1102 + System 104)
    $clearLogQueries = @(
        @{ LogName = 'Security'; Id = 1102; Label = 'ClearLog-Security' }
        @{ LogName = 'System';   Id = 104;  Label = 'ClearLog-System'   }
    )

    foreach ($q in $clearLogQueries) {
        try {
            # @() fuerza array: Get-WinEvent devuelve objeto único (sin .Count) si solo hay 1 evento
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $q.LogName; Id = $q.Id } -ErrorAction Stop)
            foreach ($ev in $events) {
                $results.Add([PSCustomObject]@{
                    DetectionType  = $q.Label
                    EventId        = $ev.Id
                    LogName        = $q.LogName
                    TimeCreatedUTC = $ev.TimeCreated.ToUniversalTime()
                    Message        = ($ev.Message -split "`n")[0].Trim()
                    ExtraField1    = $null
                    ExtraField2    = $null
                })
            }
            Write-SweepLog -Message "$($q.Label): $($events.Count) evento(s)." `
                           -Level $(if ($events.Count -gt 0) { 'WARN' } else { 'DEBUG' }) `
                           -Component 'Get-SweepEvents'
        }
        catch [System.Exception] {
            $msg   = $_.Exception.Message
            $level = if ($msg -match 'No events were found|no se encontraron') { 'DEBUG' } else { 'WARN' }
            Write-SweepLog -Message "$($q.Label): $msg" -Level $level -Component 'Get-SweepEvents'
        }
    }

    # DETECCION 2: Servicios sospechosos (7045)
    # FilterHashtable acota el conjunto; se parsea XML sobre los pocos resultados.
    try {
        $svcEvents          = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } -ErrorAction Stop
        $suspiciousPatterns = 'temp|appdata|powershell|\\psh|\\cmd\.exe|cmd\.exe'

        foreach ($ev in $svcEvents) {
            [xml]$evXml = $ev.ToXml()
            $ns = [System.Xml.XmlNamespaceManager]::new($evXml.NameTable)
            $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

            $svcName   = $evXml.SelectSingleNode('//e:Data[@Name="ServiceName"]', $ns).'#text'
            $imgPath   = $evXml.SelectSingleNode('//e:Data[@Name="ImagePath"]',   $ns).'#text'
            $svcType   = $evXml.SelectSingleNode('//e:Data[@Name="ServiceType"]', $ns).'#text'
            $startType = $evXml.SelectSingleNode('//e:Data[@Name="StartType"]',   $ns).'#text'

            if ("$svcName $imgPath" -notmatch $suspiciousPatterns) { continue }

            Write-SweepLog -Message "[!] Servicio sospechoso: '$svcName' -> '$imgPath'" `
                           -Level WARN -Component 'Get-SweepEvents'

            $results.Add([PSCustomObject]@{
                DetectionType  = 'SuspiciousService'
                EventId        = 7045
                LogName        = 'System'
                TimeCreatedUTC = $ev.TimeCreated.ToUniversalTime()
                Message        = "Service: $svcName | Type: $svcType | Start: $startType"
                ExtraField1    = $svcName
                ExtraField2    = $imgPath
            })
        }
        Write-SweepLog -Message "SuspiciousService: $($svcEvents.Count) evento(s) 7045 evaluados." `
                       -Level DEBUG -Component 'Get-SweepEvents'
    }
    catch [System.Exception] {
        $msg   = $_.Exception.Message
        $level = if ($msg -match 'No events were found|no se encontraron') { 'DEBUG' } else { 'WARN' }
        Write-SweepLog -Message "SuspiciousService (7045): $msg" -Level $level -Component 'Get-SweepEvents'
    }

    # DETECCION 3: Script Block sospechoso (4104)
    # Estrategia: FilterHashtable con ventana de tiempo (StartTime) para acotar I/O,
    # luego filtro en memoria sobre el XML ya leido.
    # Razon: translate() sobre EventData/Data[@Name] en XPath EVTX es inconsistente
    # entre builds de Windows 10/11 y PS 5.1 — produce "consulta no valida" en algunos sistemas.
    $suspiciousKeywords = @('base64','downloadstring','invoke-expression','-enc','iex(','iex (')
    $windowStart = (Get-Date).AddMilliseconds(-$ScriptBlockTimeDiffMs)

    try {
        $sbEvents = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-PowerShell/Operational'
            Id        = 4104
            StartTime = $windowStart
        } -ErrorAction Stop)

        $sbMatches = 0
        foreach ($ev in $sbEvents) {
            [xml]$evXml = $ev.ToXml()
            $ns = [System.Xml.XmlNamespaceManager]::new($evXml.NameTable)
            $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

            $scriptTextNode = $evXml.SelectSingleNode("//e:Data[@Name='ScriptBlockText']", $ns)
            $scriptPathNode = $evXml.SelectSingleNode("//e:Data[@Name='Path']", $ns)
            $scriptText = if ($null -ne $scriptTextNode) { $scriptTextNode.'#text' } else { '' }
            $scriptPath = if ($null -ne $scriptPathNode) { $scriptPathNode.'#text' } else { $null }

            # Filtro en memoria (case-insensitive, .NET puro): descartar bloques sin keywords
            $scriptLower = if ($scriptText) { $scriptText.ToLower() } else { '' }
            $matched = $false
            foreach ($kw in $suspiciousKeywords) {
                if ($scriptLower.Contains($kw)) { $matched = $true; break }
            }
            if (-not $matched) { continue }

            $sbMatches++
            $scriptPreview = if ($scriptText -and $scriptText.Length -gt 512) {
                $scriptText.Substring(0, 512) + '...[TRUNCADO]'
            } else { $scriptText }

            Write-SweepLog -Message "[!] ScriptBlock sospechoso (Path: '$scriptPath')" `
                           -Level WARN -Component 'Get-SweepEvents'

            $results.Add([PSCustomObject]@{
                DetectionType  = 'SuspiciousScriptBlock'
                EventId        = 4104
                LogName        = 'Microsoft-Windows-PowerShell/Operational'
                TimeCreatedUTC = $ev.TimeCreated.ToUniversalTime()
                Message        = $scriptPreview
                ExtraField1    = $scriptPath
                ExtraField2    = $null
            })
        }
        Write-SweepLog -Message "ScriptBlock (4104): $($sbEvents.Count) evento(s) evaluados, $sbMatches sospechoso(s)." `
                       -Level $(if ($sbMatches -gt 0) { 'WARN' } else { 'INFO' }) `
                       -Component 'Get-SweepEvents'
    }
    catch [System.Exception] {
        $msg   = $_.Exception.Message
        $level = if ($msg -match 'No events were found|no se encontraron|does not exist|no existe|not enabled') {
            'DEBUG'
        } else { 'WARN' }
        Write-SweepLog -Message "ScriptBlock (4104): $msg" -Level $level -Component 'Get-SweepEvents'
    }

    Write-SweepLog -Message "Events: $($results.Count) deteccion(es) totales." -Level INFO -Component 'Get-SweepEvents'
    return $results.ToArray()
}

#endregion

# =============================================================================
# REGION 6 - MOTOR DE EXPORTACION MARKDOWN
# =============================================================================
#region Export Markdown

function _ConvertTo-MarkdownTable {
    <#
    .SYNOPSIS
        Convierte un array de PSCustomObject en tabla Markdown.
        Renderiza datetime, bool y null con formato consistente.
        Escapa caracteres que romperians la sintaxis de tabla.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [PSCustomObject[]]$Objects,
        [Parameter()]          [string[]]$Properties = $null
    )

    if (-not $Objects -or $Objects.Count -eq 0) { return '_Sin datos._' }

    $props = if ($Properties) { $Properties } else { $Objects[0].PSObject.Properties.Name }
    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add('| ' + ($props -join ' | ') + ' |')
    $lines.Add('|' + (($props | ForEach-Object { '---|' }) -join ''))

    foreach ($obj in $Objects) {
        $cells = foreach ($p in $props) {
            $val = $obj.$p
            if ($null -eq $val)          { '-' }
            elseif ($val -is [datetime]) { $val.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
            elseif ($val -is [bool])     { if ($val) { 'SI' } else { 'NO' } }
            else                         { [string]$val -replace '\|', '\|' -replace "`r?`n", ' ' }
        }
        $lines.Add('| ' + ($cells -join ' | ') + ' |')
    }

    return $lines -join "`r`n"
}


function _New-MdSection {
    <#
    .SYNOPSIS
        Genera una seccion Markdown completa para una categoria de $CollectedData.
        Tablas con mas de $CollapseThreshold filas se envuelven en <details> HTML.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]$Title,
        [Parameter(Mandatory)] [string]$Emoji,
        [Parameter()]          [AllowNull()][AllowEmptyCollection()][object[]]$Data = @(),
        [Parameter()]          [string[]]$Properties        = $null,
        [Parameter()]          [string]$Description         = '',
        [Parameter()]          [int]$CollapseThreshold      = 10
    )

    # Normalizar: null o array vacio -> array vacio tipado para que .Count funcione siempre
    if ($null -eq $Data) { $Data = @() }
    $lines = [System.Collections.Generic.List[string]]::new()
    $count = $Data.Count

    $lines.Add("## $Emoji $Title")
    $lines.Add('')
    if ($Description) { $lines.Add("> $Description"); $lines.Add('') }
    $lines.Add("**Total:** $count registro(s)")
    $lines.Add('')

    if ($count -eq 0) {
        $lines.Add('_Sin hallazgos para esta categoria._')
        $lines.Add('')
        return $lines -join "`r`n"
    }

    $tableMarkdown = _ConvertTo-MarkdownTable -Objects $Data -Properties $Properties

    if ($count -gt $CollapseThreshold) {
        $lines.Add('<details>')
        $lines.Add("<summary>Ver tabla ($count entradas)</summary>")
        $lines.Add('')
        $lines.Add($tableMarkdown)
        $lines.Add('')
        $lines.Add('</details>')
    }
    else {
        $lines.Add($tableMarkdown)
    }

    $lines.Add('')
    return $lines -join "`r`n"
}


function Export-SweepMarkdown {
    <#
    .SYNOPSIS
        Genera RegSweepX_Report.md con reporte forense completo y estructurado.
        Incluye resumen ejecutivo con semaforo, secciones por vector y tabla de analista.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [hashtable]$Data,
        [Parameter(Mandatory)] [string]$OutputDir,
        [Parameter()]          [PSCustomObject]$Metadata        = $null,
        [Parameter()]          [int]$CollapseThreshold          = 10
    )

    $mdFile = Join-Path -Path $OutputDir -ChildPath 'RegSweepX_Report.md'
    Write-SweepLog -Message "Generando Markdown -> '$mdFile'" -Level INFO -Component 'Export-MD'

    try {
        $doc = [System.Collections.Generic.List[string]]::new()

        # CABECERA
        $doc.Add('# RegSweep-X - Reporte Forense de Registro y Eventos')
        $doc.Add('')
        $doc.Add('> DOCUMENTO GENERADO AUTOMATICAMENTE. No modificar manualmente.')
        $doc.Add('> Uso restringido a personal autorizado en el contexto de la investigacion.')
        $doc.Add('')

        # METADATOS DE SESION
        $doc.Add('## Metadatos de la Sesion')
        $doc.Add('')
        $doc.Add('| Campo | Valor |')
        $doc.Add('|---|---|')

        $meta = if ($Metadata) { $Metadata } else {
            [PSCustomObject]@{
                Host           = $env:COMPUTERNAME
                Domain         = $env:USERDOMAIN
                User           = $env:USERNAME
                TimestampLocal = (Get-Date).ToString('o')
                TimestampUTC   = (Get-Date).ToUniversalTime().ToString('o')
                PSVersion      = $PSVersionTable.PSVersion.ToString()
                OSVersion      = [System.Environment]::OSVersion.VersionString
                Phase          = '4 / 4 - Completo'
            }
        }
        foreach ($p in $meta.PSObject.Properties) {
            $doc.Add("| **$($p.Name)** | $($p.Value) |")
        }
        $doc.Add('')

        # RESUMEN EJECUTIVO
        $doc.Add('## Resumen Ejecutivo')
        $doc.Add('')
        $doc.Add('| Categoria | Artefactos | Estado |')
        $doc.Add('|---|---|---|')

        $categories = [ordered]@{
            BAM    = @{ Emoji = '[BAM]';    Label = 'BAM/DAM - Evidencia de Ejecucion'      }
            LSA    = @{ Emoji = '[LSA]';    Label = 'LSA/SSP - Paquetes de Autenticacion'   }
            IFEO   = @{ Emoji = '[IFEO]';   Label = 'IFEO - Image File Execution Hijacking'  }
            RDP    = @{ Emoji = '[RDP]';    Label = 'RDP - Conexiones Salientes'             }
            USB    = @{ Emoji = '[USB]';    Label = 'USB - Dispositivos de Almacenamiento'   }
            Events = @{ Emoji = '[EVENTS]'; Label = 'Eventos - Anomalias del Sistema'        }
        }

        $totalArtifacts = 0
        foreach ($key in $categories.Keys) {
            $count = if ($Data.ContainsKey($key)) { @($Data[$key]).Count } else { 0 }
            $totalArtifacts += $count
            $status = if ($count -eq 0)                                          { 'OK - Sin hallazgos'    }
                      elseif ($key -in @('IFEO','Events') -and $count -gt 0)    { 'ALERTA - Revisar'      }
                      else                                                       { 'INFO - Datos presentes' }
            $doc.Add("| $($categories[$key].Emoji) $($categories[$key].Label) | **$count** | $status |")
        }
        $doc.Add('')
        $doc.Add("**Total de artefactos recolectados: $totalArtifacts**")
        $doc.Add('')
        $doc.Add('---')
        $doc.Add('')

        # Helper local: extrae una categoria de $Data como ArrayList con .Count siempre disponible.
        # [PSCustomObject[]]@(...) en PS 5.1 StrictMode puede perder .Count con 1 solo elemento.
        # System.Collections.ArrayList.Count es siempre un Int32 — no falla con StrictMode.
        filter _SafeList {
            param([string]$Key)
            $list = [System.Collections.ArrayList]::new()
            if ($Data.ContainsKey($Key) -and $null -ne $Data[$Key]) {
                @($Data[$Key]) | ForEach-Object { $null = $list.Add($_) }
            }
            return ,$list   # coma fuerza return del objeto, no del contenido
        }

        # SECCION BAM
        $bamData = _SafeList 'BAM'
        $doc.Add((_New-MdSection `
            -Title             'BAM/DAM - Evidencia de Ejecucion' `
            -Emoji             '[BAM]' `
            -Data              $bamData.ToArray() `
            -Properties        @('SID','ExecutablePath','LastRunUTC','TimestampRaw') `
            -Description       'Background Activity Moderator. Ejecucion de binarios por usuario (SID). Un timestamp valido confirma ejecucion real.' `
            -CollapseThreshold $CollapseThreshold
        ))
        $doc.Add('---'); $doc.Add('')

        # SECCION LSA
        $lsaData     = _SafeList 'LSA'
        $lsaAlert    = [System.Collections.ArrayList]::new()
        $lsaBaseline = [System.Collections.ArrayList]::new()
        $lsaData | ForEach-Object {
            if (-not $_.IsKnownDefault) { $null = $lsaAlert.Add($_)   }
            else                        { $null = $lsaBaseline.Add($_) }
        }

        $doc.Add('## [LSA] LSA/SSP - Paquetes de Autenticacion')
        $doc.Add('')
        $doc.Add('> Paquetes en HKLM\SYSTEM\CurrentControlSet\Control\Lsa.')
        $doc.Add('> Un paquete NO ESTANDAR = indicador de credential theft (T1556.002).')
        $doc.Add('')
        $doc.Add("**Total:** $($lsaData.Count) paquete(s) - ALERTA No estandar: $($lsaAlert.Count) | OK Conocidos: $($lsaBaseline.Count)")
        $doc.Add('')

        if ($lsaAlert.Count -gt 0) {
            $doc.Add('### ALERTA - Paquetes NO estandar (Prioridad alta)')
            $doc.Add('')
            $doc.Add((_ConvertTo-MarkdownTable -Objects $lsaAlert.ToArray() -Properties @('ValueName','Package','Source')))
            $doc.Add('')
        }
        if ($lsaBaseline.Count -gt 0) {
            $baselineTable = _ConvertTo-MarkdownTable -Objects $lsaBaseline.ToArray() -Properties @('ValueName','Package')
            if ($lsaBaseline.Count -gt $CollapseThreshold) {
                $doc.Add("<details><summary>Ver paquetes conocidos ($($lsaBaseline.Count) entradas)</summary>")
                $doc.Add('')
                $doc.Add($baselineTable)
                $doc.Add('')
                $doc.Add('</details>')
            }
            else {
                $doc.Add('### OK - Paquetes conocidos (Referencia)')
                $doc.Add('')
                $doc.Add($baselineTable)
            }
        }
        $doc.Add(''); $doc.Add('---'); $doc.Add('')

        # SECCION IFEO
        $ifeoData = _SafeList 'IFEO'
        $doc.Add((_New-MdSection `
            -Title             'IFEO - Image File Execution Options Hijacking' `
            -Emoji             '[IFEO]' `
            -Data              $ifeoData.ToArray() `
            -Properties        @('ImageName','ValueName','HandlerPath') `
            -Description       'T1546.012 (MITRE). Cualquier entrada redirige la ejecucion del binario objetivo. TODOS los resultados son sospechosos.' `
            -CollapseThreshold $CollapseThreshold
        ))
        $doc.Add('---'); $doc.Add('')

        # SECCION RDP
        $rdpData = _SafeList 'RDP'
        $doc.Add((_New-MdSection `
            -Title             'RDP - Historial de Conexiones Salientes' `
            -Emoji             '[RDP]' `
            -Data              $rdpData.ToArray() `
            -Properties        @('User','RecordType','HostOrIP','MRUPosition','UsernameHint') `
            -Description       'Evidencia de movimiento lateral saliente. Cada entrada = host al que el usuario se ha conectado via RDP.' `
            -CollapseThreshold $CollapseThreshold
        ))
        $doc.Add('---'); $doc.Add('')

        # SECCION USB
        $usbData = _SafeList 'USB'
        $doc.Add((_New-MdSection `
            -Title             'USB - Dispositivos de Almacenamiento' `
            -Emoji             '[USB]' `
            -Data              $usbData.ToArray() `
            -Properties        @('Vendor','Product','Revision','SerialNumber','HasRealSerial','FriendlyName','FirstSeenUTC') `
            -Description       'Dispositivos USBSTOR. FirstSeenUTC = primera instalacion del driver segun setupapi.dev.log.' `
            -CollapseThreshold $CollapseThreshold
        ))
        $doc.Add('---'); $doc.Add('')

        # SECCION EVENTS
        $eventsData = _SafeList 'Events'

        $doc.Add('## [EVENTS] Eventos - Anomalias del Sistema')
        $doc.Add('')
        $doc.Add('> Detecciones basadas en Event IDs de alto valor forense.')
        $doc.Add('')

        if ($eventsData.Count -eq 0) {
            $doc.Add('**Total:** 0 detecciones.')
            $doc.Add('')
            $doc.Add('_Sin anomalias detectadas en los logs de eventos._')
        }
        else {
            $doc.Add("**Total:** $($eventsData.Count) deteccion(es)")
            $doc.Add('')

            $detectionTypes = @(
                @{ Type = 'ClearLog-Security';     Label = 'ALERTA - Borrado de Log de Seguridad (EID 1102)';  Desc = 'Anti-forense (T1070.001). Alguien borro el log de Seguridad.' }
                @{ Type = 'ClearLog-System';       Label = 'ALERTA - Borrado de Log de Sistema (EID 104)';     Desc = 'Borrado del log de System. Posible anti-forense.' }
                @{ Type = 'SuspiciousService';     Label = 'ALERTA - Servicio Sospechoso (EID 7045)';          Desc = 'Servicio con ruta en directorio volatil o interprete de comandos (T1543.003).' }
                @{ Type = 'SuspiciousScriptBlock'; Label = 'ALERTA - Script Block Sospechoso (EID 4104)';      Desc = 'PS con indicadores de ofuscacion o descarga en memoria (T1059.001). Ultimos 30 dias.' }
            )

            foreach ($dt in $detectionTypes) {
                $subset = [System.Collections.ArrayList]::new()
                $eventsData | Where-Object { $_.DetectionType -eq $dt.Type } | ForEach-Object { $null = $subset.Add($_) }
                if ($subset.Count -eq 0) { continue }

                $doc.Add("### $($dt.Label)")
                $doc.Add('')
                $doc.Add("> $($dt.Desc)")
                $doc.Add('')
                $doc.Add("**Instancias:** $($subset.Count)")
                $doc.Add('')

                $evTable = _ConvertTo-MarkdownTable -Objects $subset.ToArray() `
                           -Properties @('TimeCreatedUTC','Message','ExtraField1','ExtraField2')

                if ($subset.Count -gt $CollapseThreshold) {
                    $doc.Add("<details><summary>Ver eventos ($($subset.Count) entradas)</summary>")
                    $doc.Add('')
                    $doc.Add($evTable)
                    $doc.Add('')
                    $doc.Add('</details>')
                }
                else { $doc.Add($evTable) }

                $doc.Add('')
            }
        }
        $doc.Add(''); $doc.Add('---'); $doc.Add('')

        # PIE DE REPORTE
        $doc.Add('## Notas del Analista')
        $doc.Add('')
        $doc.Add('> Espacio reservado para anotaciones del investigador.')
        $doc.Add('')
        $doc.Add('| # | Hallazgo | Severidad | Accion |')
        $doc.Add('|---|---|---|---|')
        $doc.Add('| 1 | | | |')
        $doc.Add('')
        $doc.Add('---')
        $doc.Add('')
        $doc.Add("*RegSweep-X - Reporte generado el $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC " +
                 "en $env:COMPUTERNAME - Todas las fases completadas.*")

        # ESCRITURA EN DISCO
        $content = $doc -join "`r`n"

        if ($PSCmdlet.ShouldProcess($mdFile, 'Escribir reporte Markdown')) {
            [System.IO.File]::WriteAllText($mdFile, $content, [System.Text.Encoding]::UTF8)
        }

        Write-SweepLog -Message "Markdown exportado ($([math]::Round($content.Length/1KB,1)) KB)." `
                       -Level INFO -Component 'Export-MD'
    }
    catch {
        Write-SweepLog -Message "ERROR exportando Markdown: $_" -Level ERROR -Component 'Export-MD'
        throw
    }

    return $mdFile
}

#endregion

# =============================================================================
# REGION 7 - FUNCION PRINCIPAL
# =============================================================================
#region Main

function Main {
    <#
    .SYNOPSIS
        Orquesta la ejecucion completa de RegSweep-X (Fases 1-4).
        Devuelve un PSCustomObject con rutas y datos para uso en pipeline o testing.
    #>
    [CmdletBinding()]
    param()

    # 1. Privilegios
    Assert-AdminPrivilege

    # 2. Directorio de salida
    $Script:OutputDir = New-SweepOutputDirectory -Root $OutputRoot

    # 3. Inicializar log
    $Script:LogFilePath = Join-Path -Path $Script:OutputDir -ChildPath 'RegSweepX.log'

    Write-SweepLog -Message ('=' * 60)                                            -Level INFO
    Write-SweepLog -Message 'RegSweep-X iniciado - Todas las fases activas'       -Level INFO
    Write-SweepLog -Message "Directorio de salida : $Script:OutputDir"            -Level INFO
    Write-SweepLog -Message "Host                 : $env:COMPUTERNAME"            -Level INFO
    Write-SweepLog -Message "Usuario              : $env:USERNAME"                -Level INFO
    Write-SweepLog -Message "PS Version           : $($PSVersionTable.PSVersion)" -Level INFO
    Write-SweepLog -Message ('=' * 60)                                            -Level INFO

    # 4. Recoleccion
    [hashtable]$CollectedData = @{}

    Write-SweepLog -Message 'Iniciando recoleccion de artefactos (6 vectores).' -Level INFO -Component 'Main'

    Write-SweepLog -Message '[1/6] BAM/DAM...'       -Level INFO -Component 'Main'
    $CollectedData['BAM']    = Get-SweepBAM

    Write-SweepLog -Message '[2/6] LSA/SSP...'       -Level INFO -Component 'Main'
    $CollectedData['LSA']    = Get-SweepLSA

    Write-SweepLog -Message '[3/6] IFEO...'           -Level INFO -Component 'Main'
    $CollectedData['IFEO']   = Get-SweepIFEO

    Write-SweepLog -Message '[4/6] RDP saliente...'   -Level INFO -Component 'Main'
    $CollectedData['RDP']    = Get-SweepRDP

    Write-SweepLog -Message '[5/6] USB & Storage...'  -Level INFO -Component 'Main'
    $CollectedData['USB']    = Get-SweepUSB

    Write-SweepLog -Message '[6/6] Eventos...'        -Level INFO -Component 'Main'
    $CollectedData['Events'] = Get-SweepEvents

    Write-SweepLog -Message 'Recoleccion completada.' -Level INFO -Component 'Main'
    foreach ($cat in $CollectedData.Keys | Sort-Object) {
        $count = @($CollectedData[$cat]).Count
        Write-SweepLog -Message "  $cat : $count artefacto(s)" -Level INFO -Component 'Main'
    }

    # 5. Metadatos de sesion
    [PSCustomObject]$SessionMetadata = [PSCustomObject]@{
        Host           = $env:COMPUTERNAME
        Domain         = $env:USERDOMAIN
        User           = $env:USERNAME
        TimestampLocal = (Get-Date).ToString('o')
        TimestampUTC   = (Get-Date).ToUniversalTime().ToString('o')
        PSVersion      = $PSVersionTable.PSVersion.ToString()
        OSVersion      = [System.Environment]::OSVersion.VersionString
        Phase          = '4 / 4 - Completo'
    }

    # 6. Exportar
    Write-SweepLog -Message 'Exportando resultados...' -Level INFO -Component 'Main'

    $jsonPath = Export-SweepJson     -Data $CollectedData -OutputDir $Script:OutputDir
    $mdPath   = Export-SweepMarkdown -Data $CollectedData -OutputDir $Script:OutputDir `
                                     -Metadata $SessionMetadata -CollapseThreshold 10

    # 7. Resumen final
    Write-SweepLog -Message ('=' * 60)                    -Level INFO
    Write-SweepLog -Message 'RegSweep-X COMPLETADO.'       -Level INFO
    Write-SweepLog -Message "  LOG  -> $Script:LogFilePath" -Level INFO
    Write-SweepLog -Message "  JSON -> $jsonPath"           -Level INFO
    Write-SweepLog -Message "  MD   -> $mdPath"             -Level INFO
    Write-SweepLog -Message ('=' * 60)                    -Level INFO

    return [PSCustomObject]@{
        OutputDir    = $Script:OutputDir
        LogFile      = $Script:LogFilePath
        JsonFile     = $jsonPath
        MarkdownFile = $mdPath
        Metadata     = $SessionMetadata
        Data         = $CollectedData
    }
}

#endregion

# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================
Main
