#Requires -Version 5.1
<#
.SYNOPSIS
    Notepad Session Persistence Manager
.DESCRIPTION
    Controla la persistencia de sesion del nuevo Microsoft Notepad
    manipulando permisos ACL sobre la carpeta TabState.
#>

# --- ELEVACION AUTOMATICA ---------------------------------------------------
function Test-AdminPrivileges {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator
    )
}

if (-not (Test-AdminPrivileges)) {
    Write-Host "[-] Requiere privilegios de Administrador. Solicitando elevacion..." -ForegroundColor Yellow

    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }

    if ($scriptPath) {
        Start-Process -FilePath "powershell.exe" `
                      -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" `
                      -Verb RunAs
    } else {
        Write-Host "[!] Guarda el script como archivo .ps1 y ejecutalo directamente." -ForegroundColor Red
    }
    exit
}

# --- VARIABLES GLOBALES -----------------------------------------------------
$TabStatePath = "$env:LocalAppData\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState"
$CurrentUser  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# --- HELPER: Invocar icacls con validacion de ExitCode ----------------------
function Invoke-Icacls {
    param([string[]]$Arguments)
    $result = & icacls @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "icacls fallo (exit $LASTEXITCODE): $result"
    }
}

# --- FUNCIONES CORE ---------------------------------------------------------

function Get-Banner {
    Clear-Host
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "   NOTEPAD SESSION MANAGER  |  v1.1           " -ForegroundColor Cyan
    Write-Host "   Target: TabState Persistence Control        " -ForegroundColor DarkCyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Stop-Notepad {
    $procs = Get-Process -Name "Notepad" -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Proceso Notepad.exe terminado." -ForegroundColor Green
        Start-Sleep -Milliseconds 900
    } else {
        Write-Host "  [i] Notepad.exe no estaba en ejecucion." -ForegroundColor DarkGray
    }
}

function Disable-NotepadMemory {
    if (-not (Test-Path $TabStatePath)) {
        Write-Host "  [!] Ruta TabState no encontrada. Notepad instalado?" -ForegroundColor Red
        return
    }

    Stop-Notepad

    try {
        Remove-Item -Path "$TabStatePath\*" -Recurse -Force -ErrorAction Stop
        Write-Host "  [+] Contenido de TabState eliminado." -ForegroundColor Green
    } catch {
        Write-Host "  [!] Error al vaciar TabState: $_" -ForegroundColor Red
        return
    }

    try {
        Invoke-Icacls $TabStatePath, "/inheritance:d"
        Invoke-Icacls $TabStatePath, "/deny", "${CurrentUser}:(W)"

        Write-Host "  [+] Herencia desactivada. Escritura DENEGADA para: $CurrentUser" -ForegroundColor Green
        Write-Host ""
        Write-Host "  [OK] MEMORIA DESACTIVADA - Notepad no podra guardar sesion." -ForegroundColor Cyan
    } catch {
        Write-Host "  [!] Error configurando ACL: $_" -ForegroundColor Red
    }
}

function Enable-NotepadMemory {
    if (-not (Test-Path $TabStatePath)) {
        Write-Host "  [!] Ruta TabState no encontrada." -ForegroundColor Red
        return
    }

    Stop-Notepad

    try {
        Invoke-Icacls $TabStatePath, "/remove:d", $CurrentUser
        Write-Host "  [+] ACE Deny eliminada para: $CurrentUser" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Error al eliminar ACE Deny: $_" -ForegroundColor Red
        return
    }

    try {
        Invoke-Icacls $TabStatePath, "/reset"
        Write-Host "  [+] Permisos reseteados a herencia por defecto." -ForegroundColor Green
        Write-Host ""
        Write-Host "  [OK] MEMORIA RESTAURADA - Notepad puede guardar sesion." -ForegroundColor Cyan
    } catch {
        Write-Host "  [!] Error al restaurar herencia: $_" -ForegroundColor Red
    }
}

function Show-CurrentStatus {
    if (-not (Test-Path $TabStatePath)) {
        Write-Host "  [!] TabState no encontrada - Notepad posiblemente no instalado." -ForegroundColor DarkYellow
        Write-Host ""
        return
    }

    Write-Host "  [i] Estado actual de TabState:" -ForegroundColor DarkCyan
    try {
        $acl = Get-Acl -Path $TabStatePath -ErrorAction Stop
        $denyRules = $acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' }

        if ($denyRules) {
            Write-Host "  [!] Denegaciones activas - Memoria: DESACTIVADA" -ForegroundColor Red
            foreach ($rule in $denyRules) {
                Write-Host "      -> Deny [$($rule.IdentityReference)]: $($rule.FileSystemRights)" -ForegroundColor DarkRed
            }
        } else {
            Write-Host "  [OK] Sin denegaciones - Memoria: ACTIVA" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] No se pudo leer ACL: $_" -ForegroundColor Red
    }
    Write-Host ""
}

# --- MENU PRINCIPAL ---------------------------------------------------------
do {
    Get-Banner
    Show-CurrentStatus

    Write-Host "  OPCIONES:" -ForegroundColor Cyan
    Write-Host "  ---------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  [1]  Desactivar memoria  (Kill - Permanente)" -ForegroundColor White
    Write-Host "  [2]  Restaurar memoria   (Restore - Default)" -ForegroundColor White
    Write-Host "  [3]  Salir" -ForegroundColor DarkGray
    Write-Host "  ---------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""

    $choice = (Read-Host "  Selecciona una opcion").Trim()

    Get-Banner

    switch ($choice) {
        '1' {
            Write-Host "  [*] Ejecutando: KILL MEMORY..." -ForegroundColor Yellow
            Write-Host ""
            Disable-NotepadMemory
        }
        '2' {
            Write-Host "  [*] Ejecutando: RESTORE MEMORY..." -ForegroundColor Yellow
            Write-Host ""
            Enable-NotepadMemory
        }
        '3' {
            Write-Host "  [i] Saliendo..." -ForegroundColor DarkGray
        }
        default {
            Write-Host "  [!] Opcion no valida. Usa 1, 2 o 3." -ForegroundColor Red
        }
    }

    if ($choice -ne '3') {
        Write-Host ""
        Write-Host "  Presiona cualquier tecla para continuar..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }

} while ($choice -ne '3')
