# Notepad Again!

> PowerShell script para controlar la persistencia de sesión del nuevo Microsoft Notepad (Windows 11).  

---

## 🇪🇸 Español

### ¿Qué es esto?

El nuevo **Microsoft Notepad** (Windows 11) guarda automáticamente el estado de las pestañas abiertas al cerrar la aplicación, restaurándolas en el siguiente inicio. Este script permite **desactivar o restaurar** ese comportamiento manipulando los permisos ACL de la carpeta `TabState`, sin necesidad de modificar el registro ni desinstalar la aplicación.

### Características técnicas

- **Target**: `%LocalAppData%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState`
- **Motor de permisos**: `icacls` nativo de Windows con validación de `ExitCode`
- **Elevación automática**: detecta si corre sin privilegios y solicita UAC automáticamente
- **Kill Memory**: cierra `Notepad.exe`, vacía `TabState` y deniega permisos de escritura (`W`) al usuario actual desactivando la herencia ACL
- **Restore Memory**: elimina la ACE de denegación explícita y resetea los permisos a herencia por defecto con `/reset`
- **TUI interactiva**: menú `do-while` + `switch` con colores por `Write-Host`
- **Compatibilidad**: PowerShell 5.1+ · Windows 10/11 con Notepad de Microsoft Store

### Requisitos

| Requisito | Detalle |
|-----------|---------|
| OS | Windows 10 / 11 |
| PowerShell | 5.1 o superior |
| Notepad | Versión Microsoft Store (nuevo Notepad) |
| Permisos | Administrador (elevación automática incluida) |

### Uso

**1. Ejecutar el script**
```powershell
# Opción A: clic derecho sobre notepad.ps1 → "Ejecutar con PowerShell"

# Opción B: desde terminal
powershell.exe -ExecutionPolicy Bypass -File .\notepad.ps1
```

> Si la política de ejecución lo bloquea, ejecuta primero:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

**3. Navegar el menú**

```
===============================================
   NOTEPAD AGAIN!  |  v1.0
   Target: TabState Persistence Control
===============================================

  [i] Estado actual de TabState: [OK] Sin denegaciones - Memoria: ACTIVA

  OPCIONES:
  ---------------------------------------------
  [1]  Desactivar memoria  (Kill - Permanente)
  [2]  Restaurar memoria   (Restore - Default)
  [3]  Salir
  ---------------------------------------------
```

### ¿Cómo funciona internamente?

```
Disable-NotepadMemory
│
├── Stop-Process "Notepad"
├── Remove-Item TabState\*          ← vacía el historial actual
├── icacls TabState /inheritance:d  ← desactiva herencia ACL
└── icacls TabState /deny USER:(W)  ← bloquea escritura futura

Enable-NotepadMemory
│
├── Stop-Process "Notepad"
├── icacls TabState /remove:d USER  ← elimina ACE de denegación
└── icacls TabState /reset          ← restaura herencia por defecto
```

### Notas de seguridad

- El script **no modifica el registro**, no instala servicios ni altera archivos del sistema.
- La denegación ACL afecta **únicamente** a la carpeta `TabState`, sin impacto en el resto de la aplicación.
- La acción **Kill** es **permanente** hasta que se ejecute **Restore**: Notepad seguirá funcionando con normalidad pero no podrá persistir sesiones.

---

## 🇬🇧 English

### What is this?

The new **Microsoft Notepad** (Windows 11) automatically saves the state of open tabs when closing, restoring them on the next launch. This script lets you **disable or restore** that behavior by manipulating ACL permissions on the `TabState` folder — no registry edits, no app uninstall required.

### Technical features

- **Target**: `%LocalAppData%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState`
- **Permission engine**: Native Windows `icacls` with `ExitCode` validation
- **Auto-elevation**: detects unprivileged execution and triggers UAC automatically
- **Kill Memory**: terminates `Notepad.exe`, clears `TabState` contents, denies write permissions (`W`) for the current user and disables ACL inheritance
- **Restore Memory**: removes the explicit Deny ACE and resets permissions to inherited defaults via `/reset`
- **Interactive TUI**: `do-while` + `switch` menu with color output via `Write-Host`
- **Compatibility**: PowerShell 5.1+ · Windows 10/11 with Microsoft Store Notepad

### Requirements

| Requirement | Detail |
|-------------|--------|
| OS | Windows 10 / 11 |
| PowerShell | 5.1 or higher |
| Notepad | Microsoft Store version (new Notepad) |
| Permissions | Administrator (auto-elevation included) |

### Usage

**1. Run the script**
```powershell
# Option A: right-click notepad.ps1 → "Run with PowerShell"

# Option B: from terminal
powershell.exe -ExecutionPolicy Bypass -File .\notepad.ps1
```

> If execution policy blocks it, run first:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

**3. Navigate the menu**

```
===============================================
   NOTEPAD AGAIN!  |  v1.0
   Target: TabState Persistence Control
===============================================

  [i] Current TabState status: [OK] No denials - Memory: ACTIVE

  OPTIONS:
  ---------------------------------------------
  [1]  Disable memory  (Kill - Permanent)
  [2]  Restore memory  (Restore - Default)
  [3]  Exit
  ---------------------------------------------
```

### How it works internally

```
Disable-NotepadMemory
│
├── Stop-Process "Notepad"
├── Remove-Item TabState\*          ← clears current session history
├── icacls TabState /inheritance:d  ← disables ACL inheritance
└── icacls TabState /deny USER:(W)  ← blocks future write access

Enable-NotepadMemory
│
├── Stop-Process "Notepad"
├── icacls TabState /remove:d USER  ← removes Deny ACE
└── icacls TabState /reset          ← restores default inherited permissions
```

### Security notes

- The script does **not modify the registry**, install services, or alter system files.
- The ACL denial targets **only** the `TabState` folder with no impact on the rest of the application.
- The **Kill** action is **permanent** until **Restore** is executed: Notepad continues to work normally but cannot persist sessions.

---

## License

MIT — free to use, modify and distribute.
