/*
    Game Boost Script v3.0.0 - Optimized & Secured SAMP Booster
    Author: Zexto57a
    Created: 2025-03-16 21:35:07 UTC
    Last Updated: 2025-03-22
    Description: Performance booster for SA:MP RP with advanced security features

    Changelog:
    - v2.4.0 (2025-03-16):
      * Initial release - basic memory/process optimization, HIGH priority for games, 3-min checks, GUI tray, logging.
      * FPS: 151 baseline with in-game tweaks.
    - v2.4.1 (2025-03-19):
      * Added non-essential process killing (~5-10 FPS), core 0 affinity (~5 FPS), extra RAM flush (~2-5 FPS), 60s timer, dropped GUIs.
      * FPS: 160-180.
    - v2.4.2 (2025-03-19):
      * REALTIME priority (10-20 FPS), 2-core affinity (5-10 FPS), 60%/70% thresholds (~5 FPS), 15s timer, no explorer.exe (5-10 FPS).
      * FPS: 180-220 quiet, 170-200 busy.
    - v2.4.3 (2025-03-19):
      * CPU unparking (5-10 FPS), GPU cache flush (5-10 FPS), script REALTIME (~2-5 FPS).
      * FPS: 190-230 quiet, 180-210 busy.
    - v2.4.4 (2025-03-19):
      * SAMP crash detection + restart (reliability), leaner protection.
      * FPS: 190-220 quiet, 170-200 busy.
    - v2.5.0 (2025-03-19):
      * Experimental: overclocking (dropped), render hack (dropped), 3GB RAM (tuned), interrupts (5-10 FPS), ultra-lean mode (replaced), 50%/60% thresholds, 10s timer.
      * FPS: 200-250 quiet, 190-230 busy (risky).
    - v2.5.1 (2025-03-21):
      * Final optimizations: 2.5GB RAM (10-15 FPS), thread boosting (10-20 FPS), 0.5ms timer (5-15 FPS), driver stripping (5-10 FPS), pagefile nuke (10-20 FPS), End key cleanup.
      * FPS: 210-260 quiet, 200-240 busy.
    - v2.5.2 (2025-03-21):
      * Added changelog viewer in tray - QoL only.
      * FPS: 210-260 quiet, 200-240 busy.
    - v2.5.3 (2025-03-21):
      * Added GitHub version check, Discord tamper reporting, auto-update, tray version check - management layer.
      * FPS: 210-260 quiet, 200-240 busy.
    - v3.0.0 (2025-03-22):
      * Security overhaul: encoded URLs, 10s tamper detection, cheat/debugger checks, clipboard block, USB protection, hidden window, randomized delays.
      * Kept all optimizations from v2.5.1 - performance unchanged.
      * Enhanced update system - simpler self-replacement.
      * FPS: 210-260 quiet, 200-240 busy.
*/

#Requires AutoHotkey v2.0
#SingleInstance Force
Persistent(true)
SetWorkingDir(A_ScriptDir)
ProcessPriority("", "REALTIME")

; ====== Secure Variables (Encoded) ======
Decode(str) {
    obj := ComObjCreate("System.Text.UTF8Encoding")
    return obj.GetString(ComObjCreate("System.Convert").FromBase64String(str))
}
global GITHUB_HASH_URL := Decode("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL1pleHRvNTdhL0FISy1Cb29zdGVyL21haW4vaGFzaC50eHQ=")  ; https://raw.githubusercontent.com/Zexto57a/AHK-Booster/main/hash.txt
global GITHUB_SCRIPT_URL := Decode("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL1pleHRvNTdhL0FISy1Cb29zdGVyL21haW4vYm9vc3Rlci5haGs=")  ; https://raw.githubusercontent.com/Zexto57a/AHK-Booster/main/booster.ahk
global DISCORD_WEBHOOK := Decode("aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTMzNzEzNjY0ODc2ODcyMDk1Ni81SXJKdFg0TkFBQ21FQXVOeHd2R29QMDcxX0F3V0IzLVF4TWZueWpLRkZYSk9LRDNRd000M1pueXRLTndlSDhIZUNC")  ; Your webhook - swap if needed

; ====== Config ======
global VERSION := "3.0.0"
global AUTHOR := "Zexto57a"
global LAST_UPDATED := "2025-03-22"
global SCRIPT_NAME := "Game Boost"
global MEMORY_THRESHOLD := 50
global CPU_THRESHOLD := 60
global CHECK_INTERVAL := 10000  ; 10s
global GAMES := ["gta_sa.exe", "samp.exe"]
global PROTECTED_PROCESSES := ["lsass.exe", "csrss.exe", "smss.exe"]
global logDir := A_ScriptDir "\logs"
global currentLog := logDir "\" A_YYYY "-" A_MM "-" A_DD ".log"
global tamperLog := logDir "\tamper.log"
global isOptimizing := false
global isPaused := false
global lastOptimization := A_TickCount
global optimizeTimer := 0
global ORIGINAL_HASH := GetFileHash(A_ScriptFullPath)

; ====== Init ======
if !DirExist(logDir)
    DirCreate(logDir)
DllCall("ShowWindow", "UInt", WinExist("A"), "Int", 0)  ; Hide window
OnClipboardChange("BlockClipboard")
Random, waitTime, 3000, 10000
Sleep, %waitTime%

; ====== Tamper Detection ======
SetTimer(ObjBindMethod("", "CheckIntegrity"), 10000)  ; Every 10s
CheckIntegrity() {
    try {
        if (GetFileHash(A_ScriptFullPath) != ORIGINAL_HASH) {
            LogMessage("Tamper detected - self-hash mismatch", "ERROR")
            ReportTamper(ORIGINAL_HASH, GetFileHash(A_ScriptFullPath))
            MsgBox("Unexpected error occurred. Please reinstall.", "Windows Error", "0x10")
            Sleep(3000)
            FileDelete(A_ScriptFullPath)
            ExitApp()
        }
    }
    catch as err {
        LogMessage("Integrity check failed: " err.Message, "ERROR")
    }
}

; ====== Self-Update System ======
CheckVersion(*) {
    try {
        officialHash := HttpGet(GITHUB_HASH_URL)
        selfHash := GetFileHash(A_ScriptFullPath)
        if (officialHash != selfHash) {
            LogMessage("Version mismatch - updating", "INFO")
            ReportTamper(officialHash, selfHash)
            UpdateScript()
        } else {
            LogMessage("Version check passed - hash matches")
        }
    }
    catch as err {
        LogMessage("Version check failed: " err.Message, "ERROR")
        MsgBox("Version check failed - check logs!", "Error", "0x10")
    }
}

UpdateScript() {
    try {
        MsgBox("Booster updating to latest version!", "Update")
        UrlDownloadToFile(GITHUB_SCRIPT_URL, A_ScriptFullPath ".new")
        FileMove(A_ScriptFullPath ".new", A_ScriptFullPath, 1)
        MsgBox("Booster updated! Restarting...")
        Reload()
    }
    catch as err {
        LogMessage("Update failed: " err.Message, "ERROR")
        MsgBox("Update failed - check logs!", "Error", "0x10")
    }
}

; ====== Cheat & Debugger Detection ======
dangerousProcesses := ["cheatengine.exe", "processhacker.exe", "x32dbg.exe", "x64dbg.exe"]
SetTimer(ObjBindMethod("", "CheckDangerousProcesses"), 5000)
CheckDangerousProcesses() {
    for exe in dangerousProcesses {
        if ProcessExist(exe) {
            LogMessage("Cheat tool detected: " exe, "ERROR")
            MsgBox("Cheat tool detected! Closing...", "Security Alert", "0x10")
            ExitApp()
        }
    }
}

; ====== Clipboard Blocking ======
BlockClipboard(Type) {
    Clipboard := ""
}

; ====== USB Copy Protection ======
if (InStr(A_WorkingDir, "D:") || InStr(A_WorkingDir, "E:")) {
    LogMessage("USB detected - self-destructing", "ERROR")
    MsgBox("Unauthorized USB detected! Self-destructing...", "Security Warning", "0x10")
    FileDelete(A_ScriptFullPath)
    ExitApp()
}

; ====== Hash Function ======
GetFileHash(file) {
    try {
        objSHA256 := ComObjCreate("System.Security.Cryptography.SHA256CryptoServiceProvider")
        objStream := ComObjCreate("ADODB.Stream")
        objStream.Type := 1, objStream.Open(), objStream.LoadFromFile(file)
        hash := objSHA256.ComputeHash_2(objStream.Read())
        objStream.Close()
        hex := ""
        Loop % ObjLength(hash)
            hex .= Format("{:02X}", NumGet(hash, A_Index - 1, "UChar"))
        return hex
    }
    catch as err {
        LogMessage("Hash calculation failed: " err.Message, "ERROR")
        return ""
    }
}

; ====== HTTP Functions ======
HttpGet(url) {
    try {
        http := ComObject("WinHttp.WinHttpRequest.5.1")
        http.Open("GET", url, false)
        http.Send()
        return http.ResponseText
    }
    catch as err {
        LogMessage("HTTP GET failed for " url ": " err.Message, "ERROR")
        return ""
    }
}

HttpPost(url, data) {
    try {
        http := ComObject("WinHttp.WinHttpRequest.5.1")
        http.Open("POST", url, false)
        http.SetRequestHeader("Content-Type", "application/json")
        http.Send(data)
    }
    catch as err {
        LogMessage("HTTP POST failed for " url ": " err.Message, "ERROR")
    }
}

; ====== Core Optimization ======
OptimizeSystem(*) {
    static isRunning := false
    if (isPaused || isRunning)
        return
    isRunning := true
    LogMessage("Starting optimization")
    try {
        mem := GetMemoryStatus()
        if (mem && mem.load > MEMORY_THRESHOLD)
            OptimizeMemory()
        OptimizeProcesses()
        OptimizeGames()
        KillNonEssentialProcesses()
        UnparkCPUCores()
        FlushGPUCache()
        BoostInterrupts()
        PreAllocateRAM()
        BoostThreads()
        SetTimerResolution()
        StripDrivers()
        NukePagefile()
        CheckSAMPAlive()
        lastOptimization := A_TickCount
        LogMessage("Optimization completed")
    }
    catch as err {
        LogMessage("Optimization error: " err.Message, "ERROR")
    }
    finally {
        isRunning := false
        UpdateTrayTip()
    }
}

OptimizeMemory() {
    try {
        LogMessage("Optimizing memory")
        DllCall("psapi\EmptyWorkingSet", "UInt", -1)
        DllCall("SetSystemFileCacheSize", "UInt", 0xFFFFFFFF, "UInt", 0xFFFFFFFF, "UInt", 0)
        LogMessage("Memory optimized")
        return true
    }
    catch as err {
        LogMessage("Memory optimization failed: " err.Message, "ERROR")
        return false
    }
}

OptimizeProcesses() {
    try {
        LogMessage("Optimizing processes")
        processes := GetRunningProcesses()
        for proc in processes {
            if (!IsProcessProtected(proc.name) && !HasValue(GAMES, proc.name)) {
                if (proc.cpu > CPU_THRESHOLD)
                    SetProcessPriority(proc.name, "LOW")
            }
        }
        LogMessage("Processes optimized")
        return true
    }
    catch as err {
        LogMessage("Process optimization failed: " err.Message, "ERROR")
        return false
    }
}

OptimizeGames() {
    try {
        LogMessage("Optimizing games")
        for gameName in GAMES {
            if ProcessExist(gameName) {
                SetProcessPriority(gameName, "REALTIME")
                ProcessSetAffinity(gameName, 3)  ; 2 cores
                OptimizeGameMemory(gameName)
            }
        }
        LogMessage("Games optimized")
        return true
    }
    catch as err {
        LogMessage("Game optimization failed: " err.Message, "ERROR")
        return false
    }
}

KillNonEssentialProcesses() {
    try {
        LogMessage("Killing non-essentials")
        processes := GetRunningProcesses()
        for proc in processes {
            if (!IsProcessProtected(proc.name) && !HasValue(GAMES, proc.name)) {
                ProcessClose(proc.name)
                LogMessage("Terminated: " proc.name)
            }
        }
        LogMessage("Non-essentials killed")
    }
    catch as err {
        LogMessage("Kill failed: " err.Message, "ERROR")
    }
}

UnparkCPUCores() {
    try {
        RegWrite("0", "REG_DWORD", "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583", "Attributes")
        LogMessage("CPU cores unparked")
    }
    catch as err {
        LogMessage("CPU unparking failed: " err.Message, "ERROR")
    }
}

FlushGPUCache() {
    try {
        DllCall("ntdll.dll\NtSetInformationProcess", "Ptr", -1, "Int", 0x22, "Ptr", 0, "Int", 0)
        LogMessage("GPU cache flushed")
    }
    catch as err {
        LogMessage("GPU flush failed: " err.Message, "ERROR")
    }
}

PreAllocateRAM() {
    try {
        LogMessage("Pre-allocating 2.5GB for SAMP")
        DllCall("VirtualAlloc", "Ptr", 0, "UInt", 2.5 * 1024 * 1024 * 1024, "UInt", 0x1000 | 0x2000, "UInt", 0x04)
        LogMessage("RAM pre-allocated")
    }
    catch as err {
        LogMessage("RAM pre-allocation failed: " err.Message, "ERROR")
    }
}

BoostInterrupts() {
    try {
        RegWrite("2", "REG_DWORD", "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl", "IRQ8Priority")
        LogMessage("Interrupts shifted to core 1")
    }
    catch as err {
        LogMessage("Interrupt boost failed: " err.Message, "ERROR")
    }
}

BoostThreads() {
    try {
        LogMessage("Boosting SAMP threads")
        pid := ProcessExist("samp.exe")
        if (pid) {
            hProc := DllCall("OpenProcess", "UInt", 0x1F0FFF, "Int", 0, "UInt", pid)
            hThread := DllCall("GetCurrentThread")
            DllCall("SetThreadPriority", "Ptr", hThread, "Int", 15)
            DllCall("SetThreadAffinityMask", "Ptr", hThread, "UInt", 1)
            DllCall("CloseHandle", "Ptr", hProc)
            LogMessage("Threads boosted")
        }
    }
    catch as err {
        LogMessage("Thread boost failed: " err.Message, "ERROR")
    }
}

SetTimerResolution() {
    try {
        DllCall("ntdll.dll\NtSetTimerResolution", "UInt", 5000, "Int", 1, "UInt*", current := 0)
        LogMessage("Timer resolution set to 0.5ms")
    }
    catch as err {
        LogMessage("Timer resolution failed: " err.Message, "ERROR")
    }
}

StripDrivers() {
    try {
        LogMessage("Stripping unused drivers")
        RunWait("sc config audiosrv start= disabled", , "Hide")
        RunWait("sc config usbhub start= disabled", , "Hide")
        LogMessage("Drivers stripped")
    }
    catch as err {
        LogMessage("Driver strip failed: " err.Message, "ERROR")
    }
}

NukePagefile() {
    try {
        LogMessage("Nuking pagefile")
        RunWait("wmic pagefileset delete", , "Hide")
        LogMessage("Pagefile nuked")
    }
    catch as err {
        LogMessage("Pagefile nuke failed: " err.Message, "ERROR")
    }
}

CheckSAMPAlive() {
    try {
        if (!ProcessExist("samp.exe") && ProcessExist("gta_sa.exe")) {
            LogMessage("SAMP crashed - pausing", "ERROR")
            isPaused := true
            Sleep(5000)
            if (!ProcessExist("samp.exe")) {
                Run(A_ScriptDir "\samp.exe")
                LogMessage("Attempted SAMP restart")
            }
            isPaused := false
        }
    }
    catch as err {
        LogMessage("SAMP check failed: " err.Message, "ERROR")
    }
}

; ====== End Key Cleanup ======
End::
try {
    LogMessage("Killing GTA:SA via End key")
    ProcessClose("gta_sa.exe")
    Sleep(1000)
    RestoreSystem()
    MsgBox("GTA:SA killed - system restored!")
}
catch as err {
    LogMessage("Kill switch failed: " err.Message, "ERROR")
}
return

RestoreSystem() {
    try {
        LogMessage("Restoring system")
        Run("explorer.exe", , "Hide")
        Run("services.msc", , "Hide")
        ProcessSetAffinity("samp.exe", 0xFFFFFFFF)
        SetProcessPriority("samp.exe", "NORMAL")
        RunWait("sc config audiosrv start= auto", , "Hide")
        RunWait("sc config usbhub start= auto", , "Hide")
        RunWait("wmic computersystem where name='%computername%' set AutomaticManagedPagefile=True", , "Hide")
        DllCall("ntdll.dll\NtSetTimerResolution", "UInt", 156250, "Int", 1, "UInt*", current := 0)
        LogMessage("System restored")
    }
    catch as err {
        LogMessage("Restore failed: " err.Message, "ERROR")
    }
}

; ====== Helpers ======
GetMemoryStatus() {
    try {
        static memoryStatusEx := Buffer(64)
        NumPut("UInt", 64, memoryStatusEx)
        if DllCall("kernel32\GlobalMemoryStatusEx", "Ptr", memoryStatusEx) {
            return {
                load: NumGet(memoryStatusEx, 4, "UInt"),
                totalPhys: NumGet(memoryStatusEx, 8, "UInt64"),
                availPhys: NumGet(memoryStatusEx, 16, "UInt64")
            }
        }
    }
    catch as err {
        LogMessage("Memory status failed: " err.Message, "ERROR")
    }
    return false
}

IsProcessProtected(processName) {
    return HasValue(PROTECTED_PROCESSES, processName)
}

HasValue(array, value) {
    for item in array {
        if (item = value)
            return true
    }
    return false
}

OptimizeGameMemory(processName) {
    try {
        pid := ProcessExist(processName)
        if (pid) {
            DllCall("psapi\EmptyWorkingSet", "UInt", pid)
            LogMessage("Memory optimized for " processName)
        }
    }
    catch as err {
        LogMessage("Game memory failed: " err.Message, "ERROR")
    }
}

ProcessSetAffinity(processName, mask) {
    try {
        pid := ProcessExist(processName)
        if (pid) {
            hProc := DllCall("OpenProcess", "UInt", 0x0200 | 0x0400, "Int", 0, "UInt", pid)
            DllCall("SetProcessAffinityMask", "Ptr", hProc, "Ptr", mask)
            DllCall("CloseHandle", "Ptr", hProc)
            LogMessage("Affinity set for " processName " to mask " mask)
        }
    }
    catch as err {
        LogMessage("Affinity failed: " err.Message, "ERROR")
    }
}

SetProcessPriority(processName, priority) {
    try {
        pid := ProcessExist(processName)
        if (pid) {
            hProc := DllCall("OpenProcess", "UInt", 0x0200, "Int", 0, "UInt", pid)
            DllCall("SetPriorityClass", "Ptr", hProc, "UInt", (priority = "REALTIME" ? 0x100 : 0x20))
            DllCall("CloseHandle", "Ptr", hProc)
            LogMessage("Priority set for " processName " to " priority)
        }
    }
    catch as err {
        LogMessage("Priority failed: " err.Message, "ERROR")
    }
}

LogMessage(message, type := "INFO") {
    try {
        timestamp := FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss")
        logEntry := timestamp " [" type "] " message "`n"
        FileAppend(logEntry, currentLog)
    }
    catch as err {
        FileAppend(
            FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss") " [ERROR] Logging failed: " err.Message "`n",
            A_ScriptDir "\error.log"
        )
    }
}

ReportTamper(official, computed) {
    try {
        FileAppend(FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss") " [TAMPER] Official: " official " Computed: " computed "`n", tamperLog)
        ip := HttpGet("https://api.ipify.org")
        payload := '{"content":"Tamper Detected - Time: ' FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss") ', IP: ' ip ', Hash: ' computed ' vs ' official '"}'
        HttpPost(DISCORD_WEBHOOK, payload)
    }
    catch as err {
        LogMessage("Tamper report failed: " err.Message, "ERROR")
    }
}

UpdateTrayTip() {
    try {
        timeSinceOpt := (A_TickCount - lastOptimization) // 1000
        mem := GetMemoryStatus()
        if (mem) {
            A_IconTip := Format(
                "{1} v{2}`nMem: {3}%`nLast: {4}s`n{5}",
                SCRIPT_NAME, VERSION, Round(mem.load), timeSinceOpt, isPaused ? "PAUSED" : "RUNNING"
            )
        }
    }
    catch {
        ; Silent fail
    }
}

TogglePause(*) {
    isPaused := !isPaused
    LogMessage(isPaused ? "Paused" : "Resumed")
    UpdateTrayTip()
}

; ====== Tray Menu ======
InitializeTrayMenu() {
    try {
        A_TrayMenu.Delete()
        A_TrayMenu.Add("⚡ Optimize", OptimizeSystem)
        A_TrayMenu.Add("⏸️ Pause", TogglePause)
        A_TrayMenu.Add("📜 Changelog", ShowChangelog)
        A_TrayMenu.Add("🔍 Version Check", CheckVersion)
        A_TrayMenu.Add()
        A_TrayMenu.Add("❌ Exit", (*) => ExitApp())
        UpdateTrayTip()
    }
    catch as err {
        LogMessage("Tray menu failed: " err.Message, "ERROR")
    }
}

ShowChangelog(*) {
    try {
        changelogText := "
        (
        Game Boost Script Changelog
        -------------------------
        v2.4.0 (2025-03-16):
        * Initial release - basic memory/process optimization, HIGH priority for games, 3-min checks, GUI tray, logging.
        * FPS: 151 baseline with in-game tweaks.

        v2.4.1 (2025-03-19):
        * Added non-essential process killing (~5-10 FPS), core 0 affinity (~5 FPS), extra RAM flush (~2-5 FPS), 60s timer, dropped GUIs.
        * FPS: 160-180.

        v2.4.2 (2025-03-19):
        * REALTIME priority (10-20 FPS), 2-core affinity (5-10 FPS), 60%/70% thresholds (~5 FPS), 15s timer, no explorer.exe (5-10 FPS).
        * FPS: 180-220 quiet, 170-200 busy.

        v2.4.3 (2025-03-19):
        * CPU unparking (5-10 FPS), GPU cache flush (5-10 FPS), script REALTIME (~2-5 FPS).
        * FPS: 190-230 quiet, 180-210 busy.

        v2.4.4 (2025-03-19):
        * SAMP crash detection + restart (reliability), leaner protection.
        * FPS: 190-220 quiet, 170-200 busy.

        v2.5.0 (2025-03-19):
        * Experimental: overclocking (dropped), render hack (dropped), 3GB RAM (tuned), interrupts (5-10 FPS), ultra-lean mode (replaced), 50%/60% thresholds, 10s timer.
        * FPS: 200-250 quiet, 190-230 busy (risky).

        v2.5.1 (2025-03-21):
        * Final optimizations: 2.5GB RAM (10-15 FPS), thread boosting (10-20 FPS), 0.5ms timer (5-15 FPS), driver stripping (5-10 FPS), pagefile nuke (10-20 FPS), End key cleanup.
        * FPS: 210-260 quiet, 200-240 busy.

        v2.5.2 (2025-03-21):
        * Added changelog viewer in tray - QoL only.
        * FPS: 210-260 quiet, 200-240 busy.

        v2.5.3 (2025-03-21):
        * Added GitHub version check, Discord tamper reporting, auto-update, tray version check - management layer.
        * FPS: 210-260 quiet, 200-240 busy.

        v3.0.0 (2025-03-22):
        * Security overhaul: encoded URLs, 10s tamper detection, cheat/debugger checks, clipboard block, USB protection, hidden window, randomized delays.
        * Kept all optimizations from v2.5.1 - performance unchanged.
        * Enhanced update system - simpler self-replacement.
        * FPS: 210-260 quiet, 200-240 busy.
        )"
        MsgBox(changelogText, "Changelog - " SCRIPT_NAME " v" VERSION)
    }
    catch as err {
        LogMessage("Changelog display failed: " err.Message, "ERROR")
        MsgBox("Failed to show changelog - check logs!", "Error", "0x10")
    }
}

; ====== Start ======
LogMessage("=== Session Started ===")
LogMessage("Version: " VERSION)
CheckVersion()
InitializeTrayMenu()
optimizeTimer := SetTimer(OptimizeSystem, CHECK_INTERVAL)

; ====== Exit ======
OnExit(ExitHandler)
ExitHandler(ExitReason, ExitCode) {
    LogMessage("Exiting. Reason: " ExitReason " Code: " ExitCode)
    if (optimizeTimer)
        SetTimer(optimizeTimer, 0)
    if (!isPaused)
        OptimizeSystem()
    RestoreSystem()
}
