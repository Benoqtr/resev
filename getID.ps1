#region Restore Proxy Function (using $script: scope to access saved variables)
function Restore-Proxy {
    Write-Host "Restoring original proxy settings..." -ForegroundColor Cyan
    # Check if script scope variables exist using Get-Variable
    $oldEnableExists = Get-Variable -Name 'oldProxyEnable' -Scope 'Script' -ErrorAction SilentlyContinue
    $oldServerExists = Get-Variable -Name 'oldProxyServer' -Scope 'Script' -ErrorAction SilentlyContinue

    if ($oldEnableExists) {
         # Restore ProxyEnable using saved value
         try {
             Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value $script:oldProxyEnable -ErrorAction Stop
             Write-Host "  Restored ProxyEnable to: $($script:oldProxyEnable)"
         }
         catch {
              Write-Warning "Failed to restore ProxyEnable: $($_.Exception.Message)"
         }
    }
    else {
         Write-Host "No saved original ProxyEnable value found, skipping restore."
    }

    if ($oldServerExists) {
         # Restore ProxyServer using saved value (if it had a value)
         if (-not [string]::IsNullOrEmpty($script:oldProxyServer)) {
             try {
                 Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value $script:oldProxyServer -ErrorAction Stop
                 Write-Host "  Restored ProxyServer to: $($script:oldProxyServer)"
             }
             catch {
                  Write-Warning "Failed to restore ProxyServer: $($_.Exception.Message)"
             }
         }
         else {
             # If original value was empty, remove the registry key
             Write-Host "  Original ProxyServer was empty, attempting to remove registry key..."
             Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -ErrorAction SilentlyContinue
         }
    }
    else {
         Write-Host "No saved original ProxyServer value found, skipping restore."
    }
    Write-Host "Original proxy settings have been attempted to restore." -ForegroundColor Green
}
#endregion

#region Global Exception Handling and Resource Cleanup
trap [Exception] {
    Write-Warning "Unexpected error occurred during script execution: $($_.Exception.Message)"
    Write-Warning "  Error occurred at: $($_.InvocationInfo.ScriptName) - Line: $($_.InvocationInfo.ScriptLineNumber)"

    # --- Cleanup potential temp python script on error ---
    if (Get-Variable -Name 'tempScriptPath' -Scope 'Script' -ErrorAction SilentlyContinue) {
        if ($script:tempScriptPath -and (Test-Path $script:tempScriptPath)) {
            Write-Host "DEBUG: Cleaning up temporary script file from trap: $script:tempScriptPath"
            Remove-Item -Path $script:tempScriptPath -Force -ErrorAction SilentlyContinue
        }
    }

    # --- Always attempt to restore proxy on error, ONLY IF it was potentially set ---
    # Check if the saving variables exist, implying we might have changed the proxy
    if ((Get-Variable -Name 'oldProxyEnable' -Scope 'Script' -ErrorAction SilentlyContinue) -or `
        (Get-Variable -Name 'oldProxyServer' -Scope 'Script' -ErrorAction SilentlyContinue)) {
        Write-Host "DEBUG: Error occurred, attempting proxy restore from trap..."
        Restore-Proxy
    }
    else {
        Write-Host "DEBUG: Error occurred before proxy settings were saved/modified, skipping restore from trap."
    }

    Read-Host "Error occurred, press Enter to exit..."
    exit 1
}
#endregion

#region File Download Helper Function
function DownloadFileIfNeeded {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileUrl,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $FileName = Split-Path -Path $DestinationPath -Leaf

    if (-not (Test-Path $DestinationPath)) {
        Write-Host "File '$FileName' does not exist, attempting to download from $FileUrl..." -ForegroundColor Yellow
        try {
            # Use Invoke-WebRequest to download file - it will use current system proxy settings (if any)
            Write-Host "  (Using current system network settings for download...)"
            Invoke-WebRequest -Uri $FileUrl -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
            Write-Host "File '$FileName' downloaded successfully, saved to: $DestinationPath" -ForegroundColor Green
            return $true # Indicates successful download
        }
        catch {
            Write-Warning "Failed to download file '$FileName': $($_.Exception.Message)"
            if (Test-Path $DestinationPath) { Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue }
            return $false # Indicates download failure
        }
    }
    else {
        Write-Host "File '$FileName' already exists at: $DestinationPath"
        return $true # Indicates file already exists
    }
}
#endregion

# --- Python Script Content ---
$pythonScriptContent = @"
from mitmproxy import http, ctx
import asyncio
import os

script_dir = os.environ.get('MITMPROXY_SCRIPT_DIR', '.')
output_file = os.path.join(script_dir, "ID.txt")

print("'confused about Chinese error'")
print("'interactivate whith gym in Wecom'")
print("'interactivate whith gym in Wecom'")
print("'interactivate whith gym in Wecom'")
SESSION_FOUND = False

def request(flow: http.HTTPFlow):
    global SESSION_FOUND
    if SESSION_FOUND: return
    if flow.request.pretty_host != "reservation.bupt.edu.cn": return

    cookie_header = flow.request.headers.get("Cookie", "")
    if "PHPSESSID=" in cookie_header:
        parts = cookie_header.split(";")
        for part in parts:
            part = part.strip()
            if part.startswith("PHPSESSID="):
                phpsessid = part.split("=", 1)[1].split(",", 1)[0].strip()
                if phpsessid and phpsessid.isalnum() and len(phpsessid) > 10:
                    try:
                        with open(output_file, "w", encoding="utf-8") as f: f.write(phpsessid)
                        print(f"[YES] CATCHED PHPSESSID: {phpsessid},WRITE INTO {output_file}")
                        SESSION_FOUND = True
                    except Exception as e:
                        print(f"[NO] WRITE INTO {output_file} ERROR:{e}")
                else:
                    print(f"[?] INVALID PHPSESSID: '{phpsessid}'")
                return

def response(flow: http.HTTPFlow):
    if SESSION_FOUND:
        loop = asyncio.get_event_loop()
        if loop.is_running(): loop.call_later(5, ctx.master.shutdown)
        else: ctx.master.shutdown()
"@

function Main {
    param (
        [string]$PassedScriptDir = $null
    )

    try {
        # --- Robust Script Directory Determination ---
        $ScriptDir = $null
        
        # Check if script is executed via irm|iex
        $isIrmExecution = $MyInvocation.InvocationName -eq '.' -or $MyInvocation.InvocationName -eq ''
        
        if ($isIrmExecution) {
            Write-Host "Script appears to be executed via irm|iex, using temporary directory..." -ForegroundColor Yellow
            # Create temporary directory
            $tempDir = Join-Path $env:TEMP "getID_temp_$(Get-Random)"
            if (-not (Test-Path $tempDir)) {
                New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
            }
            $ScriptDir = $tempDir
            Write-Host "Using temporary directory: $ScriptDir"
        }
        else {
            # Normal file execution method
            if ($PSScriptRoot) { 
                $ScriptDir = $PSScriptRoot 
                Write-Host "Using PSScriptRoot: $ScriptDir"
            }
            elseif ($MyInvocation.MyCommand.Path) { 
                $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path 
                Write-Host "Using MyInvocation.MyCommand.Path: $ScriptDir"
            }
            elseif ($PassedScriptDir -and (Test-Path $PassedScriptDir -PathType Container)) { 
                $ScriptDir = $PassedScriptDir 
                Write-Host "Using PassedScriptDir: $ScriptDir"
            }
            else {
                # If still cannot determine, try using current directory
                $ScriptDir = Get-Location
                Write-Host "Using current directory: $ScriptDir"
            }
        }
        
        if (-not $ScriptDir) { 
            Write-Error "Cannot determine script directory"; 
            Read-Host "Press Enter to exit..."; 
            exit 1 
        }
        
        if (-not (Test-Path $ScriptDir -PathType Container)) { 
            Write-Error "Invalid script directory: $ScriptDir"; 
            Read-Host "Press Enter to exit..."; 
            exit 1 
        }
        
        Write-Host "DEBUG: Final Script Directory confirmed as: '$ScriptDir'"

        #region Elevate to Administrator (if needed and possible)
        $currIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currIdentity)
        if (-not $currPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Host "Current user is not an administrator, attempting to rerun script as administrator..." -ForegroundColor Yellow
            
            # If executed via irm|iex, cannot restart as administrator
            if ($isIrmExecution) {
                Write-Warning "Cannot elevate to administrator when running via irm|iex. Please download the script and run it directly."
                Write-Warning "Continuing without administrator privileges, some features may not work correctly."
                # Do not exit, continue execution but with limited functionality
            }
            else {
                # Try multiple methods to get script path
                $scriptFullPath = $null
                
                # Method 1: Use $PSCommandPath
                if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
                    $scriptFullPath = $PSCommandPath
                    Write-Host "Using PSCommandPath: $scriptFullPath"
                }
                # Method 2: Use $MyInvocation
                elseif ($MyInvocation.MyCommand.Path -and (Test-Path $MyInvocation.MyCommand.Path)) {
                    $scriptFullPath = $MyInvocation.MyCommand.Path
                    Write-Host "Using MyInvocation.MyCommand.Path: $scriptFullPath"
                }
                # Method 3: Use $PSScriptRoot
                elseif ($PSScriptRoot) {
                    $scriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
                    $scriptFullPath = Join-Path -Path $PSScriptRoot -ChildPath $scriptName
                    if (Test-Path $scriptFullPath) {
                        Write-Host "Using PSScriptRoot + script name: $scriptFullPath"
                    } else {
                        $scriptFullPath = $null
                    }
                }
                
                if ($scriptFullPath -and (Test-Path $scriptFullPath)) {
                    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptFullPath`" -PassedScriptDir `"$ScriptDir`""
                    Write-Host "Attempting to restart with admin privileges using: $scriptFullPath"
                    try { 
                        Start-Process powershell -Verb runAs -ArgumentList $arguments -ErrorAction Stop
                        Write-Host "Successfully launched new process with admin privileges."
                        exit 0 
                    }
                    catch { 
                        Write-Warning "Failed to rerun script as administrator: $($_.Exception.Message)"
                        Write-Warning "Continuing without administrator privileges, some features may not work correctly."
                        # Do not exit, continue execution but with limited functionality
                    }
                }
                else { 
                    Write-Warning "Cannot find current script path. Continuing without administrator privileges."
                    Write-Warning "Some features may not work correctly. Please run this script directly from its location."
                    # Do not exit, continue execution but with limited functionality
                }
            }
        }
        else { Write-Host "Already running with administrator privileges." -ForegroundColor Green }
        #endregion

        Write-Host "Current script directory is: $ScriptDir"

        # --- V V V Modified Order V V V ---

        #region 1. Check and Download Dependencies (Certificate) - Before Modifying Proxy
        $certUrl = "https://raw.githubusercontent.com/Benoqtr/resev/main/mitmproxy-ca-cert.p12"
        $certPath = Join-Path -Path $ScriptDir -ChildPath "mitmproxy-ca-cert.p12"
        # If download fails (function returns $false), don't continue with critical steps
        if (-not (DownloadFileIfNeeded -FileUrl $certUrl -DestinationPath $certPath)) {
             Write-Warning "Certificate file could not be downloaded or found, but script will attempt to continue (certificate installation step will be skipped)."
             # Don't force exit as certificate is not absolutely required to run mitmdump (though it will cause HTTPS errors)
        }
        #endregion

        #region 2. Install mitmproxy Certificate (if exists) - Before Modifying Proxy
        if (Test-Path $certPath) {
            try {
                Write-Host "Checking mitmproxy root certificate..."
                $plainPassword = $null # If p12 file has password, fill in string here

                $certToImport = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                if ([string]::IsNullOrWhiteSpace($plainPassword)) {
                    $certToImport.Import($certPath) # Import without password
                }
                else {
                    # More standard way to handle password for PFX import
                    $certToImport.Import($certPath, $plainPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                }

                $thumbprint = $certToImport.Thumbprint
                # Check if certificate already exists in target store (current user's root certificates)
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
                $store.Open("ReadOnly")
                # Use correct FindType enum and parameters to find certificate
                $existing = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumbprint, $false) # $false means don't find invalid certificates
                $store.Close()

                if ($existing.Count -gt 0) {
                    Write-Host "Certificate (Thumbprint: $thumbprint) already exists in Current User's Trusted Root Certification Authorities store, skipping installation." -ForegroundColor Green
                }
                else {
                    Write-Host "Importing mitmproxy root certificate to Current User's Trusted Root Certification Authorities store..." -ForegroundColor Yellow
                    # Open store for writing
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
                    $store.Open("ReadWrite")
                    $store.Add($certToImport)
                    $store.Close()

                    # Verify import success
                    $storeVerify = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
                    $storeVerify.Open("ReadOnly")
                    # Use correct FindType enum and parameters to find again for verification
                    $check = $storeVerify.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumbprint, $false)
                    $storeVerify.Close()

                    if ($check.Count -gt 0) {
                        Write-Host "Certificate import successful (Thumbprint: $thumbprint)." -ForegroundColor Green
                    }
                    else {
                        Write-Warning "Certificate import verification failed!"
                    }
                }
            }
            catch {
                Write-Warning "Error processing certificate: $($_.Exception.Message)"
                # Can add more detailed error information here, e.g. $_.ScriptStackTrace
            }
        }
        else {
            Write-Warning "Skipping certificate installation as file '$certPath' does not exist."
        }
        #endregion

        #region 3. Check and Download Dependencies (mitmdump) - Before Modifying Proxy
        $mitmdumpUrl = "https://raw.githubusercontent.com/Benoqtr/resev/main/mitmdump.exe"
        $mitmdumpPath = Join-Path -Path $ScriptDir -ChildPath "mitmdump.exe"
        # If mitmdump download fails (function returns $false), cannot continue, exit directly
        if (-not (DownloadFileIfNeeded -FileUrl $mitmdumpUrl -DestinationPath $mitmdumpPath)) {
             Write-Error "Critical dependency 'mitmdump.exe' could not be downloaded or found. Script cannot continue."
             Read-Host "Press Enter to exit..."
             exit 1 # Exit directly as proxy hasn't been modified, so no need to restore
        }
        #endregion

        # --- Files prepared, now can modify proxy ---

        #region 4. Save Current Proxy Settings for Restoration
        Write-Host "Saving current proxy settings..."
        $script:oldProxyEnable = $null
        $script:oldProxyServer = $null
        try {
            $initialProxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
            if ($initialProxySettings) {
                if ($initialProxySettings.PSObject.Properties.Name -contains 'ProxyEnable') { $script:oldProxyEnable = $initialProxySettings.ProxyEnable; Write-Host "  Original proxy enable state saved: $($script:oldProxyEnable)" } else { $script:oldProxyEnable = 0; Write-Host "  ProxyEnable not found, assuming 0." }
                if ($initialProxySettings.PSObject.Properties.Name -contains 'ProxyServer') { $script:oldProxyServer = $initialProxySettings.ProxyServer; Write-Host "  Original proxy server saved: $($script:oldProxyServer)" } else { $script:oldProxyServer = ""; Write-Host "  ProxyServer not found, assuming empty." }
            }
            else { $script:oldProxyEnable = 0; $script:oldProxyServer = ""; Write-Host "  Could not read registry key, assuming default values." }
        }
        catch {
             Write-Warning "Error saving original proxy settings: $($_.Exception.Message)"; $script:oldProxyEnable = 0; $script:oldProxyServer = ""; Write-Warning "  Will use default values for restoration."
        }
        #endregion

        #region 5. Set Proxy
        Write-Host "Setting temporary system proxy to 127.0.0.1:8080..." -ForegroundColor Yellow
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1 -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080" -ErrorAction Stop
            Write-Host "Temporary proxy has been set." -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to set temporary proxy: $($_.Exception.Message)."
            # Try to restore to just saved state
            Write-Warning "Attempting to restore original proxy settings..."
            Restore-Proxy
            Read-Host "Failed to set proxy, original settings restored. Press Enter to exit..."
            exit 1 # Exit as cannot set proxy
        }
        #endregion

        #region 6. Launch mitmproxy (using temporary Python script)
        $script:tempScriptPath = Join-Path $ScriptDir "_temp_mitm_extract_session.py"
        # Ensure working directory is correct
        try { 
            Set-Location $ScriptDir -ErrorAction Stop 
        } 
        catch { 
            Write-Error "Cannot set working directory"; 
            Restore-Proxy; 
            Read-Host "Press Enter to exit..."; 
            exit 1 
        }

        # mitmdumpPath is now definitely valid
        $mitmPath = $mitmdumpPath

        # --- Create Temp Python Script ---
        Write-Host "Creating temporary mitmproxy script: $script:tempScriptPath"
        try {
            $env:MITMPROXY_SCRIPT_DIR = $ScriptDir
            $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllLines($script:tempScriptPath, $pythonScriptContent, $Utf8NoBomEncoding)
            Write-Host "Temporary script created successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create temporary mitmproxy script: $($_.Exception.Message)"
            Restore-Proxy # Need to restore proxy
            Read-Host "Failed to create temporary script, press Enter to exit..."
            exit 1
        }

        # --- Launch mitmproxy using the temp script ---
        $mitmExecutable = Split-Path $mitmPath -Leaf
        try {
            Write-Host "Preparing to launch $mitmExecutable (using temporary script)..." -ForegroundColor Cyan
            $arguments = @( "-s", "`"$script:tempScriptPath`"", "--set", "block_global=false" )
            Write-Host "  Will use the following command: `"$mitmPath`" $($arguments -join ' ')"
            $env:MITMPROXY_SCRIPT_DIR = $ScriptDir
            $processInfo = Start-Process -FilePath "$mitmPath" -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
            Write-Host "$mitmExecutable has exited (Exit Code: $($processInfo.ExitCode))."
        }
        catch {
            Write-Warning "Failed to launch ${mitmExecutable}: $($_.Exception.Message)"
            # Restore-Proxy will be called in finally
        }
        finally {
            # --- Cleanup Temp Python Script ---
            if ($script:tempScriptPath -and (Test-Path $script:tempScriptPath)) {
                Write-Host "Cleaning up temporary mitmproxy script: $script:tempScriptPath"
                Remove-Item -Path $script:tempScriptPath -Force -ErrorAction SilentlyContinue
            }
            if ($env:MITMPROXY_SCRIPT_DIR) { 
                Remove-Item Env:\MITMPROXY_SCRIPT_DIR -ErrorAction SilentlyContinue 
            }
            # Don't restore proxy here, moved to end of Main function
        }
        #endregion

        # --- Restore Proxy after mitmproxy execution ---
        Write-Host "DEBUG: Reached end of Main function logic, calling Restore-Proxy..."
        Restore-Proxy

        Write-Host "Main function execution completed." -ForegroundColor Green
    }
    catch {
        Write-Error "Error occurred during Main function execution: $($_.Exception.Message)"
        Write-Error "Error occurred at: $($_.InvocationInfo.ScriptName) - Line: $($_.InvocationInfo.ScriptLineNumber)"
        Restore-Proxy
        Read-Host "Error occurred, press Enter to exit..."
        exit 1
    }
}

try {
    # Check if script is executed via irm|iex
    $isIrmExecution = $MyInvocation.InvocationName -eq '.' -or $MyInvocation.InvocationName -eq ''
    
    if ($isIrmExecution) {
        Write-Host "Script appears to be executed via irm|iex, using temporary directory..." -ForegroundColor Yellow
        # Create temporary directory
        $tempDir = Join-Path $env:TEMP "getID_temp_$(Get-Random)"
        if (-not (Test-Path $tempDir)) {
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        }
        $scriptDir = $tempDir
        Write-Host "Using temporary directory: $scriptDir"
        
        # Directly call Main function, not through PSBoundParameters
        Main -PassedScriptDir $scriptDir
    }
    else {
        # Normal call method
        Main @PSBoundParameters
    }
}
catch {
    Write-Error "Unhandled exception caught at script top level: $($_.Exception.Message)"
    # Trap handler (if triggered) should have attempted to restore proxy
}
finally {
    Write-Host "Entering script end finally block."

    # Final proxy restoration check (just in case)
    if ((Get-Variable -Name 'oldProxyEnable' -Scope 'Script' -ErrorAction SilentlyContinue) -or `
        (Get-Variable -Name 'oldProxyServer' -Scope 'Script' -ErrorAction SilentlyContinue)) {
         Write-Host "DEBUG: Final check in top-level finally block, ensuring proxy is restored..."
         Restore-Proxy
    }
    else {
         Write-Host "DEBUG: No saved proxy state found in top-level finally, skipping restore."
    }

    # Final temporary file cleanup check
    if (Get-Variable -Name 'tempScriptPath' -Scope 'Script' -ErrorAction SilentlyContinue) {
        if ($script:tempScriptPath -and (Test-Path $script:tempScriptPath)) {
            Write-Host "DEBUG: Final cleanup check for temporary script file: $script:tempScriptPath"
            Remove-Item -Path $script:tempScriptPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Script execution completed or encountered issues." -ForegroundColor Cyan
    
    # Read and display ID.txt content if it exists
    $idFilePath = Join-Path -Path $ScriptDir -ChildPath "ID.txt"
    Write-Host "`nChecking for ID.txt at: $idFilePath" -ForegroundColor Cyan
    
    # List all files in the script directory to help diagnose
    Write-Host "Files in script directory:" -ForegroundColor Cyan
    Get-ChildItem -Path $ScriptDir | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor Gray
    }
    
    if (Test-Path $idFilePath) {
        Write-Host "`n=== ID.txt Content ===" -ForegroundColor Green
        $idContent = Get-Content -Path $idFilePath -ErrorAction SilentlyContinue
        if ($idContent) {
            Write-Host "ID: $idContent" -ForegroundColor Yellow
            
            # Copy ID.txt to Downloads folder
            $DownloadsPath = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
            $destPath = Join-Path -Path $DownloadsPath -ChildPath "ID.txt"
            
            try {
                Copy-Item -Path $idFilePath -Destination $destPath -Force -ErrorAction Stop
                Write-Host "ID.txt has been copied to: $destPath" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to copy ID.txt to Downloads folder: $($_.Exception.Message)"
            }
        } else {
            Write-Host "ID.txt exists but is empty." -ForegroundColor Yellow
        }
        Write-Host "=====================`n" -ForegroundColor Green
    } else {
        Write-Host "`nID.txt file not found at: $idFilePath" -ForegroundColor Red
        
        # Check if the file might be in the current directory
        $currentDirIdPath = Join-Path -Path (Get-Location) -ChildPath "ID.txt"
        if (Test-Path $currentDirIdPath) {
            Write-Host "Found ID.txt in current directory instead:" -ForegroundColor Yellow
            $idContent = Get-Content -Path $currentDirIdPath -ErrorAction SilentlyContinue
            if ($idContent) {
                Write-Host "ID: $idContent" -ForegroundColor Yellow
                
                # Copy ID.txt to Downloads folder
                $DownloadsPath = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
                $destPath = Join-Path -Path $DownloadsPath -ChildPath "ID.txt"
                
                try {
                    Copy-Item -Path $currentDirIdPath -Destination $destPath -Force -ErrorAction Stop
                    Write-Host "ID.txt has been copied to: $destPath" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Failed to copy ID.txt to Downloads folder: $($_.Exception.Message)"
                }
            } else {
                Write-Host "ID.txt exists but is empty." -ForegroundColor Yellow
            }
        }
    }
    
    if (-not ($env:CI -eq $true -or $env:TF_BUILD -eq $true -or $MyInvocation.PipeLinePosition -gt 1)) {
        if ($Host.UI.RawUI.KeyAvailable) { 
            Write-Host "Press any key to exit..." -NoNewline; 
            $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null 
        }
        else { 
            Read-Host "Press Enter to exit..." 
        }
    }
}
