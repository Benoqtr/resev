#Requires -Version 3.0

#region 恢复代理函数（使用 $script: 作用域访问保存的变量）
function Restore-Proxy {
    Write-Host "`n🧹 正在恢复原始代理设置..." -ForegroundColor Cyan
    # 使用 Get-Variable 检查脚本作用域变量是否存在
    $oldEnableExists = Get-Variable -Name 'oldProxyEnable' -Scope 'Script' -ErrorAction SilentlyContinue
    $oldServerExists = Get-Variable -Name 'oldProxyServer' -Scope 'Script' -ErrorAction SilentlyContinue

    if ($oldEnableExists) {
         # 恢复 ProxyEnable 使用保存的值
         try {
             Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value $script:oldProxyEnable -ErrorAction Stop
             Write-Host "  已恢复 ProxyEnable 为: $($script:oldProxyEnable)"
         } catch {
              Write-Warning "❌ 恢复 ProxyEnable 失败: $($_.Exception.Message)"
         }
    } else {
         Write-Host "⚠️ 未找到保存的原始 ProxyEnable 值，跳过恢复。"
    }

    if ($oldServerExists) {
         # 恢复 ProxyServer 使用保存的值 (如果它原本有值)
         if (-not [string]::IsNullOrEmpty($script:oldProxyServer)) {
             try {
                 Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value $script:oldProxyServer -ErrorAction Stop
                 Write-Host "  已恢复 ProxyServer 为: $($script:oldProxyServer)"
             } catch {
                  Write-Warning "❌ 恢复 ProxyServer 失败: $($_.Exception.Message)"
             }
         } else {
             # 如果原始值是空的，则移除该键值
             Write-Host "  原始 ProxyServer 为空，尝试移除注册表键..."
             Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -ErrorAction SilentlyContinue
         }
    } else {
         Write-Host "⚠️ 未找到保存的原始 ProxyServer 值，跳过恢复。"
    }
    Write-Host "✅ 原代理设置已尝试恢复。" -ForegroundColor Green
}
#endregion

#region 全局异常处理与资源清理
trap [Exception] {
    Write-Warning "❌ 脚本执行过程中发生意外错误: $($_.Exception.Message)"
    Write-Warning "  错误发生在: $($_.InvocationInfo.ScriptName) - Line: $($_.InvocationInfo.ScriptLineNumber)"

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
    } else {
        Write-Host "DEBUG: Error occurred before proxy settings were saved/modified, skipping restore from trap."
    }

    Read-Host "发生错误，按 Enter 键退出..."
    exit 1
}
#endregion

#region 文件下载辅助函数
function Download-FileIfNeeded {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FileUrl,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )

    $FileName = Split-Path -Path $DestinationPath -Leaf

    if (-not (Test-Path $DestinationPath)) {
        Write-Host "⏳ 文件 '$FileName' 不存在，正在尝试从 $FileUrl 下载..." -ForegroundColor Yellow
        try {
            # 使用 Invoke-WebRequest 下载文件 - 它将使用当前的系统代理设置（如果存在）
            Write-Host "  (使用当前系统网络设置进行下载...)"
            Invoke-WebRequest -Uri $FileUrl -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
            Write-Host "✅ 文件 '$FileName' 下载成功，已保存到: $DestinationPath" -ForegroundColor Green
            return $true # 表示下载成功
        } catch {
            Write-Warning "❌ 下载文件 '$FileName' 失败: $($_.Exception.Message)"
            if (Test-Path $DestinationPath) { Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue }
            return $false # 表示下载失败
        }
    } else {
        Write-Host "👍 文件 '$FileName' 已存在于: $DestinationPath"
        return $true # 表示文件已存在
    }
}
#endregion


function Main {
    param (
        [string]$PassedScriptDir = $null
    )

    # --- Python Script Content ---
$pythonScriptContent = @'
from mitmproxy import http, ctx
import asyncio
import os

script_dir = os.environ.get('MITMPROXY_SCRIPT_DIR', '.')
output_file = os.path.join(script_dir, "ID.txt")

print('\n请打开企业微信，与体育馆进行交互\n\n')

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
                        print(f"[✓] 抓到 PHPSESSID: {phpsessid}，已写入 {output_file}")
                        SESSION_FOUND = True
                    except Exception as e:
                        print(f"[X] 写入文件 {output_file} 时出错: {e}")
                else:
                    print(f"[*] 提取到的 PHPSESSID 无效或太短: '{phpsessid}'")
                return

def response(flow: http.HTTPFlow):
    if SESSION_FOUND:
        loop = asyncio.get_event_loop()
        if loop.is_running(): loop.call_later(5, ctx.master.shutdown)
        else: ctx.master.shutdown()
'@

    # --- Robust Script Directory Determination ---
    $ScriptDir = $null
    # ... (代码与之前相同) ...
    if ($PSScriptRoot) { $ScriptDir = $PSScriptRoot }
    elseif ($MyInvocation.MyCommand.Path) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    elseif ($PassedScriptDir -and (Test-Path $PassedScriptDir -PathType Container)) { $ScriptDir = $PassedScriptDir }
    else { Write-Error "..."; Read-Host "..."; exit 1 }
    if (-not (Test-Path $ScriptDir -PathType Container)) { Write-Error "..."; Read-Host "..."; exit 1 }
    Write-Host "DEBUG: Final Script Directory confirmed as: '$ScriptDir'"
    # ... (获取当前工作目录的代码) ...

    #region 提权为管理员（如果需要且可能）
    # ... (代码与之前相同) ...
    $currIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currIdentity)
    if (-not $currPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # ... (尝试提权的代码) ...
        Write-Host "当前用户非管理员，尝试以管理员身份重新运行脚本..." -ForegroundColor Yellow
        if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
             $scriptFullPath = $PSCommandPath
             $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptFullPath`" -PassedScriptDir `"$ScriptDir`""
             try { Start-Process powershell -Verb runAs -ArgumentList $arguments -ErrorAction Stop; exit 0 }
             catch { Write-Error "..."; Read-Host "..."; exit 1 }
        } else { Write-Error "..."; Read-Host "..."; exit 1 }
    } else { Write-Host "✅ 当前已是管理员权限。" -ForegroundColor Green }
    #endregion

    Write-Host "📂 当前脚本目录为：$ScriptDir"

    # --- V V V 修改顺序 V V V ---

    #region 1. 检查并下载依赖项 (证书) - 在修改代理之前
    $certUrl = "https://raw.githubusercontent.com/Benoqtr/resev/main/mitmproxy-ca-cert.p12"
    $certPath = Join-Path -Path $ScriptDir -ChildPath "mitmproxy-ca-cert.p12"
    # 如果下载失败（函数返回 $false），不继续执行关键步骤
    if (-not (Download-FileIfNeeded -FileUrl $certUrl -DestinationPath $certPath)) {
         Write-Warning "⚠️ 证书文件无法下载或找到，但脚本将尝试继续（证书安装步骤会跳过）。"
         # 不强制退出，因为证书不是绝对必须运行 mitmdump 的（尽管会导致 HTTPS 错误）
    }
    #endregion

    #region 2. 安装 mitmproxy 证书（如果存在） - 在修改代理之前
    if (Test-Path $certPath) {
        try {
            Write-Host "📄 检查 mitmproxy 根证书..."
            $plainPassword = $null # 如果 p12 文件有密码，请在此处填写字符串

            $certToImport = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            if ([string]::IsNullOrWhiteSpace($plainPassword)) {
                $certToImport.Import($certPath) # 无密码导入
            } else {
                # 对于 PFX 导入，密码处理更标准的方式
                $certToImport.Import($certPath, $plainPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
            }

            $thumbprint = $certToImport.Thumbprint
            # 检查证书是否已存在于目标存储区 (当前用户的根证书)
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
            $store.Open("ReadOnly")
            # 使用正确的 FindType 枚举和参数查找证书
            $existing = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumbprint, $false) # $false 表示不查找无效证书
            $store.Close()

            if ($existing.Count -gt 0) {
                Write-Host "✅ 证书 (Thumbprint: $thumbprint) 已存在于 当前用户 的 受信任的根证书颁发机构 存储区，跳过安装。" -ForegroundColor Green
            } else {
                Write-Host "🔐 正在将 mitmproxy 根证书导入到 当前用户 的 受信任的根证书颁发机构 存储区..." -ForegroundColor Yellow
                # 打开存储区进行写入
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
                $store.Open("ReadWrite")
                $store.Add($certToImport)
                $store.Close()

                # 验证是否导入成功
                $storeVerify = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
                $storeVerify.Open("ReadOnly")
                # 使用正确的 FindType 枚举和参数再次查找以验证
                $check = $storeVerify.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumbprint, $false)
                $storeVerify.Close()

                if ($check.Count -gt 0) {
                    Write-Host "✅ 证书导入成功 (Thumbprint: $thumbprint)。" -ForegroundColor Green
                } else {
                    Write-Warning "❌ 证书导入后验证失败！"
                }
            }
        } catch {
            Write-Warning "❌ 处理证书时发生错误：$($_.Exception.Message)"
            # 可以在这里添加更详细的错误信息，例如 $_.ScriptStackTrace
        }
    } else {
        Write-Warning "⚠️ 跳过证书安装，因为文件 '$certPath' 不存在。"
    }
    #endregion

    #region 3. 检查并下载依赖项 (mitmdump) - 在修改代理之前
    $mitmdumpUrl = "https://raw.githubusercontent.com/Benoqtr/resev/main/mitmdump.exe"
    $mitmdumpPath = Join-Path -Path $ScriptDir -ChildPath "mitmdump.exe"
    # 如果 mitmdump 下载失败（函数返回 $false），则无法继续，直接退出
    if (-not (Download-FileIfNeeded -FileUrl $mitmdumpUrl -DestinationPath $mitmdumpPath)) {
         Write-Error "关键依赖 'mitmdump.exe' 无法下载或找到。脚本无法继续。"
         Read-Host "按 Enter 键退出..."
         exit 1 # 直接退出，因为没有修改代理，所以不需要恢复
    }
    #endregion

    # --- 文件准备完毕，现在可以修改代理了 ---

    #region 4. 保存当前代理设置供恢复时使用
    Write-Host "ℹ️ 正在保存当前代理设置..."
    $script:oldProxyEnable = $null
    $script:oldProxyServer = $null
    try {
        # ... (保存代理设置代码，与之前相同) ...
        $initialProxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($initialProxySettings) {
            if ($initialProxySettings.PSObject.Properties.Name -contains 'ProxyEnable') { $script:oldProxyEnable = $initialProxySettings.ProxyEnable; Write-Host "  原始代理启用状态已保存: $($script:oldProxyEnable)" } else { $script:oldProxyEnable = 0; Write-Host "  未找到 ProxyEnable，假定为 0。" }
            if ($initialProxySettings.PSObject.Properties.Name -contains 'ProxyServer') { $script:oldProxyServer = $initialProxySettings.ProxyServer; Write-Host "  原始代理服务器已保存: $($script:oldProxyServer)" } else { $script:oldProxyServer = ""; Write-Host "  未找到 ProxyServer，假定为空。" }
        } else { $script:oldProxyEnable = 0; $script:oldProxyServer = ""; Write-Host "  未能读取注册表项，假定默认值。" }
    } catch {
         Write-Warning "❌ 保存原始代理设置时出错: $($_.Exception.Message)"; $script:oldProxyEnable = 0; $script:oldProxyServer = ""; Write-Warning "  将使用默认值恢复。"
    }
    #endregion

    #region 5. 设置代理
    Write-Host "📡 正在设置临时系统代理为 127.0.0.1:8080..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080" -ErrorAction Stop
        Write-Host "✔️ 临时代理已设置。" -ForegroundColor Green
    } catch {
        Write-Warning "❌ 设置临时代理失败: $($_.Exception.Message)。"
        # 尝试恢复到刚保存的状态
        Write-Warning "尝试恢复原始代理设置..."
        Restore-Proxy
        Read-Host "设置代理失败，已恢复原始设置。按 Enter 键退出..."
        exit 1 # 退出，因为无法设置代理
    }
    #endregion

    #region 6. 启动 mitmproxy (使用临时 Python 脚本)
    $script:tempScriptPath = Join-Path $ScriptDir "_temp_mitm_extract_session.py"
    # 确保工作目录正确
    try { Set-Location $ScriptDir -ErrorAction Stop } catch { Write-Error "..."; Restore-Proxy; Read-Host "..."; exit 1 }

    # mitmdumpPath 此时必然存在且有效
    $mitmPath = $mitmdumpPath

    # --- Create Temp Python Script ---
    Write-Host "ℹ️ 正在创建临时的 mitmproxy 脚本: $script:tempScriptPath"
    try {
        # ... (创建临时 Python 脚本的代码) ...
        $env:MITMPROXY_SCRIPT_DIR = $ScriptDir
        $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($script:tempScriptPath, $pythonScriptContent, $Utf8NoBomEncoding)
        Write-Host "✅ 临时脚本创建成功。" -ForegroundColor Green
    } catch {
        Write-Error "❌ 创建临时 mitmproxy 脚本失败: $($_.Exception.Message)"
        Restore-Proxy # 需要恢复代理
        Read-Host "创建临时脚本失败，按 Enter 退出..."
        exit 1
    }

    # --- Launch mitmproxy using the temp script ---
    $mitmExecutable = Split-Path $mitmPath -Leaf
    try {
        # ... (启动 mitmproxy 的代码) ...
        Write-Host "🚀 准备启动 $mitmExecutable (使用临时脚本)..." -ForegroundColor Cyan
        $arguments = @( "-s", "`"$script:tempScriptPath`"", "--set", "block_global=false" )
        Write-Host "  将使用以下命令启动: `"$mitmPath`" $($arguments -join ' ')"
        $env:MITMPROXY_SCRIPT_DIR = $ScriptDir
        $processInfo = Start-Process -FilePath "$mitmPath" -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
        Write-Host "🛑 $mitmExecutable 已退出 (Exit Code: $($processInfo.ExitCode))。"
    } catch {
        Write-Warning "❌ 启动 $mitmExecutable 失败: $($_.Exception.Message)"
        # Restore-Proxy 会在 finally 中调用
    } finally {
        # --- Cleanup Temp Python Script ---
        if ($script:tempScriptPath -and (Test-Path $script:tempScriptPath)) {
            Write-Host "ℹ️ 正在清理临时 mitmproxy 脚本: $script:tempScriptPath"
            Remove-Item -Path $script:tempScriptPath -Force -ErrorAction SilentlyContinue
        }
        if ($env:MITMPROXY_SCRIPT_DIR) { Remove-Item Env:\MITMPROXY_SCRIPT_DIR -ErrorAction SilentlyContinue }
        # 不在此处恢复代理，移至 Main 函数末尾
    }
    #endregion

    # --- Restore Proxy after mitmproxy execution ---
    Write-Host "DEBUG: Reached end of Main function logic, calling Restore-Proxy..."
    Restore-Proxy

    Write-Host "✅ Main 函数执行完毕。" -ForegroundColor Green

} # End of Main function


# --- 脚本入口点 ---
try {
    Main @PSBoundParameters
} catch {
    Write-Error "脚本顶层捕获到未处理的异常: $($_.Exception.Message)"
    # Trap handler (如果触发) 应该已尝试恢复代理
} finally {
    Write-Host "🚪 进入脚本末尾的 finally 块。"

    # 最终的代理恢复检查 (以防万一)
    if ((Get-Variable -Name 'oldProxyEnable' -Scope 'Script' -ErrorAction SilentlyContinue) -or `
        (Get-Variable -Name 'oldProxyServer' -Scope 'Script' -ErrorAction SilentlyContinue)) {
         Write-Host "DEBUG: Final check in top-level finally block, ensuring proxy is restored..."
         Restore-Proxy
    } else {
         Write-Host "DEBUG: No saved proxy state found in top-level finally, skipping restore."
    }

    # 最终的临时文件清理检查
    if (Get-Variable -Name 'tempScriptPath' -Scope 'Script' -ErrorAction SilentlyContinue) {
        if ($script:tempScriptPath -and (Test-Path $script:tempScriptPath)) {
            Write-Host "DEBUG: Final cleanup check for temporary script file: $script:tempScriptPath"
            Remove-Item -Path $script:tempScriptPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "脚本执行完毕或遇到问题。" -ForegroundColor Cyan
    if (-not ($env:CI -eq $true -or $env:TF_BUILD -eq $true -or $MyInvocation.PipeLinePosition -gt 1)) {
      if ($Host.UI.RawUI.KeyAvailable) { Write-Host "按任意键退出..." -NoNewline; $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null }
      else { Read-Host "按 Enter 键退出..." }
    }
}