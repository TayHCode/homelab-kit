"""Fixed read-only inventories. No commands, task actions or credentials are exported."""


def powershell(script: str) -> list[str]:
    # Keep the script compatible with Windows OpenSSH's default cmd shell.
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop'; [Console]::OutputEncoding="
            "[System.Text.UTF8Encoding]::new($false); " + script]


WINDOWS_PROBE = powershell("[Environment]::OSVersion.Platform")

MAC_COMMANDS = {
    "kernel": ["uname", "-srm"],
    "os-release": ["sw_vers"],
    "hostname": ["hostname"],
    "cpu": ["sysctl", "hw.model", "hw.machine", "hw.ncpu", "machdep.cpu.brand_string"],
    "memory": ["sysctl", "hw.memsize"],
    "block-devices": ["diskutil", "list"],
    "addresses": ["ifconfig", "-a"],
    "routes": ["netstat", "-rn"],
    "listeners": ["/bin/sh", "-c", "lsof -nP -iTCP -sTCP:LISTEN -iUDP || netstat -anv"],
    "services": ["launchctl", "list"],
    "applications": ["/bin/sh", "-c", "find /Applications /System/Applications -maxdepth 1 -name '*.app' -print"],
    "packages": ["/bin/sh", "-c", "for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do "
                 "if test -x \"$b\"; then HOMEBREW_NO_AUTO_UPDATE=1 \"$b\" list --versions; exit; fi; done; exit 127"],
    "hosts": ["cat", "/etc/hosts"],
}


def inventory(script: str) -> list[str]:
    return powershell(script + " | ConvertTo-Json -Depth 5")


WINDOWS_COMMANDS = {
    "os-release": inventory("Get-ComputerInfo -Property WindowsProductName,WindowsVersion,OsName,OsVersion,OsArchitecture"),
    "hostname": powershell("[Environment]::MachineName"),
    "cpu": inventory("Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors"),
    "memory": inventory("Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory"),
    "block-devices": inventory("Get-Disk | Select-Object Number,FriendlyName,BusType,PartitionStyle,Size,OperationalStatus"),
    "volumes": inventory("Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining,HealthStatus"),
    "adapters": inventory("Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,ifIndex"),
    "addresses": inventory("Get-NetIPAddress | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressFamily"),
    "routes": inventory("Get-NetRoute | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric"),
    "listeners": inventory("@(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,State; "
                           "Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort)"),
    "services": inventory("Get-Service | Select-Object Name,DisplayName,Status,StartType"),
    "scheduled-tasks": inventory("Get-ScheduledTask | Select-Object TaskPath,TaskName,State"),
    # Only named uninstall subkeys, never registry hives, credential stores or values outside this selection.
    "programs": inventory("Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                          "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
                          "-ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion"),
    "hosts": powershell("$p=Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'; "
                        "$d=$p; while ($d) { "
                        "if ((Get-Item -LiteralPath $d).Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 1 }; "
                        "$d=Split-Path $d }; "
                        "if ((Get-Item -LiteralPath $p).Length -gt 262144) { exit 1 }; "
                        "[IO.File]::ReadAllText($p)"),
}

# Portable on macOS; resolve every symlink before the denylist sees the target.
MAC_RESOLVE = 'p=$1; n=0; while test "$n" -lt 40; do n=$((n+1)); ' \
    'd=$(dirname "$p"); b=$(basename "$p"); d=$(cd -P "$d" && pwd -P) || exit 2; ' \
    'p=$d/$b; if test -L "$p"; then t=$(readlink "$p") || exit 2; ' \
    'case "$t" in /*) p=$t;; *) p=$d/$t;; esac; ' \
    'elif test -e "$p"; then printf "%s\\n" "$p"; exit; else exit 1; fi; done; exit 2'
