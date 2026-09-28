# 02_service.ps1 - 2. 서비스 관리 (W-15 ~ W-37)

# ──────────────────────────────────────────────────────────
# IIS applicationHost.config에서 FTP 사이트 정보 파싱
#   반환: $null(파싱 불가) 또는 사이트 객체 배열
# ──────────────────────────────────────────────────────────
function Get-FtpSiteInfo {
    $cfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (-not (Test-Path $cfg)) { return $null }
    try {
        [xml]$x = Get-Content $cfg -ErrorAction Stop
    } catch {
        return $null
    }
    $sites = @()
    $siteNodes = $x.SelectNodes('//system.applicationHost/sites/site')
    foreach ($s in $siteNodes) {
        $hasFtp = $false
        foreach ($b in $s.SelectNodes('bindings/binding')) {
            if ($b.GetAttribute('protocol') -eq 'ftp') { $hasFtp = $true }
        }
        if (-not $hasFtp) { continue }
        $phys = $null
        $vd = $s.SelectSingleNode("application[@path='/']/virtualDirectory[@path='/']")
        if ($vd) { $phys = [Environment]::ExpandEnvironmentVariables($vd.GetAttribute('physicalPath')) }
        $anon = $null
        $anonNode = $s.SelectSingleNode('ftpServer/security/authentication/anonymousAuthentication')
        if ($anonNode) { $anon = $anonNode.GetAttribute('enabled') }
        $sites += [PSCustomObject]@{
            Name             = $s.GetAttribute('name')
            PhysicalPath     = $phys
            AnonymousEnabled = $anon
            Xml              = $x
        }
    }
    return ,$sites
}

function Invoke-ServiceChecks {
    Print-Section "2. 서비스 관리 (W-15 ~ W-37)"

    # ──────────────────────────────────────────────────────
    # W-15 (상) 사용자 개인키 사용 시 암호 입력
    # 양호: 사용자 개인 키를 사용할 때마다 암호 입력을 받는 경우
    #   "시스템 암호화: 컴퓨터에 저장된 사용자 키에 대해 강력한 키 보호 사용"
    #   = "키를 사용할 때마다 암호를 매 번 입력해야 함"(ForceKeyProtection=2)
    # ──────────────────────────────────────────────────────
    $forceKey = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' 'ForceKeyProtection'
    if ($forceKey -ne $null -and [int]$forceKey -eq 2) {
        Result-Pass "W-15" "사용자 개인키 사용 시 암호 입력" "'강력한 키 보호 사용' 정책: 키 사용 시마다 암호 입력(2)"
    } else {
        Result-Fail "W-15" "사용자 개인키 사용 시 암호 입력" "'강력한 키 보호 사용' 정책이 '키를 사용할 때마다 암호를 매 번 입력해야 함'으로 설정되지 않음(현재: $forceKey)"
    }

    # ──────────────────────────────────────────────────────
    # W-16 (상) 공유 권한 및 사용자 그룹 설정
    # 양호: 일반 공유 디렉터리가 없거나 접근 권한에 Everyone 권한이 없는 경우
    # ──────────────────────────────────────────────────────
    $normalShares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special })
    if ($normalShares.Count -eq 0) {
        Result-Pass "W-16" "공유 권한 및 사용자 그룹 설정" "일반 공유 디렉터리가 존재하지 않음"
    } else {
        $everyoneShares = @()
        foreach ($sh in $normalShares) {
            $access = @(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue)
            foreach ($a in $access) {
                if ($a.AccountName -match 'Everyone') { $everyoneShares += "$($sh.Name) ($($sh.Path))" }
            }
        }
        if ($everyoneShares.Count -eq 0) {
            Result-Pass "W-16" "공유 권한 및 사용자 그룹 설정" "일반 공유 $($normalShares.Count)건 존재하나 Everyone 권한 없음: $(($normalShares | ForEach-Object { $_.Name }) -join ', ')"
        } else {
            Result-Fail "W-16" "공유 권한 및 사용자 그룹 설정" ("Everyone 권한이 부여된 공유 존재`n" + (($everyoneShares | Select-Object -Unique) -join "`n"))
        }
    }

    # ──────────────────────────────────────────────────────
    # W-17 (상) 하드디스크 기본 공유 제거
    # 양호: AutoShareServer가 0이며 기본 공유가 존재하지 않는 경우 (IPC$ 제외)
    # ──────────────────────────────────────────────────────
    $autoShare = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer'
    $defaultShares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Special -and $_.Name -ne 'IPC$' })
    $issues = @()
    if ($autoShare -eq $null -or [int]$autoShare -ne 0) {
        $val = "미설정(기본값 1)"
        if ($autoShare -ne $null) { $val = "$autoShare" }
        $issues += "AutoShareServer 레지스트리: $val"
    }
    if ($defaultShares.Count -gt 0) {
        $issues += "기본 공유 존재: $(($defaultShares | ForEach-Object { $_.Name }) -join ', ')"
    }
    if ($issues.Count -eq 0) {
        Result-Pass "W-17" "하드디스크 기본 공유 제거" "AutoShareServer=0, 기본 공유(IPC$ 제외) 없음"
    } else {
        Result-Fail "W-17" "하드디스크 기본 공유 제거" ($issues -join "`n")
    }

    # ──────────────────────────────────────────────────────
    # W-18 (상) 불필요한 서비스 제거
    # 양호: 가이드에 명시된 '일반적으로 불필요한 서비스'가 중지된 경우
    # ──────────────────────────────────────────────────────
    $unnecessaryServices = @(
        @{ Name = 'Alerter';        Desc = 'Alerter' },
        @{ Name = 'wuauserv';       Desc = 'Automatic Updates' },
        @{ Name = 'ClipSrv';        Desc = 'Clipbook' },
        @{ Name = 'Browser';        Desc = 'Computer Browser' },
        @{ Name = 'CryptSvc';       Desc = 'Cryptographic Services' },
        @{ Name = 'Dhcp';           Desc = 'DHCP Client' },
        @{ Name = 'TrkWks';         Desc = 'Distributed Link Tracking Client' },
        @{ Name = 'TrkSvr';         Desc = 'Distributed Link Tracking Server' },
        @{ Name = 'Dnscache';       Desc = 'DNS Client' },
        @{ Name = 'WerSvc';         Desc = 'Error Reporting Service' },
        @{ Name = 'ERSvc';          Desc = 'Error Reporting Service(구버전)' },
        @{ Name = 'hidserv';        Desc = 'Human Interface Device Access' },
        @{ Name = 'ImapiService';   Desc = 'IMAPI CD-Burning COM Service' },
        @{ Name = 'irmon';          Desc = 'Infrared Monitor' },
        @{ Name = 'Messenger';      Desc = 'Messenger' },
        @{ Name = 'mnmsrvc';        Desc = 'NetMeeting Remote Desktop Sharing' },
        @{ Name = 'WmdmPmSN';       Desc = 'Portable Media Serial Number' },
        @{ Name = 'Spooler';        Desc = 'Print Spooler' },
        @{ Name = 'RemoteRegistry'; Desc = 'Remote Registry' },
        @{ Name = 'SimpTcp';        Desc = 'Simple TCP/IP Services' },
        @{ Name = 'upnphost';       Desc = 'Universal Plug and Play Device Host' },
        @{ Name = 'WZCSVC';         Desc = 'Wireless Zero Configuration' }
    )
    $runningUnnecessary = @()
    foreach ($svcDef in $unnecessaryServices) {
        $svc = Get-ServiceSafe $svcDef.Name
        if ($svc -and $svc.Status -eq 'Running') {
            $runningUnnecessary += "$($svcDef.Desc) ($($svcDef.Name))"
        }
    }
    if ($runningUnnecessary.Count -eq 0) {
        Result-Pass "W-18" "불필요한 서비스 제거" "가이드 목록의 불필요한 서비스가 구동 중이지 않음"
    } else {
        # 가이드 판단 기준: 목록의 서비스가 구동 중인 경우 취약
        # (업무상 필요하여 사용하는 서비스는 담당자 확인 후 예외 처리)
        Result-Fail "W-18" "불필요한 서비스 제거" ("가이드 목록의 불필요한 서비스 구동 중(업무상 필요 시 담당자 확인 후 예외 처리)`n" + ($runningUnnecessary -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-19 (상) 불필요한 IIS 서비스 구동 점검
    # 양호: IIS 서비스를 사용하지 않는 경우 또는 필요에 의해 사용하는 경우
    # ──────────────────────────────────────────────────────
    $w3svc = Get-ServiceSafe 'W3SVC'
    if (-not $w3svc -or $w3svc.Status -ne 'Running') {
        $state = "미설치"
        if ($w3svc) { $state = "중지됨" }
        Result-Pass "W-19" "불필요한 IIS 서비스 구동 점검" "IIS(W3SVC) 서비스 $state"
    } else {
        Result-Interview "W-19" "불필요한 IIS 서비스 구동 점검" "IIS(W3SVC) 서비스 구동 중 - 업무상 필요 여부 담당자 확인 필요(불필요 시 취약)"
    }

    # ──────────────────────────────────────────────────────
    # W-20 (상) NetBIOS 바인딩 서비스 구동 점검
    # 양호: TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있는 경우
    #   TcpipNetbiosOptions: 0=DHCP기본값, 1=사용, 2=사용 안 함
    # ──────────────────────────────────────────────────────
    $nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE")
    $netbiosEnabled = @()
    foreach ($nic in $nics) {
        if ($nic.TcpipNetbiosOptions -ne 2) {
            $netbiosEnabled += "$($nic.Description) (TcpipNetbiosOptions=$($nic.TcpipNetbiosOptions))"
        }
    }
    if ($nics.Count -gt 0 -and $netbiosEnabled.Count -eq 0) {
        Result-Pass "W-20" "NetBIOS 바인딩 서비스 구동 점검" "모든 활성 어댑터에서 NetBIOS over TCP/IP 사용 안 함"
    } else {
        Result-Fail "W-20" "NetBIOS 바인딩 서비스 구동 점검" ("NetBIOS over TCP/IP 바인딩이 제거되지 않은 어댑터 존재`n" + ($netbiosEnabled -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-21 (상) 암호화되지 않는 FTP 서비스 비활성화
    # 양호: FTP 서비스를 사용하지 않거나 Secure FTP 서비스를 사용하는 경우
    # ──────────────────────────────────────────────────────
    $ftpSvc = Get-ServiceSafe 'FTPSVC'
    $ftpRunning = ($ftpSvc -and $ftpSvc.Status -eq 'Running')
    if (-not $ftpRunning) {
        $state = "미설치"
        if ($ftpSvc) { $state = "중지됨" }
        Result-Pass "W-21" "암호화되지 않는 FTP 서비스 비활성화" "Microsoft FTP Service(FTPSVC) $state"
    } else {
        Result-Interview "W-21" "암호화되지 않는 FTP 서비스 비활성화" "FTP 서비스 구동 중 - Secure FTP(FTPS/SSL) 적용 여부 담당자 확인 필요(미적용 시 취약)"
    }

    # ──────────────────────────────────────────────────────
    # W-22 (상) FTP 디렉토리 접근권한 설정
    # 양호: FTP 홈 디렉터리에 Everyone 권한이 없는 경우
    # ──────────────────────────────────────────────────────
    if (-not $ftpRunning) {
        Result-Pass "W-22" "FTP 디렉토리 접근권한 설정" "FTP 서비스 미사용"
    } else {
        $ftpSites = Get-FtpSiteInfo
        if ($ftpSites -eq $null) {
            Result-Interview "W-22" "FTP 디렉토리 접근권한 설정" "IIS 구성 파일을 확인할 수 없음 - FTP 홈 디렉터리의 Everyone 권한 수동 확인 필요"
        } else {
            $everyoneDirs = @()
            $checkedDirs  = @()
            foreach ($site in $ftpSites) {
                if ($site.PhysicalPath -and (Test-Path $site.PhysicalPath)) {
                    $checkedDirs += "$($site.Name): $($site.PhysicalPath)"
                    $aces = Get-AclEveryone $site.PhysicalPath
                    if ($aces -ne $null -and $aces.Count -gt 0) {
                        $everyoneDirs += "$($site.Name): $($site.PhysicalPath)"
                    }
                }
            }
            if ($everyoneDirs.Count -eq 0) {
                Result-Pass "W-22" "FTP 디렉토리 접근권한 설정" ("FTP 홈 디렉터리에 Everyone 권한 없음`n" + ($checkedDirs -join "`n"))
            } else {
                Result-Fail "W-22" "FTP 디렉토리 접근권한 설정" ("FTP 홈 디렉터리에 Everyone 권한 존재`n" + ($everyoneDirs -join "`n"))
            }
        }
    }

    # ──────────────────────────────────────────────────────
    # W-23 (상) 공유 서비스에 대한 익명 접근 제한 설정
    # 양호: 공유 서비스를 사용하지 않거나, 익명 인증 사용 안 함으로 설정된 경우
    # ──────────────────────────────────────────────────────
    if (-not $ftpRunning) {
        Result-Pass "W-23" "공유 서비스에 대한 익명 접근 제한 설정" "FTP 공유 서비스 미사용"
    } else {
        $ftpSites = Get-FtpSiteInfo
        if ($ftpSites -eq $null -or $ftpSites.Count -eq 0) {
            Result-Interview "W-23" "공유 서비스에 대한 익명 접근 제한 설정" "IIS 구성 파일에서 FTP 사이트 정보를 확인할 수 없음 - FTP 익명 인증 설정 수동 확인 필요"
        } else {
            $anonSites = @()
            $unknownSites = @()
            foreach ($site in $ftpSites) {
                if ($site.AnonymousEnabled -eq 'true') { $anonSites += $site.Name }
                elseif ($site.AnonymousEnabled -eq $null -or $site.AnonymousEnabled -eq '') { $unknownSites += $site.Name }
            }
            if ($anonSites.Count -gt 0) {
                Result-Fail "W-23" "공유 서비스에 대한 익명 접근 제한 설정" "익명 인증이 활성화된 FTP 사이트: $($anonSites -join ', ')"
            } elseif ($unknownSites.Count -gt 0) {
                Result-Interview "W-23" "공유 서비스에 대한 익명 접근 제한 설정" "익명 인증 설정이 명시되지 않은 FTP 사이트 존재(수동 확인 필요): $($unknownSites -join ', ')"
            } else {
                Result-Pass "W-23" "공유 서비스에 대한 익명 접근 제한 설정" "모든 FTP 사이트에서 익명 인증 사용 안 함"
            }
        }
    }

    # ──────────────────────────────────────────────────────
    # W-24 (상) FTP 접근 제어 설정
    # 양호: 특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용한 경우
    # ──────────────────────────────────────────────────────
    if (-not $ftpRunning) {
        Result-Pass "W-24" "FTP 접근 제어 설정" "FTP 서비스 미사용"
    } else {
        $cfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
        $restricted = $false
        $parsed = $false
        if (Test-Path $cfg) {
            try {
                [xml]$xml = Get-Content $cfg -ErrorAction Stop
                $parsed = $true
                foreach ($node in $xml.SelectNodes('//ipSecurity')) {
                    if ($node.GetAttribute('allowUnlisted') -eq 'false') { $restricted = $true }
                }
            } catch { $parsed = $false }
        }
        if (-not $parsed) {
            Result-Interview "W-24" "FTP 접근 제어 설정" "IIS 구성 파일을 확인할 수 없음 - FTP IPv4 주소 및 도메인 제한 설정 수동 확인 필요"
        } elseif ($restricted) {
            Result-Pass "W-24" "FTP 접근 제어 설정" "지정되지 않은 클라이언트 액세스 거부(allowUnlisted=false) 설정 확인됨"
        } else {
            Result-Fail "W-24" "FTP 접근 제어 설정" "특정 IP주소로 제한하는 접근 제어(ipSecurity) 설정이 적용되지 않음"
        }
    }

    # ──────────────────────────────────────────────────────
    # W-25 (상) DNS Zone Transfer 설정
    # 양호: DNS 서비스 비활성화 / 영역 전송 허용 안 함 / 특정 서버로만 설정
    # ──────────────────────────────────────────────────────
    $dnsSvc = Get-ServiceSafe 'DNS'
    if (-not $dnsSvc -or $dnsSvc.Status -ne 'Running') {
        $state = "미설치"
        if ($dnsSvc) { $state = "중지됨" }
        Result-Pass "W-25" "DNS Zone Transfer 설정" "DNS 서버 서비스 $state"
    } else {
        $zoneResults = @()
        $vulnZones = @()
        $checked = $false
        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            $zones = @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' })
            $checked = $true
            foreach ($z in $zones) {
                $zoneResults += "$($z.ZoneName): $($z.SecureSecondaries)"
                if ($z.SecureSecondaries -eq 'TransferAnyServer') { $vulnZones += $z.ZoneName }
            }
        }
        if (-not $checked) {
            Result-Interview "W-25" "DNS Zone Transfer 설정" "DNS 서비스 구동 중이나 DnsServer 모듈을 사용할 수 없음 - 영역 전송 설정 수동 확인 필요"
        } elseif ($vulnZones.Count -gt 0) {
            Result-Fail "W-25" "DNS Zone Transfer 설정" ("모든 서버로 영역 전송을 허용하는 영역 존재: $($vulnZones -join ', ')`n" + ($zoneResults -join "`n"))
        } else {
            $detail = "주 영역 없음"
            if ($zoneResults.Count -gt 0) { $detail = $zoneResults -join "`n" }
            Result-Pass "W-25" "DNS Zone Transfer 설정" ("영역 전송이 제한되어 있음`n" + $detail)
        }
    }

    # ──────────────────────────────────────────────────────
    # W-26 (상) RDS(Remote Data Services) 제거
    # 양호 기준 2: Windows 2008 이상 버전을 사용하는 경우
    # ──────────────────────────────────────────────────────
    Result-Pass "W-26" "RDS(Remote Data Services) 제거" "Windows Server 2022는 2008 이상 버전으로 양호 기준에 해당함"

    # ──────────────────────────────────────────────────────
    # W-27 (상) 최신 Windows OS Build 버전 적용
    # 양호: 최신 Build가 설치되어 있으며 적용 절차 및 방법이 수립된 경우
    # ──────────────────────────────────────────────────────
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build   = Get-RegValue $cv 'CurrentBuild'
    $ubr     = Get-RegValue $cv 'UBR'
    $dispVer = Get-RegValue $cv 'DisplayVersion'
    Result-Interview "W-27" "최신 Windows OS Build 버전 적용" "현재 Build: $build.$ubr (버전 $dispVer) - 최신 Build 여부 및 적용 절차 수립 여부 담당자 확인 필요"

    # ──────────────────────────────────────────────────────
    # W-28 (중) 터미널 서비스 암호화 수준 설정
    # 양호: 원격 데스크톱 미사용 또는 암호화 수준 "클라이언트와 호환 가능(중간)" 이상
    #   MinEncryptionLevel: 1=낮음, 2=클라이언트 호환, 3=높음, 4=FIPS
    # ──────────────────────────────────────────────────────
    $denyTS = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($denyTS -ne $null -and [int]$denyTS -eq 1) {
        Result-Pass "W-28" "터미널 서비스 암호화 수준 설정" "원격 데스크톱 서비스 미사용(fDenyTSConnections=1)"
    } else {
        $encLevel = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MinEncryptionLevel'
        $src = "그룹 정책"
        if ($encLevel -eq $null) {
            $encLevel = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel'
            $src = "RDP-Tcp 설정"
        }
        if ($encLevel -eq $null) {
            Result-Pass "W-28" "터미널 서비스 암호화 수준 설정" "암호화 수준 미설정 시 기본값 2(클라이언트 호환) 적용됨"
        } elseif ([int]$encLevel -ge 2) {
            Result-Pass "W-28" "터미널 서비스 암호화 수준 설정" "암호화 수준: $encLevel ($src, 클라이언트 호환 이상)"
        } else {
            Result-Fail "W-28" "터미널 서비스 암호화 수준 설정" "암호화 수준이 '낮음'(1)으로 설정됨 ($src)"
        }
    }

    # ──────────────────────────────────────────────────────
    # W-29 (중) 불필요한 SNMP 서비스 구동 점검
    # 양호: SNMP 미사용 또는 Community String을 설정하여 사용하는 경우
    # ──────────────────────────────────────────────────────
    $snmpSvc = Get-ServiceSafe 'SNMP'
    $snmpRunning = ($snmpSvc -and $snmpSvc.Status -eq 'Running')
    if (-not $snmpRunning) {
        $state = "미설치"
        if ($snmpSvc) { $state = "중지됨" }
        Result-Pass "W-29" "불필요한 SNMP 서비스 구동 점검" "SNMP 서비스 $state"
    } else {
        Result-Interview "W-29" "불필요한 SNMP 서비스 구동 점검" "SNMP 서비스 구동 중 - 업무상 필요 여부 담당자 확인 필요(불필요 시 취약)"
    }

    # ──────────────────────────────────────────────────────
    # W-30 (중) SNMP Community String 복잡성 설정
    # 양호: SNMP 미사용 또는 Community String이 public, private이 아닌 경우
    # ──────────────────────────────────────────────────────
    if (-not $snmpRunning) {
        Result-Pass "W-30" "SNMP Community String 복잡성 설정" "SNMP 서비스 미사용"
    } else {
        $commKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
        $communities = @()
        try {
            $props = Get-ItemProperty -Path $commKey -ErrorAction Stop
            $communities = @($props.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' } |
                ForEach-Object { $_.Name })
        } catch { $communities = @() }
        $weak = @($communities | Where-Object { $_ -match '^(public|private)$' })
        if ($weak.Count -gt 0) {
            Result-Fail "W-30" "SNMP Community String 복잡성 설정" "기본 Community String 사용 중: $($weak -join ', ')"
        } elseif ($communities.Count -eq 0) {
            Result-Interview "W-30" "SNMP Community String 복잡성 설정" "SNMP 구동 중이나 등록된 Community String 없음 - 설정 상태 담당자 확인 필요"
        } else {
            Result-Pass "W-30" "SNMP Community String 복잡성 설정" "public/private이 아닌 Community String 사용: $($communities -join ', ')"
        }
    }

    # ──────────────────────────────────────────────────────
    # W-31 (중) SNMP Access Control 설정
    # 양호: SNMP 미사용 또는 특정 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우
    # ──────────────────────────────────────────────────────
    if (-not $snmpRunning) {
        Result-Pass "W-31" "SNMP Access Control 설정" "SNMP 서비스 미사용"
    } else {
        $mgrKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers'
        $managers = @()
        try {
            $props = Get-ItemProperty -Path $mgrKey -ErrorAction Stop
            $managers = @($props.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' } |
                ForEach-Object { $_.Value })
        } catch { $managers = @() }
        if ($managers.Count -gt 0) {
            Result-Pass "W-31" "SNMP Access Control 설정" "SNMP 패킷 허용 호스트 지정됨: $($managers -join ', ')"
        } else {
            Result-Fail "W-31" "SNMP Access Control 설정" "모든 호스트로부터 SNMP 패킷 받아들이기로 설정됨(허용 호스트 미지정)"
        }
    }

    # ──────────────────────────────────────────────────────
    # W-32 (중) DNS 서비스 구동 점검
    # 양호: DNS 서비스를 사용하지 않거나 동적 업데이트 "없음"으로 설정된 경우
    # ──────────────────────────────────────────────────────
    if (-not $dnsSvc -or $dnsSvc.Status -ne 'Running') {
        $state = "미설치"
        if ($dnsSvc) { $state = "중지됨" }
        Result-Pass "W-32" "DNS 서비스 구동 점검" "DNS 서버 서비스 $state"
    } else {
        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            $zones = @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' })
            $dynZones = @()
            $zoneInfo = @()
            foreach ($z in $zones) {
                $zoneInfo += "$($z.ZoneName): 동적 업데이트=$($z.DynamicUpdate)"
                if ($z.DynamicUpdate -ne 'None') { $dynZones += $z.ZoneName }
            }
            if ($dynZones.Count -gt 0) {
                Result-Fail "W-32" "DNS 서비스 구동 점검" ("동적 업데이트가 설정된 영역 존재: $($dynZones -join ', ')`n" + ($zoneInfo -join "`n"))
            } else {
                $detail = "주 영역 없음"
                if ($zoneInfo.Count -gt 0) { $detail = $zoneInfo -join "`n" }
                Result-Pass "W-32" "DNS 서비스 구동 점검" ("모든 영역 동적 업데이트 없음`n" + $detail)
            }
        } else {
            Result-Interview "W-32" "DNS 서비스 구동 점검" "DNS 서비스 구동 중이나 DnsServer 모듈을 사용할 수 없음 - 동적 업데이트 설정 수동 확인 필요"
        }
    }

    # ──────────────────────────────────────────────────────
    # W-33 (하) HTTP/FTP/SMTP 배너 차단
    # 양호: HTTP, FTP, SMTP 접속 시 배너 정보가 보이지 않는 경우
    # ──────────────────────────────────────────────────────
    $bannerServices = @()
    if ($w3svc -and $w3svc.Status -eq 'Running') { $bannerServices += "HTTP(W3SVC)" }
    if ($ftpRunning) { $bannerServices += "FTP(FTPSVC)" }
    $smtpSvc = Get-ServiceSafe 'SMTPSVC'
    if ($smtpSvc -and $smtpSvc.Status -eq 'Running') { $bannerServices += "SMTP(SMTPSVC)" }
    if ($bannerServices.Count -eq 0) {
        Result-Pass "W-33" "HTTP/FTP/SMTP 배너 차단" "HTTP/FTP/SMTP 서비스 미사용"
    } else {
        Result-Interview "W-33" "HTTP/FTP/SMTP 배너 차단" "구동 중 서비스: $($bannerServices -join ', ') - 접속 배너 노출 여부 수동 확인 필요(Server 헤더, FTP 배너, SMTP 응답)"
    }

    # ──────────────────────────────────────────────────────
    # W-34 (중) Telnet 서비스 비활성화
    # 점검 대상: Windows NT, 2000, 2003, 2008, 2012 → Windows Server 2022 미포함
    # ※ 가이드 참고: Windows 2016 이상 버전에서는 보안상 이슈로 인해
    #    Telnet 서버 설치를 제공하지 않음 → 판단 기준이 성립하지 않아 해당없음 처리
    # ──────────────────────────────────────────────────────
    $telnetSvc = Get-ServiceSafe 'TlntSvr'
    $telnetState = "TlntSvr 서비스 없음"
    if ($telnetSvc) { $telnetState = "TlntSvr 서비스 존재(상태: $($telnetSvc.Status), 시작 유형: $($telnetSvc.StartType))" }
    $telnetDetail = "점검 대상 OS(NT~2012)에 Windows Server 2022 미포함, Telnet 서버 미제공 - $telnetState"
    if ($telnetSvc -and $telnetSvc.Status -eq 'Running') {
        $telnetDetail += "`n※ Telnet 서비스가 구동 중임 - 서드파티 설치 여부 및 중지 필요성 담당자 확인 권고"
    }
    Result-NA "W-34" "Telnet 서비스 비활성화" $telnetDetail

    # ──────────────────────────────────────────────────────
    # W-35 (중) 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거
    # 양호: 시스템 DSN 부분의 데이터 소스를 현재 사용하고 있는 경우
    # ──────────────────────────────────────────────────────
    $dsnPaths = @(
        'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources',
        'HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\ODBC Data Sources'
    )
    $dsnList = @()
    foreach ($p in $dsnPaths) {
        try {
            $props = Get-ItemProperty -Path $p -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                    $dsnList += "$($prop.Name) ($($prop.Value))"
                }
            }
        } catch { }
    }
    $dsnList = @($dsnList | Select-Object -Unique)
    if ($dsnList.Count -eq 0) {
        Result-Pass "W-35" "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거" "등록된 시스템 DSN 없음"
    } else {
        Result-Interview "W-35" "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거" ("등록된 시스템 DSN의 사용 여부 담당자 확인 필요(미사용 시 취약)`n" + ($dsnList -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-36 (중) 원격터미널 접속 타임아웃 설정
    # 양호: 원격 제어 시 Timeout 제어 설정을 30분 이하로 설정한 경우
    # ──────────────────────────────────────────────────────
    if ($denyTS -ne $null -and [int]$denyTS -eq 1) {
        Result-Pass "W-36" "원격터미널 접속 타임아웃 설정" "원격 데스크톱 서비스 미사용(fDenyTSConnections=1)"
    } else {
        $maxIdle = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MaxIdleTime'
        $src = "그룹 정책"
        if ($maxIdle -eq $null) {
            $maxIdle = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MaxIdleTime'
            $src = "RDP-Tcp 설정"
        }
        if ($maxIdle -ne $null -and [int64]$maxIdle -gt 0 -and [int64]$maxIdle -le 1800000) {
            $minutes = [math]::Round([int64]$maxIdle / 60000, 0)
            Result-Pass "W-36" "원격터미널 접속 타임아웃 설정" "유휴 세션 제한: ${minutes}분 ($src, 30분 이하)"
        } elseif ($maxIdle -eq $null -or [int64]$maxIdle -eq 0) {
            Result-Fail "W-36" "원격터미널 접속 타임아웃 설정" "유휴 세션 제한(Timeout)이 설정되지 않음"
        } else {
            $minutes = [math]::Round([int64]$maxIdle / 60000, 0)
            Result-Fail "W-36" "원격터미널 접속 타임아웃 설정" "유휴 세션 제한: ${minutes}분 (30분 초과)"
        }
    }

    # ──────────────────────────────────────────────────────
    # W-37 (중) 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검
    # 양호: 불필요한 예약 작업을 주기적으로 점검하고 제거한 경우
    # ──────────────────────────────────────────────────────
    $userTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft*' })
    if ($userTasks.Count -eq 0) {
        Result-Pass "W-37" "예약된 작업에 의심스러운 명령이 등록되어 있는지 점검" "Microsoft 기본 작업 외 등록된 예약 작업 없음"
    } else {
        $taskLines = @()
        foreach ($t in $userTasks) {
            $exec = ""
            if ($t.Actions -and $t.Actions[0].Execute) { $exec = $t.Actions[0].Execute }
            $taskLines += "$($t.TaskPath)$($t.TaskName) [$($t.State)] $exec"
        }
        Result-Interview "W-37" "예약된 작업에 의심스러운 명령이 등록되어 있는지 점검" ("등록된 예약 작업의 필요·의심 여부 담당자 확인 필요`n" + ($taskLines -join "`n"))
    }
}
