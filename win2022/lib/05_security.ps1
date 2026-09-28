# 05_security.ps1 - 5. 보안 관리 (W-44 ~ W-64)

function Invoke-SecurityChecks {
    Print-Section "5. 보안 관리 (W-44 ~ W-64)"

    # ──────────────────────────────────────────────────────
    # W-44 (상) 원격으로 액세스할 수 있는 레지스트리 경로
    # 양호: Remote Registry Service가 중지된 경우
    # ──────────────────────────────────────────────────────
    $remoteReg = Get-ServiceSafe 'RemoteRegistry'
    if ($remoteReg -and $remoteReg.Status -eq 'Running') {
        Result-Fail "W-44" "원격으로 액세스할 수 있는 레지스트리 경로" "Remote Registry 서비스가 사용 중임(시작 유형: $($remoteReg.StartType))"
    } else {
        $note = "서비스 없음"
        if ($remoteReg) {
            $note = "중지됨(시작 유형: $($remoteReg.StartType))"
            if ($remoteReg.StartType -ne 'Disabled') { $note += " - '사용 안 함' 설정 권장" }
        }
        Result-Pass "W-44" "원격으로 액세스할 수 있는 레지스트리 경로" "Remote Registry 서비스 $note"
    }

    # ──────────────────────────────────────────────────────
    # W-45 (상) 백신 프로그램 설치
    # 양호: 바이러스 백신 프로그램이 설치된 경우
    # ──────────────────────────────────────────────────────
    $avFound = @()
    $defender = Get-ServiceSafe 'WinDefend'
    if ($defender -and $defender.Status -eq 'Running') { $avFound += "Microsoft Defender Antivirus" }
    $avPatterns = 'AhnLab|V3 |ALYac|ESTsoft|ViRobot|Hauri|Symantec|McAfee|Kaspersky|Trend Micro|ESET|Sophos|CrowdStrike|SentinelOne|Avast|Bitdefender'
    $thirdParty = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match $avPatterns -and $_.Status -eq 'Running' } |
        ForEach-Object { $_.DisplayName })
    $avFound += $thirdParty
    $avFound = @($avFound | Select-Object -Unique)
    if ($avFound.Count -gt 0) {
        Result-Pass "W-45" "백신 프로그램 설치" "백신 프로그램 확인됨: $($avFound -join ', ')"
    } else {
        Result-Fail "W-45" "백신 프로그램 설치" "실행 중인 백신 프로그램을 확인할 수 없음"
    }

    # ──────────────────────────────────────────────────────
    # W-46 (상) SAM 파일 접근 통제 설정
    # 양호: SAM 파일 접근 권한에 Administrator, System 그룹만 모든 권한으로 설정된 경우
    # ──────────────────────────────────────────────────────
    $samPath = Join-Path $env:SystemRoot 'System32\config\SAM'
    try {
        $samAcl = Get-Acl -Path $samPath -ErrorAction Stop
        $samOthers = @()
        foreach ($ace in $samAcl.Access) {
            $sid = $null
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $sid = $ace.IdentityReference.Value }
            if ($sid -ne 'S-1-5-18' -and $sid -ne 'S-1-5-32-544') {
                $samOthers += "$($ace.IdentityReference.Value) ($($ace.FileSystemRights))"
            }
        }
        if ($samOthers.Count -eq 0) {
            Result-Pass "W-46" "SAM 파일 접근 통제 설정" "SAM 파일 권한이 SYSTEM, Administrators만 설정됨"
        } else {
            Result-Fail "W-46" "SAM 파일 접근 통제 설정" ("SYSTEM, Administrators 외 권한 존재`n" + ($samOthers -join "`n"))
        }
    } catch {
        Result-Interview "W-46" "SAM 파일 접근 통제 설정" "SAM 파일 권한을 조회할 수 없음 - 수동 확인 필요($samPath)"
    }

    # ──────────────────────────────────────────────────────
    # W-47 (하) 화면 보호기 설정
    # 양호: 화면 보호기 설정 + 대기 시간 10분 이하 + 해제 시 암호 사용
    # ※ 현재 로그온(진단 실행) 사용자 기준으로 점검
    # ──────────────────────────────────────────────────────
    $ssPolicy = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
    $ssUser   = 'HKCU:\Control Panel\Desktop'
    $ssActive  = Get-RegValue $ssPolicy 'ScreenSaveActive'
    $ssTimeout = Get-RegValue $ssPolicy 'ScreenSaveTimeOut'
    $ssSecure  = Get-RegValue $ssPolicy 'ScreenSaverIsSecure'
    if ($ssActive -eq $null)  { $ssActive  = Get-RegValue $ssUser 'ScreenSaveActive' }
    if ($ssTimeout -eq $null) { $ssTimeout = Get-RegValue $ssUser 'ScreenSaveTimeOut' }
    if ($ssSecure -eq $null)  { $ssSecure  = Get-RegValue $ssUser 'ScreenSaverIsSecure' }
    $ssIssues = @()
    if ($ssActive -eq $null -or "$ssActive" -ne '1') { $ssIssues += "화면 보호기 미사용($ssActive)" }
    if ($ssTimeout -eq $null -or [int]$ssTimeout -gt 600 -or [int]$ssTimeout -le 0) { $ssIssues += "대기 시간 ${ssTimeout}초(10분 초과 또는 미설정)" }
    if ($ssSecure -eq $null -or "$ssSecure" -ne '1') { $ssIssues += "해제 시 암호(로그온 화면 표시) 미사용($ssSecure)" }
    if ($ssIssues.Count -eq 0) {
        $ssMin = [int]([int]$ssTimeout / 60)
        Result-Pass "W-47" "화면 보호기 설정" "화면 보호기 사용, 대기 시간 ${ssMin}분, 해제 시 암호 사용 (현재 사용자 기준)"
    } else {
        Result-Fail "W-47" "화면 보호기 설정" (("현재 사용자($env:USERNAME) 기준 미충족: ") + ($ssIssues -join ", "))
    }

    # ──────────────────────────────────────────────────────
    # W-48 (상) 로그온하지 않고 시스템 종료 허용
    # 양호: "로그온하지 않고 시스템 종료 허용"이 "사용 안 함"으로 설정된 경우
    # ──────────────────────────────────────────────────────
    $shutdownNoLogon = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ShutdownWithoutLogon'
    if ($shutdownNoLogon -ne $null -and [int]$shutdownNoLogon -eq 0) {
        Result-Pass "W-48" "로그온하지 않고 시스템 종료 허용" "'시스템 종료: 로그온하지 않고 시스템 종료 허용' 정책: 사용 안 함(0)"
    } else {
        Result-Fail "W-48" "로그온하지 않고 시스템 종료 허용" "'시스템 종료: 로그온하지 않고 시스템 종료 허용' 정책: 사용($shutdownNoLogon)"
    }

    # ──────────────────────────────────────────────────────
    # W-49 (상) 원격 시스템에서 강제로 시스템 종료
    # 양호: 해당 정책에 "Administrators"만 존재하는 경우
    # ──────────────────────────────────────────────────────
    $remoteShutRaw   = Get-PrivilegeRawEntries (Get-SecPol 'SeRemoteShutdownPrivilege')
    $remoteShutNames = Convert-PrivilegeEntries (Get-SecPol 'SeRemoteShutdownPrivilege')
    $shutOthers = @()
    for ($i = 0; $i -lt $remoteShutRaw.Count; $i++) {
        if ($remoteShutRaw[$i] -ne '*S-1-5-32-544') { $shutOthers += $remoteShutNames[$i] }
    }
    if ($remoteShutRaw.Count -gt 0 -and $shutOthers.Count -eq 0) {
        Result-Pass "W-49" "원격 시스템에서 강제로 시스템 종료" "'원격 시스템에서 강제로 시스템 종료' 정책: Administrators만 존재"
    } elseif ($remoteShutRaw.Count -eq 0) {
        Result-Pass "W-49" "원격 시스템에서 강제로 시스템 종료" "해당 권한이 할당된 계정/그룹 없음"
    } else {
        Result-Fail "W-49" "원격 시스템에서 강제로 시스템 종료" "Administrators 외 계정/그룹 존재: $($shutOthers -join ', ')"
    }

    # ──────────────────────────────────────────────────────
    # W-50 (상) 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료
    # 양호: 해당 정책이 "사용 안 함"으로 되어있는 경우
    # ──────────────────────────────────────────────────────
    $crashOnAudit = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'CrashOnAuditFail'
    if ($crashOnAudit -eq $null -or [int]$crashOnAudit -eq 0) {
        $val = "0(기본값)"
        if ($crashOnAudit -ne $null) { $val = "$crashOnAudit" }
        Result-Pass "W-50" "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료" "'감사: 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료' 정책: 사용 안 함($val)"
    } else {
        Result-Fail "W-50" "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료" "'감사: 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료' 정책: 사용($crashOnAudit)"
    }

    # ──────────────────────────────────────────────────────
    # W-51 (상) SAM 계정과 공유의 익명 열거 허용 안 함
    # 양호: 해당 정책이 "사용"으로 설정된 경우
    #   RestrictAnonymous(계정과 공유), RestrictAnonymousSAM(SAM 계정)
    # ──────────────────────────────────────────────────────
    $restrictAnon    = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous'
    $restrictAnonSam = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM'
    $anonIssues = @()
    if ($restrictAnon -eq $null -or [int]$restrictAnon -ne 1) { $anonIssues += "SAM 계정과 공유의 익명 열거 허용 안 함: 사용 안 함($restrictAnon)" }
    if ($restrictAnonSam -ne $null -and [int]$restrictAnonSam -ne 1) { $anonIssues += "SAM 계정의 익명 열거 허용 안 함: 사용 안 함($restrictAnonSam)" }
    if ($anonIssues.Count -eq 0) {
        Result-Pass "W-51" "SAM 계정과 공유의 익명 열거 허용 안 함" "RestrictAnonymous=1, RestrictAnonymousSAM=$restrictAnonSam (사용)"
    } else {
        Result-Fail "W-51" "SAM 계정과 공유의 익명 열거 허용 안 함" ($anonIssues -join "`n")
    }

    # ──────────────────────────────────────────────────────
    # W-52 (상) Autologon 기능 제어
    # 양호: AutoAdminLogon 값이 없거나 0으로 설정된 경우
    # ──────────────────────────────────────────────────────
    $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $autoLogon = Get-RegValue $winlogonKey 'AutoAdminLogon'
    $defaultPw = Get-RegValue $winlogonKey 'DefaultPassword'
    if ($autoLogon -eq $null -or "$autoLogon" -eq '0') {
        $val = "값 없음(기본값 비활성화)"
        if ($autoLogon -ne $null) { $val = "0" }
        $extra = ""
        if ($defaultPw -ne $null) { $extra = " ※ DefaultPassword 값이 존재함 - 제거 권장" }
        Result-Pass "W-52" "Autologon 기능 제어" "AutoAdminLogon: $val$extra"
    } else {
        $extra = ""
        if ($defaultPw -ne $null) { $extra = " (DefaultPassword 값도 존재 - 제거 필요)" }
        Result-Fail "W-52" "Autologon 기능 제어" "AutoAdminLogon 값이 $autoLogon 으로 설정됨$extra"
    }

    # ──────────────────────────────────────────────────────
    # W-53 (상) 이동식 미디어 포맷 및 꺼내기 허용
    # 양호: 해당 정책이 "Administrators"로 되어있는 경우 (AllocateDASD=0)
    # ──────────────────────────────────────────────────────
    $allocateDasd = Get-RegValue $winlogonKey 'AllocateDASD'
    if ($allocateDasd -eq $null -or "$allocateDasd" -eq '0') {
        $val = "미설정(기본값 Administrators)"
        if ($allocateDasd -ne $null) { $val = "0(Administrators)" }
        Result-Pass "W-53" "이동식 미디어 포맷 및 꺼내기 허용" "'장치: 이동식 미디어 포맷 및 꺼내기 허용': $val"
    } else {
        $meaning = "Administrators 및 Power Users"
        if ("$allocateDasd" -eq '2') { $meaning = "Administrators 및 Interactive Users" }
        Result-Fail "W-53" "이동식 미디어 포맷 및 꺼내기 허용" "'장치: 이동식 미디어 포맷 및 꺼내기 허용': $allocateDasd ($meaning)"
    }

    # ──────────────────────────────────────────────────────
    # W-54 (중) Dos 공격 방어 레지스트리 설정
    # 양호: SynAttackProtect>=1, EnableDeadGWDetect=0,
    #       KeepAliveTime=300,000, NoNameReleaseOnDemand=1
    # ──────────────────────────────────────────────────────
    $tcpipKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $syn       = Get-RegValue $tcpipKey 'SynAttackProtect'
    $deadGw    = Get-RegValue $tcpipKey 'EnableDeadGWDetect'
    $keepAlive = Get-RegValue $tcpipKey 'KeepAliveTime'
    $noName    = Get-RegValue $tcpipKey 'NoNameReleaseOnDemand'
    $dosUnmet = @()
    if ($syn -eq $null -or [int]$syn -lt 1)             { $dosUnmet += "SynAttackProtect: $syn (1 이상 필요)" }
    if ($deadGw -eq $null -or [int]$deadGw -ne 0)       { $dosUnmet += "EnableDeadGWDetect: $deadGw (0 필요)" }
    if ($keepAlive -eq $null -or [int64]$keepAlive -gt 300000 -or [int64]$keepAlive -le 0) { $dosUnmet += "KeepAliveTime: $keepAlive (300,000 필요)" }
    if ($noName -eq $null -or [int]$noName -ne 1)       { $dosUnmet += "NoNameReleaseOnDemand: $noName (1 필요)" }
    if ($dosUnmet.Count -eq 0) {
        Result-Pass "W-54" "Dos 공격 방어 레지스트리 설정" "SynAttackProtect=$syn, EnableDeadGWDetect=$deadGw, KeepAliveTime=$keepAlive, NoNameReleaseOnDemand=$noName"
    } else {
        Result-Fail "W-54" "Dos 공격 방어 레지스트리 설정" ("DoS 방어 레지스트리 미설정 항목 존재`n" + ($dosUnmet -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-55 (중) 사용자가 프린터 드라이버를 설치할 수 없게 함
    # 양호: 해당 정책이 "사용"인 경우 (AddPrinterDrivers=1)
    # ──────────────────────────────────────────────────────
    $addPrinter = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers'
    if ($addPrinter -ne $null -and [int]$addPrinter -eq 1) {
        Result-Pass "W-55" "사용자가 프린터 드라이버를 설치할 수 없게 함" "'장치: 사용자가 프린터 드라이버를 설치할 수 없게 함' 정책: 사용(1)"
    } else {
        Result-Fail "W-55" "사용자가 프린터 드라이버를 설치할 수 없게 함" "'장치: 사용자가 프린터 드라이버를 설치할 수 없게 함' 정책: 사용 안 함($addPrinter)"
    }

    # ──────────────────────────────────────────────────────
    # W-56 (중) SMB 세션 중단 관리 설정
    # 양호: "로그온 시간이 만료되면 클라이언트 연결 끊기" 사용 +
    #       "세션 연결을 중단하기 전에 필요한 유휴 시간" 15분 이하
    # ──────────────────────────────────────────────────────
    $lanmanKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $forcedLogoff   = Get-RegValue $lanmanKey 'EnableForcedLogoff'
    $autoDisconnect = Get-RegValue $lanmanKey 'AutoDisconnect'
    $smbIssues = @()
    if ($forcedLogoff -ne $null -and [int]$forcedLogoff -ne 1) { $smbIssues += "로그온 시간 만료 시 클라이언트 연결 끊기: 사용 안 함($forcedLogoff)" }
    if ($autoDisconnect -ne $null -and ([int]$autoDisconnect -gt 15 -or [int]$autoDisconnect -lt 0)) { $smbIssues += "세션 중단 전 필요한 유휴 시간: ${autoDisconnect}분 (15분 초과)" }
    if ($smbIssues.Count -eq 0) {
        $fVal = "1(기본값)"
        if ($forcedLogoff -ne $null) { $fVal = "$forcedLogoff" }
        $aVal = "15(기본값)"
        if ($autoDisconnect -ne $null) { $aVal = "$autoDisconnect" }
        Result-Pass "W-56" "SMB 세션 중단 관리 설정" "EnableForcedLogoff=$fVal, AutoDisconnect=${aVal}분"
    } else {
        Result-Fail "W-56" "SMB 세션 중단 관리 설정" ($smbIssues -join "`n")
    }

    # ──────────────────────────────────────────────────────
    # W-57 (하) 로그온 시 경고 메시지 설정
    # 양호: 로그인 경고 메시지 제목 및 내용이 설정된 경우
    # ──────────────────────────────────────────────────────
    $policySystem = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $noticeCaption = Get-RegValue $policySystem 'LegalNoticeCaption'
    $noticeText    = Get-RegValue $policySystem 'LegalNoticeText'
    if ($noticeCaption -and $noticeText -and "$noticeCaption".Trim() -and "$noticeText".Trim()) {
        Result-Pass "W-57" "로그온 시 경고 메시지 설정" "경고 메시지 제목/내용 설정됨 (제목: $noticeCaption)"
    } else {
        Result-Fail "W-57" "로그온 시 경고 메시지 설정" "로그온 경고 메시지 제목 또는 내용이 설정되어 있지 않음"
    }

    # ──────────────────────────────────────────────────────
    # W-58 (중) 사용자별 홈 디렉터리 권한 설정
    # 양호: 홈 디렉터리에 Everyone 권한이 없는 경우 (Public, Default 등 제외)
    # ──────────────────────────────────────────────────────
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    $excludeDirs = @('Public', 'Default', 'Default User', 'All Users')
    $homeDirs = @(Get-ChildItem -Path $usersRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $excludeDirs -notcontains $_.Name })
    $homeEveryone = @()
    foreach ($d in $homeDirs) {
        $aces = Get-AclEveryone $d.FullName
        if ($aces -ne $null -and $aces.Count -gt 0) { $homeEveryone += $d.FullName }
    }
    if ($homeEveryone.Count -eq 0) {
        Result-Pass "W-58" "사용자별 홈 디렉터리 권한 설정" "사용자 홈 디렉터리($($homeDirs.Count)개)에 Everyone 권한 없음"
    } else {
        Result-Fail "W-58" "사용자별 홈 디렉터리 권한 설정" ("Everyone 권한이 존재하는 홈 디렉터리`n" + ($homeEveryone -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-59 (중) LAN Manager 인증 수준
    # 양호: "NTLMv2 응답만 보냄" 설정 (LmCompatibilityLevel 3 이상)
    # ──────────────────────────────────────────────────────
    $lmLevel = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    if ($lmLevel -eq $null) {
        # 가이드 양호 기준은 "NTLMv2 응답만 보냄"이 '설정'되어 있는 경우이므로
        # 정책 미정의(정책 화면에 '정의되지 않음' 표시) 상태는 양호 기준 미충족.
        # 가이드 조치 시 영향이 "일반적인 경우 영향 없음"이므로 명시 설정을 권고하며
        # 보수적으로 취약 식별
        Result-Fail "W-59" "LAN Manager 인증 수준" "LmCompatibilityLevel 미설정(정책 '정의되지 않음') - 'NTLMv2 응답만 보냄'이 명시 설정되어 있지 않음`n※ 조치: 로컬 보안 정책 > 로컬 정책 > 보안 옵션 > '네트워크 보안: LAN Manager 인증 수준' > 'NTLMv2 응답만 보냄' 설정"
    } elseif ([int]$lmLevel -ge 3) {
        Result-Pass "W-59" "LAN Manager 인증 수준" "LmCompatibilityLevel: $lmLevel (NTLMv2 응답만 보냄 이상)"
    } else {
        Result-Fail "W-59" "LAN Manager 인증 수준" "LmCompatibilityLevel: $lmLevel (LM/NTLM 인증 허용 상태)"
    }

    # ──────────────────────────────────────────────────────
    # W-60 (중) 보안 채널 데이터 디지털 암호화 또는 서명
    # 양호: 아래 3가지 정책 모두 "사용"인 경우
    # ──────────────────────────────────────────────────────
    $netlogonKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $requireSS = Get-RegValue $netlogonKey 'RequireSignOrSeal'
    $sealSC    = Get-RegValue $netlogonKey 'SealSecureChannel'
    $signSC    = Get-RegValue $netlogonKey 'SignSecureChannel'
    $scIssues = @()
    if ($requireSS -eq $null -or [int]$requireSS -ne 1) { $scIssues += "보안 채널 데이터를 디지털 암호화 또는 서명(항상): 사용 안 함($requireSS)" }
    if ($sealSC -eq $null -or [int]$sealSC -ne 1)       { $scIssues += "보안 채널 데이터를 디지털 암호화(가능한 경우): 사용 안 함($sealSC)" }
    if ($signSC -eq $null -or [int]$signSC -ne 1)       { $scIssues += "보안 채널 데이터 디지털 서명(가능한 경우): 사용 안 함($signSC)" }
    if ($scIssues.Count -eq 0) {
        Result-Pass "W-60" "보안 채널 데이터 디지털 암호화 또는 서명" "RequireSignOrSeal=1, SealSecureChannel=1, SignSecureChannel=1 (모두 사용)"
    } else {
        Result-Fail "W-60" "보안 채널 데이터 디지털 암호화 또는 서명" ($scIssues -join "`n")
    }

    # ──────────────────────────────────────────────────────
    # W-61 (중) 파일 및 디렉토리 보호
    # 양호: NTFS 파일 시스템을 사용하는 경우
    # ──────────────────────────────────────────────────────
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")
    $fatDrives = @()
    $diskInfo = @()
    foreach ($disk in $disks) {
        $diskInfo += "$($disk.DeviceID) $($disk.FileSystem)"
        if ($disk.FileSystem -match 'FAT') { $fatDrives += "$($disk.DeviceID) ($($disk.FileSystem))" }
    }
    if ($fatDrives.Count -eq 0) {
        Result-Pass "W-61" "파일 및 디렉토리 보호" "모든 고정 드라이브가 NTFS 계열 사용: $($diskInfo -join ', ')"
    } else {
        Result-Fail "W-61" "파일 및 디렉토리 보호" "FAT 파일 시스템 사용 드라이브 존재: $($fatDrives -join ', ')"
    }

    # ──────────────────────────────────────────────────────
    # W-62 (중) 시작프로그램 목록 분석
    # 양호: 시작 프로그램 목록을 정기적으로 검사하고 불필요한 서비스를 비활성화한 경우
    # ──────────────────────────────────────────────────────
    $startupItems = @()
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($rk in $runKeys) {
        try {
            $props = Get-ItemProperty -Path $rk -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                    $startupItems += "[$rk] $($prop.Name) = $($prop.Value)"
                }
            }
        } catch { }
    }
    $startupFolders = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'),
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    foreach ($sf in $startupFolders) {
        if (Test-Path $sf) {
            foreach ($f in (Get-ChildItem -Path $sf -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
                $startupItems += "[시작프로그램 폴더] $($f.FullName)"
            }
        }
    }
    if ($startupItems.Count -eq 0) {
        Result-Pass "W-62" "시작프로그램 목록 분석" "등록된 시작 프로그램 없음"
    } else {
        Result-Interview "W-62" "시작프로그램 목록 분석" ("시작 프로그램 목록의 정기 점검 여부 및 불필요·의심 항목 담당자 확인 필요`n" + ($startupItems -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-63 (중) 도메인 컨트롤러-사용자의 시간 동기화
    # 양호: 컴퓨터 시계 동기화 최대 허용 오차값이 5분 이하인 경우 (Kerberos 정책)
    # ──────────────────────────────────────────────────────
    $partOfDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    $maxClockSkew = Get-SecPol 'MaxClockSkew'
    if (-not $partOfDomain) {
        Result-Pass "W-63" "도메인 컨트롤러-사용자의 시간 동기화" "도메인 미가입 시스템으로 Kerberos 정책 해당 없음"
    } elseif ($maxClockSkew -ne $null) {
        if ([int]$maxClockSkew -le 5) {
            Result-Pass "W-63" "도메인 컨트롤러-사용자의 시간 동기화" "컴퓨터 시계 동기화 최대 허용 오차: ${maxClockSkew}분 (5분 이하)"
        } else {
            Result-Fail "W-63" "도메인 컨트롤러-사용자의 시간 동기화" "컴퓨터 시계 동기화 최대 허용 오차: ${maxClockSkew}분 (5분 초과)"
        }
    } else {
        Result-Interview "W-63" "도메인 컨트롤러-사용자의 시간 동기화" "도메인 가입 시스템이나 로컬에서 Kerberos 정책 값을 확인할 수 없음 - 도메인 GPO의 '컴퓨터 시계 동기화 최대 허용 오차' 확인 필요"
    }

    # ──────────────────────────────────────────────────────
    # W-64 (중) 윈도우 방화벽 설정
    # 양호: Windows 방화벽 "사용"으로 설정된 경우
    # ──────────────────────────────────────────────────────
    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    if ($profiles.Count -eq 0) {
        Result-Interview "W-64" "윈도우 방화벽 설정" "방화벽 프로필 정보를 조회할 수 없음 - 수동 확인 필요"
    } else {
        $disabledProfiles = @($profiles | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
        $profileInfo = ($profiles | ForEach-Object {
            $state = "사용 안 함"
            if ($_.Enabled) { $state = "사용" }
            "$($_.Name): $state"
        }) -join ', '
        if ($disabledProfiles.Count -eq 0) {
            Result-Pass "W-64" "윈도우 방화벽 설정" "모든 방화벽 프로필 사용 중 ($profileInfo)"
        } else {
            Result-Fail "W-64" "윈도우 방화벽 설정" "사용 안 함 상태의 방화벽 프로필 존재 ($profileInfo)"
        }
    }
}
