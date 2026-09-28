# 04_log.ps1 - 4. 로그 관리 (W-40 ~ W-43)

function Invoke-LogChecks {
    Print-Section "4. 로그 관리 (W-40 ~ W-43)"

    # ──────────────────────────────────────────────────────
    # W-40 (중) 정책에 따른 시스템 로깅 설정
    # 양호: 감사 정책 권고 기준에 따라 감사 설정이 되어 있는 경우
    #   계정 관리: 실패 / 계정 로그온 이벤트: 성공,실패 / 권한 사용: 성공,실패
    #   디렉터리 서비스 액세스: 실패 / 로그온 이벤트: 성공,실패 / 정책 변경: 성공,실패
    # secedit [Event Audit] 값은 2022에서 유효 감사 정책을 반영하지 못해
    # (설정돼 있어도 항상 '미설정'으로 조회됨) auditpol 유효 정책의
    # 대표 하위 범주 GUID로 판정한다.
    # ──────────────────────────────────────────────────────
    $auditMap = @(
        @{ Guid = '0CCE9235-69AE-11D9-BED3-505054503030'; Name = '계정 관리';          NeedS = $false; NeedF = $true;  Std = '실패' },        # User Account Management
        @{ Guid = '0CCE923F-69AE-11D9-BED3-505054503030'; Name = '계정 로그온 이벤트'; NeedS = $true;  NeedF = $true;  Std = '성공/실패' },   # Credential Validation
        @{ Guid = '0CCE9228-69AE-11D9-BED3-505054503030'; Name = '권한 사용';          NeedS = $true;  NeedF = $true;  Std = '성공/실패' },   # Sensitive Privilege Use
        @{ Guid = '0CCE9215-69AE-11D9-BED3-505054503030'; Name = '로그온 이벤트';      NeedS = $true;  NeedF = $true;  Std = '성공/실패' },   # Logon
        @{ Guid = '0CCE922F-69AE-11D9-BED3-505054503030'; Name = '정책 변경';          NeedS = $true;  NeedF = $true;  Std = '성공/실패' }    # Audit Policy Change
    )
    # 디렉터리 서비스 액세스는 도메인 컨트롤러에서만 기록되므로 DC일 때만 점검
    $isDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)
    if ($isDC) {
        $auditMap += @{ Guid = '0CCE923B-69AE-11D9-BED3-505054503030'; Name = '디렉터리 서비스 액세스'; NeedS = $false; NeedF = $true; Std = '실패' }  # Directory Service Access
    }
    $auditUnmet = @()
    $auditDetail = @()
    foreach ($a in $auditMap) {
        $setting = Get-AuditSubcategorySetting $a.Guid
        $cur = '미설정'
        if ($setting) { $cur = $setting }
        $auditDetail += "$($a.Name): $cur (권고: $($a.Std))"
        $hasS = ($setting -match 'Success|성공')
        $hasF = ($setting -match 'Failure|실패')
        if (($a.NeedS -and -not $hasS) -or ($a.NeedF -and -not $hasF)) { $auditUnmet += $a.Name }
    }
    if ($auditUnmet.Count -eq 0) {
        Result-Pass "W-40" "정책에 따른 시스템 로깅 설정" ("감사 정책 권고 기준 충족(auditpol 유효 정책 기준)`n" + ($auditDetail -join "`n"))
    } else {
        Result-Fail "W-40" "정책에 따른 시스템 로깅 설정" ("권고 기준 미충족 항목: $($auditUnmet -join ', ')`n" + ($auditDetail -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-41 (중) NTP 및 시각 동기화 설정
    # 양호: NTP 및 시각 동기화를 설정한 경우
    # ──────────────────────────────────────────────────────
    $w32time = Get-ServiceSafe 'W32Time'
    $syncType = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type'
    $ntpServer = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'NtpServer'
    if ($w32time -and $w32time.Status -eq 'Running' -and $syncType -and $syncType.ToUpper() -ne 'NOSYNC') {
        Result-Pass "W-41" "NTP 및 시각 동기화 설정" "Windows Time 서비스 실행 중, 동기화 유형: $syncType, NTP 서버: $ntpServer"
    } else {
        $svcState = "서비스 없음"
        if ($w32time) { $svcState = "서비스 $($w32time.Status)" }
        Result-Fail "W-41" "NTP 및 시각 동기화 설정" "시각 동기화 미설정 ($svcState, 동기화 유형: $syncType)"
    }

    # ──────────────────────────────────────────────────────
    # W-42 (하) 이벤트 로그 관리 설정
    # 양호: 최대 로그 크기 10,240KB 이상, "90일 이후 이벤트 덮어씀" 설정
    # ※ 가이드: Windows 2008 이상 서버는 덮어쓰기 날짜 지정 불가능
    # ※ v3 보수적 판정: 날짜 지정이 불가능한 대신, 로그 유실을 방지하는
    #    "로그가 꽉 차면 로그 보관. 이벤트를 덮어쓰지 않음"(LogMode=AutoBackup)이
    #    설정되지 않은 경우 취약으로 식별
    #    - Circular   : 필요한 경우 이벤트 덮어쓰기 → 취약
    #    - AutoBackup : 로그가 꽉 차면 로그 보관     → 양호
    #    - Retain     : 이벤트 덮어쓰지 않음(수동)   → 취약
    # ──────────────────────────────────────────────────────
    $minBytes = 10240KB
    $logUnmet = @()
    $logDetail = @()
    $modeText = @{
        'Circular'   = '필요한 경우 이벤트 덮어쓰기'
        'AutoBackup' = '로그가 꽉 차면 로그 보관(덮어쓰지 않음)'
        'Retain'     = '이벤트 덮어쓰지 않음(수동으로 로그 지우기)'
    }
    foreach ($logName in @('Application', 'Security', 'System')) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $sizeKB = [int]($log.MaximumSizeInBytes / 1KB)
            $mode = "$($log.LogMode)"
            $modeDesc = $mode
            if ($modeText.ContainsKey($mode)) { $modeDesc = $modeText[$mode] }
            $logDetail += "${logName}: 최대 크기 ${sizeKB}KB, 보존 방법 ${modeDesc}"

            $reasons = @()
            if ($log.MaximumSizeInBytes -lt $minBytes) { $reasons += "최대 크기 10,240KB 미만" }
            if ($mode -ne 'AutoBackup') { $reasons += "보존 방법이 '로그 보관'이 아님" }
            if ($reasons.Count -gt 0) { $logUnmet += ("${logName}(" + ($reasons -join ', ') + ")") }
        } catch {
            $logDetail += "${logName}: 조회 실패"
            $logUnmet += "${logName}(조회 실패)"
        }
    }
    if ($logUnmet.Count -eq 0) {
        Result-Pass "W-42" "이벤트 로그 관리 설정" (($logDetail -join ", ") + " (10,240KB 이상, 로그 보관 설정)")
    } else {
        Result-Fail "W-42" "이벤트 로그 관리 설정" ("기준 미충족 로그: $($logUnmet -join ', ')`n" + ($logDetail -join "`n") + "`n※ 조치: 이벤트 뷰어 > Windows 로그 > 해당 로그 > 속성 > '로그가 꽉 차면 로그 보관. 이벤트를 덮어쓰지 않음' 선택")
    }

    # ──────────────────────────────────────────────────────
    # W-43 (중) 이벤트 로그 파일 접근 통제 설정
    # 양호: 로그 디렉터리의 접근 권한에 Everyone 권한이 없는 경우
    #   시스템 로그: %systemroot%\system32\config
    #   IIS 로그  : %systemroot%\system32\LogFiles
    # ──────────────────────────────────────────────────────
    $logDirs = @(
        (Join-Path $env:SystemRoot 'System32\config'),
        (Join-Path $env:SystemRoot 'System32\LogFiles')
    )
    $everyoneDirs = @()
    $failedDirs = @()
    foreach ($d in $logDirs) {
        if (-not (Test-Path $d)) { continue }
        $aces = Get-AclEveryone $d
        if ($aces -eq $null) { $failedDirs += $d }
        elseif ($aces.Count -gt 0) { $everyoneDirs += $d }
    }
    if ($everyoneDirs.Count -gt 0) {
        Result-Fail "W-43" "이벤트 로그 파일 접근 통제 설정" ("Everyone 권한이 존재하는 로그 디렉터리`n" + ($everyoneDirs -join "`n"))
    } elseif ($failedDirs.Count -gt 0) {
        Result-Interview "W-43" "이벤트 로그 파일 접근 통제 설정" ("일부 디렉터리 권한 조회 실패 - 수동 확인 필요`n" + ($failedDirs -join "`n"))
    } else {
        Result-Pass "W-43" "이벤트 로그 파일 접근 통제 설정" "로그 디렉터리(config, LogFiles)에 Everyone 권한 없음"
    }
}
