# common.ps1 - 공통 함수 및 변수 정의
# 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026) Windows 서버

# ────────────────────────────────────────────────────────────
# 카운터 및 결과 저장
# ────────────────────────────────────────────────────────────
$script:PASS      = 0
$script:FAIL      = 0
$script:INTERVIEW = 0
$script:NA        = 0
$script:RESULTS   = @()

# ────────────────────────────────────────────────────────────
# 결과 출력 함수
# ────────────────────────────────────────────────────────────
function Write-Detail {
    param([string]$Detail)
    if ($Detail) {
        foreach ($ln in ($Detail -split "`r?`n")) {
            Write-Host "        └─ $ln" -ForegroundColor DarkGray
        }
    }
}

function Result-Pass {
    param([string]$Id, [string]$Title, [string]$Detail = "")
    Write-Host "[" -NoNewline
    Write-Host "양호" -ForegroundColor Green -NoNewline
    Write-Host ("]   {0,-6} {1}" -f $Id, $Title)
    Write-Detail $Detail
    $script:RESULTS += [PSCustomObject]@{ Status = "PASS"; Id = $Id; Title = $Title; Detail = $Detail }
    $script:PASS++
}

function Result-Fail {
    param([string]$Id, [string]$Title, [string]$Detail = "")
    Write-Host "[" -NoNewline
    Write-Host "취약" -ForegroundColor Red -NoNewline
    Write-Host ("]   {0,-6} {1}" -f $Id, $Title)
    Write-Detail $Detail
    $script:RESULTS += [PSCustomObject]@{ Status = "FAIL"; Id = $Id; Title = $Title; Detail = $Detail }
    $script:FAIL++
}

function Result-Interview {
    param([string]$Id, [string]$Title, [string]$Detail = "")
    Write-Host "[" -NoNewline
    Write-Host "인터뷰" -ForegroundColor Yellow -NoNewline
    Write-Host ("] {0,-6} {1}" -f $Id, $Title)
    Write-Detail $Detail
    $script:RESULTS += [PSCustomObject]@{ Status = "INTERVIEW"; Id = $Id; Title = $Title; Detail = $Detail }
    $script:INTERVIEW++
}

# 해당없음: 가이드의 '점검 대상' OS에 Windows Server 2022가 포함되지 않아
#           판단 기준 자체가 성립하지 않는 항목에 사용
function Result-NA {
    param([string]$Id, [string]$Title, [string]$Detail = "")
    Write-Host "[" -NoNewline
    Write-Host "해당없음" -ForegroundColor Cyan -NoNewline
    Write-Host ("] {0,-6} {1}" -f $Id, $Title)
    Write-Detail $Detail
    $script:RESULTS += [PSCustomObject]@{ Status = "N/A"; Id = $Id; Title = $Title; Detail = $Detail }
    $script:NA++
}

# ────────────────────────────────────────────────────────────
# 섹션 헤더 출력
# ────────────────────────────────────────────────────────────
function Print-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
}

# ────────────────────────────────────────────────────────────
# 레지스트리 값 조회 (없으면 $null 반환)
# ────────────────────────────────────────────────────────────
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

# ────────────────────────────────────────────────────────────
# 로컬 보안 정책 내보내기 (secedit) 후 파싱
#   [System Access], [Event Audit], [Privilege Rights],
#   [Kerberos Policy] 등의 키=값을 해시테이블로 보관
# ────────────────────────────────────────────────────────────
function Initialize-SecPol {
    $tmp = Join-Path $env:TEMP ("secpol_" + [guid]::NewGuid().ToString('N') + ".inf")
    $null = secedit /export /cfg "$tmp" /quiet
    $script:SecPol = @{}
    if (Test-Path $tmp) {
        foreach ($line in (Get-Content $tmp)) {
            if ($line -match '^\s*(.+?)\s*=\s*(.*)$') {
                $script:SecPol[$matches[1]] = $matches[2].Trim().Trim('"')
            }
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "[경고] secedit 정책 내보내기에 실패했습니다. 정책 기반 항목이 부정확할 수 있습니다." -ForegroundColor Yellow
    }
}

function Get-SecPol {
    param([string]$Key)
    if ($script:SecPol -and $script:SecPol.ContainsKey($Key)) { return $script:SecPol[$Key] }
    return $null
}

# ────────────────────────────────────────────────────────────
# 감사 정책 조회 (auditpol 유효 정책 기반)
#   secedit [Event Audit] 값은 2008 이상에서 유효 감사 정책을
#   반영하지 못하므로(고급 감사 정책이 우선 적용) auditpol
#   /get /category:* /r 의 CSV를 하위 범주 GUID로 조회한다.
#   GUID 기반 매칭이므로 OS 표시 언어와 무관하게 동작한다.
# ────────────────────────────────────────────────────────────
$script:AuditPolCsv = $null

function Get-AuditSubcategorySetting {
    # 반환: 설정 문자열("Success and Failure"/"성공 및 실패" 등), 미확인 시 $null
    param([string]$Guid)
    if ($script:AuditPolCsv -eq $null) {
        $script:AuditPolCsv = @(auditpol /get /category:* /r 2>$null |
            Where-Object { $_ -match '\{[0-9A-Fa-f-]{36}\}' })
    }
    $line = $script:AuditPolCsv | Where-Object { $_ -match [regex]::Escape($Guid) } | Select-Object -First 1
    if (-not $line) { return $null }
    # CSV 컬럼: 머신,정책대상,하위범주,하위범주GUID,포함설정,제외설정
    # (헤더명이 로케일 의존이므로 GUID 다음 칸을 위치 기반으로 취함)
    $parts = $line -split ','
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -match [regex]::Escape($Guid)) {
            if ($i + 1 -lt $parts.Count) { return $parts[$i + 1].Trim() }
        }
    }
    return $null
}

# ────────────────────────────────────────────────────────────
# 사용자 권한 할당 값(*SID,계정,...)을 계정명 배열로 변환
# ────────────────────────────────────────────────────────────
function Convert-PrivilegeEntries {
    param([string]$Value)
    $names = @()
    if (-not $Value) { return ,$names }
    foreach ($item in ($Value -split ',')) {
        $t = $item.Trim()
        if (-not $t) { continue }
        if ($t.StartsWith('*')) {
            $sid = $t.Substring(1)
            try {
                $acct = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value
                $names += "$acct"
            } catch {
                $names += $sid
            }
        } else {
            $names += $t
        }
    }
    return ,$names
}

# 사용자 권한 할당 원본 항목(SID 유지) 배열
function Get-PrivilegeRawEntries {
    param([string]$Value)
    $entries = @()
    if (-not $Value) { return ,$entries }
    foreach ($item in ($Value -split ',')) {
        $t = $item.Trim()
        if ($t) { $entries += $t }
    }
    return ,$entries
}

# ────────────────────────────────────────────────────────────
# 경로 ACL에서 Everyone(S-1-1-0) ACE 목록 조회
#   반환: $null(조회 실패) 또는 ACE 배열(비어 있을 수 있음)
# ────────────────────────────────────────────────────────────
function Get-AclEveryone {
    param([string]$Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
    } catch {
        return $null
    }
    $hits = @()
    foreach ($ace in $acl.Access) {
        $sid = $null
        try {
            $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            $sid = $ace.IdentityReference.Value
        }
        if ($sid -eq 'S-1-1-0' -or $ace.IdentityReference.Value -eq 'Everyone') {
            $hits += $ace
        }
    }
    return ,$hits
}

# ────────────────────────────────────────────────────────────
# 로컬 그룹 구성원 조회 (Get-LocalGroupMember 실패 시 net localgroup 대체)
# ────────────────────────────────────────────────────────────
function Get-LocalGroupMembersSafe {
    param([string]$SidValue, [string]$NameFallback)
    try {
        $members = @(Get-LocalGroupMember -SID $SidValue -ErrorAction Stop)
        return ,@($members | ForEach-Object { $_.Name })
    } catch {
        $names = @()
        $out = net localgroup "$NameFallback" 2>$null
        $inList = $false
        foreach ($line in $out) {
            if ($line -match '^-{5,}') { $inList = $true; continue }
            if ($inList) {
                if ($line -match '완료|completed successfully') { break }
                if ($line.Trim()) { $names += $line.Trim() }
            }
        }
        return ,$names
    }
}

# ────────────────────────────────────────────────────────────
# 서비스 조회 (없으면 $null)
# ────────────────────────────────────────────────────────────
function Get-ServiceSafe {
    param([string]$Name)
    return (Get-Service -Name $Name -ErrorAction SilentlyContinue)
}

# ────────────────────────────────────────────────────────────
# 최종 요약 리포트 생성
# ────────────────────────────────────────────────────────────
function New-Report {
    param([string]$ScriptRoot)

    $reportDir = Join-Path $ScriptRoot 'report'
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir | Out-Null
    }
    $ts  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $out = Join-Path $reportDir ("result_{0}_{1}.txt" -f $env:COMPUTERNAME, $ts)

    $total = $script:PASS + $script:FAIL + $script:INTERVIEW + $script:NA
    $os    = (Get-CimInstance Win32_OperatingSystem).Caption
    $build = (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuild')
    $ubr   = (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR')

    $lines = @()
    $lines += "============================================================"
    $lines += "  Windows Server 2022 보안 진단 결과"
    $lines += "  주요정보통신기반시설 기술적 취약점 분석·평가 가이드 기준"
    $lines += "============================================================"
    $lines += "  진단 일시  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += "  호스트명   : $env:COMPUTERNAME"
    $lines += "  OS 정보    : $os"
    $lines += "  Build 버전 : $build.$ubr"
    $lines += "  진단 계정  : $env:USERNAME"
    $lines += "------------------------------------------------------------"
    $lines += ("  [결과 요약]  전체: {0}  양호: {1}  취약: {2}  인터뷰: {3}  해당없음: {4}" -f $total, $script:PASS, $script:FAIL, $script:INTERVIEW, $script:NA)
    $lines += ("  ※ 해당없음: 가이드 '점검 대상' OS에 Windows Server 2022 미포함 항목")
    $lines += "============================================================"
    $lines += ""
    $lines += ("{0,-11} {1,-6} {2}" -f "결과", "항목", "제목 :: 세부내용")
    $lines += "------------------------------------------------------------"
    foreach ($r in $script:RESULTS) {
        $detail = $r.Detail -replace "`r?`n", ' ; '
        $lines += ("{0,-11} {1,-6} {2} :: {3}" -f "[$($r.Status)]", $r.Id, $r.Title, $detail)
    }
    $lines += ""
    $lines += "  * 보고서 파일: $out"
    $lines += "============================================================"

    $lines | Out-File -FilePath $out -Encoding UTF8

    Write-Host ""
    Write-Host "리포트 저장 완료: $out" -ForegroundColor White
}
