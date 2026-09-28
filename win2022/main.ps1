# main.ps1 - Windows Server 2022 보안 진단 자동화 스크립트 (v2)
# 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#       02. Windows 서버 (W-01 ~ W-64)
#
# [v2 변경 내역] 2026-07-11, 실서버(Build 20348.587) 검증 반영. 원본: win2022-diag
#   - W-40: secedit [Event Audit] 값이 2022 유효 감사 정책을 반영하지 못하는
#           결함 수정 → auditpol 하위 범주 GUID 기반 판정 (lib\04_log.ps1, common.ps1)
#   - W-18: 가이드 판단 기준(목록 서비스 구동 중 = 취약)에 맞춰 인터뷰 → 취약
#   - W-59: 미설정 시 가이드 양호 기준('설정'된 경우) 미충족이므로 양호 → 인터뷰
#
# 사용법: 관리자 권한 PowerShell에서 실행
#   powershell -ExecutionPolicy Bypass -File .\main.ps1
#   powershell -ExecutionPolicy Bypass -File .\main.ps1 -Section account
#
# 옵션:
#   -Section <all|account|service|patch|log|security>  (기본값: all)
#     account  : 1. 계정 관리   (W-01 ~ W-14)
#     service  : 2. 서비스 관리 (W-15 ~ W-37)
#     patch    : 3. 패치 관리   (W-38 ~ W-39)
#     log      : 4. 로그 관리   (W-40 ~ W-43)
#     security : 5. 보안 관리   (W-44 ~ W-64)

param(
    [ValidateSet('all', 'account', 'service', 'patch', 'log', 'security')]
    [string]$Section = 'all'
)

$ErrorActionPreference = 'Continue'

# ────────────────────────────────────────────────────────────
# 스크립트 경로 기준 설정 및 공통 함수 로드
# ────────────────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LibDir    = Join-Path $ScriptDir 'lib'

. (Join-Path $LibDir 'common.ps1')

# ────────────────────────────────────────────────────────────
# 관리자 권한 확인
# ────────────────────────────────────────────────────────────
function Test-Admin {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[오류] 관리자 권한으로 실행해야 합니다." -ForegroundColor Red
    Write-Host "  실행 방법: 관리자 권한 PowerShell에서 powershell -ExecutionPolicy Bypass -File .\main.ps1"
    exit 1
}

# ────────────────────────────────────────────────────────────
# OS 확인
# ────────────────────────────────────────────────────────────
$osInfo = Get-CimInstance Win32_OperatingSystem
if ($osInfo.Caption -notmatch '2022') {
    Write-Host "[경고] Windows Server 2022가 아닌 시스템입니다. 일부 항목이 부정확할 수 있습니다." -ForegroundColor Yellow
    Write-Host "  현재 OS: $($osInfo.Caption)"
    Write-Host ""
}

# ────────────────────────────────────────────────────────────
# 헤더 출력
# ────────────────────────────────────────────────────────────
$buildKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = Get-RegValue $buildKey 'CurrentBuild'
$ubr   = Get-RegValue $buildKey 'UBR'

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  Windows Server 2022 보안 진단" -ForegroundColor White
Write-Host "  기준: 주요정보통신기반시설 취약점 분석·평가 가이드 2026" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host "  진단 일시  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  호스트명   : $env:COMPUTERNAME"
Write-Host "  OS         : $($osInfo.Caption)"
Write-Host "  Build      : $build.$ubr"
Write-Host "============================================================" -ForegroundColor White

# ────────────────────────────────────────────────────────────
# 로컬 보안 정책 내보내기(secedit) - 정책 기반 항목에서 공통 사용
# ────────────────────────────────────────────────────────────
Initialize-SecPol

# ────────────────────────────────────────────────────────────
# 섹션 실행
# ────────────────────────────────────────────────────────────
function Invoke-DiagSection {
    param([string]$Name)
    switch ($Name) {
        'account'  { . (Join-Path $LibDir '01_account.ps1');  Invoke-AccountChecks }
        'service'  { . (Join-Path $LibDir '02_service.ps1');  Invoke-ServiceChecks }
        'patch'    { . (Join-Path $LibDir '03_patch.ps1');    Invoke-PatchChecks }
        'log'      { . (Join-Path $LibDir '04_log.ps1');      Invoke-LogChecks }
        'security' { . (Join-Path $LibDir '05_security.ps1'); Invoke-SecurityChecks }
    }
}

if ($Section -eq 'all') {
    Invoke-DiagSection 'account'
    Invoke-DiagSection 'service'
    Invoke-DiagSection 'patch'
    Invoke-DiagSection 'log'
    Invoke-DiagSection 'security'
} else {
    Invoke-DiagSection $Section
}

# ────────────────────────────────────────────────────────────
# 최종 요약 및 리포트
# ────────────────────────────────────────────────────────────
$total = $script:PASS + $script:FAIL + $script:INTERVIEW + $script:NA
Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  진단 완료 요약" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host "  전체: $total  " -NoNewline
Write-Host "양호: $($script:PASS)  " -ForegroundColor Green -NoNewline
Write-Host "취약: $($script:FAIL)  " -ForegroundColor Red -NoNewline
Write-Host "인터뷰: $($script:INTERVIEW)  " -ForegroundColor Yellow -NoNewline
Write-Host "해당없음: $($script:NA)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor White

New-Report -ScriptRoot $ScriptDir
