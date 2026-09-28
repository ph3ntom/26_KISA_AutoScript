# 01_account.ps1 - 1. 계정 관리 (W-01 ~ W-14)

function Invoke-AccountChecks {
    Print-Section "1. 계정 관리 (W-01 ~ W-14)"

    # ──────────────────────────────────────────────────────
    # W-01 (상) Administrator 계정 이름 변경 등 보안성 강화
    # 양호: Administrator 기본 계정 이름을 변경하거나 강화된 비밀번호를 적용한 경우
    # ──────────────────────────────────────────────────────
    $builtinAdmin = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }
    # 500 : Administrator 계정, 501 : Guest 계정, 1000 이상 : 일반 사용자 계정
    # $_ : 파이프로 넘겨받은 객체 지정
    if ($builtinAdmin -and $builtinAdmin.Name -ne 'Administrator') {
        Result-Pass "W-01" "Administrator 계정 이름 변경 등 보안성 강화" "기본 관리자 계정명이 변경됨: $($builtinAdmin.Name)"
    } else {
        Result-Interview "W-01" "Administrator 계정 이름 변경 등 보안성 강화" "기본 관리자 계정명이 Administrator로 유지됨 - 강화된 비밀번호 적용 여부 담당자 확인 필요"
    }

    # ──────────────────────────────────────────────────────
    # W-02 (상) Guest 계정 비활성화
    # 양호: Guest 계정이 비활성화되어 있는 경우
    # ──────────────────────────────────────────────────────
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }
    if ($guest -and $guest.Enabled) {
        Result-Fail "W-02" "Guest 계정 비활성화" "Guest 계정($($guest.Name))이 활성화되어 있음"
    } else {
        $guestName = "Guest"
        if ($guest) { $guestName = $guest.Name }
        Result-Pass "W-02" "Guest 계정 비활성화" "Guest 계정($guestName)이 비활성화 상태임"
    }

    # ──────────────────────────────────────────────────────
    # W-03 (상) 불필요한 계정 제거
    # 양호: 불필요한 계정이 존재하지 않는 경우 (담당자 확인 필요)
    # ──────────────────────────────────────────────────────
    $userLines = @()
    foreach ($u in (Get-LocalUser)) {
        $state = "비활성"
        if ($u.Enabled) { $state = "활성" }
        $lastLogon = "기록없음"
        if ($u.LastLogon) { $lastLogon = $u.LastLogon.ToString('yyyy-MM-dd') }
        $userLines += "{0} [{1}] 마지막로그온: {2}" -f $u.Name, $state, $lastLogon
    }
    Result-Interview "W-03" "불필요한 계정 제거" ("등록 계정 목록 확인 후 불필요·의심 계정 여부 담당자 확인 필요`n" + ($userLines -join "`n"))

    # ──────────────────────────────────────────────────────
    # W-04 (상) 계정 잠금 임계값 설정
    # 양호: 계정 잠금 임계값이 5 이하의 값으로 설정된 경우
    # ──────────────────────────────────────────────────────
    $lockoutBadCount = Get-SecPol 'LockoutBadCount'
    if ($lockoutBadCount -ne $null -and [int]$lockoutBadCount -ge 1 -and [int]$lockoutBadCount -le 5) {
        Result-Pass "W-04" "계정 잠금 임계값 설정" "계정 잠금 임계값: $lockoutBadCount (5 이하)"
    } elseif ($lockoutBadCount -eq $null -or [int]$lockoutBadCount -eq 0) {
        Result-Fail "W-04" "계정 잠금 임계값 설정" "계정 잠금 임계값이 설정되지 않음(0 또는 미설정)"
    } else {
        Result-Fail "W-04" "계정 잠금 임계값 설정" "계정 잠금 임계값: $lockoutBadCount (5 초과)"
    }

    # ──────────────────────────────────────────────────────
    # W-05 (상) 해독 가능한 암호화를 사용하여 암호 저장 해제
    # 양호: 해당 정책이 "사용 안 함"으로 설정된 경우
    # ──────────────────────────────────────────────────────
    $clearText = Get-SecPol 'ClearTextPassword'
    if ($clearText -ne $null -and [int]$clearText -eq 0) {
        Result-Pass "W-05" "해독 가능한 암호화를 사용하여 암호 저장 해제" "'해독 가능한 암호화를 사용하여 암호 저장' 정책: 사용 안 함(0)"
    } else {
        Result-Fail "W-05" "해독 가능한 암호화를 사용하여 암호 저장 해제" "'해독 가능한 암호화를 사용하여 암호 저장' 정책: 사용($clearText)"
    }

    # ──────────────────────────────────────────────────────
    # W-06 (상) 관리자 그룹에 최소한의 사용자 포함
    # 양호: Administrators 그룹 구성원 1명 이하 또는 불필요한 관리자 계정 없음
    # ──────────────────────────────────────────────────────
    # S-1-5-32-544 : Administrators 그룹 SID
    $adminMembers = Get-LocalGroupMembersSafe -SidValue 'S-1-5-32-544' -NameFallback 'Administrators'
    if ($adminMembers.Count -le 1) {
        Result-Pass "W-06" "관리자 그룹에 최소한의 사용자 포함" "Administrators 그룹 구성원 $($adminMembers.Count)명: $($adminMembers -join ', ')"
    } else {
        Result-Interview "W-06" "관리자 그룹에 최소한의 사용자 포함" ("Administrators 그룹 구성원 $($adminMembers.Count)명 - 불필요한 관리자 계정 여부 담당자 확인 필요`n" + ($adminMembers -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-07 (중) Everyone 사용 권한을 익명 사용자에 적용
    # 양호: 해당 정책이 "사용 안 함"으로 되어 있는 경우
    # ──────────────────────────────────────────────────────
    $everyoneAnon = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous'
    if ($everyoneAnon -eq $null -or [int]$everyoneAnon -eq 0) {
        $val = "0(기본값)"
        if ($everyoneAnon -ne $null) { $val = "$everyoneAnon" }
        Result-Pass "W-07" "Everyone 사용 권한을 익명 사용자에 적용" "'Everyone 사용 권한을 익명 사용자에게 적용' 정책: 사용 안 함($val)"
    } else {
        Result-Fail "W-07" "Everyone 사용 권한을 익명 사용자에 적용" "'Everyone 사용 권한을 익명 사용자에게 적용' 정책: 사용($everyoneAnon)"
    }

    # ──────────────────────────────────────────────────────
    # W-08 (중) 계정 잠금 기간 설정
    # 양호: "계정 잠금 기간" 및 "계정 잠금 기간 원래대로 설정 기간"이 60분 이상
    # ──────────────────────────────────────────────────────
    $lockoutDuration = Get-SecPol 'LockoutDuration'
    $resetLockout    = Get-SecPol 'ResetLockoutCount'
    if ($lockoutDuration -ne $null -and $resetLockout -ne $null -and
        [int]$lockoutDuration -ge 60 -and [int]$resetLockout -ge 60) {
        Result-Pass "W-08" "계정 잠금 기간 설정" "계정 잠금 기간: ${lockoutDuration}분, 원래대로 설정 기간: ${resetLockout}분 (60분 이상)"
    } elseif ($lockoutDuration -eq $null -and $resetLockout -eq $null) {
        Result-Fail "W-08" "계정 잠금 기간 설정" "계정 잠금 정책이 설정되지 않음(계정 잠금 임계값 미설정 시 함께 미설정됨)"
    } else {
        Result-Fail "W-08" "계정 잠금 기간 설정" "계정 잠금 기간: ${lockoutDuration}분, 원래대로 설정 기간: ${resetLockout}분 (60분 미만 또는 미설정)"
    }

    # ──────────────────────────────────────────────────────
    # W-09 (상) 비밀번호 관리 정책 설정
    # 양호: 계정 비밀번호 관리 정책이 모두 적용된 경우
    #   복잡성 사용, 최근 암호 기억 4개, 최대 사용 기간 90일,
    #   최소 암호 길이 8문자, 최소 사용 기간 1일
    # ──────────────────────────────────────────────────────
    $complexity = Get-SecPol 'PasswordComplexity'
    $history    = Get-SecPol 'PasswordHistorySize'
    $maxAge     = Get-SecPol 'MaximumPasswordAge'
    $minAge     = Get-SecPol 'MinimumPasswordAge'
    $minLen     = Get-SecPol 'MinimumPasswordLength'
    $unmet = @()
    if ($complexity -eq $null -or [int]$complexity -ne 1) { $unmet += "암호 복잡성: 사용 안 함($complexity)" }
    if ($history -eq $null -or [int]$history -lt 4)       { $unmet += "최근 암호 기억: $history (4 미만)" }
    if ($maxAge -eq $null -or [int]$maxAge -lt 1 -or [int]$maxAge -gt 90) { $unmet += "최대 암호 사용 기간: $maxAge (90일 초과 또는 무제한)" }
    if ($minLen -eq $null -or [int]$minLen -lt 8)         { $unmet += "최소 암호 길이: $minLen (8문자 미만)" }
    if ($minAge -eq $null -or [int]$minAge -lt 1)         { $unmet += "최소 암호 사용 기간: $minAge (1일 미만)" }
    if ($unmet.Count -eq 0) {
        Result-Pass "W-09" "비밀번호 관리 정책 설정" "복잡성: 사용, 암호 기억: $history, 최대 사용 기간: ${maxAge}일, 최소 길이: $minLen, 최소 사용 기간: ${minAge}일"
    } else {
        Result-Fail "W-09" "비밀번호 관리 정책 설정" ("미충족 정책 존재`n" + ($unmet -join "`n"))
    }

    # ──────────────────────────────────────────────────────
    # W-10 (중) 마지막 사용자 이름 표시 안 함
    # 양호: "마지막 사용자 이름 표시 안 함"이 "사용"으로 설정된 경우
    # ──────────────────────────────────────────────────────
    $dontDisplay = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLastUserName'
    if ($dontDisplay -ne $null -and [int]$dontDisplay -eq 1) {
        Result-Pass "W-10" "마지막 사용자 이름 표시 안 함" "'대화형 로그온: 마지막 사용자 이름 표시 안 함' 정책: 사용(1)"
    } else {
        Result-Fail "W-10" "마지막 사용자 이름 표시 안 함" "'대화형 로그온: 마지막 사용자 이름 표시 안 함' 정책: 사용 안 함($dontDisplay)"
    }

    # ──────────────────────────────────────────────────────
    # W-11 (중) 로컬 로그온 허용
    # 양호: 로컬 로그온 허용 정책에 Administrators, IUSR_ 만 존재하는 경우
    # ──────────────────────────────────────────────────────
    $interactiveRaw = Get-PrivilegeRawEntries (Get-SecPol 'SeInteractiveLogonRight')
    $interactiveNames = Convert-PrivilegeEntries (Get-SecPol 'SeInteractiveLogonRight')
    $notAllowed = @()
    for ($i = 0; $i -lt $interactiveRaw.Count; $i++) {
        $raw  = $interactiveRaw[$i]
        $name = $interactiveNames[$i]
        $isAdmins = ($raw -eq '*S-1-5-32-544')
        $isIusr   = ($name -match 'IUSR')
        if (-not $isAdmins -and -not $isIusr) { $notAllowed += $name }
    }
    if ($interactiveRaw.Count -gt 0 -and $notAllowed.Count -eq 0) {
        Result-Pass "W-11" "로컬 로그온 허용" "로컬 로그온 허용: $($interactiveNames -join ', ')"
    } else {
        Result-Fail "W-11" "로컬 로그온 허용" "Administrators, IUSR_ 외 계정/그룹 존재: $($notAllowed -join ', ') (전체: $($interactiveNames -join ', '))"
    }

    # ──────────────────────────────────────────────────────
    # W-12 (중) 익명 SID/이름 변환 허용 해제
    # 양호: "익명 SID/이름 변환 허용" 정책이 "사용 안 함"으로 설정된 경우
    # ──────────────────────────────────────────────────────
    $anonSid = Get-SecPol 'LSAAnonymousNameLookup'
    if ($anonSid -ne $null -and [int]$anonSid -eq 0) {
        Result-Pass "W-12" "익명 SID/이름 변환 허용 해제" "'네트워크 액세스: 익명 SID/이름 변환 허용' 정책: 사용 안 함(0)"
    } else {
        Result-Fail "W-12" "익명 SID/이름 변환 허용 해제" "'네트워크 액세스: 익명 SID/이름 변환 허용' 정책: 사용($anonSid)"
    }

    # ──────────────────────────────────────────────────────
    # W-13 (중) 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한
    # 양호: 해당 정책이 "사용"인 경우
    # ──────────────────────────────────────────────────────
    $limitBlank = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse'
    if ($limitBlank -eq $null -or [int]$limitBlank -eq 1) {
        $val = "1(기본값)"
        if ($limitBlank -ne $null) { $val = "$limitBlank" }
        Result-Pass "W-13" "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한" "'계정: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 정책: 사용($val)"
    } else {
        Result-Fail "W-13" "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한" "'계정: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 정책: 사용 안 함($limitBlank)"
    }

    # ──────────────────────────────────────────────────────
    # W-14 (중) 원격터미널 접속 가능한 사용자 그룹 제한
    # 양호: 원격 접속 가능 계정을 별도 생성·제한하고 불필요한 계정이 없는 경우
    # ──────────────────────────────────────────────────────
    $denyTS = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($denyTS -ne $null -and [int]$denyTS -eq 1) {
        Result-Pass "W-14" "원격터미널 접속 가능한 사용자 그룹 제한" "원격 데스크톱 연결이 비활성화되어 있음(fDenyTSConnections=1)"
    } else {
        $rdpMembers = Get-LocalGroupMembersSafe -SidValue 'S-1-5-32-555' -NameFallback 'Remote Desktop Users'
        $memberInfo = "구성원 없음(관리자 그룹만 접속 가능)"
        if ($rdpMembers.Count -gt 0) { $memberInfo = $rdpMembers -join ', ' }
        Result-Interview "W-14" "원격터미널 접속 가능한 사용자 그룹 제한" "원격 데스크톱 사용 중 - 별도 원격 접속 계정 운영 및 불필요 계정 여부 담당자 확인 필요`nRemote Desktop Users 그룹: $memberInfo"
    }
}
