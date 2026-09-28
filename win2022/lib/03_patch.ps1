# 03_patch.ps1 - 3. 패치 관리 (W-38 ~ W-39)

function Invoke-PatchChecks {
    Print-Section "3. 패치 관리 (W-38 ~ W-39)"

    # ──────────────────────────────────────────────────────
    # W-38 (상) 주기적 보안 패치 및 벤더 권고사항 적용
    # 양호: 패치 절차를 수립하여 주기적으로 패치를 확인 및 설치하는 경우
    # ──────────────────────────────────────────────────────
    $hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending)
    if ($hotfixes.Count -gt 0) {
        $recent = @($hotfixes | Select-Object -First 5 | ForEach-Object {
            $dt = "날짜미상"
            if ($_.InstalledOn) { $dt = $_.InstalledOn.ToString('yyyy-MM-dd') }
            "$($_.HotFixID) ($dt)"
        })
        Result-Interview "W-38" "주기적 보안 패치 및 벤더 권고사항 적용" ("패치 절차 수립 및 주기적 설치 여부 담당자 확인 필요`n최근 설치 패치: " + ($recent -join ', '))
    } else {
        Result-Interview "W-38" "주기적 보안 패치 및 벤더 권고사항 적용" "설치된 HotFix 정보를 확인할 수 없음 - 패치 절차 수립 여부 담당자 확인 필요"
    }

    # ──────────────────────────────────────────────────────
    # W-39 (상) 백신 프로그램 업데이트
    # 양호: 백신 최신 엔진 업데이트 설치 또는 (망 격리 환경) 업데이트 절차 수립
    # ──────────────────────────────────────────────────────
    $defender = Get-ServiceSafe 'WinDefend'
    $sigInfo = $null
    if ($defender -and $defender.Status -eq 'Running' -and (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $sigInfo = $mp.AntivirusSignatureLastUpdated
        } catch { $sigInfo = $null }
    }
    # ※ '최신 엔진 업데이트 여부'와 '망 격리 환경의 업데이트 절차 수립 여부'는
    #    자동 판정이 불가하므로 수집한 근거자료와 함께 인터뷰 항목으로 처리
    if ($sigInfo -ne $null) {
        $ageDays = [int]((Get-Date) - $sigInfo).TotalDays
        Result-Interview "W-39" "백신 프로그램 업데이트" "Microsoft Defender 백신 정의 최종 업데이트: $($sigInfo.ToString('yyyy-MM-dd')) (${ageDays}일 경과) - 최신 엔진 적용 여부 및 망 격리 환경의 업데이트 절차 수립 여부 담당자 확인 필요"
    } else {
        Result-Interview "W-39" "백신 프로그램 업데이트" "백신 엔진 업데이트 정보를 자동 확인할 수 없음 - 설치된 백신의 최신 업데이트 여부 및 절차 수립 여부 담당자 확인 필요"
    }
}
