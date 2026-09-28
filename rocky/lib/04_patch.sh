#!/bin/bash
# 04_patch.sh - 패치 관리 진단 (U-64)

# ────────────────────────────────────────────────────────────
# U-64: 주기적 보안 패치 및 벤더 권고사항 적용
# 판단: 패치 정책 수립 및 주기적 패치 관리 여부
# ※ 정책 수립/주기적 관리 여부는 인터뷰 필요
# ────────────────────────────────────────────────────────────
check_U64() {
    local id="U-64" title="주기적 보안 패치 및 벤더 권고사항 적용"
    local issues=()
    local info=()

    # ── OS 및 커널 정보 ──
    local kernel_ver os_pretty os_ver
    kernel_ver=$(uname -r)
    os_pretty=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    # ※ grep -P(PCRE)는 로케일에 따라 실행이 실패할 수 있어 POSIX 방식으로 대체
    os_ver=$(grep -E '^VERSION_ID=' /etc/os-release 2>/dev/null \
             | head -1 | cut -d= -f2 | tr -d '"' | cut -d. -f1)
    info+=("OS: ${os_pretty}")
    info+=("커널: ${kernel_ver}")

    # ── Rocky Linux EOL 상태 확인 ──
    if [[ -n "$os_ver" ]]; then
        case "$os_ver" in
            (8)  info+=("Rocky Linux 8 - EOL 2029-05 (지원 중)") ;;
            (9)  info+=("Rocky Linux 9 - EOL 2032-05 (지원 중)") ;;
            (10) info+=("Rocky Linux 10 - EOL 2035-05 (지원 중)") ;;
            (*)  issues+=("Rocky Linux ${os_ver} - EOL 상태 불명확") ;;
        esac
    fi

    # ── 미적용 보안 업데이트 확인 ──
    # ※ v2는 dnf 출력만 grep -c 했기 때문에 폐쇄망·저장소 오류·타임아웃(30초)
    #   상황이 모두 "업데이트 0건"으로 수렴해 미적용 패치를 놓쳤음(미탐)
    #   → dnf 종료 코드로 조회 성공 여부를 먼저 판별
    #     0=업데이트 없음, 100=업데이트 있음, 124=타임아웃, 그 외=조회 실패
    if command -v dnf &>/dev/null; then
        local dnf_out dnf_rc security_updates total_updates

        dnf_out=$(timeout 60 dnf check-update --security --quiet 2>/dev/null)
        dnf_rc=$?

        # 패키지 라인만 카운트: "이름.아키텍처  버전  리포지토리" 형식
        # (빈 줄/메타데이터 문구/Obsoleting Packages 등 안내 라인 오집계 방지)
        local pkg_re='^[[:alnum:]][^[:space:]]*\.(noarch|x86_64|i686|aarch64|src)[[:space:]]'

        case "$dnf_rc" in
            (124)
                issues+=("보안 업데이트 조회 실패(60초 타임아웃) — 패치 현황 수동 확인 필요")
                ;;
            (0|100)
                security_updates=$(printf '%s\n' "$dnf_out" | grep -cE "$pkg_re" || true)

                if [[ "${security_updates:-0}" -gt 0 ]]; then
                    issues+=("미적용 보안 업데이트 ${security_updates}개 존재")
                else
                    # 보안 메타데이터 부재 환경 대비 일반 업데이트 fallback
                    local all_out all_rc
                    all_out=$(timeout 60 dnf check-update --quiet 2>/dev/null)
                    all_rc=$?
                    if [[ "$all_rc" -eq 0 || "$all_rc" -eq 100 ]]; then
                        total_updates=$(printf '%s\n' "$all_out" | grep -cE "$pkg_re" || true)
                        if [[ "${total_updates:-0}" -gt 0 ]]; then
                            issues+=("미적용 패키지 업데이트 ${total_updates}개 존재 (보안 패치 포함 가능성)")
                        else
                            info+=("미적용 업데이트 없음 (dnf check-update 정상 조회)")
                        fi
                    else
                        issues+=("전체 업데이트 조회 실패(dnf 종료코드 ${all_rc}) — 패치 현황 수동 확인 필요")
                    fi
                fi
                ;;
            (*)
                issues+=("보안 업데이트 조회 실패(dnf 종료코드 ${dnf_rc}, 저장소 접근 불가 등) — 패치 현황 수동 확인 필요")
                ;;
        esac
    fi

    # ── 마지막 패키지 설치 일시 ──
    # ※ v2는 로케일이 적용된 rpm 출력(예: "2026년 06월 14일 (일) 오후 02시 48분")을
    #   date -d로 파싱하려 해 항상 실패하고 원문이 그대로 리포트에 출력됐음
    #   → rpm --qf로 epoch(INSTALLTIME)를 직접 받아 변환 (로케일 무관)
    local last_pkg last_epoch last_update_formatted
    last_pkg=$(rpm -qa --last --qf '%{INSTALLTIME} %{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null | head -1)
    # --qf 미지원 등으로 값을 얻지 못하면 C 로케일 원문으로 대체
    [[ -z "$last_pkg" ]] && last_pkg=$(LC_ALL=C rpm -qa --last 2>/dev/null | head -1)
    if [[ -n "$last_pkg" ]]; then
        last_epoch="${last_pkg%% *}"
        if [[ "$last_epoch" =~ ^[0-9]+$ ]]; then
            last_update_formatted=$(date -d "@${last_epoch}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
            info+=("마지막 패키지 설치: ${last_update_formatted} (${last_pkg#* })")

            # 마지막 설치 이후 경과일 (패치 주기 판단 참고용)
            local days_ago
            days_ago=$(( ( $(date +%s) - last_epoch ) / 86400 ))
            info+=("마지막 패치 후 경과: ${days_ago}일")
        else
            info+=("마지막 패키지 설치: ${last_pkg}")
        fi
    fi

    # ── 결과 판정 ──
    # 가이드 원문(상세가이드 p.160) 판단 기준:
    #   양호 : "패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며,
    #           패치 관련 내용을 확인하고 적용하였을 경우"
    #   취약 : "패치 적용 정책을 수립하지 않고 주기적으로 패치 관리를 하지 않거나…"
    #
    # 판단 기준이 "정책 수립 여부"와 "주기적 관리 여부"이며, 이는 정책 문서·운영
    # 절차 확인이 필요한 영역으로 스크립트가 자동 판정할 수 없다.
    # 미적용 업데이트 건수·조회 실패·EOL 상태는 그 자체가 취약 판정 근거가 아니라
    # (정책에 따라 영향도 검증 후 적용 대기 중일 수 있음) 인터뷰 판단 자료이므로
    # 항상 인터뷰로 분류하고, 탐지된 사실은 '확인 필요' 항목으로 함께 제시한다.
    # ※ v3 초기 구현은 미적용 업데이트가 있으면 취약으로 판정했으나
    #   가이드 판단 기준과 맞지 않아 인터뷰로 통일함 (2026-08-01 사용자 지시)
    local detail="패치 적용 정책 수립 및 주기적 패치 관리 여부 인터뷰 확인 필요"

    if [[ ${#issues[@]} -gt 0 ]]; then
        detail+=" | [확인 필요] $(join_by '; ' "${issues[@]}")"
    fi
    [[ ${#info[@]} -gt 0 ]] && detail+=" | $(join_by ', ' "${info[@]}")"

    result_interview "$id" "$title" "$detail"
}

# ────────────────────────────────────────────────────────────
# 패치 관리 전체 실행
# ────────────────────────────────────────────────────────────
run_patch_checks() {
    print_section "4. 패치 관리 (U-64)"
    check_U64
}
