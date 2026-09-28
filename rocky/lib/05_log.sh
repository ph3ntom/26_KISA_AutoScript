#!/bin/bash
# 05_log.sh - 로그 관리 진단 (U-65 ~ U-67)

# ────────────────────────────────────────────────────────────
# U-65: NTP 및 시각 동기화 설정
# 판단: NTP/Chrony 서비스 활성화 및 동기화 설정 여부
# Rocky Linux 10 (RHEL 8+): chronyd 사용
# ────────────────────────────────────────────────────────────
check_U65() {
    local id="U-65" title="NTP 및 시각 동기화 설정"
    local issues=()

    # ── Chrony 확인 (RHEL 8+ 기본) ──
    if systemctl is-active --quiet chronyd 2>/dev/null; then
        local chrony_conf="/etc/chrony.conf"

        if [[ ! -f "$chrony_conf" ]]; then
            issues+=("chronyd 활성화 상태이나 /etc/chrony.conf 없음")
        else
            # server/pool 설정 확인
            local ntp_server_count
            ntp_server_count=$(grep -vE '^\s*#|^\s*$' "$chrony_conf" 2>/dev/null \
                               | grep -cE '^\s*(server|pool)\s+' || true)
            if [[ "${ntp_server_count:-0}" -eq 0 ]]; then
                issues+=("chrony.conf: NTP 서버(server/pool) 미설정")
            fi

            # chronyc -n sources로 동기화 상태 확인
            if command -v chronyc &>/dev/null; then
                local synced_count
                synced_count=$(timeout 10 chronyc -n sources 2>/dev/null \
                               | grep -cE '^\^\*|^\^\+' || true)
                if [[ "${synced_count:-0}" -eq 0 ]]; then
                    issues+=("NTP 동기화 안 됨 (chronyc -n sources 동기화 서버 없음)")
                fi
            fi
        fi

    # ── NTP 확인 (레거시) ──
    elif systemctl is-active --quiet ntpd 2>/dev/null || \
         systemctl is-active --quiet ntp 2>/dev/null; then
        local ntp_conf="/etc/ntp.conf"

        if [[ ! -f "$ntp_conf" ]]; then
            issues+=("ntpd 활성화 상태이나 /etc/ntp.conf 없음")
        else
            # server 설정 확인
            local ntp_svr_count
            ntp_svr_count=$(grep -vE '^\s*#|^\s*$' "$ntp_conf" 2>/dev/null \
                           | grep -cE '^\s*server\s+' || true)
            if [[ "${ntp_svr_count:-0}" -eq 0 ]]; then
                issues+=("ntp.conf: NTP 서버(server) 미설정")
            fi

            # ntpq -pn으로 동기화 상태 확인
            if command -v ntpq &>/dev/null; then
                local synced_count
                synced_count=$(timeout 10 ntpq -pn 2>/dev/null \
                               | grep -cE '^\*' || true)
                if [[ "${synced_count:-0}" -eq 0 ]]; then
                    issues+=("NTP 동기화 안 됨 (ntpq -pn 동기화 서버 없음)")
                fi
            fi
        fi

    else
        issues+=("NTP/Chrony 서비스 모두 비활성화")
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "NTP/Chrony 서비스 활성화 및 동기화 설정 양호"
    fi
}
# 26/06/15 완료

# ────────────────────────────────────────────────────────────
# U-66: 정책에 따른 시스템 로깅 설정
# 판단: rsyslog 활성화 및 주요 로그 정책 설정 여부
# ────────────────────────────────────────────────────────────
check_U66() {
    local id="U-66" title="정책에 따른 시스템 로깅 설정"
    local issues=()

    # ── rsyslog 서비스 활성화 확인 ──
    if ! systemctl is-active --quiet rsyslog 2>/dev/null; then
        result_fail "$id" "$title" "rsyslog 서비스 비활성화"
        return
    fi

    # ── 설정 파일 수집 ──
    local rsyslog_files=()
    [[ -f /etc/rsyslog.conf ]] && rsyslog_files+=("/etc/rsyslog.conf")
    while IFS= read -r -d '' f; do
        rsyslog_files+=("$f")
    done < <(find /etc/rsyslog.d -maxdepth 1 -name "*.conf" -type f -print0 2>/dev/null)

    if [[ ${#rsyslog_files[@]} -eq 0 ]]; then
        result_fail "$id" "$title" "rsyslog 설정 파일 없음"
        return
    fi

    local all_conf
    all_conf=$(cat "${rsyslog_files[@]}" 2>/dev/null | grep -vE '^\s*#|^\s*$')

    # ── 주요 로그 항목 확인 (가이드 기준) ──

    # authpriv.* → /var/log/secure
    if ! echo "$all_conf" | grep -qE 'authpriv[\.\*]'; then
        issues+=("authpriv 로그 설정 없음")
    fi

    # *.info;mail.none;authpriv.none;cron.none → /var/log/messages
    if ! echo "$all_conf" | grep -qE '\*\.info(;[a-z\.]+)*[[:space:]]+/var/log/messages'; then
        issues+=("시스템 메시지(*.info) /var/log/messages 설정 없음")
    fi

    # cron.* → /var/log/cron
    if ! echo "$all_conf" | grep -qE 'cron[\.\*]'; then
        issues+=("cron 로그 설정 없음")
    fi

    # mail.* → /var/log/maillog
    if ! echo "$all_conf" | grep -qE 'mail[\.\*]'; then
        issues+=("mail 로그 설정 없음")
    fi

    # *.emerg
    if ! echo "$all_conf" | grep -qE '\*\.emerg'; then
        issues+=("긴급(emerg) 로그 설정 없음")
    fi

    # *.alert
    if ! echo "$all_conf" | grep -qE '\*\.alert'; then
        issues+=("경보(alert) 로그 설정 없음")
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "rsyslog 활성화 및 주요 로그 정책 설정 양호"
    fi
}
# 26/06/15 완료


# ────────────────────────────────────────────────────────────
# U-67: 로그 디렉터리 소유자 및 권한 설정
# 판단: /var/log/ 내 로그 파일 소유자 root, 권한 644 이하
# ────────────────────────────────────────────────────────────
check_U67() {
    local id="U-67" title="로그 디렉터리 소유자 및 권한 설정"
    local bad_files=()

    if [[ ! -d /var/log ]]; then
        result_pass "$id" "$title" "/var/log 디렉터리 없음"
        return
    fi

    # /var/log 전체 하위 파일 점검 (깊이 제한 없음)
    # ※ 아래 파일들은 시스템 구조상 root 외 소유자/644 초과 권한이 정상일 수 있음
    #   - btmp, wtmp, lastlog : utmp 그룹 쓰기 필요 (660/664)
    #   - mysqld.log          : mysql 계정 소유 (서비스 데몬 관리)
    #   - chrony/             : chrony 계정 소유 (시각 동기화 데몬)
    #   - sssd/               : sssd 계정 소유 (인증 데몬)
    #   - audit/audit.log     : root 소유이나 640 권한 (audit 그룹)
    #   위 항목 취약 식별 시 인터뷰를 통해 정상 여부 확인 필요
    # ※ v2는 basename만 기록해 access.log / error.log 처럼 이름이 겹치는 파일이
    #   어느 디렉터리 소속인지 알 수 없었고(증적 불충분),
    #   소유자 불일치 시 continue로 권한 점검을 건너뛰어 두 문제가 동시에 있는
    #   파일은 한 가지만 보고됐음 → 전체 경로 기록 + 두 조건 모두 점검
    while IFS= read -r -d '' f; do
        local owner perm
        local reasons=()
        owner=$(get_owner "$f")
        perm=$(get_perm "$f")

        [[ "$owner" != "root" ]] && reasons+=("소유자 ${owner}(root 아님)")
        perm_le 644 "$perm" || reasons+=("권한 ${perm}(644 초과)")

        [[ ${#reasons[@]} -gt 0 ]] && \
            bad_files+=("${f}: $(join_by ', ' "${reasons[@]}")")
    done < <(find /var/log -type f -print0 2>/dev/null)

    if [[ ${#bad_files[@]} -gt 0 ]]; then
        result_fail "$id" "$title" \
            "기준 미충족 로그 파일 ${#bad_files[@]}개: $(join_by '; ' "${bad_files[@]}")"
        print_evidence "$id" "${bad_files[@]}"
    else
        local total_files
        total_files=$(find /var/log -type f 2>/dev/null | wc -l)
        result_pass "$id" "$title" "/var/log 내 ${total_files}개 파일 소유자/권한 양호"
    fi
}

# ────────────────────────────────────────────────────────────
# 로그 관리 전체 실행
# ────────────────────────────────────────────────────────────
run_log_checks() {
    print_section "5. 로그 관리 (U-65 ~ U-67)"

    check_U65
    check_U66
    check_U67
}
