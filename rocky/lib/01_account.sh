#!/bin/bash
# 01_account.sh - 계정 관리 진단 (U-01 ~ U-13)
# 대상 OS: Rocky Linux 10.1 (RHEL 10 계열)

check_U01() {
    local id="U-01" title="root 계정 원격 접속 제한"
    local sshd_conf="/etc/ssh/sshd_config"
    local sshd_conf_dir="/etc/ssh/sshd_config.d"
    local securetty="/etc/securetty"
    local issues=() notes=()

    # ── 1. SSH 점검 ──────────────────────────────────────────
    if systemctl is-active --quiet sshd 2>/dev/null || \
       systemctl is-active --quiet ssh  2>/dev/null || \
       [[ -f "$sshd_conf" ]]; then

        local ssh_val
        ssh_val=$(sshd -T 2>/dev/null | awk '/^permitrootlogin/ {print $2}')

        # sshd -T 실패 시 (권한 없음 등) 파일 직접 파싱으로 폴백
        if [[ -z "$ssh_val" ]]; then
            ssh_val=$(grep -Eih '^\s*PermitRootLogin' \
                "$sshd_conf" "$sshd_conf_dir"/*.conf 2>/dev/null \
                | awk '{print $2}' | tail -1)
        fi
        # grep option -E: 확장 정규식 사용 -i: 대소문자 구분 없이 검색, -h: 파일명 출력 안함
        # ^ : 줄 시작, \s* : 공백 0개 이상 
        # [[-z]] : 문자열이 비어있는지 확인, [[-n]] : 문자열이 비어있지 않은지 확인

        case "${ssh_val,,}" in  
        #,, 소문자 변환
            (no|prohibit-password|without-password)
                notes+=("SSH:PermitRootLogin=${ssh_val}")
                ;; 
                # ;; : c언어의 break와 유사, 다음 case로 넘어가지 않음
            (yes)
                issues+=("SSH:PermitRootLogin=yes (root 접속 허용)")
                ;;
            (*)
                issues+=("SSH:PermitRootLogin=${ssh_val:-미설정} (명시적 설정 필요)")
                ;;
        esac
    else
        notes+=("SSH:비활성")
    fi

    # ── 2. Telnet 점검 ───────────────────────────────────────
    local telnet_running=false

    # systemd socket 방식 (Rocky 10 기본)
    if systemctl is-active --quiet telnet.socket 2>/dev/null || \
       systemctl is-active --quiet telnetd       2>/dev/null; then
        telnet_running=true
    fi

    # xinetd 방식 (레거시)
    if ! $telnet_running && systemctl is-active --quiet xinetd 2>/dev/null; then
        if [[ -f /etc/xinetd.d/telnet ]]; then
            grep -qi 'disable\s*=\s*yes' /etc/xinetd.d/telnet || telnet_running=true
        fi
    fi

    if $telnet_running; then

        # 조건 1: PAM pam_securetty.so 적용 여부 (/etc/pam.d/remote 또는 login)
        local pam_ok=false
        for pam_file in /etc/pam.d/remote /etc/pam.d/login; do
            grep -qE '^\s*auth\s+required\s+.*pam_securetty\.so' "$pam_file" 2>/dev/null \
                && pam_ok=true && break
        done
        # && : 앞 명령이 성공하면 뒤 명령 실행 성공(0) 실패(1)

        # 조건 2: /etc/securetty 파일 존재 여부
        local securetty_ok=false
        [[ -f "$securetty" ]] && securetty_ok=true
        # -f : 파일 존재 여부 확인, -d : 디렉토리 존재 여부 확인, -r : 읽기 권한 확인 등

        # 조건 3: /etc/securetty 내 pts/* 항목 없음
        #         파일이 없으면 ②에서 이미 취약으로 기록되므로 검사 스킵
        local no_pts=false
        if $securetty_ok; then
            grep -qE '^\s*pts/' "$securetty" 2>/dev/null || no_pts=true
        else
            no_pts=true   # 파일 없음 → pts/* 메시지 중복 출력 방지
        fi

        if $pam_ok && $securetty_ok && $no_pts; then
            notes+=("Telnet:활성,pam_securetty 적용,securetty 정상")
        else
            $pam_ok       || issues+=("Telnet:pam_securetty.so 미적용")
            $securetty_ok || issues+=("Telnet:/etc/securetty 없음")
            # securetty 파일이 존재할 때만 pts/* 메시지 출력
            if $securetty_ok && ! $no_pts; then
                issues+=("Telnet:securetty에 pts/* 존재")
            fi
        fi

    else
        notes+=("Telnet:비활성")
    fi

    # ── 3. 최종 판정 ─────────────────────────────────────────
    # ※ v2는 '|'로 연결했으나 RESULTS 레코드 구분자(STATUS|ID|TITLE|DETAIL)와 동일해
    #   리포트 파싱 시 필드가 밀릴 위험이 있었음 → 다른 항목과 동일하게 '; '로 통일
    local detail
    detail=$(join_by '; ' "${notes[@]}" "${issues[@]}")

    if [[ ${#issues[@]} -eq 0 ]]; then
    # 문자를 비교 시 "==", 숫자를 비교 시 "-eq" 사용
    # # : 문자열 길이, ${#배열[@]} : 배열 요소 개수
        result_pass "$id" "$title" "$detail"
    else
        result_fail "$id" "$title" "$detail"
    fi
}
# 26/05/17 분석 완료

# ────────────────────────────────────────────────────────────
# U-02 (상) 비밀번호 관리정책 설정
# 판단 기준:
#   - 최소 길이: 8자 이상
#   - 최대 사용기간: 90일 이하
#   - 최소 사용기간: 1일 이상
#   - 복잡성: 숫자/대문자/소문자/특수문자 각 1개 이상
#   - 최근 비밀번호 기억: 4회 이상
# ────────────────────────────────────────────────────────────
check_U02() {
    local id="U-02" title="비밀번호 관리정책 설정"
    local login_defs="/etc/login.defs"
    local pwquality_conf="/etc/security/pwquality.conf"
    local pwhistory_conf="/etc/security/pwhistory.conf"

    local fail_reasons=()
    local pass_items=()

    # ── 1) /etc/login.defs: 최대/최소 사용기간 ──
    if [[ -f "$login_defs" ]]; then
        local max_days min_days
        max_days=$(grep -E '^\s*PASS_MAX_DAYS' "$login_defs" | awk '{print $2}')
        min_days=$(grep -E '^\s*PASS_MIN_DAYS' "$login_defs" | awk '{print $2}')

        if [[ -n "$max_days" && "$max_days" -le 90 ]]; then
            pass_items+=("PASS_MAX_DAYS=${max_days}")
        else
            fail_reasons+=("PASS_MAX_DAYS=${max_days:-미설정} (90 이하 필요)")
        fi

        if [[ -n "$min_days" && "$min_days" -ge 1 ]]; then
        # -ge : 숫자 비교 시 "greater than or equal" (크거나 같음)
            pass_items+=("PASS_MIN_DAYS=${min_days}")
        else
            fail_reasons+=("PASS_MIN_DAYS=${min_days:-미설정} (1 이상 필요)")
        fi
    else
        fail_reasons+=("/etc/login.defs 없음")
    fi

    # ── 2) /etc/security/pwquality.conf: 복잡성 및 최소 길이 ──
    if [[ -f "$pwquality_conf" ]]; then
        local minlen dcredit ucredit lcredit ocredit
        minlen=$(grep -E '^\s*minlen\s*=' "$pwquality_conf" | awk -F'=' '{print $2}' | tr -d ' ')
        # /etc/login.defs 파일 내 PASS_MIN_LEN과는 별개로, pwquality.conf의 minlen이 실제 패스워드 최소 길이로 적용됨 이유는 PAM 모듈이 pwquality.conf의 설정을 우선적으로 참조하기 때문입니다.
        # 따라서 minlen이 8 이상으로 설정되어 있어야 합니다.
        dcredit=$(grep -E '^\s*dcredit\s*=' "$pwquality_conf" | awk -F'=' '{print $2}' | tr -d ' ')
        ucredit=$(grep -E '^\s*ucredit\s*=' "$pwquality_conf" | awk -F'=' '{print $2}' | tr -d ' ')
        lcredit=$(grep -E '^\s*lcredit\s*=' "$pwquality_conf" | awk -F'=' '{print $2}' | tr -d ' ')
        ocredit=$(grep -E '^\s*ocredit\s*=' "$pwquality_conf" | awk -F'=' '{print $2}' | tr -d ' ')
        # awk -F'=' : 구분자 '='로 필드 분리, tr -d ' ' : 공백 제거

        [[ -n "$minlen" && "$minlen" -ge 8 ]] \
            && pass_items+=("minlen=${minlen}") \
            || fail_reasons+=("minlen=${minlen:-미설정} (8 이상 필요)")

        [[ -n "$dcredit" && "$dcredit" -le -1 ]] \
            && pass_items+=("dcredit=${dcredit}") \
            || fail_reasons+=("dcredit=${dcredit:-미설정} (-1 이하 필요, 숫자 요구)")

        [[ -n "$ucredit" && "$ucredit" -le -1 ]] \
            && pass_items+=("ucredit=${ucredit}") \
            || fail_reasons+=("ucredit=${ucredit:-미설정} (-1 이하 필요, 대문자 요구)")

        [[ -n "$lcredit" && "$lcredit" -le -1 ]] \
            && pass_items+=("lcredit=${lcredit}") \
            || fail_reasons+=("lcredit=${lcredit:-미설정} (-1 이하 필요, 소문자 요구)")

        [[ -n "$ocredit" && "$ocredit" -le -1 ]] \
            && pass_items+=("ocredit=${ocredit}") \
            || fail_reasons+=("ocredit=${ocredit:-미설정} (-1 이하 필요, 특수문자 요구)")
    else
        fail_reasons+=("/etc/security/pwquality.conf 없음")
    fi

    # ── 3) 패스워드 히스토리: pwhistory.conf 또는 pam_unix remember ──
    local remember=0
    if [[ -f "$pwhistory_conf" ]]; then
        remember=$(grep -E '^\s*remember\s*=' "$pwhistory_conf" | awk -F'=' '{print $2}' | tr -d ' ')
    fi
    # pam 설정에서도 확인
    if [[ "$remember" -lt 4 ]]; then
        local pam_remember
        # ※ grep -P(PCRE)는 로케일이 UTF-8/단일바이트가 아니면 실행 자체가 실패해
        #   점검이 조용히 건너뛰어질 수 있음(미탐) → POSIX 확장정규식(-E)으로 대체
        pam_remember=$(grep -h 'remember=' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null \
                       | grep -oE 'remember=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
        [[ -n "$pam_remember" ]] && remember="$pam_remember"
    fi

    if [[ -n "$remember" && "$remember" -ge 4 ]]; then
        pass_items+=("remember=${remember}")
    else
        fail_reasons+=("비밀번호 재사용 기억=${remember:-미설정} (4회 이상 필요)")
    fi

    # ── 최종 판정 ──
    if [[ ${#fail_reasons[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "$(join_by ', ' "${pass_items[@]}")"
        # IFS=, : 내부 필드 구분자 설정, echo "${pass_items[*]}" : 배열 요소를 공백으로 구분하여 출력, IFS로 구분자 변경하여 출력

    else
        result_fail "$id" "$title" "$(join_by '; ' "${fail_reasons[@]}")"
    fi
}
# 26/05/17 분석 완료

# ────────────────────────────────────────────────────────────
# U-03 (상) 계정 잠금 임계값 설정
# Rocky Linux 10: pam_faillock 사용 (/etc/security/faillock.conf)
# 판단: deny <= 10, unlock_time >= 120 이면 양호
# ────────────────────────────────────────────────────────────
check_U03() {
    local id="U-03" title="계정 잠금 임계값 설정"
    local faillock_conf="/etc/security/faillock.conf"

    local deny="" unlock_time=""
    local source=""

    # ── 1) faillock.conf 확인 (Rocky Linux 10 권장 방식) ──
    if [[ -f "$faillock_conf" ]]; then
        deny=$(grep -E '^\s*deny\s*=' "$faillock_conf" | awk -F'=' '{print $2}' | tr -d ' ' | tail -1)
        unlock_time=$(grep -E '^\s*unlock_time\s*=' "$faillock_conf" | awk -F'=' '{print $2}' | tr -d ' ' | tail -1)
        source="faillock.conf"
    fi

    # ── 2) PAM 설정에서 직접 확인 (fallback) ──
    if [[ -z "$deny" || -z "$unlock_time" ]]; then
        local pam_line
        pam_line=$(grep -h 'pam_faillock' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)
        # grep -h : 파일명 출력 안함, pam_faillock 관련 라인에서 deny와 unlock_time 값 추출
        # ※ v2는 deny/unlock_time 모두 최솟값(head -1)을 채택했으나,
        #   deny는 값이 클수록 느슨한 설정이므로 최솟값 채택 시 미탐이 발생함
        #   (예: preauth deny=5, authfail deny=20 → 실효 위험값은 20)
        #   → deny는 최댓값(tail -1), unlock_time은 최솟값(head -1)으로 보수적 판정
        # ※ grep -P(PCRE)는 로케일이 UTF-8/단일바이트가 아니면 실행 자체가 실패해
        #   점검이 조용히 건너뛰어질 수 있음(미탐) → POSIX 확장정규식(-E)으로 대체
        #   even_deny_root 옵션에는 '=' 가 없으므로 'deny=[0-9]+' 와 오매치되지 않음
        [[ -z "$deny" ]]         && deny=$(echo "$pam_line"        | grep -oE 'deny=[0-9]+'        | cut -d= -f2 | sort -n | tail -1)
        [[ -z "$unlock_time" ]]  && unlock_time=$(echo "$pam_line" | grep -oE 'unlock_time=[0-9]+' | cut -d= -f2 | sort -n | head -1)
        # sort -n : 숫자 기준 정렬

        # 출처 표기: faillock.conf에서 일부 값을 이미 얻은 경우 혼합 표기
        if [[ -n "$source" ]]; then
            source="faillock.conf+pam.d"
        else
            source="pam.d"
        fi
    fi

    if [[ -z "$deny" && -z "$unlock_time" ]]; then
        result_fail "$id" "$title" "계정 잠금 임계값 미설정 (pam_faillock 미적용)"
        return
    fi

    local msg="deny=${deny:-미설정}, unlock_time=${unlock_time:-미설정} [출처: ${source}]"
    local ok=1

    if [[ -z "$deny" || "$deny" -gt 10 ]]; then
    #-gt : 숫자 비교 시 "greater than" (크다)
        ok=0
    fi
    if [[ -z "$unlock_time" || "$unlock_time" -lt 120 ]]; then
    #-lt : 숫자 비교 시 "less than" (작다)
        ok=0
    fi

    if [[ "$ok" -eq 1 ]]; then
        result_pass "$id" "$title" "$msg"
    else
        local reason=""
        [[ -z "$deny" || "$deny" -gt 10 ]]          && reason+="deny=${deny:-미설정} (10 이하 필요) "
        [[ -z "$unlock_time" || "$unlock_time" -lt 120 ]] && reason+="unlock_time=${unlock_time:-미설정} (120 이상 필요)"
        result_fail "$id" "$title" "${reason% } [출처: ${source}]"
    fi
}

# ────────────────────────────────────────────────────────────
# U-04 (상) 비밀번호 파일 보호
# 판단: /etc/passwd 두 번째 필드가 'x' → shadow 사용 → 양호
# ────────────────────────────────────────────────────────────
check_U04() {
    local id="U-04" title="비밀번호 파일 보호"
    local passwd_file="/etc/passwd"
    local shadow_file="/etc/shadow"

    if [[ ! -f "$passwd_file" ]]; then
        result_na "$id" "$title" "/etc/passwd 파일 없음"
        return
    fi

    # passwd 두 번째 필드 확인
    local plaintext_count
    plaintext_count=$(awk -F: '$2 != "x" && $2 != "*" && $2 != "!" && $2 != "" {print $1}' "$passwd_file" | wc -l)
    # wc -l : 줄 수 세기, awk로 2번째 필드가 'x', '*', '!', ''이 아닌 계정 추출 후 개수 확인

    if [[ ! -f "$shadow_file" ]]; then
        result_fail "$id" "$title" "/etc/shadow 파일 없음 (shadow password 미적용)"
        return
    fi

    if [[ "$plaintext_count" -eq 0 ]]; then
        result_pass "$id" "$title" "shadow password 적용됨 (/etc/passwd 2번째 필드: x)"
    else
        local plain_accounts
        plain_accounts=$(awk -F: '$2 != "x" && $2 != "*" && $2 != "!" && $2 != "" {print $1}' "$passwd_file" | tr '\n' ',')
        result_fail "$id" "$title" "평문 저장 계정 존재: ${plain_accounts%,}"
    fi
}

# ────────────────────────────────────────────────────────────
# U-05 (상) root 이외의 UID가 '0' 금지
# 판단: root 외 UID=0인 계정이 없으면 양호
# ────────────────────────────────────────────────────────────
check_U05() {
    local id="U-05" title="root 이외의 UID가 '0' 금지"
    local passwd_file="/etc/passwd"

    local uid0_accounts
    uid0_accounts=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$passwd_file")
    
    if [[ -z "$uid0_accounts" ]]; then
        result_pass "$id" "$title" "root 외 UID=0 계정 없음"
    else
        result_fail "$id" "$title" "UID=0 중복 계정: $(echo "$uid0_accounts" | tr '\n' ' ')"
    fi
}
# 26/05/18 분석 완료 동적 확인 완료

# ────────────────────────────────────────────────────────────
# U-06 (상) 사용자 계정 su 기능 제한
# 판단: /etc/pam.d/su에 pam_wheel 설정 또는 /usr/bin/su 권한이
#       wheel 그룹으로 제한(4750)되어 있으면 양호
# ────────────────────────────────────────────────────────────
check_U06() {
    local id="U-06" title="사용자 계정 su 기능 제한"
    local su_pam="/etc/pam.d/su"
    local su_bin="/usr/bin/su"

    # 일반 사용자 계정 존재 여부 확인 (UID >= 1000)
    local normal_users
    normal_users=$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)
    if [[ -z "$normal_users" ]]; then
        result_na "$id" "$title" "일반 사용자 계정 없음 (su 제한 불필요)"
        return
    fi

    # ── 1) PAM wheel 설정 확인 ──
    local pam_wheel_set=false
    if [[ -f "$su_pam" ]]; then
        if grep -qE '^\s*auth\s+required\s+pam_wheel\.so' "$su_pam"; then
            pam_wheel_set=true
        fi
    fi

    # ── 2) su 바이너리 권한/그룹 확인 ──
    local su_perm su_group
    su_perm=$(get_perm "$su_bin")
    su_group=$(stat -c "%G" "$su_bin" 2>/dev/null)

    # ── 3) wheel 그룹에 멤버가 있는지 확인 ──
    local wheel_members
    wheel_members=$(grep -E '^wheel:' /etc/group | cut -d: -f4)

    if $pam_wheel_set && [[ -n "$wheel_members" ]]; then
        result_pass "$id" "$title" "pam_wheel 설정됨, wheel 멤버: ${wheel_members}"
    elif [[ "$su_perm" == "4750" && "$su_group" == "wheel" && -n "$wheel_members" ]]; then
        result_pass "$id" "$title" "su 권한=4750, 그룹=wheel, 멤버: ${wheel_members}"
    elif $pam_wheel_set && [[ -z "$wheel_members" ]]; then
        result_interview "$id" "$title" "pam_wheel 설정됨, 그러나 wheel 그룹 멤버 없음 — su 필요 계정 존재 여부 담당자 확인 필요"
    else
        result_fail "$id" "$title" "su 기능 제한 미설정 (pam_wheel 또는 4750 wheel 권한 필요)"
    fi
}
# 26/05/24 분석 완료

# ────────────────────────────────────────────────────────────
# U-07 (하) 불필요한 계정 제거
# 판단:
#   취약  : OS 기본 불필요 계정(games, gopher, lp, uucp 등)이 로그인 가능 shell 보유
#   인터뷰: 위 계정이 없더라도 일반 사용자 계정(UID>=1000)이 존재하는 경우
#           → 해당 계정의 업무상 필요 여부는 시스템 담당자만 판단 가능하므로
#             진단자가 임의로 양호 처리할 수 없음 (자동 판정 불가 영역)
#   양호  : 불필요 기본 계정도, 일반 사용자 계정도 없는 경우
# ────────────────────────────────────────────────────────────
check_U07() {
    local id="U-07" title="불필요한 계정 제거"

    # Rocky Linux 10 기준 불필요 기본 계정 목록
    local unnecessary_accounts=(
        games gopher ftp news uucp operator
        lp halt shutdown sync
    )

    local found_accounts=()

    for acct in "${unnecessary_accounts[@]}"; do
        local shell
        shell=$(awk -F: -v u="$acct" '$1==u {print $7}' /etc/passwd)
        if [[ -n "$shell" ]]; then
            # 로그인 가능 shell인지 확인
            case "$shell" in
                /bin/false|/sbin/nologin|/usr/sbin/nologin)
                    ;;  # 로그인 불가 → 문제 없음
                *)
                    found_accounts+=("${acct}(shell=${shell})")
                    ;;
            esac
        fi
    done

    # UID >= 1000 일반 사용자 계정 수집 (담당자 확인 대상)
    local normal_users=()
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ ! "$uid" =~ ^[0-9]+$ ]] && continue
        [[ "$uid" -lt 1000 || "$uid" -eq 65534 ]] && continue
        normal_users+=("${user}(uid=${uid},shell=${shell})")
    done < /etc/passwd

    if [[ ${#found_accounts[@]} -gt 0 ]]; then
        # 불필요 기본 계정이 로그인 가능 → 취약 확정
        # (일반 사용자 계정 목록도 함께 제시해 담당자 확인이 가능하도록 함)
        local detail
        detail="로그인 가능 불필요 계정: $(join_by ', ' "${found_accounts[@]}")"
        if [[ ${#normal_users[@]} -gt 0 ]]; then
            detail+=" / 일반 사용자 계정 ${#normal_users[@]}개도 사용 여부 확인 필요: $(join_by ', ' "${normal_users[@]}")"
        fi
        result_fail "$id" "$title" "$detail"

    elif [[ ${#normal_users[@]} -gt 0 ]]; then
        # ※ v2는 이 경우를 양호로 처리했으나, 일반 사용자 계정의 업무상 필요 여부
        #   (퇴직자·미사용·임시 계정 여부)는 시스템 담당자만 판단할 수 있으므로
        #   진단자가 자동으로 양호 판정할 수 없음 → 인터뷰로 분류
        result_interview "$id" "$title" \
            "불필요 기본 계정은 로그인 불가 상태이나, 일반 사용자 계정 ${#normal_users[@]}개 존재 — 퇴직자/미사용/임시 계정 여부 담당자 확인 필요: $(join_by ', ' "${normal_users[@]}")"

    else
        result_pass "$id" "$title" \
            "불필요 기본 계정 로그인 불가 상태 / 일반 사용자 계정 없음"
    fi
}

# ────────────────────────────────────────────────────────────
# U-08 (중) 관리자 그룹에 최소한의 계정 포함
# 판단: wheel/root 그룹에 root 외 계정이 있으면 목록 출력 후 담당자 확인 필요
#       → 불필요 계정 포함 여부는 운영자가 최종 판단
# ────────────────────────────────────────────────────────────
check_U08() {
    local id="U-08" title="관리자 그룹에 최소한의 계정 포함"

    # root 그룹 멤버
    local root_group_members
    root_group_members=$(grep -E '^root:' /etc/group | cut -d: -f4)

    # wheel 그룹 멤버 (sudo 권한 그룹)
    local wheel_group_members
    wheel_group_members=$(grep -E '^wheel:' /etc/group | cut -d: -f4)

    # sudoers 파일에서 개별 사용자 권한 확인
    local sudo_users
    sudo_users=$(grep -E '^\s*[^#%].*ALL\s*=\s*\(ALL' /etc/sudoers 2>/dev/null \
                 | awk '{print $1}' | tr '\n' ' ')
    
    local detail="root그룹=[${root_group_members:-없음}] wheel그룹=[${wheel_group_members:-없음}] sudoers개별=[${sudo_users:-없음}]"

    # ── root 이외의 관리자 권한 보유 계정 수집 ──
    # ※ v2는 root 그룹 멤버만 보고 판정해, wheel 그룹이나 sudoers에 일반 계정이
    #   등록되어 있어도 양호로 처리했음(미탐) → 관리자 권한 계정이 하나라도 있으면
    #   인터뷰(담당자 확인)로 판정. 취약 단정이 아니므로 가이드 판단 기준과 상충하지 않음
    local admin_extra=()
    local m
    for m in ${root_group_members//,/ } ${wheel_group_members//,/ } ${sudo_users}; do
        [[ -z "$m" || "$m" == "root" ]] && continue
        admin_extra+=("$m")
    done

    if [[ ${#admin_extra[@]} -gt 0 ]]; then
        result_interview "$id" "$title" \
            "root 외 관리자 권한 계정 존재: $(join_by ', ' "${admin_extra[@]}") — 업무상 필요 여부 담당자 확인 필요 → ${detail}"
    else
        result_pass "$id" "$title" "root 외 관리자 권한 계정 없음 → ${detail}"
    fi
}

# ────────────────────────────────────────────────────────────
# U-09 (하) 계정이 존재하지 않는 GID 금지
# 판단: /etc/group에 멤버가 아무도 없는 GID가 있고,
#       해당 GID를 기본 그룹으로 갖는 passwd 계정도 없으면 불필요 그룹
# ────────────────────────────────────────────────────────────
check_U09() {
    local id="U-09" title="계정이 존재하지 않는 GID 금지"

    local orphan_groups=()

    while IFS=: read -r grp_name _ gid members; do
        # 이 GID를 기본 그룹으로 사용하는 passwd 계정이 있는지 확인
        local has_primary
        has_primary=$(awk -F: -v g="$gid" '$4 == g {print $1}' /etc/passwd | head -1)
        # 그룹 멤버가 있는지 확인
        local has_member
        has_member=$(echo "$members" | grep -v '^$')

        if [[ -z "$has_primary" && -z "$has_member" ]]; then
            orphan_groups+=("${grp_name}(gid=${gid})")
        fi
    done < /etc/group
    # < : 파일을 입력으로 사용

    if [[ ${#orphan_groups[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "멤버 없는 불필요 그룹 없음"
    else
        result_interview "$id" "$title" "멤버 없는 그룹(담당자 확인): $(join_by ', ' "${orphan_groups[@]}")"
    fi
}

# ────────────────────────────────────────────────────────────
# U-10 (중) 동일한 UID 금지
# 판단: /etc/passwd에 중복 UID가 있으면 취약
# ────────────────────────────────────────────────────────────
check_U10() {
    local id="U-10" title="동일한 UID 금지"

    local dup_uids
    dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    # uniq -d : 중복된 항목만 출력, sort로 정렬 후 중복 UID 추출

    if [[ -z "$dup_uids" ]]; then
        result_pass "$id" "$title" "중복 UID 없음"
    else
        local dup_detail=""
        for uid in $dup_uids; do
            local accounts
            accounts=$(awk -F: -v u="$uid" '$3==u {print $1}' /etc/passwd | tr '\n' ',')
            dup_detail+="UID=${uid}:[${accounts%,}] "
        done
        result_fail "$id" "$title" "중복 UID 존재: ${dup_detail}"
    fi
}

# ────────────────────────────────────────────────────────────
# U-11 (하) 사용자 shell 점검
# 판단: 로그인 불필요 계정(시스템 계정)에 유효 shell이 부여되어 있으면 취약
# ────────────────────────────────────────────────────────────
check_U11() {
    local id="U-11" title="사용자 shell 점검"

    # 로그인 불필요한 기본 계정 목록
    local nologin_accounts=(
        daemon bin sys adm listen nobody noaccess
        diag operator games gopher lp ftp mail
        news uucp dbus polkitd systemd-network
        systemd-resolve tss sssd chrony
    )

    local vuln_accounts=()
    declare -A checked=()

    # ── 판정 헬퍼: 로그인 가능한 shell이면 취약 목록에 추가 ──
    _u11_inspect() {
        local acct="$1" shell="$2"
        [[ -n "${checked[$acct]:-}" ]] && return
        checked["$acct"]=1

        case "$shell" in
            (/bin/false|/sbin/nologin|/usr/sbin/nologin|"")
                ;;  # 정상
            (*)
                vuln_accounts+=("${acct}(shell=${shell})")
                ;;
        esac
    }

    # ── 1) 가이드 명시 기본 계정 점검 ──
    for acct in "${nologin_accounts[@]}"; do
        local shell
        shell=$(awk -F: -v u="$acct" '$1==u {print $7}' /etc/passwd 2>/dev/null)
        [[ -z "$shell" ]] && continue  # 계정 없으면 skip
        _u11_inspect "$acct" "$shell"
    done

    # ── 2) UID < 1000 시스템 계정 전수 점검 ──
    # ※ v2는 하드코딩 목록만 점검해 목록에 없는 시스템 계정(임의 생성 계정 포함)을
    #   놓쳤음(미탐). 가이드 점검 명령이 /etc/passwd 전체 조회이므로 전수 점검으로 변경
    #   root(UID 0)와 nobody(65534)는 판정 대상에서 제외
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ "$user" == "root" ]] && continue
        [[ ! "$uid" =~ ^[0-9]+$ ]] && continue
        [[ "$uid" -ge 1000 ]] && continue
        # halt/shutdown/sync는 OS 기본 제공 명령 실행 전용 계정으로
        # U-07(불필요한 계정 제거)에서 이미 판정하므로 중복 계상 방지를 위해 제외
        case "$user" in (halt|shutdown|sync) continue ;; esac
        _u11_inspect "$user" "$shell"
    done < /etc/passwd

    if [[ ${#vuln_accounts[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "시스템 계정 전체 nologin/false shell 적용됨"
    else
        result_fail "$id" "$title" \
            "로그인 가능 시스템 계정 ${#vuln_accounts[@]}개: $(join_by ', ' "${vuln_accounts[@]}")"
    fi
}

# ────────────────────────────────────────────────────────────
# U-12 (하) 세션 종료 시간 설정
# 판단: TMOUT <= 600 (초)이면 양호
# ────────────────────────────────────────────────────────────
check_U12() {
    local id="U-12" title="세션 종료 시간 설정"

    local tmout_val=""
    local tmout_source=""

    # 확인할 파일 목록 (실제 적용 우선순위 낮은 것 → 높은 것 순서로 나열, 마지막 값이 덮어씀)
    local check_files=(
        /etc/profile            # login shell, 시스템 전체 (모든 사용자)
        /etc/bashrc             # non-login shell, 시스템 전체 (/etc/profile 또는 ~/.bashrc 에서 호출)
        /etc/profile.d/*.sh     # login shell, 시스템 전체 (/etc/profile 내부에서 source)
        /root/.bash_profile     # login shell, root 사용자 한정
        /root/.bashrc           # non-login shell, root 사용자 한정
        # 우선순위: /root/.bashrc > /root/.bash_profile > /etc/profile.d/*.sh > /etc/bashrc > /etc/profile
    )

    for f in "${check_files[@]}"; do
        for file in $f; do
            [[ -f "$file" ]] || continue

            # unset TMOUT 감지: 이전에 설정된 값을 무효화하는 경우
            if grep -qE '^\s*unset\s+TMOUT' "$file"; then
                tmout_val=""
                tmout_source="unset in $file"
                continue
            fi

            local val
            # export / readonly 접두어 포함 패턴 대응, 인라인 주석 제거
            val=$(grep -E '^\s*(readonly\s+|export\s+)*TMOUT\s*=' "$file" \
                  | tail -1 | awk -F'=' '{print $2}' | sed 's/#.*//' | tr -d ' "')
            if [[ -n "$val" ]]; then
                tmout_val="$val"
                tmout_source="$file"
            fi
        done
    done

    # readonly 선언 여부 확인 (root 파일 포함)
    local readonly_check
    readonly_check=$(grep -rh 'readonly\s*TMOUT\|declare.*-r.*TMOUT' \
                     /etc/profile /etc/profile.d/ /etc/bashrc \
                     /root/.bash_profile /root/.bashrc 2>/dev/null | head -1)

    if [[ -z "$tmout_val" ]]; then
        result_fail "$id" "$title" "TMOUT 미설정 (600초 이하 설정 필요)"
        return
    fi

    # TMOUT=$SOME_VAR 처럼 숫자가 아닌 값이면 정적 분석으로 판정 불가
    # → 취약 단정(오탐)도 양호 처리(미탐)도 할 수 없으므로 인터뷰(수동 확인) 처리
    #   (숫자가 아닌 값을 [[ -le ]]에 넣으면 bash가 변수명으로 재귀 평가해
    #    set -u 환경에서 unbound variable 오류가 날 수 있음 → 사전 차단)
    if ! [[ "$tmout_val" =~ ^[0-9]+$ ]]; then
        result_interview "$id" "$title" \
            "TMOUT=${tmout_val} — 숫자가 아닌 값(변수 참조 등)으로 자동 판정 불가, 실제 적용값 수동 확인 필요 [출처: ${tmout_source}]"
        return
    fi

    if [[ "$tmout_val" -le 600 && "$tmout_val" -gt 0 ]]; then
        local readonly_note=""
        [[ -n "$readonly_check" ]] && readonly_note=" (readonly 설정됨)"
        result_pass "$id" "$title" "TMOUT=${tmout_val}초 [출처: ${tmout_source}]${readonly_note}"
    else
        result_fail "$id" "$title" "TMOUT=${tmout_val}초 (600 이하 필요) [출처: ${tmout_source}]"
    fi
}

# ────────────────────────────────────────────────────────────
# U-13 (중) 안전한 비밀번호 암호화 알고리즘 사용
# 판단: SHA-256($5$) 또는 SHA-512($6$) 이상이면 양호
#       Rocky Linux 10: yescrypt($y$)도 안전한 알고리즘으로 허용
# ────────────────────────────────────────────────────────────
check_U13() {
    local id="U-13" title="안전한 비밀번호 암호화 알고리즘 사용"
    local shadow_file="/etc/shadow"
    local login_defs="/etc/login.defs"          # 계정 생성 시 기본 암호화 알고리즘 설정 확인용 useradd, newusers 등에서 참조
    local pam_file="/etc/pam.d/system-auth"     # 패스워드 변경 시 적용되는 PAM 모듈 설정 확인용 (passwd 명령어 등에서 참조)

    # ── 1) /etc/login.defs ENCRYPT_METHOD 확인 ──
    local encrypt_method=""
    if [[ -f "$login_defs" ]]; then
        encrypt_method=$(grep -E '^\s*ENCRYPT_METHOD' "$login_defs" | awk '{print $2}')
    fi

    # ── 2) /etc/pam.d/system-auth PAM 알고리즘 확인 ──
    local pam_algo=""
    if [[ -f "$pam_file" ]]; then
        pam_algo=$(grep -E '^\s*password.*pam_unix\.so' "$pam_file" \
                   | grep -oiE 'sha512|sha256|md5|blowfish|yescrypt' | head -1)
    fi

    # ── 3) /etc/shadow 실제 해시 알고리즘 확인 ──
    local weak_accounts=()
    if [[ -f "$shadow_file" && -r "$shadow_file" ]]; then
        while IFS=: read -r user hash _; do     # shadow 파일은 username:password_hash:... 형식, 2번째 필드가 해시값, 나머지는 무시
            [[ -z "$hash" ]] && continue
            # 잠금/미설정 계정 판별: 선행 '!'를 모두 제거한 뒤 남은 값이 비어있거나
            # '*'로 시작하면 패스워드가 없는 계정이므로 알고리즘 판정 대상에서 제외
            # ※ 기존 "!", "*", "!!" 비교 방식은 "!*" 형태(Rocky 10 기본 잠금 표기)를
            #   놓쳐 잠금 계정을 취약 알고리즘으로 오판했음
            # ※ "!$1$..." 처럼 잠금됐지만 해시가 남은 계정은 잠금 해제 시 취약해지므로
            #   '!' 제거 후 남은 해시 기준으로 판정 (미탐 방지)
            local h="$hash"
            while [[ "$h" == '!'* ]]; do h="${h#!}"; done
            [[ -z "$h" || "$h" == '*'* ]] && continue
            case "$h" in
                ('$y$'*|'$6$'*|'$5$'*)
                    ;;  # yescrypt, SHA-512, SHA-256 → 안전
                ('$2'*|'$2b$'*|'$2y$'*)
                    ;;  # bcrypt → 안전
                (*)
                    weak_accounts+=("${user}(${h:0:3}...)")
                    ;;  # $1$(MD5), DES(접두어 없음) 등 → 취약
            esac
        done < "$shadow_file"
    else
        result_interview "$id" "$title" \
            "/etc/shadow 읽기 권한 없음 (root 실행 필요) — 실제 해시 알고리즘 수동 확인 필요 / ENCRYPT_METHOD=${encrypt_method:-미설정}"
        return
    fi

    # ── 4) login.defs 기준 안전 여부 ──
    local method_ok=false
    case "${encrypt_method^^}" in       # ^^ : 대문자로 변환, 쉘 내장 기능
        (SHA512|SHA256|SHA-512|SHA-256|YESCRYPT) method_ok=true ;;
    esac

    # ── 5) PAM 기준 안전 여부 ──
    local pam_ok=false
    local pam_note=""
    if [[ -z "$pam_algo" ]]; then
        pam_note="PAM 알고리즘 미설정 또는 확인 불가"
    else
        case "${pam_algo,,}" in
            (sha512|sha256|yescrypt)
                pam_ok=true
                pam_note="PAM=${pam_algo}"
                ;;
            (*)
                pam_note="PAM=${pam_algo}(취약)"
                ;;
        esac
    fi

    # ── 6) 최종 판정 ──
    local config_summary="ENCRYPT_METHOD=${encrypt_method:-미설정}, ${pam_note}"

    if [[ ${#weak_accounts[@]} -gt 0 ]]; then
        # shadow에 실제 취약 해시 존재 → 무조건 취약
        result_fail "$id" "$title" \
            "취약 알고리즘 계정: $(join_by ', ' "${weak_accounts[@]}") / ${config_summary}"
        return
    fi

    if [[ $method_ok == true && $pam_ok == true ]]; then
        result_pass "$id" "$title" \
            "모든 계정 안전한 알고리즘 사용 / ${config_summary}"
    elif [[ $method_ok == false ]]; then
        result_fail "$id" "$title" \
            "login.defs ENCRYPT_METHOD 미설정 또는 취약 알고리즘 / ${config_summary}"
    else
        # method_ok=true, pam_ok=false
        result_fail "$id" "$title" \
            "PAM 알고리즘 취약 또는 미설정 (passwd 변경 시 적용됨) / ${config_summary}"
    fi
}

# ────────────────────────────────────────────────────────────
# 계정 관리 전체 실행
# ────────────────────────────────────────────────────────────
run_account_checks() {
    print_section "1. 계정 관리 (U-01 ~ U-13)"
    check_U01
    check_U02
    check_U03
    check_U04
    check_U05
    check_U06
    check_U07
    check_U08
    check_U09
    check_U10
    check_U11
    check_U12
    check_U13
}
