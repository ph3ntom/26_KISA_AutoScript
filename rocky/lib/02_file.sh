#!/bin/bash
# 02_file.sh - 파일 및 디렉토리 관리 진단 (U-14 ~ U-33)
# 대상 OS: Rocky Linux 10.1 (RHEL 10 계열)

# ────────────────────────────────────────────────────────────
# U-14 (상) root 홈, PATH 디렉터리 권한 및 PATH 설정
# 판단: PATH 환경변수에 "." 이 맨 앞이나 중간에 없으면 양호
# ────────────────────────────────────────────────────────────
check_U14() {
    local id="U-14" title="root PATH 환경변수 '.' 포함 여부"
    local vuln_files=()

: << 'EOF'
    # ── 1) 런타임 PATH 검사 (직접 export한 경우 포함) KISA 가이드에 명시되어있지 않아 주석처리 ──
    local runtime_arr
    IFS=':' read -ra runtime_arr <<< "$PATH"
    local last_idx=$(( ${#runtime_arr[@]} - 1 ))
    for i in "${!runtime_arr[@]}"; do
        local entry="${runtime_arr[$i]}"
        if [[ "$entry" == "." || "$entry" == ./* ]]; then
            if [[ "$i" -ne "$last_idx" || "$entry" != "." ]]; then
                vuln_files+=("runtime \$PATH(${entry})")
                break
            fi
        fi
    done
EOF

    # ── 2) 설정 파일 검사 ──
    local check_files=(
        /etc/profile
        /etc/bashrc
        /root/.bash_profile
        /root/.bashrc
        /root/.profile
    )
    for f in /etc/profile.d/*.sh; do
        [[ -f "$f" ]] && check_files+=("$f")
    done

    for file in "${check_files[@]}"; do
        [[ -f "$file" ]] || continue

        while IFS= read -r path_line; do
            local path_val
            path_val=$(echo "$path_line" | sed 's/.*PATH=//' | tr -d '"' | tr -d "'")
            local arr
            IFS=':' read -ra arr <<< "$path_val"
            local last_idx=$(( ${#arr[@]} - 1 ))

            for i in "${!arr[@]}"; do
                local entry="${arr[$i]}"
                if [[ "$entry" == "." || "$entry" == ./* ]]; then
                    if [[ "$i" -ne "$last_idx" || "$entry" != "." ]]; then
                        vuln_files+=("${file}(${entry})")
                        break 2
                    fi
                fi
            done
        done < <(grep 'PATH=' "$file" | grep -v '^\s*#')
    done

    if [[ ${#vuln_files[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "PATH에 '.' 또는 상대경로 포함 없음"
    else
        result_fail "$id" "$title" "취약 항목: $(join_by ', ' "${vuln_files[@]}")"
    fi
}
#26/5/26 확인

# ────────────────────────────────────────────────────────────
# U-15 (상) 파일 및 디렉터리 소유자 설정
# 판단: 소유자 없는(-nouser) 또는 그룹 없는(-nogroup) 파일/디렉토리가 없으면 양호
# ────────────────────────────────────────────────────────────
check_U15() {
    local id="U-15" title="소유자 없는 파일 및 디렉터리 존재 여부"

    echo "       ※ 전체 파일시스템 탐색 중... (시간 소요)"

    # ※ v2는 -xdev를 표현식 뒤에 배치해 GNU find가 경고를 출력했음
    #   (find: warning: you have specified the global option -xdev after ...)
    #   → 전역 옵션은 경로 바로 뒤에 위치시킴 (동작은 동일)
    local noowner_files=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && noowner_files+=("$line")
    done < <(find / -xdev \( -nouser -o -nogroup \) -ls 2>/dev/null)
    # -xdev 옵션으로 루트 파일시스템만 탐색하여 시간 단축 (외부 마운트 제외), -nouser, -nogroup : 소유자, 그룹 없는 파일 탐색, -o : or 조건

    # 별도 마운트(-xdev 제외 대상)가 있으면 점검 범위를 명시
    local skipped_mounts
    skipped_mounts=$(findmnt -rn -o TARGET -t ext4,xfs,btrfs,ext3,vfat 2>/dev/null \
                     | grep -v '^/$' | tr '\n' ' ')
    local scope_note=""
    [[ -n "$skipped_mounts" ]] && \
        scope_note=" / 점검 제외(별도 마운트): ${skipped_mounts% }"

    if [[ ${#noowner_files[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "소유자/그룹 없는 파일 없음${scope_note}"
    else
        result_fail "$id" "$title" "소유자/그룹 없는 파일 ${#noowner_files[@]}개 존재 (확인 필요)${scope_note}"
        print_evidence "$id" "${noowner_files[@]}"
    fi
}
# 26/5/27 확인

# ────────────────────────────────────────────────────────────
# 내부 헬퍼: 파일 권한/소유자 일괄 점검
# check_file_perm <id> <title> <file> <max_perm> <owner1> [<owner2> ...]
# ────────────────────────────────────────────────────────────
_check_file_perm() {
    local id="$1" title="$2" file="$3" max_perm="$4"
    shift 4
    local allowed_owners=("$@")

    if [[ ! -f "$file" && ! -d "$file" ]]; then
        result_na "$id" "$title" "${file} 파일 없음"
        return
    fi

    local actual_perm actual_owner
    actual_perm=$(get_perm "$file")
    actual_owner=$(get_owner "$file")

    local owner_ok=false
    for o in "${allowed_owners[@]}"; do
        [[ "$actual_owner" == "$o" ]] && owner_ok=true && break
    done

    local perm_ok=false
    perm_le "$max_perm" "$actual_perm" && perm_ok=true

    if $owner_ok && $perm_ok; then
        result_pass "$id" "$title" "${file} [소유자=${actual_owner}, 권한=${actual_perm}]"
    elif ! $owner_ok; then
        result_fail "$id" "$title" "${file} 소유자=${actual_owner} (root 필요), 권한=${actual_perm}"
    else
        result_fail "$id" "$title" "${file} 소유자=${actual_owner}, 권한=${actual_perm} (${max_perm} 이하 필요)"
    fi
}

# ────────────────────────────────────────────────────────────
# U-16 (상) /etc/passwd 파일 소유자 및 권한 설정
# 판단: 소유자=root, 권한<=644
# ────────────────────────────────────────────────────────────
check_U16() {
    _check_file_perm "U-16" "/etc/passwd 소유자 및 권한 설정" \
        "/etc/passwd" "644" "root"
}
# 26/5/28 확인

# ────────────────────────────────────────────────────────────
# U-17 (상) 시스템 시작 스크립트 권한 설정
# 판단: root 소유, 일반 사용자 쓰기 권한 없음 (other w 비트 = 0)
# Rocky Linux 10: systemd 기반 → /etc/systemd/system/
# ────────────────────────────────────────────────────────────
check_U17() {
    local id="U-17" title="시스템 시작 스크립트 권한 설정"
    local vuln_list=()
    declare -A seen_reals=()

    local -a target_dirs=("/etc/systemd/system" "/etc/rc.d")

    _u17_inspect() {
        local f="$1" label="$2"
        local owner perm other_bit

        owner=$(get_owner "$f")
        perm=$(get_perm "$f")

        # get_perm 반환값 검증: 숫자가 아니거나 비어있으면 스킵
        [[ "$perm" =~ ^[0-7]+$ ]] || return

        other_bit="${perm: -1}"

        if [[ "$owner" != "root" ]] || [[ "$other_bit" =~ [2367] ]]; then
        # =~ 정규식으로 other 쓰기 권한(2, 3, 6, 7) 확인
            vuln_list+=("${label}(owner=${owner},perm=${perm})")
        fi
    }

    for dir in "${target_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        # -d 옵션으로 디렉토리 존재 여부 확인, 존재하지 않으면 다음 디렉토리로 넘어감

        # 1) 일반 파일 검사
        while IFS= read -r -d '' f; do
            seen_reals["$f"]=1
            _u17_inspect "$f" "$(basename "$f")"
        done < <(find "$dir" -type f -print0 2>/dev/null)

        # 2) 심볼릭 링크 → 실제 파일 검사
        while IFS= read -r -d '' link; do
            local real
            real=$(readlink -f "$link" 2>/dev/null)
            [[ -f "$real" ]] || continue
            [[ -v seen_reals["$real"] ]] && continue
            seen_reals["$real"]=1
            _u17_inspect "$real" "$(basename "$link")→$(basename "$real")"
        done < <(find "$dir" -type l -print0 2>/dev/null)
    done

    if [[ ${#vuln_list[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "시작 스크립트 root 소유, other 쓰기 없음"
    else
        local fail_msg
        fail_msg=$(join_by ', ' "${vuln_list[@]:0:5}")
        result_fail "$id" "$title" \
            "취약 파일 ${#vuln_list[@]}개 (상위 5): $fail_msg"
        print_evidence "$id" "${vuln_list[@]}"
    fi
}
# 26/5/28 확인

# ────────────────────────────────────────────────────────────
# U-18 (상) /etc/shadow 파일 소유자 및 권한 설정
# 판단: 소유자=root, 권한<=400
# ────────────────────────────────────────────────────────────
check_U18() {
    _check_file_perm "U-18" "/etc/shadow 소유자 및 권한 설정" \
        "/etc/shadow" "400" "root"
}
# 26/5/28 확인

# ────────────────────────────────────────────────────────────
# U-19 (상) /etc/hosts 파일 소유자 및 권한 설정
# 판단: 소유자=root, 권한<=644
# ────────────────────────────────────────────────────────────
check_U19() {
    _check_file_perm "U-19" "/etc/hosts 소유자 및 권한 설정" \
        "/etc/hosts" "644" "root"
}
# 26/5/28 확인

# ────────────────────────────────────────────────────────────
# U-20 (상) /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# Rocky Linux 10: /etc/systemd/system.conf를 기본적으로 생성하지 않고,
#                 시스템 컴파일 시 내장된 기본값(Built-in Defaults)으로 동작
# 판단: 소유자=root, 권한<=600
# ────────────────────────────────────────────────────────────
check_U20() {
    local id="U-20" title="inetd/systemd.conf 소유자 및 권한 설정"
    local issues=()
    local checked=()

    # ※ 결과 함수(result_*)의 반환값은 판정 신호로 신뢰할 수 없으므로
    #   파일별로 직접 권한을 비교해 issues 배열에 모은 뒤 결과를 1회만 출력한다
    #   (이전 구현은 파일 존재 시 결과가 이중 출력되는 문제가 있었음)
    _u20_inspect() {
        local f="$1"
        local owner perm
        owner=$(get_owner "$f")
        perm=$(get_perm "$f")
        checked+=("${f}[${owner}/${perm}]")
        if [[ "$owner" != "root" ]] || ! perm_le "600" "$perm"; then
            issues+=("${f} [owner=${owner}, perm=${perm}] (root 소유, 600 이하 필요)")
        fi
    }

    # 1. inetd/xinetd 레거시 파일 + systemd system.conf (존재 시만 점검)
    #    systemd system.conf 미존재 시 Built-in Defaults로 동작 → 양호
    for f in /etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf; do
        [[ -f "$f" ]] && _u20_inspect "$f"
    done

    # 2. /etc/xinetd.d 디렉토리 내부 파일 점검
    if [[ -d /etc/xinetd.d ]]; then
        while IFS= read -r f; do
            _u20_inspect "$f"
        done < <(find /etc/xinetd.d/ -type f 2>/dev/null)
    fi

    # 최종 판정 (결과는 반드시 1회만 출력)
    if [[ ${#checked[@]} -eq 0 ]]; then
        result_pass "$id" "$title" \
            "inetd/xinetd/systemd.conf 해당 파일 없음 — Built-in Defaults로 동작 중"
    elif [[ ${#issues[@]} -eq 0 ]]; then
        result_pass "$id" "$title" \
            "존재하는 모든 슈퍼데몬 설정 파일 기준 충족: $(join_by ' ' "${checked[@]}")"
    else
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    fi
}
# 26/5/29 확인

# ────────────────────────────────────────────────────────────
# U-21 (상) /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# Rocky Linux 10: /etc/rsyslog.conf + /etc/rsyslog.d/ 드롭인 파일 포함
# 판단: 소유자=root(또는 bin, sys), 권한<=640
# ────────────────────────────────────────────────────────────
check_U21() {
    local id="U-21" title="rsyslog.conf 소유자 및 권한 설정"

    local syslog_files=()
    for f in /etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf; do
        [[ -f "$f" ]] && syslog_files+=("$f")
    done

: << 'EOF'
    # rsyslog.d 드롭인 파일 추가 (텍스트 conf만 존재 → 640 점검 안전) KISA 가이드에 명시되어있지 않아 주석처리
    if [[ -d /etc/rsyslog.d ]]; then
        while IFS= read -r f; do
            syslog_files+=("$f")
        done < <(find /etc/rsyslog.d/ -type f 2>/dev/null)
    fi
EOF

    if [[ ${#syslog_files[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "rsyslog/syslog 설정 파일 없음"
        return
    fi

    # 파일별 취약 사항은 issues 배열에 모아 결과를 1회만 출력
    # (파일별로 result_fail을 호출하면 같은 항목이 결과에 중복 집계됨)
    local issues=()
    for f in "${syslog_files[@]}"; do
        local owner perm
        owner=$(get_owner "$f")
        perm=$(get_perm "$f")
        if [[ "$owner" =~ ^(root|bin|sys)$ ]] && perm_le "640" "$perm"; then
            :
        else
            issues+=("${f} [owner=${owner}, perm=${perm}] (기준: root/bin/sys 소유, 640 이하)")
        fi
    done

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" \
            "$(for f in "${syslog_files[@]}"; do \
                printf '%s[%s/%s] ' "$f" "$(get_owner "$f")" "$(get_perm "$f")"; done)"
    fi
}
# 26/5/29 확인

# ────────────────────────────────────────────────────────────
# U-22 (상) /etc/services 파일 소유자 및 권한 설정
# 판단: 소유자=root(또는 bin, sys), 권한<=644
# ────────────────────────────────────────────────────────────
check_U22() {
    local id="U-22" title="/etc/services 소유자 및 권한 설정"
    local f="/etc/services"

    if [[ ! -f "$f" ]]; then
        result_pass "$id" "$title" "/etc/services 파일 없음"
        return
    fi

    local owner perm
    owner=$(get_owner "$f")
    perm=$(get_perm "$f")

    if [[ "$owner" =~ ^(root|bin|sys)$ ]] && perm_le "644" "$perm"; then
        result_pass "$id" "$title" "[owner=${owner}, perm=${perm}]"
    else
        result_fail "$id" "$title" "[owner=${owner}, perm=${perm}] (root/bin/sys 소유, 644 이하 필요)"
    fi
}

# ────────────────────────────────────────────────────────────
# U-23 (상) SUID, SGID 설정 파일 점검
# KISA 가이드 기준: SUID/SGID 설정 파일 목록 확인 후 불필요한 항목 제거
# ────────────────────────────────────────────────────────────
check_U23() {
    local id="U-23" title="SUID/SGID 설정 파일 점검"

    echo "       ※ SUID/SGID 파일 탐색 중 (시간 소요)..."

    local found=()
    while IFS= read -r line; do
        found+=("$line")
    done < <(find / -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) \
             -exec ls -al {} + 2>/dev/null)
    # -xdev: 루트 파일시스템만 탐색, -user root: 소유자 root, -type f: 일반 파일, -perm -04000: SUID, -perm -02000: SGID, -exec ls -al {} + : 상세 정보 출력

    if [[ ${#found[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "SUID/SGID 설정 파일 없음"
    else
        # passwd, su, sudo 등 OS 표준 SUID 바이너리는 모든 시스템에 존재하므로
        # 발견 자체를 취약으로 판정하면 항상 취약(오탐)이 됨.
        # KISA 가이드 취지(목록 확인 후 "불필요한" 항목 제거)에 따라
        # 전체 목록을 출력하고 담당자 확인(인터뷰)으로 판정
        result_interview "$id" "$title" \
            "SUID/SGID 설정 파일 ${#found[@]}개 발견 — 불필요한 항목 존재 여부 담당자 확인 필요"
        print_evidence "$id" "${found[@]}"
    fi
}
# 26/5/30 확인

# ────────────────────────────────────────────────────────────
# U-24 (상) 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# 판단: 소유자=root 또는 해당 계정, other 쓰기 권한 없음
# ────────────────────────────────────────────────────────────
check_U24() {
    local id="U-24" title="사용자 환경변수 파일 소유자 및 권한 설정"

    local env_files=(
        .profile .bash_profile .bashrc .bash_login
        .kshrc .cshrc .login .exrc .netrc
    )

    local vuln_list=()

    while IFS=: read -r user _ _ _ _ homedir _; do
    # _ _ _ _ : /etc/passwd 필드 중 사용하지 않는 부분을 무시하기 위한 자리 표시자

        # KISA 가이드 기준: /etc/passwd 전체 계정 대상 검사
        # 필요 시 nologin/false 계정 제외 가능:
        # [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        [[ -z "$homedir" || ! -d "$homedir" ]] && continue

        for env_f in "${env_files[@]}"; do
            local full_path="${homedir}/${env_f}"
            [[ -f "$full_path" ]] || continue

            local owner perm
            owner=$(get_owner "$full_path")
            perm=$(get_perm "$full_path")
            local other_bit="${perm: -1}"

            if [[ "$owner" != "$user" && "$owner" != "root" ]] || (( other_bit & 2 )); then
                vuln_list+=("${full_path} [owner=${owner}, perm=${perm}]")
            fi
        done
    done < /etc/passwd

    if [[ ${#vuln_list[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "모든 환경변수 파일 소유자/권한 양호"
    else
        result_fail "$id" "$title" \
            "취약한 환경변수 파일 ${#vuln_list[@]}개 발견 (소유자 변경 및 other 쓰기 권한 제거 필요)"
        print_evidence "$id" "${vuln_list[@]}"
    fi
}

# ────────────────────────────────────────────────────────────
# U-25 (상) world writable 파일 점검
# 판단: world writable 파일 없으면 양호
#       존재 시 담당자가 설정 이유 인지 여부 확인 필요
# ────────────────────────────────────────────────────────────
check_U25() {
    local id="U-25" title="world writable 파일 점검"

    echo "       ※ world writable 파일 탐색 중 (시간 소요)..."

    # /proc, /sys 는 커널 가상 파일시스템으로, 내부의 world writable 항목은
    # 커널 인터페이스이지 관리자가 조치할 수 있는 실제 파일이 아님.
    # 포함 시 실제 파일 0개인 시스템도 수천 건 취약으로 오판(오탐)되므로 제외.
    # (실측: Rocky 10 기본 상태에서 /proc 6,453건 + /sys 7건 검출, 실제 파일시스템 0건)

    local ww_files=()
    while IFS= read -r line; do
        ww_files+=("$line")
    done < <(find / \( -path /proc -o -path /sys \) -prune -o \
             -type f -perm -2 -exec ls -l {} + 2>/dev/null)

    if [[ ${#ww_files[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "world writable 파일 없음"
    else
        result_fail "$id" "$title" \
            "world writable 파일 ${#ww_files[@]}개 발견 — 설정 이유 확인 및 불필요한 파일 제거 필요"
        print_evidence "$id" "${ww_files[@]}"
    fi
}
# 26/5/30 확인

# ────────────────────────────────────────────────────────────
# U-26 (상) /dev에 존재하지 않는 device 파일 점검
# 판단: /dev 내에 일반 파일(type f)이 존재하면 취약
#       mqueue, shm 하위는 정상이므로 제외
# ────────────────────────────────────────────────────────────
check_U26() {
    local id="U-26" title="/dev 내 불필요 일반 파일 존재 여부"

    echo "       ※ /dev 내 의심스러운 일반 파일 탐색 중..."

    local suspicious_list=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && suspicious_list+=("$line")
    done < <(find /dev -type f \
        -not -path "/dev/mqueue/*" \
        -not -path "/dev/shm/*" \
        -exec ls -al {} + 2>/dev/null)

    if [[ ${#suspicious_list[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "/dev 내 일반 파일 없음"
    else
        result_fail "$id" "$title" \
            "/dev 내 일반 파일 ${#suspicious_list[@]}개 발견 — 악의적인 파일 여부 확인 필요"
        print_evidence "$id" "${suspicious_list[@]}"
    fi
}
# 26/5/30 확인

# ────────────────────────────────────────────────────────────
# U-27 (상) $HOME/.rhosts, hosts.equiv 사용 금지
# 판단:
#   파일 존재 시: 소유자=root/계정, 권한<=600, '+' 설정 없어야 양호
#   r-command 비활성 + 파일 없음: 양호
# ────────────────────────────────────────────────────────────
check_U27() {
    local id="U-27" title=".rhosts / hosts.equiv 사용 금지"

    # r-command 서비스 활성화 여부 확인
    local rservice_active=false
    for svc in rlogin rsh rexec rsh.socket rlogin.socket; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            rservice_active=true
            break
        fi
    done

    local issues=()

    # /etc/hosts.equiv 점검
    if [[ -f /etc/hosts.equiv ]]; then
        local owner perm
        owner=$(get_owner /etc/hosts.equiv)
        perm=$(get_perm /etc/hosts.equiv)

        if [[ "$owner" != "root" ]] || ! perm_le "600" "$perm"; then
            issues+=("hosts.equiv [owner=${owner}, perm=${perm}]")
        fi
        # 주석(#) 제외 후 '+' 설정 검사
        if grep -v '^\s*#' /etc/hosts.equiv 2>/dev/null | grep -q '+'; then
            issues+=("hosts.equiv에 '+' 설정 존재")
        fi
    fi

    # 각 계정의 $HOME/.rhosts 점검
    # nologin/false 계정 제외: r-command 사용 불가 계정이므로 점검 불필요
    # 제외 해제 시: while IFS=: read -r user _ _ _ _ homedir _; do 로 변경
    while IFS=: read -r user _ _ _ _ homedir shell; do
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        [[ ! -d "$homedir" ]] && continue

        local rhost="${homedir}/.rhosts"
        [[ -f "$rhost" ]] || continue

        local owner perm
        owner=$(get_owner "$rhost")
        perm=$(get_perm "$rhost")

        if [[ "$owner" != "$user" && "$owner" != "root" ]] || ! perm_le "600" "$perm"; then
            issues+=("${user}/.rhosts [owner=${owner}, perm=${perm}]")
        fi

        # 주석(#) 제외 후 '+' 설정 검사
        if grep -v '^\s*#' "$rhost" 2>/dev/null | grep -q '+'; then
        #  grep -v : 주석 라인 제외, ^ : 행 시작, \s* : 공백 0개 이상, # : 주석
            issues+=("${user}/.rhosts에 '+' 설정 존재")
        fi
    done < /etc/passwd

    if [[ ${#issues[@]} -eq 0 ]]; then
        if $rservice_active; then
            if [[ ! -f /etc/hosts.equiv ]]; then
                result_pass "$id" "$title" \
                    "r-command 활성화, hosts.equiv 파일 없음 및 .rhosts 이상 없음"
            else
                result_pass "$id" "$title" \
                    "r-command 활성화, hosts.equiv 및 .rhosts 권한/설정 양호"
            fi
        else
            if [[ ! -f /etc/hosts.equiv ]]; then
                result_pass "$id" "$title" \
                    "r-command 비활성화, hosts.equiv 파일 없음 및 .rhosts 이상 없음"
            else
                result_pass "$id" "$title" \
                    "r-command 비활성화, hosts.equiv 및 .rhosts 권한/설정 양호"
            fi
        fi
    else
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    fi
}
# 26/6/1 확인

# ────────────────────────────────────────────────────────────
# U-28 (상) 접속 IP 및 포트 제한
# 판단: 방화벽/TCP Wrapper 활성화 여부 및 현재 정책 출력
#       실제 정책 적절성은 담당자 확인 필요
# ────────────────────────────────────────────────────────────
check_U28() {
    local id="U-28" title="접속 IP 및 포트 제한"

    local active_controls=()
    # ※ v2는 정책 내용을 콘솔에만 출력해 리포트에 남지 않았음
    #   → evidence 배열에 수집 후 판정 결과와 함께 리포트/증적 파일에 기록
    local policy=()

    # ※ 가이드 판단 기준은 "접속을 허용할 IP 주소 및 포트를 제한"이므로
    #   포트 제한(방화벽 가동)만으로는 기준을 충족하지 못함.
    #   v2/v3 초기 구현은 방화벽이 가동 중이기만 하면 양호로 판정했으나,
    #   출발지(sources/rich rule) 지정이 전혀 없으면 허용 서비스가 0.0.0.0/0에
    #   개방된 상태이므로 양호로 단정할 수 없음.
    #   다만 업무상 전체 개방이 필요한 서비스(http 등)가 있을 수 있어
    #   진단자가 취약으로 단정할 수도 없음 → 인터뷰(담당자 확인)로 분류
    local ip_restricted=false
    local ip_evidence=()

    # firewalld 확인 및 정책 수집
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        active_controls+=("firewalld")
        policy+=("[firewalld 현재 정책]")
        while IFS= read -r line; do
            [[ -n "$line" ]] && policy+=("| $line")
        done < <(firewall-cmd --list-all 2>/dev/null)

        # 활성 zone별 출발지 IP 제한(sources / source 지정 rich rule) 확인
        local z src rich
        while IFS= read -r z; do
            [[ -z "$z" ]] && continue
            src=$(firewall-cmd --zone="$z" --list-sources 2>/dev/null | tr -d '[:space:]')
            if [[ -n "$src" ]]; then
                ip_restricted=true
                ip_evidence+=("firewalld[${z}] sources=${src}")
            fi
            rich=$(firewall-cmd --zone="$z" --list-rich-rules 2>/dev/null | grep -c 'source' || true)
            if [[ "${rich:-0}" -gt 0 ]]; then
                ip_restricted=true
                ip_evidence+=("firewalld[${z}] source 지정 rich rule ${rich}건")
            fi
        done < <(firewall-cmd --get-active-zones 2>/dev/null | grep -vE '^[[:space:]]')
    fi

    # iptables 규칙 확인 및 수집
    # ※ Rocky 10의 firewalld는 nftables 백엔드를 사용하므로 firewalld 규칙은
    #   iptables 명령에 나타나지 않음 (iptables가 비어 있어도 방화벽 미설정이 아님)
    if iptables -L INPUT 2>/dev/null | grep -qv "^Chain\|^target\|^$"; then
        active_controls+=("iptables")
        policy+=("[iptables INPUT 체인 현재 정책]")
        while IFS= read -r line; do
            [[ -n "$line" ]] && policy+=("| $line")
        done < <(iptables -L INPUT --line-numbers 2>/dev/null)

        # source가 0.0.0.0/0(전체)이 아닌 규칙이 있으면 IP 제한 적용으로 인정
        local ipt_src
        ipt_src=$(iptables -L INPUT -n 2>/dev/null \
                  | awk 'NR>2 && $4 != "0.0.0.0/0" && $4 != "" {c++} END{print c+0}')
        if [[ "${ipt_src:-0}" -gt 0 ]]; then
            ip_restricted=true
            ip_evidence+=("iptables 출발지 지정 규칙 ${ipt_src}건")
        fi
    fi

    # TCP Wrapper 확인 및 수집
    if [[ -f /etc/hosts.deny || -f /etc/hosts.allow ]]; then
        active_controls+=("TCP Wrapper")
        policy+=("[TCP Wrapper 현재 설정]")
        local hf wrapper_lines=0
        for hf in /etc/hosts.deny /etc/hosts.allow; do
            [[ -f "$hf" ]] || continue
            policy+=("| [$(basename "$hf")]")
            while IFS= read -r line; do
                [[ -n "$line" ]] && policy+=("| $line") && wrapper_lines=$((wrapper_lines + 1))
            done < <(grep -v '^\s*#' "$hf" 2>/dev/null | grep -v '^\s*$')
        done
        # 주석/빈 줄을 제외한 유효 설정이 있어야 접근 제한 수단으로 인정
        if [[ "$wrapper_lines" -gt 0 ]]; then
            ip_restricted=true
            ip_evidence+=("TCP Wrapper 유효 설정 ${wrapper_lines}줄")
        fi
    fi

    # 최종 판정
    if [[ ${#active_controls[@]} -eq 0 ]]; then
        result_fail "$id" "$title" \
            "방화벽 및 TCP Wrapper 미설정 — IP/포트 제한 수단 없음"
    elif $ip_restricted; then
        result_pass "$id" "$title" \
            "$(join_by ', ' "${active_controls[@]}") 설정 및 출발지 IP 제한 적용 확인: $(join_by ', ' "${ip_evidence[@]}") — 정책 적정성은 아래 내용 확인"
    else
        result_interview "$id" "$title" \
            "$(join_by ', ' "${active_controls[@]}") 가동으로 포트는 제한되나 출발지 IP 제한(sources/rich rule) 미적용 — 허용 서비스가 전체(0.0.0.0/0) 개방 상태이므로 업무상 필요 여부 담당자 확인 필요"
    fi

    [[ ${#policy[@]} -gt 0 ]] && print_evidence "$id" "${policy[@]}"
}
#26/6/1 확인

# ────────────────────────────────────────────────────────────
# U-29 (하) hosts.lpd 파일 소유자 및 권한 설정
# 판단: 파일 없으면 양호, 있으면 root 소유 600 이하
# ────────────────────────────────────────────────────────────
check_U29() {
    local id="U-29" title="hosts.lpd 파일 소유자 및 권한 설정"
    local f="/etc/hosts.lpd"

    if [[ ! -f "$f" ]]; then
        result_pass "$id" "$title" "/etc/hosts.lpd 파일 없음 (양호)"
        return
    fi

    local owner perm
    owner=$(get_owner "$f")
    perm=$(get_perm "$f")

    if [[ "$owner" == "root" ]] && perm_le "600" "$perm"; then
        result_pass "$id" "$title" "[owner=${owner}, perm=${perm}]"
    else
        result_fail "$id" "$title" "[owner=${owner}, perm=${perm}] (root 소유, 600 이하 필요)"
    fi
}
#26/6/1 확인

# ────────────────────────────────────────────────────────────
# U-30 (중) UMASK 설정 관리
# 판단: UMASK >= 022 (group, other 쓰기 권한 차단)이면 양호
# ────────────────────────────────────────────────────────────
check_U30() {
    local id="U-30" title="UMASK 설정 관리"
    local issues=()
    local pass_list=()

    # group, other 자리가 각각 2 이상이면 양호 (쓰기 권한 차단)
    is_safe_umask() {
        local val
        val=$(echo "$1" | grep -o '[0-7]\+' | tail -n1)
        # grep -o : 숫자만 추출(8진수)
        # tail -n1 : 마지막 숫자(최종 umask 값) 가져오기
        # [0-7]\+ : 8진수 숫자 1개 이상 반복
        [[ -z "$val" ]] && return 1

        # 3자리로 정규화
        if   [[ ${#val} -eq 2 ]]; then val="0${val}"      # 2자리 → 앞에 0 추가 (22 → 022)
        elif [[ ${#val} -gt 3 ]]; then val="${val: -3}"    # 4자리 이상 → 뒤 3자리만 (0022 → 022)
        fi
        # ${#val} : val의 문자열 길이, -gt : 초과(greater than)

        local group_bit="${val:1:1}"   # 두 번째 자리 (group 권한)
        local other_bit="${val:2:1}"   # 세 번째 자리 (other 권한)
        # 종료코드로 반환: 0=양호, 1=취약
        # ※ 쓰기 차단 여부는 쓰기 비트(2)가 켜져 있는지로 판단해야 함
        #   "-ge 2" 비교는 umask 044(r만 차단, 쓰기 허용) 같은 값을 양호로 오판함
        [[ $((group_bit & 2)) -ne 0 && $((other_bit & 2)) -ne 0 ]]
    }

    # umask 값 추출 공통 함수
    # $1: 파일 경로, $2: grep 패턴 (어떤 라인을 볼지)
    # 함수 내부에서 주석 제거 및 숫자 추출까지 처리
    # ※ v2는 tail -n1로 "파일 내 마지막 값" 1개만 채택했으나, RHEL 계열
    #   /etc/profile·/etc/bashrc는 조건 분기로 umask를 2회 설정하므로
    #     if [ $UID -gt 199 ] && ... ; then umask 002 ; else umask 022 ; fi
    #   마지막 값(022)만 보면 일반 사용자 실효값 002(취약)를 놓침(미탐)
    #   → 설정된 모든 값을 추출해 하나라도 기준 미달이면 취약으로 판정
    extract_umask_all() {
        local file="$1" pattern="$2"
        grep -iE "$pattern" "$file" 2>/dev/null \
            | grep -v '^\s*#' \
            | grep -oE '[0-7]+'
    }

    # 파일 내 모든 umask 값을 판정해 pass_list/issues에 분류
    _judge_umask_file() {
        local file="$1" pattern="$2" label="$3" tag="$4"
        local vals v
        vals=$(extract_umask_all "$file" "$pattern")
        [[ -z "$vals" ]] && return
        while IFS= read -r v; do
            [[ -z "$v" ]] && continue
            if is_safe_umask "$v"; then
                pass_list+=("${label}(${v})")
            else
                issues+=("${label} [${tag}=${v}] — 022 이상 필요")
            fi
        done <<< "$vals"
    }

    # ── 1. 시스템 전역 파일 (우선순위 낮은 순으로 나열)
    local sys_files=(/etc/login.defs /etc/profile /etc/bash.bashrc /etc/bashrc)
    for f in /etc/profile.d/*.sh; do
        [[ -f "$f" ]] && sys_files+=("$f")
    done

    for file in "${sys_files[@]}"; do
        [[ -f "$file" ]] || continue
        _judge_umask_file "$file" '^\s*(UMASK|umask)' "$file" "UMASK"
    done

    # ── 2. 사용자별 환경파일
    # nologin/false 계정 제외: 로그인 불가 계정이므로 umask 적용 불필요
    # 제외 해제 시: while IFS=: read -r user _ _ _ _ homedir _; do 로 변경
    while IFS=: read -r user _ _ _ _ homedir shell; do
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        [[ ! -d "$homedir" ]] && continue

        for uf in .bashrc .bash_profile .profile .cshrc .kshrc; do
            local full="${homedir}/${uf}"
            [[ -f "$full" ]] || continue
            _judge_umask_file "$full" '^\s*umask' "${user}/${uf}" "UMASK"
        done
    done < /etc/passwd

    # ── 3. FTP 서비스 설정 파일
    local ftp_files=(
        /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf
        /etc/proftpd/proftpd.conf /etc/proftpd.conf
    )
    for ftp_conf in "${ftp_files[@]}"; do
        [[ -f "$ftp_conf" ]] || continue
        _judge_umask_file "$ftp_conf" '^\s*(local_umask|umask)' "$ftp_conf" "FTP_UMASK"
    done

    # ── 4. 설정 파일에서 umask를 찾지 못한 경우
    if [[ ${#issues[@]} -eq 0 && ${#pass_list[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "umask 설정 파일 없음 — 시스템 기본값 사용 중"
        return
    fi

    # ── 최종 판정
    if [[ ${#issues[@]} -eq 0 ]]; then
        result_pass "$id" "$title" \
            "모든 UMASK 설정 양호 ($(join_by ', ' "${pass_list[@]}"))"
    else
        result_fail "$id" "$title" \
            "취약 UMASK 설정 ${#issues[@]}개 발견: $(join_by '; ' "${issues[@]}")"
        print_evidence "$id" "${issues[@]}"
        [[ ${#pass_list[@]} -gt 0 ]] && \
            print_evidence "$id" "[참고] 기준 충족 설정: $(join_by ', ' "${pass_list[@]}")"
    fi
}
# 26/6/1 확인

# ────────────────────────────────────────────────────────────
# U-31 (중) 홈디렉토리 소유자 및 권한 설정
# 가이드 원문(상세가이드 p.65) 기준:
#   점검 목적 : "사용자 홈 디렉토리 내 설정 파일이 비인가자에 의한 변조를 방지"
#   판단 기준 : 양호 — 홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한 제거
#               취약 — 소유자가 해당 계정이 아니거나, 타 사용자 쓰기 권한 부여
#   조치 방법 : chown <사용자 이름> <사용자 홈 디렉토리> / chmod o-w
#   조치 시 영향: "일반적인 경우 영향 없음"
#
# 점검 대상 한정 근거:
#   가이드는 일관되게 "사용자 홈 디렉토리"를 대상으로 하며(U-32 참고란:
#   "홈 디렉토리: 사용자가 로그인한 후 작업을 수행하는 디렉토리",
#    "일반 사용자의 홈 디렉토리 위치: /home/<user 명>"),
#   시스템 계정(sync/halt/shutdown 등)의 홈으로 지정된 /sbin은 사용자가 작업하는
#   디렉토리가 아니라 시스템 바이너리 디렉터리이고 설정 파일도 존재하지 않는다.
#   또한 가이드의 조치 방법(chown sync /sbin, chmod o-w /sbin)을 적용하면
#   시스템이 손상되므로 "조치 시 영향 없음"이라는 전제와도 맞지 않는다.
#   → 점검 대상: UID>=1000 일반 사용자 + root + 홈이 /home 하위인 계정
#     (v2 및 v3 초기 구현은 nologin 여부로만 걸러 sync/halt/shutdown이 취약으로
#      잡혔으나, 이는 가이드 취지에 맞지 않는 오탐임)
# ────────────────────────────────────────────────────────────
check_U31() {
    local id="U-31" title="홈 디렉토리 소유자 및 권한 설정"

    local vuln_list=()

    while IFS=: read -r user _ uid _ _ homedir shell; do
        [[ ! "$uid" =~ ^[0-9]+$ ]] && continue
        [[ -z "$homedir" || "$homedir" == "/" ]] && continue

        # ── 점검 대상 판별 ──
        local target=false
        [[ "$user" == "root" ]] && target=true
        [[ "$uid" -ge 1000 && "$uid" -ne 65534 ]] && target=true
        # UID<1000이라도 홈이 /home 하위면 실사용 계정으로 보고 점검(미탐 방지)
        [[ "$homedir" == /home/* ]] && target=true
        $target || continue

        [[ -d "$homedir" ]] || continue

        # ── 심볼릭 링크 홈은 실제 대상 디렉터리 기준으로 판정 ──
        # stat은 링크 자체를 보므로 심볼릭 링크는 항상 777로 읽혀 오탐이 발생함
        # (예: /sbin -> usr/sbin 은 lrwxrwxrwx = 777, 실제 /usr/sbin은 root 755)
        local real_home note=""
        real_home=$(readlink -f "$homedir" 2>/dev/null)
        [[ -z "$real_home" ]] && real_home="$homedir"
        [[ "$real_home" != "$homedir" ]] && note=" → ${real_home}"

        local owner perm
        owner=$(get_owner "$real_home")
        perm=$(get_perm "$real_home")
        local other_bit="${perm: -1}"
        # ${perm: -1} : 권한의 마지막 자리(other 권한) 추출
        # [2367] : 쓰기(w) 권한이 포함된 8진수 숫자 (2=-w-, 3=-wx, 6=rw-, 7=rwx)

        # ※ v2는 홈 경로만 기록해 여러 계정이 같은 홈을 공유할 때
        #   동일 문구가 반복되고 어느 계정 문제인지 식별할 수 없었음 → 계정명 병기
        if [[ "$owner" != "$user" ]] || [[ "$other_bit" =~ [2367] ]]; then
            vuln_list+=("${user}: ${homedir}${note} [owner=${owner}, perm=${perm}]")
        fi
    done < /etc/passwd

    if [[ ${#vuln_list[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "모든 홈 디렉토리 소유자/권한 양호"
    else
        result_fail "$id" "$title" \
            "취약 홈 디렉토리 ${#vuln_list[@]}개 발견: $(join_by '; ' "${vuln_list[@]}")"
        print_evidence "$id" "${vuln_list[@]}"
    fi
}

# ────────────────────────────────────────────────────────────
# U-32 (중) 홈 디렉토리로 지정한 디렉토리 존재 관리
# 판단: /etc/passwd에 설정된 홈 디렉토리가 실제 존재하면 양호
# ────────────────────────────────────────────────────────────
check_U32() {
    local id="U-32" title="홈 디렉토리 실존 여부 관리"

    local missing=()

    # nologin/false 계정 제외: 실제 사용자 계정만 점검
    # 제외 해제 시: while IFS=: read -r user _ _ _ _ homedir _; do 로 변경
    while IFS=: read -r user _ _ _ _ homedir shell; do
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        [[ -z "$homedir" || "$homedir" == "/" ]] && continue

        [[ -d "$homedir" ]] || missing+=("${user} [홈=${homedir}]")
    done < /etc/passwd

    if [[ ${#missing[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "모든 계정의 홈 디렉토리 존재 확인"
    else
        result_fail "$id" "$title" \
            "홈 디렉토리 없는 계정 ${#missing[@]}개 발견: $(join_by '; ' "${missing[@]}")"
        print_evidence "$id" "${missing[@]}"
    fi
}

# ────────────────────────────────────────────────────────────
# U-33 (하) 숨겨진 파일 및 디렉토리 검색 및 제거
# 판단: 숨김 파일/디렉토리 목록 출력 후 담당자 확인 필요
#       의심 여부는 자동 판단 불가 → 인터뷰 필요 항목
# ────────────────────────────────────────────────────────────
check_U33() {
    local id="U-33" title="숨겨진 파일 및 디렉토리 검색"

    echo "       ※ 숨김 파일/디렉토리 탐색 중 (시간 소요)..."

    # KISA 가이드 기준 명령어
    # ! -name "." ! -name ".." : 현재/상위 디렉토리 제외
    # ※ v2는 개수 산정용 find 2회 + 목록 출력용 find 2회로 전체 파일시스템을
    #   4번 탐색했음 → 탐색 1회 결과를 배열에 담아 개수/목록에 함께 사용
    local hidden_files=() hidden_dirs=()

    while IFS= read -r line; do
        [[ -n "$line" ]] && hidden_files+=("$line")
    done < <(find / -type f -name ".*" ! -name "." ! -name ".." \
             -exec ls -l {} + 2>/dev/null)

    while IFS= read -r line; do
        [[ -n "$line" ]] && hidden_dirs+=("$line")
    done < <(find / -type d -name ".*" ! -name "." ! -name ".." \
             -exec ls -ld {} + 2>/dev/null)

    local file_count=${#hidden_files[@]}
    local dir_count=${#hidden_dirs[@]}
    local total=$(( file_count + dir_count ))

    if [[ "$total" -eq 0 ]]; then
        result_pass "$id" "$title" "숨김 파일 및 디렉토리 없음"
    else
        result_interview "$id" "$title" \
            "숨김 파일 ${file_count}개, 디렉토리 ${dir_count}개 발견 — 담당자 확인 필요"

        [[ $file_count -gt 0 ]] && print_evidence "$id" "[숨김 파일 목록]" "${hidden_files[@]}"
        [[ $dir_count  -gt 0 ]] && print_evidence "$id" "[숨김 디렉토리 목록]" "${hidden_dirs[@]}"
    fi
}
# 26/6/3 확인

# ────────────────────────────────────────────────────────────
# 파일 및 디렉토리 관리 전체 실행
# ────────────────────────────────────────────────────────────
run_file_checks() {
    print_section "2. 파일 및 디렉토리 관리 (U-14 ~ U-33)"
    check_U14
    check_U15
    check_U16
    check_U17
    check_U18
    check_U19
    check_U20
    check_U21
    check_U22
    check_U23
    check_U24
    check_U25
    check_U26
    check_U27
    check_U28
    check_U29
    check_U30
    check_U31
    check_U32
    check_U33
}
