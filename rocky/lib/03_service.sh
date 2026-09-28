#!/bin/bash
# 03_service.sh - 서비스 관리 진단 (U-34 ~ U-63)

# ────────────────────────────────────────────────────────────
# U-34: Finger 서비스 비활성화
# 판단: finger 서비스가 비활성화 상태이면 양호
# ────────────────────────────────────────────────────────────
check_U34() {
    local id="U-34" title="Finger 서비스 비활성화"

    # [inetd] /etc/inetd.conf 내 finger 항목 활성화 여부 확인
    if [[ -f /etc/inetd.conf ]]; then
        if grep -qE '^\s*finger' /etc/inetd.conf 2>/dev/null; then
            result_fail "$id" "$title" "/etc/inetd.conf finger 서비스 활성화됨"
            return
        fi
    fi

    # [xinetd] /etc/xinetd.d/finger 내 disable=yes 여부 확인
    if [[ -f /etc/xinetd.d/finger ]]; then
        if ! grep -qiE '^\s*disable\s*=\s*yes' /etc/xinetd.d/finger 2>/dev/null; then
            result_fail "$id" "$title" "/etc/xinetd.d/finger disable = yes 미설정"
            return
        fi
    fi

    # [systemd] finger.socket / finger 서비스 활성화 여부 확인
    # ※ KISA 가이드에는 inetd/xinetd만 명시되어 있으나, Rocky 10은 systemd socket
    #   방식으로 finger가 구동될 수 있어 이를 점검하지 않으면 미탐 발생
    #   (동일 성격의 U-52 Telnet 점검은 systemd를 포함하고 있어 기준 일관성 차원에서도 필요)
    local active=""
    for svc in finger.socket finger; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            active="$svc"
            break
        fi
    done

    # finger 데몬이 socket 등록 없이 직접 listen 중인 경우도 확인 (port 79)
    if [[ -z "$active" ]]; then
        if ss -tlnp 2>/dev/null | grep -qE ':79\b'; then
            active="port 79 (finger)"
        fi
    fi

    if [[ -n "$active" ]]; then
        result_fail "$id" "$title" "finger 서비스 활성화됨: ${active}"
        return
    fi

    result_pass "$id" "$title" "finger 서비스 비활성화"
}
# 26/6/4 완료

# ────────────────────────────────────────────────────────────
# U-35: 공유 서비스에 대한 익명 접근 제한
# 판단: 공유 서비스 익명 접근이 비활성화된 경우 양호
# ────────────────────────────────────────────────────────────
check_U35() {
    local id="U-35" title="공유 서비스에 대한 익명 접근 제한"
    local issues=()

    # ── 기본 FTP: /etc/passwd 내 ftp/anonymous 계정 존재 여부
    for user in ftp anonymous; do
        if grep -qE "^${user}:" /etc/passwd 2>/dev/null; then
            issues+=("기본FTP: ${user} 계정 존재")
        fi
    done

    # ── vsFTP: anonymous_enable=YES 여부
    local vsftpd_conf=""
    [[ -f /etc/vsftpd/vsftpd.conf ]] && vsftpd_conf="/etc/vsftpd/vsftpd.conf"
    [[ -f /etc/vsftpd.conf ]]         && vsftpd_conf="/etc/vsftpd.conf"
    if [[ -n "$vsftpd_conf" ]]; then
        local anon_val
        anon_val=$(grep -vE '^\s*#' "$vsftpd_conf" 2>/dev/null \
                   | grep -iE '^\s*anonymous_enable\s*=' \
                   | tail -1 \
                   | grep -oi 'YES\|NO')
        # 미설정 시 vsftpd 기본값은 YES
        if [[ -z "$anon_val" ]] || [[ "${anon_val^^}" == "YES" ]]; then
            issues+=("vsFTP: anonymous_enable=${anon_val:-미설정(기본 YES)}")
        fi
    fi

    # ── ProFTP: Anonymous 블록 내 User/UserAlias 설정 여부
    local proftpd_conf=""
    [[ -f /etc/proftpd/proftpd.conf ]] && proftpd_conf="/etc/proftpd/proftpd.conf"
    [[ -f /etc/proftpd.conf ]]          && proftpd_conf="/etc/proftpd.conf"
    if [[ -n "$proftpd_conf" ]]; then
        local anon_block
        anon_block=$(sed -n '/<Anonymous/,/<\/Anonymous>/p' "$proftpd_conf" 2>/dev/null \
                     | grep -v '^\s*#')
        if echo "$anon_block" | grep -qiE '^\s*(User|UserAlias)\s+'; then
            issues+=("ProFTP: Anonymous 블록 내 User/UserAlias 설정 존재")
        fi
    fi

    # ── NFS: /etc/exports 내 anonuid/anongid 옵션 존재 여부 (존재 자체가 취약)
    if [[ -f /etc/exports ]]; then
        if grep -vE '^\s*#' /etc/exports 2>/dev/null | grep -qE 'anonuid|anongid'; then
            issues+=("NFS: /etc/exports에 anonuid/anongid 옵션 설정")
        fi
    fi

    # ── Samba: guest ok = yes 여부 (# 및 ; 주석 제외)
    if [[ -f /etc/samba/smb.conf ]]; then
        if grep -vE '^\s*[#;]' /etc/samba/smb.conf 2>/dev/null \
           | grep -qiE '^\s*guest\s+ok\s*=\s*yes'; then
            issues+=("Samba: guest ok = yes 설정 존재")
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "공유 서비스 익명 접근 비활성화"
    fi
}
# 26/6/4 완료

# ────────────────────────────────────────────────────────────
# U-36: r-command 서비스 비활성화
# 판단: rlogin/rsh/rexec 서비스가 비활성화이면 양호
# ────────────────────────────────────────────────────────────
check_U36() {
    local id="U-36" title="r-command 서비스 비활성화"
    local active_svcs=()
    local trust_files=()
    local details=()

    # 1) inetd 기반 확인
    if [[ -f /etc/inetd.conf ]]; then
        local inetd_hits
        inetd_hits=$(grep -E '^\s*(shell|login|exec)\s' /etc/inetd.conf 2>/dev/null | grep -v '^\s*#')
        if [[ -n "$inetd_hits" ]]; then
            active_svcs+=("inetd(shell/login/exec)")
        fi
    fi

    # 2) xinetd 기반 확인
    if [[ -d /etc/xinetd.d ]]; then
        for f in /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec \
                  /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec; do
            [[ -f "$f" ]] || continue
            if grep -qiE '^\s*disable\s*=\s*no' "$f" 2>/dev/null; then
                active_svcs+=("xinetd($(basename "$f"))")
            fi
        done
    fi

    # 3) systemd 기반 확인
    local rcmds=(rlogin.socket rlogin rsh.socket rsh rexec.socket rexec
                  rsh-server rlogin-server)
    for svc in "${rcmds[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            active_svcs+=("$svc")
        fi
    done

    # 4) hosts.equiv / .rhosts 파일 존재 여부 확인
    # ※ set -u 환경에서 HOME 미설정 시 스크립트가 중단되므로 기본값 지정
    [[ -f /etc/hosts.equiv ]] && trust_files+=("/etc/hosts.equiv")
    [[ -f "${HOME:-/root}/.rhosts" ]] && trust_files+=("${HOME:-/root}/.rhosts")

    # 5) 판단
    if [[ ${#active_svcs[@]} -gt 0 ]]; then
        details+=("활성화된 r-command: $(join_by ', ' "${active_svcs[@]}")")
        if [[ ${#trust_files[@]} -gt 0 ]]; then
            details+=("신뢰 파일 존재(인증 우회 위험): $(join_by ', ' "${trust_files[@]}")")
        else
            details+=("hosts.equiv/.rhosts 미존재 (실사용 여부 담당자 인터뷰 필요)")
        fi
        result_fail "$id" "$title" "$(join_by '; ' "${details[@]}")"
    else
        result_pass "$id" "$title" "r-command 서비스 비활성화"
    fi
}
#26/6/6 완료

# ────────────────────────────────────────────────────────────
# U-37: crontab 파일 권한 설정
# 판단 기준:
#   - crontab/at 바이너리: root 소유, Others 실행권한 없음(750 이하)
#   - cron/at 관련 파일:   root 소유, 640 이하
#   - cron/at 관련 디렉터리: root 소유, 750 이하
# ────────────────────────────────────────────────────────────
check_U37() {
    local id="U-37" title="crontab 파일 권한 설정"
    local issues=()

    # ── Step 3 대상: 바이너리 (750 이하, Others 실행권한 없음) ──
    local bins=()
    local cb at_bin
    cb=$(command -v crontab 2>/dev/null)
    at_bin=$(command -v at 2>/dev/null)
    [[ -n "$cb" ]]     && bins+=("$cb")
    # -n : 빈 문자열이 아닌 경우 참 (즉, crontab 명령이 존재할 때 추가)
    [[ -n "$at_bin" ]] && bins+=("$at_bin")

    for bin in "${bins[@]}"; do
        local perm owner
        perm=$(get_perm "$bin")
        owner=$(get_owner "$bin")

        [[ "$owner" != "root" ]] && issues+=("${bin} 소유자: ${owner}(root 아님)")

        # Others 자리(마지막 자리)가 0이어야 양호 (SUID 유지 허용)
        if [[ ! "$perm" =~ [0-9][0-9]0$ ]]; then
            issues+=("${bin} 권한: ${perm}(Others 실행권한 차단 필요, 750 이하)")
        fi
    done

    # ── Step 4 대상: 단일 파일 (640 이하) ──
    local cron_files=(
        /etc/crontab
        /etc/cron.allow
        /etc/cron.deny
        /etc/at.allow
        /etc/at.deny
    )
    for f in "${cron_files[@]}"; do
        [[ -f "$f" ]] || continue
        local p o
        p=$(get_perm "$f")
        o=$(get_owner "$f")
        [[ "$o" != "root" ]] && issues+=("${f} 소유자: ${o}(root 아님)")
        perm_le 640 "$p" || issues+=("${f} 파일 권한: ${p}(640 초과)")
    done

    # ── Step 4 대상: 디렉터리 + 하위 파일 동적 탐색 ──
    # 디렉터리 자체: 750 이하 / 하위 파일: 640 이하
    local cron_dirs=(
        /etc/cron.hourly
        /etc/cron.daily
        /etc/cron.weekly
        /etc/cron.monthly
        /etc/cron.d
        /var/spool/cron
        /var/spool/cron/crontabs
        /var/spool/at
        /var/spool/cron/atjobs
    )
    for dir in "${cron_dirs[@]}"; do
        [[ -d "$dir" ]] || continue

        # 디렉터리 자체 권한 (750 이하)
        local dp do_
        dp=$(get_perm "$dir")
        do_=$(get_owner "$dir")
        [[ "$do_" != "root" ]] && issues+=("${dir} 소유자: ${do_}(root 아님)")
        perm_le 750 "$dp" || issues+=("${dir} 디렉터리 권한: ${dp}(750 초과)")

        # 하위 파일 동적 탐색 (640 이하)
        while IFS= read -r -d '' f; do
            local p o
            p=$(get_perm "$f")
            o=$(get_owner "$f")
            [[ "$o" != "root" ]] && issues+=("${f} 소유자: ${o}(root 아님)")
            perm_le 640 "$p" || issues+=("${f} 파일 권한: ${p}(640 초과)")
        done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null)
    done

    # ── 판단 ──
    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "crontab/at 권한 및 소유자 설정 양호"
    fi
}
# 26/6/6 완료

# ────────────────────────────────────────────────────────────
# U-38: DoS 유발 서비스 비활성화
# 판단: echo/discard/daytime/chargen/ntp/dns/snmp/smtp
#       서비스가 비활성화이면 양호
# ※ chronyd/postfix 등 업무 필수 서비스 포함 시 담당자 인터뷰 필요
# ────────────────────────────────────────────────────────────
check_U38() {
    local id="U-38" title="DoS 유발 서비스 비활성화"
    local active_svcs=()

    # 1) inetd 기반 확인
    if [[ -f /etc/inetd.conf ]]; then
        local inetd_hits
        inetd_hits=$(grep -E '^\s*(echo|discard|daytime|chargen)\s' \
                     /etc/inetd.conf 2>/dev/null | grep -v '^\s*#')
        [[ -n "$inetd_hits" ]] && active_svcs+=("inetd(echo/discard/daytime/chargen)")
    fi

    # 2) xinetd 기반 확인
    if [[ -d /etc/xinetd.d ]]; then
        for svc in echo discard daytime chargen; do
            local f="/etc/xinetd.d/${svc}"
            [[ -f "$f" ]] || continue
            if grep -qiE '^\s*disable\s*=\s*no' "$f" 2>/dev/null || \
               ! grep -q 'disable' "$f" 2>/dev/null; then
                active_svcs+=("xinetd(${svc})")
            fi
        done
    fi

    # 3) systemd 기반 확인 (active 또는 enabled 모두 취약)
    local dos_svcs=(
        # echo/discard/daytime/chargen
        echo.socket echo-dgram.socket echo-stream.socket
        discard.socket discard-dgram.socket discard-stream.socket
        daytime.socket daytime-dgram.socket daytime-stream.socket
        chargen.socket chargen-dgram.socket chargen-stream.socket
        # NTP (Rocky Linux 10: chronyd가 기본)
        ntp.service chronyd.service
        # DNS
        named.service dnsmasq.service
        # SNMP
        snmpd.service
        # SMTP
        postfix.service sendmail.service exim.service
    )

    for svc in "${dos_svcs[@]}"; do
        local state=""
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            state="active"
        else
            # ※ systemctl is-enabled --quiet 는 static/indirect/generated 유닛에도
            #   exit 0을 반환하므로 v2 방식은 자동실행 설정이 아닌 유닛까지
            #   취약으로 집계될 수 있었음(과탐) → 출력 문자열로 enabled 계열만 선별
            local en
            en=$(systemctl is-enabled "$svc" 2>/dev/null)
            case "$en" in
                (enabled|enabled-runtime) state="$en" ;;
            esac
        fi
        [[ -n "$state" ]] && active_svcs+=("${svc}(${state})")
    done

    if [[ ${#active_svcs[@]} -gt 0 ]]; then
        # ※ chronyd(U-65 시각 동기화), postfix 등은 업무상 필수인 경우가 많으며
        #   U-65는 chronyd 활성화를 양호 조건으로 판정하므로 상충이 발생함.
        #   가이드 판단 기준(해당 서비스 구동 = 취약)은 그대로 유지하되,
        #   운영 필요성은 담당자 인터뷰로 확인하도록 안내 문구를 함께 기록
        result_fail "$id" "$title" \
            "활성화(또는 자동실행)된 DoS 유발 서비스: $(join_by ', ' "${active_svcs[@]}") — 업무상 필수 서비스(chronyd/postfix 등) 여부는 담당자 확인 필요"
    else
        result_pass "$id" "$title" \
            "DoS 유발 서비스(echo/discard/daytime/chargen/ntp/dns/snmp/smtp) 비활성화"
    fi
}
# 26/6/6 완료

# ────────────────────────────────────────────────────────────
# U-39: NFS 서비스 비활성화
# 판단: NFS 관련 서비스가 비활성화이면 양호
# ※ NFS 사용 중인 경우 담당자 인터뷰 후 U-40 항목 조치 여부 확인
# ────────────────────────────────────────────────────────────
check_U39() {
    local id="U-39" title="NFS 서비스 비활성화"
    # ※ declare -A seen 처럼 초기화 없이 선언하면 "선언만 되고 unset" 상태라
    #   set -u 환경에서 참조 시 unbound variable 오류 발생 가능 → =() 필수
    declare -A seen=()
    local active_svcs=()

    # 1) 현재 active 상태인 NFS 서비스 수집
    #    .service$로 필터링하여 systemctl 하단 안내 문구 제거
    while IFS= read -r svc; do
        [[ -n "$svc" ]] && seen["$svc"]=1 && active_svcs+=("$svc")
    done < <(systemctl list-units --type=service --state=active 2>/dev/null \
             | awk '{print $1}' \
             | grep -i 'nfs' \
             | grep '\.service$')

    # 2) enabled(자동실행) 상태인 NFS 서비스 수집 (associative array로 중복 제거)
    while IFS= read -r svc; do
        [[ -n "$svc" && -z "${seen[$svc]:-}" ]] && seen["$svc"]=1 && active_svcs+=("$svc")
        # ${seen[$svc]:-} : 키가 없을 때 set -u 오류 대신 빈 문자열 반환
    done < <(systemctl list-unit-files --type=service --state=enabled 2>/dev/null \
             | awk '{print $1}' \
             | grep -i 'nfs' \
             | grep '\.service$')

    # 3) 판정
    if [[ ${#active_svcs[@]} -gt 0 ]]; then
        local detail
        detail="활성화된 NFS 서비스: $(join_by ', ' "${active_svcs[@]}")"

        if [[ -s /etc/exports ]]; then
            local exported
            exported=$(grep -cvE '^\s*#|^\s*$' /etc/exports 2>/dev/null)
            [[ "$exported" -gt 0 ]] && \
                detail+="; /etc/exports ${exported}개 공유 설정 존재 (U-40 조치 필요)"
        fi

        result_interview "$id" "$title" "$detail"
    else
        result_pass "$id" "$title" "NFS 서비스 비활성화"
    fi
}
# 26/6/6 완료

# ────────────────────────────────────────────────────────────
# U-40: NFS 접근 제한
# 판단: /etc/exports 파일 root 소유+644 이하, 전역 허용 미사용
# ────────────────────────────────────────────────────────────
check_U40() {
    local id="U-40" title="NFS 접근 제한"
    local issues=()
    local warn_items=()

    # NFS 서비스 활성화 여부 확인
    if ! systemctl is-active --quiet nfs-server 2>/dev/null && \
       ! systemctl is-active --quiet nfs 2>/dev/null; then
        result_na "$id" "$title" "NFS 서비스 미사용"
        return
    fi

    # /etc/exports 파일 존재 여부 확인
    if [[ ! -f /etc/exports ]]; then
        result_fail "$id" "$title" "/etc/exports 파일 없음"
        return
    fi

    # 파일 권한/소유자 확인
    local perm owner
    perm=$(get_perm /etc/exports)
    owner=$(get_owner /etc/exports)

    if [[ "$owner" != "root" ]]; then
        issues+=("소유자: ${owner}(root 아님)")
    fi
    if ! perm_le 644 "$perm"; then
        issues+=("권한: ${perm}(644 초과)")
    fi

    local exports_content
    exports_content=$(grep -vE '^\s*#' /etc/exports)

    if [[ -n "$exports_content" ]]; then

        # 1) 와일드카드(*) 호스트 허용 검사
        #    예: /share *(rw,sync) / /share *.example.com(ro) / /share host1(rw) *(ro)
        # ※ v2는 '^\s*/\S+\s+\*' 패턴으로 "첫 번째 호스트"만 검사해
        #   /data 192.168.0.0/24(rw) *(ro) 처럼 두 번째 이후 항목의 와일드카드를
        #   놓쳤음(미탐) → 경로($1)를 제외한 모든 호스트 필드에서 '*' 탐지
        local wildcard_lines
        wildcard_lines=$(echo "$exports_content" \
                         | awk '{for(i=2;i<=NF;i++) if ($i ~ /\*/) {print; break}}' \
                         | tr '\n' ' ')
        if [[ -n "$wildcard_lines" ]]; then
            issues+=("와일드카드(*) 호스트 허용 설정 존재: ${wildcard_lines% }")
        fi

        # 2) 호스트명 생략 검사 → 전체 호스트 허용으로 동작
        #    예: /share (rw,sync) — 호스트 없이 바로 괄호 옵션
        # ※ grep -P(PCRE)는 로케일이 UTF-8/단일바이트가 아니면 실행 자체가 실패해
        #   점검이 조용히 건너뛰어질 수 있음(미탐) → POSIX 확장정규식(-E)으로 대체
        if echo "$exports_content" | grep -qE '^[[:space:]]*/[^[:space:]]+[[:space:]]*\('; then
            issues+=("호스트 지정 없이 옵션만 설정 (전체 호스트 허용)")
        fi

        # 3) 전체 네트워크 대역 허용 검사
        #    예: /share 0.0.0.0/0(rw)
        if echo "$exports_content" | grep -qE '0\.0\.0\.0(/0)?'; then
            issues+=("전체 네트워크 대역(0.0.0.0/0) 허용 설정 존재")
        fi
    fi

    # 판정 및 결과 출력
    if [[ ${#issues[@]} -gt 0 ]]; then
        local msg
        msg="$(join_by '; ' "${issues[@]}")"
        if [[ ${#warn_items[@]} -gt 0 ]]; then
            msg+=" | 참고: $(join_by '; ' "${warn_items[@]}")"
        fi
        result_fail "$id" "$title" "$msg"
    else
        local pass_msg="/etc/exports 권한 양호, 전역 허용 미설정"
        if [[ ${#warn_items[@]} -gt 0 ]]; then
            pass_msg+=" | 참고: $(join_by '; ' "${warn_items[@]}")"
        fi
        result_pass "$id" "$title" "$pass_msg"
    fi
}
# 26/6/7 완료 - 수정필요

# ────────────────────────────────────────────────────────────
# U-41: automountd 비활성화
# 판단: autofs 서비스가 비활성화이면 양호
# ────────────────────────────────────────────────────────────
check_U41() {
    local id="U-41" title="automountd 비활성화"

    if systemctl is-active --quiet autofs 2>/dev/null; then
        result_fail "$id" "$title" "autofs 서비스 활성화 상태"
    else
        result_pass "$id" "$title" "autofs 서비스 비활성화"
    fi
}
# 26/6/7 완료

check_U42() {
    local id="U-42" title="불필요한 RPC 서비스 비활성화"
    local active_svcs=()

    # KISA 가이드 명시 불필요 RPC 서비스 목록
    local rpc_svcs=(
        "rpc.cmsd:rpc-cmsd"
        "rpc.ttdbserverd:rpc-ttdbserverd"
        "sadmind:sadmind"
        "rstatd:rstatd"
        "rusersd:rpc-rusersd"
        "rwalld:rpc-rwalld"
        "sprayd:rpc-sprayd"
        "rpc.nisd:rpc-nisd"
        "rexd:rpc-rexd"
        "rpc.pcnfsd:rpc-pcnfsd"
        "rpc.statd:rpc-statd"
        "rpc.ypupdated:rpc-ypupdated"
        "rpc.rquotad:rpc-rquotad"
        "kcms_server:kcms_server"
        "cachefsd:cachefsd"
    )

    # 1) systemctl 및 프로세스 확인
    for entry in "${rpc_svcs[@]}"; do
        local proc_name="${entry%%:*}"   # : 앞 = 프로세스명
        local svc_name="${entry##*:}"    # : 뒤 = systemctl 서비스명

        if systemctl is-active --quiet "${svc_name}.service" 2>/dev/null; then
            active_svcs+=("${proc_name}(systemctl)")
            continue
        fi
        if pgrep -x "$proc_name" > /dev/null 2>&1; then
            active_svcs+=("${proc_name}(process)")
        fi
    done

    # 2) inetd.conf 확인
    if [[ -f /etc/inetd.conf ]]; then
        local inetd_hits
        inetd_hits=$(grep -vE '^\s*#' /etc/inetd.conf | \
                     grep -E 'rpc\.cmsd|ttdbserverd|sadmind|rstatd|rusersd|walld|sprayd|rexd|pcnfsd|rquotad')
        if [[ -n "$inetd_hits" ]]; then
            active_svcs+=("inetd.conf 내 RPC 서비스 활성화")
        fi
    fi

    # 3) xinetd.d 확인
    if [[ -d /etc/xinetd.d ]]; then
        local xinetd_hits
        xinetd_hits=$(grep -rlE 'rpc\.cmsd|ttdbserverd|sadmind|rstatd|rusersd|walld|sprayd|rexd|pcnfsd|rquotad' \
                      /etc/xinetd.d/ 2>/dev/null | xargs grep -l 'disable\s*=\s*no' 2>/dev/null)
        if [[ -n "$xinetd_hits" ]]; then
            active_svcs+=("xinetd.d 내 RPC 서비스 활성화: $(basename -a $xinetd_hits | tr '\n' ' ')")
        fi
    fi

    if [[ ${#active_svcs[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "활성화된 RPC: $(join_by ', ' "${active_svcs[@]}")"
    else
        result_pass "$id" "$title" "불필요한 RPC 서비스 비활성화"
    fi
}
# 26/6/7 완료

# ────────────────────────────────────────────────────────────
# U-43: NIS/NIS+ 서비스 비활성화
# 판단기준
#   양호: NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우
#   취약: NIS 서비스가 활성화된 경우
# ────────────────────────────────────────────────────────────
check_U43() {
    local id="U-43" title="NIS/NIS+ 서비스 비활성화"
    declare -A detected=()
    # =() 초기화 필수: 미초기화 시 set -u 환경에서 ${#detected[@]} 참조 오류로 종료됨

    # systemctl 서비스명
    local svc_names=(ypserv ypbind yppasswdd ypxfrd rpc.ypupdated)

    # 실제 데몬 프로세스명
    local proc_names=(ypserv ypbind rpc.yppasswdd ypxfrd rpc.ypupdated)

    # Step 1) systemctl 기반 활성화 여부 확인 (독립 실행)
    for svc in "${svc_names[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            detected["$svc"]="service"
        fi
    done

    # Step 2) 프로세스 직접 확인 (독립 실행 — 수동 구동 데몬 탐지)
    for proc in "${proc_names[@]}"; do
        if pgrep -x "$proc" > /dev/null 2>&1; then
            if [[ -v detected["$proc"] ]]; then
                detected["$proc"]="service+process"
            else
                detected["$proc"]="process"
            fi
        fi
    done

    if [[ ${#detected[@]} -gt 0 ]]; then
        local found_list=""
        for key in "${!detected[@]}"; do
            found_list+="${key}(${detected[$key]}), "
        done
        found_list="${found_list%, }"  # 후행 쉼표 제거
        result_fail "$id" "$title" \
            "NIS 관련 서비스 활성화 발견: ${found_list}"
    else
        result_pass "$id" "$title" \
            "NIS/NIS+ 서비스 비활성화 확인 (RHEL 8+의 경우 패키지 자체 제거됨)"
    fi
}
# 26/6/8 완료

# ────────────────────────────────────────────────────────────
# U-44: tftp/talk 서비스 비활성화
# 판단기준
#   양호: tftp, talk, ntalk 서비스가 비활성화된 경우
#   취약: tftp, talk, ntalk 서비스가 활성화된 경우
# ────────────────────────────────────────────────────────────
check_U44() {
    local id="U-44" title="tftp/talk 서비스 비활성화"
    local findings=()

    # Step 1) systemctl 동적 탐지 (KISA 가이드: systemd 환경)
    while IFS= read -r svc; do
        findings+=("${svc}(systemctl)")
    done < <(systemctl list-units --type=service --state=active 2>/dev/null \
             | awk '{print $1}' \
             | grep -E "(tftp|talk|ntalk)")

    # Step 2) inetd.conf 확인 (KISA 가이드: inetd 환경)
    if [[ -f /etc/inetd.conf ]]; then
        local inetd_hits
        inetd_hits=$(grep -E "^\s*(tftp|talk|ntalk)\b" /etc/inetd.conf 2>/dev/null)
        if [[ -n "$inetd_hits" ]]; then
            findings+=("inetd.conf(inetd)")
        fi
    fi

    # Step 3) xinetd 설정 확인 (KISA 가이드: xinetd 환경)
    local xinetd_files=()
    [[ -f /etc/xinetd.conf ]] && xinetd_files+=("/etc/xinetd.conf")
    if [[ -d /etc/xinetd.d ]]; then
        while IFS= read -r -d '' f; do
            xinetd_files+=("$f")
        done < <(find /etc/xinetd.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi

    if [[ ${#xinetd_files[@]} -gt 0 ]]; then
        local xinetd_hit
        xinetd_hit=$(awk '
            /^[[:space:]]*#/ { next }
            /service[[:space:]]+(tftp|talk|ntalk)[[:space:]]*(\{)?/ {
                match($0, /service[[:space:]]+([a-z]+)/, arr)
                in_block = arr[1]
                depth = 0
            }
            in_block {
                n = split($0, chars, "")
                for (i = 1; i <= n; i++) {
                    if (chars[i] == "{") depth++
                    if (chars[i] == "}") { depth--; if (depth <= 0) in_block = "" }
                }
            }
            in_block && /disable[[:space:]]*=[[:space:]]*no/ { print in_block }
            ENDFILE { in_block = ""; depth = 0 }
        ' "${xinetd_files[@]}" 2>/dev/null)

        if [[ -n "$xinetd_hit" ]]; then
            while IFS= read -r svc_name; do
                [[ -n "$svc_name" ]] && findings+=("${svc_name}(xinetd)")
            done <<< "$xinetd_hit"
        fi
    fi

    if [[ ${#findings[@]} -gt 0 ]]; then
        result_fail "$id" "$title" \
            "활성화된 항목 발견: $(join_by ', ' "${findings[@]}")"
    else
        result_pass "$id" "$title" \
            "tftp/talk/ntalk 서비스 비활성화 확인"
    fi
}
# 26/6/8 완료

# ────────────────────────────────────────────────────────────
# U-45: 메일 서비스 버전 점검
# 판단기준
#   양호: 메일 서비스 버전이 최신 버전인 경우
#   취약: 메일 서비스 버전이 최신 버전이 아닌 경우
# ────────────────────────────────────────────────────────────
check_U45() {
    local id="U-45" title="메일 서비스 버전 점검"
    local details=()

    # Step 1) 실행 중인 메일 서비스 확인 (KISA 가이드: systemctl list-units)
    local active_mail
    active_mail=$(systemctl list-units --type=service --state=active 2>/dev/null \
                  | awk '{print $1}' \
                  | grep -E "(sendmail|postfix|exim)")

    if [[ -z "$active_mail" ]]; then
        result_pass "$id" "$title" "메일 서비스(Sendmail, Postfix, Exim) 미실행"
        return
    fi

    # Step 2) Sendmail 버전 확인 (KISA 가이드: sendmail -d0 -bt)
    if echo "$active_mail" | grep -q "sendmail"; then
        local sm_ver
        sm_ver=$(sendmail -d0 -bt < /dev/null 2>&1 \
                 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?[-_a-zA-Z0-9.]*' | head -1)
        details+=("sendmail: ${sm_ver:-버전확인불가}")
    fi

    # Step 3) Postfix 버전 확인 (KISA 가이드: postconf mail_version)
    if echo "$active_mail" | grep -q "postfix"; then
        local pf_ver
        pf_ver=$(postconf -h mail_version 2>/dev/null)
        [[ -z "$pf_ver" ]] && \
            pf_ver=$(postconf mail_version 2>/dev/null | awk '{print $3}')
        details+=("postfix: ${pf_ver:-버전확인불가}")
    fi

    # Step 4) Exim 버전 확인 (KISA 가이드: exim -bV)
    if echo "$active_mail" | grep -q "exim"; then
        local exim_ver
        exim_ver=$(exim -bV 2>&1 \
                   | grep -oE '[0-9]+\.[0-9]+[-_a-zA-Z0-9.]*' | head -1)
        details+=("exim: ${exim_ver:-버전확인불가}")
    fi

    result_interview "$id" "$title" \
        "실행 중인 메일 서비스: $(join_by ', ' "${details[@]}") — 최신 보안 패치 적용 여부 인터뷰 필요"
}
# 26/6/8 완료

# ────────────────────────────────────────────────────────────
# U-46: 일반 사용자의 메일 서비스 실행 방지
# 판단기준
#   양호: 일반 사용자의 메일 서비스 실행 방지가 설정된 경우
#   취약: 일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않은 경우
# ────────────────────────────────────────────────────────────
check_U46() {
    local id="U-46" title="일반 사용자의 메일 서비스 실행 방지"
    local issues=()

    # Step 1) 실행 중인 메일 서비스 확인
    local active_mail
    active_mail=$(systemctl list-units --type=service --state=active 2>/dev/null \
                  | awk '{print $1}' \
                  | grep -E "(sendmail|postfix|exim)")

    # 서비스 미실행 시 공격 벡터 없음 → 양호
    if [[ -z "$active_mail" ]]; then
        result_pass "$id" "$title" "메일 서비스 미실행"
        return
    fi

    # ── Sendmail: PrivacyOptions restrictqrun 확인 ──
    if echo "$active_mail" | grep -q "sendmail"; then
        local sm_conf=""
        for f in /etc/mail/sendmail.cf /etc/sendmail.cf; do
            [[ -f "$f" ]] && sm_conf="$f" && break
        done

        if [[ -z "$sm_conf" ]]; then
            issues+=("sendmail: sendmail.cf 파일 미발견")
        else
            local privacy
            privacy=$(grep -E '^[[:space:]]*O[[:space:]]+PrivacyOptions[[:space:]]*=' \
                      "$sm_conf" 2>/dev/null | tail -1)
            if [[ -z "$privacy" ]]; then
                issues+=("sendmail: PrivacyOptions 미설정")
            elif ! echo "$privacy" | grep -qi 'restrictqrun'; then
                issues+=("sendmail: PrivacyOptions에 restrictqrun 없음 (현재: ${privacy})")
            fi
        fi
    fi

    # ── Postfix: /usr/sbin/postsuper others 실행 권한 확인 ──
    if echo "$active_mail" | grep -q "postfix"; then
        local postsuper_path="/usr/sbin/postsuper"
        if [[ -f "$postsuper_path" ]]; then
            local perms
            perms=$(stat -L -c "%A" "$postsuper_path" 2>/dev/null)
            # ※ v2는 '......[r-][w-][x]' 정규식(앵커 없음)으로 판정해 SELinux 접미사
            #   ('.', '+')가 붙으면 매칭 위치가 흔들릴 수 있었음
            #   → 심볼릭 표기 10번째 문자(others 실행 비트)를 인덱스로 직접 판정
            if [[ "${perms:9:1}" =~ [xt] ]]; then
                issues+=("postfix: postsuper 일반 사용자 실행 권한 존재 (현재: $perms)")
            fi
        else
            issues+=("postfix: postsuper 파일 미발견 ($postsuper_path)")
        fi
    fi

    # ── Exim: /usr/sbin/exiqgrep others 실행 권한 확인 ──
    if echo "$active_mail" | grep -q "exim"; then
        local exiqgrep_path="/usr/sbin/exiqgrep"
        if [[ -f "$exiqgrep_path" ]]; then
            local perms
            perms=$(stat -L -c "%A" "$exiqgrep_path" 2>/dev/null)
            if [[ "${perms:9:1}" =~ [xt] ]]; then
                issues+=("exim: exiqgrep 일반 사용자 실행 권한 존재 (현재: $perms)")
            fi
        else
            issues+=("exim: exiqgrep 파일 미발견 ($exiqgrep_path)")
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "일반 사용자 메일 서비스 실행 방지 설정 양호"
    fi
}
# 26/6/8 완료

# ────────────────────────────────────────────────────────────
# U-47: 스팸 메일 릴레이 제한
# 판단기준
#   양호: 릴레이 제한이 설정된 경우
#   취약: 릴레이 제한이 설정되어 있지 않은 경우
# ────────────────────────────────────────────────────────────
check_U47() {
    local id="U-47" title="스팸 메일 릴레이 제한"
    local issues=()

    # Step 1) 실행 중인 메일 서비스 확인
    local active_mail
    active_mail=$(systemctl list-units --type=service --state=active 2>/dev/null \
                  | awk '{print $1}' \
                  | grep -E "(sendmail|postfix|exim)")

    # 서비스 미실행 시 양호
    if [[ -z "$active_mail" ]]; then
        result_pass "$id" "$title" "메일 서비스 미실행"
        return
    fi

    # ── Sendmail 점검 ──
    if echo "$active_mail" | grep -q "sendmail"; then

        # promiscuous_relay 설정 존재 시 취약
        if [[ -f /etc/mail/sendmail.mc ]]; then
            if grep -qE '^\s*FEATURE\(`?promiscuous_relay' \
               /etc/mail/sendmail.mc 2>/dev/null; then
                issues+=("sendmail: sendmail.mc에 promiscuous_relay 설정 존재")
            fi
        fi

        # /etc/mail/access 파일 존재 여부 확인
        if [[ ! -f /etc/mail/access ]]; then
            issues+=("sendmail: /etc/mail/access 파일 미존재")
        fi
    fi

    # ── Postfix 점검 ──
    if echo "$active_mail" | grep -q "postfix"; then
        local pf_cf="/etc/postfix/main.cf"
        if [[ -f "$pf_cf" ]]; then
            local pf_active
            pf_active=$(grep -vE '^\s*#' "$pf_cf" 2>/dev/null)
            # grep -v : verbose 옵션으로 주석과 빈 줄 제거

            # mynetworks 설정 존재 여부 확인
            if ! echo "$pf_active" | grep -qE '^\s*mynetworks\s*='; then
                issues+=("postfix: mynetworks 미설정")
            fi

            # smtpd_recipient_restrictions 설정 존재 여부 확인
            if ! echo "$pf_active" | grep -qE '^\s*smtpd_recipient_restrictions'; then
                issues+=("postfix: smtpd_recipient_restrictions 미설정")
            fi
        else
            issues+=("postfix: /etc/postfix/main.cf 파일 미발견")
        fi
    fi

    # ── Exim 점검 ──
    if echo "$active_mail" | grep -q "exim"; then
        local exim_cf=""
        for f in /etc/exim/exim.conf /etc/exim4/exim4.conf; do
            [[ -f "$f" ]] && exim_cf="$f" && break
        done

        if [[ -z "$exim_cf" ]]; then
            issues+=("exim: exim.conf 파일 미발견")
        else
            local exim_active
            exim_active=$(grep -vE '^\s*#|^\s*$' "$exim_cf" 2>/dev/null)

            # relay_from_hosts 또는 hosts 설정 존재 여부 확인
            if ! echo "$exim_active" | grep -qE 'relay_from_hosts|hosts\s*='; then
                issues+=("exim: relay_from_hosts 릴레이 제한 설정 미확인")
            fi
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "스팸 메일 릴레이 제한 설정 양호"
    fi
}

# ────────────────────────────────────────────────────────────
# U-48: expn/vrfy 명령어 제한
# 판단기준
#   양호: noexpn, novrfy 옵션이 설정된 경우
#   취약: noexpn, novrfy 옵션이 설정되어 있지 않은 경우
# ────────────────────────────────────────────────────────────
check_U48() {
    local id="U-48" title="expn/vrfy 명령어 제한"
    local issues=()

    # Step 1) 실행 중인 메일 서비스 확인
    local active_mail
    active_mail=$(systemctl list-units --type=service --state=active 2>/dev/null \
                  | awk '{print $1}' \
                  | grep -E "(sendmail|postfix|exim)")

    # 서비스 미실행 시 양호
    if [[ -z "$active_mail" ]]; then
        result_pass "$id" "$title" "메일 서비스 미실행"
        return
    fi

    # ── Sendmail: PrivacyOptions noexpn/novrfy 또는 goaway 확인 ──
    if echo "$active_mail" | grep -q "sendmail"; then
        local sm_conf=""
        for f in /etc/mail/sendmail.cf /etc/sendmail.cf; do
            [[ -f "$f" ]] && sm_conf="$f" && break
        done

        if [[ -z "$sm_conf" ]]; then
            issues+=("sendmail: sendmail.cf 파일 미발견")
        else
            # 주석 제외 후 유효한 PrivacyOptions 라인 추출
            local privacy
            privacy=$(grep -vE '^\s*#' "$sm_conf" 2>/dev/null \
                      | grep -E '^[[:space:]]*O[[:space:]]+PrivacyOptions[[:space:]]*=' \
                      | tail -1)

            if [[ -z "$privacy" ]]; then
                issues+=("sendmail: PrivacyOptions 미설정")
            elif echo "$privacy" | grep -qi 'goaway'; then
                : # goaway는 noexpn, novrfy 포함 단축 옵션 — 양호
            else
                if ! echo "$privacy" | grep -qi 'noexpn'; then
                    issues+=("sendmail: PrivacyOptions에 noexpn 없음 (현재: ${privacy})")
                fi
                if ! echo "$privacy" | grep -qi 'novrfy'; then
                    issues+=("sendmail: PrivacyOptions에 novrfy 없음 (현재: ${privacy})")
                fi
            fi
        fi
    fi

    # ── Postfix: disable_vrfy_command=yes 확인 ──
    # Postfix는 기본적으로 expn 미지원, vrfy만 확인
    if echo "$active_mail" | grep -q "postfix"; then
        local pf_cf="/etc/postfix/main.cf"
        if [[ -f "$pf_cf" ]]; then
            local vrfy
            vrfy=$(grep -vE '^\s*#' "$pf_cf" 2>/dev/null \
                   | grep -E '^\s*disable_vrfy_command\s*=' | tail -1 \
                   | awk -F '=' '{print $2}' | tr -d '[:space:]')

            if [[ "${vrfy,,}" != "yes" ]]; then
                issues+=("postfix: disable_vrfy_command=${vrfy:-미설정(기본 no)}")
            fi
        else
            issues+=("postfix: /etc/postfix/main.cf 파일 미발견")
        fi
    fi

    # ── Exim: acl_smtp_vrfy, acl_smtp_expn accept 설정 확인 ──
    if echo "$active_mail" | grep -q "exim"; then
        local exim_cf=""
        for f in /etc/exim/exim.conf /etc/exim4/exim4.conf; do
            [[ -f "$f" ]] && exim_cf="$f" && break
        done

        if [[ -z "$exim_cf" ]]; then
            issues+=("exim: exim.conf 파일 미발견")
        else
            local exim_active
            exim_active=$(grep -vE '^\s*#' "$exim_cf" 2>/dev/null)

            if echo "$exim_active" | grep -qE 'acl_smtp_vrfy\s*=\s*accept'; then
                issues+=("exim: acl_smtp_vrfy가 accept로 설정됨")
            fi
            if echo "$exim_active" | grep -qE 'acl_smtp_expn\s*=\s*accept'; then
                issues+=("exim: acl_smtp_expn이 accept로 설정됨")
            fi
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "expn/vrfy 명령어 제한 설정 양호"
    fi
}
# 26/6/9 완료

# ────────────────────────────────────────────────────────────
# U-49: DNS 보안 버전 패치
# 판단기준
#   양호: 주기적으로 패치를 관리하는 경우
#   취약: 주기적으로 패치를 관리하고 있지 않은 경우
# ────────────────────────────────────────────────────────────
check_U49() {
    local id="U-49" title="DNS 보안 버전 패치"

    # Step 1) DNS 서비스 활성화 여부 확인 (KISA 가이드: systemctl list-units | grep named)
    local active_named
    active_named=$(systemctl list-units --type=service --state=active 2>/dev/null \
                   | awk '{print $1}' \
                   | grep -E "named")

    # 서비스 미실행 시 양호
    if [[ -z "$active_named" ]]; then
        result_pass "$id" "$title" "DNS(BIND) 서비스 미실행"
        return
    fi

    # Step 2) BIND 버전 확인 (KISA 가이드: named -v)
    local raw_ver bind_ver
    raw_ver=$(named -v 2>/dev/null)

    if [[ -n "$raw_ver" ]]; then
        bind_ver=$(echo "$raw_ver" | grep -oE 'BIND\s*[0-9]+[^[:space:]]*')
    fi

    result_interview "$id" "$title" \
        "DNS(BIND) 서비스 실행 중 — 버전: ${bind_ver:-${raw_ver:-확인불가}} — 주기적 패치 관리 여부 인터뷰 필요"
}
# 26/6/9 완료

# ────────────────────────────────────────────────────────────
# U-50: DNS Zone Transfer 접근 제한
# 판단기준
#   양호: Zone Transfer를 허가된 사용자에게만 허용한 경우
#   취약: Zone Transfer를 모든 사용자에게 허용한 경우
# ────────────────────────────────────────────────────────────
check_U50() {
    local id="U-50" title="DNS Zone Transfer 접근 제한"
    local issues=()

    # Step 1) DNS 서비스 활성화 여부 확인
    local active_named
    active_named=$(systemctl list-units --type=service --state=active 2>/dev/null \
                   | awk '{print $1}' \
                   | grep -E "named")

    if [[ -z "$active_named" ]]; then
        result_pass "$id" "$title" "DNS(BIND) 서비스 미실행"
        return
    fi

    # Step 2) named.conf 파일 탐색
    local named_conf=""
    for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options; do
        [[ -f "$f" ]] && named_conf="$f" && break
    done

    if [[ -z "$named_conf" ]]; then
        issues+=("named.conf 파일 미발견")
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
        return
    fi

    # Step 3) include 파일 수집
    local conf_files=("$named_conf")
    while IFS= read -r inc_file; do
        inc_file=$(echo "$inc_file" | grep -oE '"[^"]+"' | tr -d '"')
        
        [[ -f "$inc_file" ]] && conf_files+=("$inc_file")
    done < <(grep -iE '^\s*include\s+' "$named_conf" 2>/dev/null)

    # Step 4) 주석 제거 후 단일 라인으로 정제
    # //, #, /* */ 주석 제거 및 멀티라인 → 단일라인 변환
    local clean_conf=""
    for cf in "${conf_files[@]}"; do
        [[ -f "$cf" ]] || continue
        local content
        content=$(awk '
            # 블록 주석 내부는 무조건 skip
            in_block {
                if (/\*\//) { in_block=0; gsub(/.*\*\//, "") }
                else { next }
            }

            # 같은 줄에서 /* */ 완결되는 경우 제거 후 계속 처리
            { gsub(/\/\*[^*]*\*\//, "") }

            # 멀티라인 블록 주석 시작
            /\/\*/ { in_block=1; gsub(/\/\*.*/, "") }

            # 단일 행 주석 제거 후 출력
            { gsub(/\/\/.*/, ""); gsub(/#.*/, ""); print }
        ' "$cf" 2>/dev/null | tr -s '[:space:]' ' ')
        clean_conf+=" $content"
    done

    # Step 5) xfrnets 설정 확인 (KISA 가이드: named.boot 구버전 환경)
    for f in /etc/named.boot /etc/bind/named.boot; do
        if [[ -f "$f" ]]; then
            if ! grep -qE 'xfrnets' "$f" 2>/dev/null; then
                issues+=("named.boot: xfrnets 미설정")
            fi
        fi
    done

    # Step 6) allow-transfer 설정 확인
    if ! echo "$clean_conf" | grep -qE 'allow-transfer'; then
        issues+=("named.conf: allow-transfer 미설정 (기본값 전체 허용)")
    else
        if echo "$clean_conf" | grep -oE 'allow-transfer[^;]*;' \
           | grep -qE '\bany\b'; then
            issues+=("named.conf: allow-transfer { any; } 전체 허용 설정")
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "Zone Transfer 접근 제한 설정 양호"
    fi
}
# 26/6/11 완료

# ────────────────────────────────────────────────────────────
# U-51: DNS 동적 업데이트 제한
# 판단: allow-update가 any 또는 0.0.0.0/0인 경우 취약
#      미설정 시 BIND 기본값(none)으로 양호 처리
# ────────────────────────────────────────────────────────────
check_U51() {
    local id="U-51" title="DNS 동적 업데이트 제한"

    if ! systemctl is-active --quiet named 2>/dev/null && \
       ! command -v named &>/dev/null; then
        result_pass "$id" "$title" "DNS(BIND) 서비스 미사용"
        return
    fi

    local named_conf=""
    for f in /etc/named.conf /etc/bind/named.conf; do
        [[ -f "$f" ]] && named_conf="$f" && break
    done

    if [[ -z "$named_conf" ]]; then
        result_fail "$id" "$title" "named.conf 파일을 찾을 수 없음"
        return
    fi

    # 주석 제거 함수 (perl 미사용 - sed만으로 처리)
    strip_comments() {
        sed \
            -e 's|//.*||g' \
            -e 's|#.*||g' \
            -e '/^[[:space:]]*$/d' "$1" | \
        awk '
            /\/\*/ { in_block=1 }
            !in_block { print }
            /\*\// { in_block=0 }
        '
    }

    # 설정 수집 (include 1단계 추적)
    local all_conf
    all_conf=$(strip_comments "$named_conf")

    while IFS= read -r inc_file; do
        [[ -f "$inc_file" ]] && all_conf+=$'\n'"$(strip_comments "$inc_file")"
    done < <(echo "$all_conf" | sed -n 's/.*include[[:space:]]*"\([^"]*\)".*/\1/p')

    local issues=()

    local update_lines
    update_lines=$(echo "$all_conf" | grep -i 'allow-update')

    # 미설정 시 BIND 기본값(none) 적용 → 양호
    if [[ -z "$update_lines" ]]; then
        result_pass "$id" "$title" "allow-update 미설정 (BIND 기본값 none 적용으로 동적 업데이트 차단)"
        return
    fi

    # 전체 허용 탐지 (any 또는 0.0.0.0/0)
    if echo "$update_lines" | grep -qE '\bany\b|0\.0\.0\.0/0'; then
        issues+=("allow-update 전체 허용 설정 (any 또는 0.0.0.0/0)")
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "DNS 동적 업데이트 특정 대상으로 제한되어 양호"
    fi
}
# 26/6/13 완료

# ────────────────────────────────────────────────────────────
# U-52: Telnet 서비스 비활성화
# 판단: systemd, inetd, xinetd Telnet 활성화 여부 점검
# ────────────────────────────────────────────────────────────
check_U52() {
    local id="U-52" title="Telnet 서비스 비활성화"
    local issues=()

    # systemd 방식
    for svc in telnet.socket telnet telnetd; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            issues+=("$svc 활성화")
        fi
    done

    # inetd 방식 (주석 제외, 첫 필드가 telnet인 경우만)
    if [[ -f /etc/inetd.conf ]]; then
        if grep -vE '^\s*#' /etc/inetd.conf | awk '{print $1}' | grep -qiE '^telnet$'; then
            issues+=("inetd.conf: telnet 서비스 활성화")
        fi
    fi

    # xinetd 방식 (주석 제거 후 service telnet 블록 내 disable 여부 확인)
    local xinetd_content=""
    for f in /etc/xinetd.d/* /etc/xinetd.conf; do
        [[ -f "$f" ]] && xinetd_content+=$'\n'"$(sed 's/#.*//g' "$f")"
    done

    if [[ -n "$xinetd_content" ]]; then
        local telnet_block
        telnet_block=$(echo "$xinetd_content" | awk '
            # ※ 표준 xinetd 설정은 여는 중괄호가 "service telnet" 다음 줄에 오므로
            #   같은 줄 중괄호({)를 필수로 요구하면 표준 포맷을 미탐함 → 중괄호 없이 매치
            #   ([[:space:]{]|$) : telnetd 등 다른 서비스명 오매치 방지용 경계
            /service[[:space:]]+telnet([[:space:]{]|$)/ { in_block=1 }
            in_block { block=block"\n"$0 }
            /\}/ && in_block { in_block=0 }
            END { print block }
        ')
        if [[ -n "$telnet_block" ]]; then
            if ! echo "$telnet_block" | grep -qiE 'disable[[:space:]]*=[[:space:]]*yes'; then
                issues+=("xinetd: telnet 서비스 활성화 (disable=yes 미설정)")
            fi
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "Telnet 서비스 비활성화 양호"
    fi
}
# 26/6/13 완료

# ────────────────────────────────────────────────────────────
# U-53: FTP 배너 정보 노출 제한 (KISA 가이드라인 기준)
# ────────────────────────────────────────────────────────────
check_U53() {
    local id="U-53" title="FTP 배너 정보 노출 제한"
    local issues=()
    local ftp_found=0

    # ── vsftpd 점검 ──
    local vsftpd_conf=""
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [[ -f "$f" ]] && vsftpd_conf="$f" && break
    done

    if [[ -n "$vsftpd_conf" ]]; then
        ftp_found=1
        local vs_banner
        vs_banner=$(grep -vE '^\s*#' "$vsftpd_conf" | grep -E '^\s*ftpd_banner\s*=' | tail -1)

        if [[ -z "$vs_banner" ]]; then
            issues+=("vsftpd: ftpd_banner 미설정 (주석 처리 또는 누락)")
        fi
    fi

    # ── ProFTPd 점검 ──
    local proftpd_conf=""
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        [[ -f "$f" ]] && proftpd_conf="$f" && break
    done

    if [[ -n "$proftpd_conf" ]]; then
        ftp_found=1
        local pro_ident
        pro_ident=$(grep -vE '^\s*#' "$proftpd_conf" | grep -iE 'ServerIdent' | tail -1)

        if [[ -z "$pro_ident" ]]; then
            issues+=("proftpd: ServerIdent 미설정")
        else
            if ! echo "$pro_ident" | grep -qiE '\boff\b' && \
               ! echo "$pro_ident" | grep -qE 'on\s+".+"'; then
                issues+=("proftpd: ServerIdent 설정 미흡 (off 또는 on \"변경할 배너\" 형태가 아님)")
            fi
        fi
    fi

    if [[ $ftp_found -eq 0 ]]; then
        result_pass "$id" "$title" "FTP 서비스(vsftpd, proftpd) 미사용"
        return
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "FTP 배너 정보 노출 제한 설정 양호"
    fi
}
# 26/6/13 완료

# ────────────────────────────────────────────────────────────
# U-54: 암호화되지 않은 FTP 서비스 비활성화
# ────────────────────────────────────────────────────────────
check_U54() {
    local id="U-54" title="암호화되지 않은 FTP 서비스 비활성화"
    local issues=()

    # inetd 방식 - FTP 자체가 암호화 미지원
    if [[ -f /etc/inetd.conf ]]; then
        if grep -vE '^\s*#' /etc/inetd.conf | awk '{print $1}' | grep -qiE '^ftp$'; then
            issues+=("inetd.conf: ftp 서비스 활성화")
        fi
    fi

    # xinetd 방식 - FTP 자체가 암호화 미지원
    if [[ -f /etc/xinetd.d/ftp ]]; then
        local clean_content
        clean_content=$(sed 's/#.*//g' /etc/xinetd.d/ftp)
        if echo "$clean_content" | grep -qiE 'service[[:space:]]+ftp\b'; then
            if ! echo "$clean_content" | grep -qiE 'disable[[:space:]]*=[[:space:]]*yes'; then
                issues+=("xinetd: ftp 서비스 활성화 (disable=yes 미설정)")
            fi
        fi
    fi

    # vsftpd - 활성화 시 ssl_enable=YES 여부 확인
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
        local vsftpd_conf=""
        for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            [[ -f "$f" ]] && vsftpd_conf="$f" && break
        done

        local ssl_enable
        ssl_enable=$(grep -vE '^\s*#' "$vsftpd_conf" 2>/dev/null \
                    | grep -E '^\s*ssl_enable\s*=' | tail -1 \
                    | grep -oi 'YES\|NO')

        if [[ "${ssl_enable^^}" != "YES" ]]; then
            issues+=("vsftpd: 암호화(ssl_enable=YES) 미설정 상태로 활성화")
        fi
    fi

    # proftpd - 활성화 시 TLSEngine on 여부 확인
    if systemctl is-active --quiet proftpd 2>/dev/null; then
        local proftpd_conf=""
        for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
            [[ -f "$f" ]] && proftpd_conf="$f" && break
        done

        if ! grep -vE '^\s*#' "$proftpd_conf" 2>/dev/null \
             | grep -qiE 'TLSEngine[[:space:]]+on'; then
            issues+=("proftpd: 암호화(TLSEngine on) 미설정 상태로 활성화")
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "암호화되지 않은 FTP 서비스 비활성화 양호"
    fi
}
# 26/6/13 완료

# ────────────────────────────────────────────────────────────
# U-55: FTP 서비스 계정 Shell 제한
# 판단: ftp 계정의 login shell이 nologin 또는 false이면 양호
# ────────────────────────────────────────────────────────────
check_U55() {
    local id="U-55" title="FTP 서비스 계정 Shell 제한"

    local ftp_shell
    ftp_shell=$(getent passwd ftp 2>/dev/null | cut -d: -f7)

    if [[ -z "$ftp_shell" ]]; then
        result_pass "$id" "$title" "ftp 계정 없음"
        return
    fi

    if echo "$ftp_shell" | grep -qE '(nologin|false)$'; then
        result_pass "$id" "$title" "ftp 계정 shell: ${ftp_shell}"
    else
        result_fail "$id" "$title" "ftp 계정 shell: ${ftp_shell} (nologin/false 아님)"
    fi
}
# 26/6/14 완료

# ────────────────────────────────────────────────────────────
# U-56: FTP 접근 제어 설정
# 판단: FTP 접근 제어 설정 적용 여부 점검
# ────────────────────────────────────────────────────────────
check_U56() {
    local id="U-56" title="FTP 접근 제어 설정"
    local issues=()
    local ftp_found=0
    # vsftpd/proftpd가 같은 파일(/etc/ftpusers)을 참조할 때 중복 점검 방지
    declare -A perm_checked=()

    # 파일 소유자 root 및 권한 640 이하 검사 함수
    check_file_perm() {
        local f="$1"
        [[ ! -f "$f" ]] && return
        [[ -n "${perm_checked[$f]:-}" ]] && return
        perm_checked["$f"]=1

        local owner perms
        owner=$(get_owner "$f")
        perms=$(get_perm "$f")

        [[ "$owner" != "root" ]] && issues+=("$f: 소유자 root 아님 (${owner})")

        if [[ -n "$perms" ]]; then
            local clean_perms="${perms: -3}"
            if ! perm_le 640 "$clean_perms"; then
                issues+=("$f: 권한 640 초과 (${perms})")
            fi
        else
            issues+=("$f: 권한 확인 불가")
        fi
    }

    # ── vsftpd 점검 ──
    local vsftpd_conf=""
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [[ -f "$f" ]] && vsftpd_conf="$f" && break
    done

    if [[ -n "$vsftpd_conf" ]]; then
        ftp_found=1

        # ftpusers는 설정과 무관하게 항상 점검
        # /etc/vsftpd.ftpusers 는 KISA 가이드 외 경로 - 추가 필요 검토
        local ftpf=""
        for f in /etc/ftpusers /etc/vsftpd/ftpusers; do
            [[ -f "$f" ]] && ftpf="$f" && break
        done

        if [[ -z "$ftpf" ]]; then
            issues+=("vsftpd: ftpusers 파일 없음")
        else
            check_file_perm "$ftpf"
        fi

        # userlist_enable=YES 시 user_list 추가 점검
        local userlist_enable
        userlist_enable=$(grep -vE '^\s*#' "$vsftpd_conf" 2>/dev/null \
                         | grep -iE '^\s*userlist_enable\s*=' | tail -1 \
                         | grep -oi 'YES\|NO')

        if [[ "${userlist_enable^^}" == "YES" ]]; then
            local ulist=""
            for f in /etc/vsftpd/user_list /etc/vsftpd.user_list; do
                [[ -f "$f" ]] && ulist="$f" && break
            done
            if [[ -z "$ulist" ]]; then
                issues+=("vsftpd: userlist_enable=YES이나 user_list 파일 없음")
            else
                check_file_perm "$ulist"
            fi
        fi
    fi

    # ── ProFTPd 점검 ──
    local proftpd_conf=""
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        [[ -f "$f" ]] && proftpd_conf="$f" && break
    done

    if [[ -n "$proftpd_conf" ]]; then
        ftp_found=1
        local use_ftpusers
        use_ftpusers=$(grep -vE '^\s*#' "$proftpd_conf" 2>/dev/null \
                      | grep -iE '^\s*UseFtpUsers\s+' | tail -1 \
                      | grep -oi 'on\|off')

        if [[ "${use_ftpusers,,}" == "off" ]]; then
            if ! grep -qiE '<Limit[[:space:]]+LOGIN>' "$proftpd_conf" 2>/dev/null; then
                issues+=("proftpd: UseFtpUsers off이나 <Limit LOGIN> 블록 미설정")
            else
                check_file_perm "$proftpd_conf"
            fi
        else
            # /etc/proftpd/ftpusers 는 KISA 가이드 외 경로 - 추가 필요 검토
            local ftpf=""
            for f in /etc/ftpusers /etc/ftpd/ftpusers; do
                [[ -f "$f" ]] && ftpf="$f" && break
            done
            if [[ -z "$ftpf" ]]; then
                issues+=("proftpd: ftpusers 파일 없음")
            else
                check_file_perm "$ftpf"
            fi
        fi
    fi

    if [[ $ftp_found -eq 0 ]]; then
        result_pass "$id" "$title" "FTP 서비스 미사용"
        return
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "FTP 접근 제어 설정 양호"
    fi
}
# 26/6/14 완료 ... 추가 점검 필요

# ────────────────────────────────────────────────────────────
# U-57: FTP root 계정 접근 제한
# 판단: ftpusers/user_list에 root 등록, proftpd RootLogin off
# ────────────────────────────────────────────────────────────
check_U57() {
    local id="U-57" title="FTP root 계정 접근 제한"
    local issues=()
    local ftp_found=0

    # ── vsftpd 점검 ──
    local vsftpd_conf=""
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [[ -f "$f" ]] && vsftpd_conf="$f" && break
    done

    if [[ -n "$vsftpd_conf" ]]; then
        ftp_found=1

        # ftpusers 내 root 존재 여부 (userlist_enable 무관하게 항상 체크)
        # /etc/vsftpd.ftpusers 는 KISA 가이드 외 경로 - 추가 필요 검토
        local ftpf=""
        for f in /etc/ftpusers /etc/vsftpd/ftpusers; do
            [[ -f "$f" ]] && ftpf="$f" && break
        done

        local root_in_ftpusers=0
        if [[ -n "$ftpf" ]] && grep -qE '^\s*root\s*$' "$ftpf" 2>/dev/null; then
            root_in_ftpusers=1
        fi

        local ul_enable
        ul_enable=$(grep -vE '^\s*#' "$vsftpd_conf" 2>/dev/null \
                   | grep -iE '^\s*userlist_enable\s*=' | tail -1 \
                   | grep -oi 'YES\|NO')

        if [[ "${ul_enable^^}" == "YES" ]]; then
            local ulist=""
            for f in /etc/vsftpd/user_list /etc/vsftpd.user_list; do
                [[ -f "$f" ]] && ulist="$f" && break
            done

            local root_in_userlist=0
            if [[ -n "$ulist" ]] && grep -qE '^\s*root\s*$' "$ulist" 2>/dev/null; then
                root_in_userlist=1
            fi

            local ul_deny
            ul_deny=$(grep -vE '^\s*#' "$vsftpd_conf" 2>/dev/null \
                     | grep -iE '^\s*userlist_deny\s*=' | tail -1 \
                     | grep -oi 'YES\|NO')

            # userlist_deny 기본값은 YES (차단 목록 방식)
            if [[ "${ul_deny^^}" != "NO" ]]; then
                if [[ $root_in_ftpusers -eq 0 && $root_in_userlist -eq 0 ]]; then
                    issues+=("vsftpd: ftpusers 및 user_list에 root 미등록")
                fi
            fi
        else
            # userlist_enable=NO → ftpusers만으로 제어
            if [[ -z "$ftpf" ]]; then
                issues+=("vsftpd: ftpusers 파일 없음")
            elif [[ $root_in_ftpusers -eq 0 ]]; then
                issues+=("vsftpd: ftpusers에 root 미등록")
            fi
        fi

        # [참고 - KISA 가이드 외 항목]
        # vsftpd PAM(/etc/pam.d/vsftpd)이 ftpusers를 참조하여 root 차단 적용
        # PAM은 root 권한으로 실행되므로 ftpusers 권한 600이어도 정상 읽기 가능
        # root FTP 로그인 시 530 Permission Denied 발생하면 정상 차단 상태
    fi

    # ── ProFTPd 점검 ──
    local proftpd_conf=""
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        [[ -f "$f" ]] && proftpd_conf="$f" && break
    done

    if [[ -n "$proftpd_conf" ]]; then
        ftp_found=1

        local use_ftpusers
        use_ftpusers=$(grep -vE '^\s*#' "$proftpd_conf" 2>/dev/null \
                      | grep -iE '^\s*UseFtpUsers\s+' | tail -1 \
                      | grep -oi 'on\|off')

        if [[ "${use_ftpusers,,}" == "off" ]]; then
            local root_login
            root_login=$(grep -vE '^\s*#' "$proftpd_conf" 2>/dev/null \
                        | grep -iE '^\s*RootLogin\s+' | tail -1 \
                        | grep -oi 'on\|off')
            if [[ "${root_login,,}" != "off" ]]; then
                issues+=("proftpd: RootLogin=${root_login:-미설정} (off 필요)")
            fi
        else
            # /etc/proftpd/ftpusers 는 KISA 가이드 외 경로 - 추가 필요 검토
            local ftpf=""
            for f in /etc/ftpusers /etc/ftpd/ftpusers; do
                [[ -f "$f" ]] && ftpf="$f" && break
            done

            if [[ -z "$ftpf" ]]; then
                issues+=("proftpd: ftpusers 파일 없음")
            elif ! grep -qE '^\s*root\s*$' "$ftpf" 2>/dev/null; then
                issues+=("proftpd: ftpusers에 root 미등록")
            fi
        fi
    fi

    if [[ $ftp_found -eq 0 ]]; then
        result_pass "$id" "$title" "FTP 서비스 미사용"
        return
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "FTP root 접근 제한 설정 양호"
    fi
}
# 26/6/14 완료

# ────────────────────────────────────────────────────────────
# U-58: SNMP 서비스 비활성화
# 판단: snmpd 활성화 여부 점검
# ────────────────────────────────────────────────────────────
check_U58() {
    local id="U-58" title="SNMP 서비스 비활성화"

    if systemctl is-active --quiet snmpd 2>/dev/null; then
        result_fail "$id" "$title" "SNMP 서비스(snmpd) 활성화"
    else
        result_pass "$id" "$title" "SNMP 서비스 비활성화"
    fi
}
# 26/6/14 완료

# ────────────────────────────────────────────────────────────
# U-59: SNMP v3 이상 사용 설정
# 판단: SNMPv3 설정 사용 여부 점검
# ────────────────────────────────────────────────────────────
check_U59() {
    local id="U-59" title="SNMP v3 이상 사용 설정"

    if ! systemctl is-active --quiet snmpd 2>/dev/null; then
        result_pass "$id" "$title" "SNMP 서비스 미사용"
        return
    fi

    local snmpd_conf=""
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf; do
        [[ -f "$f" ]] && snmpd_conf="$f" && break
    done

    if [[ -z "$snmpd_conf" ]]; then
        result_fail "$id" "$title" "snmpd.conf 파일 없음"
        return
    fi

    # SNMPv3 설정 (createUser, rouser, rwuser) 존재 여부 확인
    if grep -vE '^\s*#' "$snmpd_conf" \
       | grep -qE '^\s*(createUser|rouser|rwuser)\b'; then
        result_pass "$id" "$title" "SNMPv3 설정 사용 중"
    else
        result_fail "$id" "$title" "SNMPv3 설정(createUser/rouser) 없음 (v2 이하 사용 중)"
    fi
}
# 26/6/14 완료

# ────────────────────────────────────────────────────────────
# U-60: SNMP Community String 복잡성
# 판단: community string 기본값/복잡성 미달 시 취약
#       SNMPv3 인증 사용 시 양호
# ────────────────────────────────────────────────────────────
check_U60() {
    local id="U-60" title="SNMP Community String 복잡성"

    if ! systemctl is-active --quiet snmpd 2>/dev/null; then
        result_pass "$id" "$title" "SNMP 서비스 미사용"
        return
    fi

    local snmpd_conf=""
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf; do
        [[ -f "$f" ]] && snmpd_conf="$f" && break
    done

    if [[ -z "$snmpd_conf" ]]; then
        result_fail "$id" "$title" "snmpd.conf 파일 없음"
        return
    fi

    local clean_conf
    clean_conf=$(grep -vE '^\s*#' "$snmpd_conf" 2>/dev/null)

    # SNMPv3 사용 시 양호
    if echo "$clean_conf" | grep -qE '^\s*(createUser|rouser|rwuser)\b'; then
        result_pass "$id" "$title" "SNMPv3 인증 사용으로 양호"
        return
    fi

    local issues=()

    check_complexity() {
        local str="$1"
        local label="$2"

        str=$(echo "$str" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")

        if echo "$str" | grep -qiE '^(public|private)$'; then
            issues+=("${label}: 기본값(public/private) 사용")
            return
        fi

        local has_alpha has_digit has_special len
        len=${#str}
        echo "$str" | grep -qE '[a-zA-Z]' && has_alpha=1 || has_alpha=0
        echo "$str" | grep -qE '[0-9]'    && has_digit=1 || has_digit=0
        echo "$str" | grep -qE '[^a-zA-Z0-9]' && has_special=1 || has_special=0

        # 영문+숫자+특수문자 8자리 이상
        if [[ $has_alpha -eq 1 && $has_digit -eq 1 && $has_special -eq 1 && $len -ge 8 ]]; then
            return
        fi
        # 영문+숫자 10자리 이상
        if [[ $has_alpha -eq 1 && $has_digit -eq 1 && $len -ge 10 ]]; then
            return
        fi

        issues+=("${label}: 복잡성 미달 (영문+숫자 10자리 이상 또는 영문+숫자+특수문자 8자리 이상 필요)")
    }

    # rocommunity/rwcommunity/rocommunity6/rwcommunity6: 2번째 필드가 community string
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local keyword comm
        keyword=$(echo "$line" | awk '{print $1}')
        comm=$(echo "$line" | awk '{print $2}')

        if [[ "$comm" == "-6" ]]; then
            comm=$(echo "$line" | awk '{print $3}')
        fi

        [[ -n "$comm" ]] && check_complexity "$comm" "$keyword"
    done < <(echo "$clean_conf" | grep -E '^\s*(rocommunity|rwcommunity|rocommunity6|rwcommunity6)\b')

    # com2sec/com2sec6 구문: com2sec [-Cn CONTEXT] NAME SOURCE COMMUNITY
    #   $1=지시어  $2=NAME  $3=SOURCE  $4=COMMUNITY
    # ※ v2는 $3(SOURCE)을 community string으로 읽어 엉뚱한 값(예: "default")의
    #   복잡성을 평가했음 → community string인 $4를 읽도록 수정
    #   (같은 파일 U-61은 $3을 SOURCE로 사용하고 있어 둘이 상충했음)
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local keyword name comm
        keyword=$(echo "$line" | awk '{print $1}')
        name=$(echo "$line"    | awk '{print $2}')
        comm=$(echo "$line"    | awk '{print $4}')

        # -Cn CONTEXT 옵션 사용 시 필드가 2칸 밀림
        if [[ "$name" == "-Cn" ]]; then
            comm=$(echo "$line" | awk '{print $6}')
            name=$(echo "$line" | awk '{print $4}')
        fi

        [[ -n "$comm" ]] && check_complexity "$comm" "${keyword} ${name}"
    done < <(echo "$clean_conf" | grep -E '^\s*(com2sec|com2sec6)\b')

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "SNMP Community String 복잡성 양호"
    fi
}
# 26/6/14 완료

# ────────────────────────────────────────────────────────────
# U-61: SNMP 접근 제한
# 판단: 접근 제어(source IP/대역) 미설정 시 취약
# ────────────────────────────────────────────────────────────
check_U61() {
    local id="U-61" title="SNMP 접근 제한"

    if ! systemctl is-active --quiet snmpd 2>/dev/null; then
        result_pass "$id" "$title" "SNMP 서비스 미사용"
        return
    fi

    local snmpd_conf=""
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf; do
        [[ -f "$f" ]] && snmpd_conf="$f" && break
    done

    if [[ -z "$snmpd_conf" ]]; then
        result_fail "$id" "$title" "snmpd.conf 파일 없음"
        return
    fi

    local clean_conf
    clean_conf=$(grep -vE '^\s*#' "$snmpd_conf" 2>/dev/null)

    local issues=()

    # rocommunity/rwcommunity: $1=지시어 $2=string $3=source
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local keyword source
        keyword=$(echo "$line" | awk '{print $1}')
        source=$(echo "$line" | awk '{print $3}')

        if [[ -z "$source" ]] || echo "$source" | grep -qE '^(default|0\.0\.0\.0(/0)?)$'; then
            issues+=("${keyword}: 접근 제어 미설정 (source 미지정 또는 전체 허용)")
        fi
    done < <(echo "$clean_conf" | grep -E '^\s*(rocommunity|rwcommunity)\b')

    # com2sec: $1=지시어 $2=NAME $3=SOURCE $4=COMMUNITY
    # ※ v2는 notConfigUser 항목만 점검해, 관리자가 추가한 다른 com2sec 항목이
    #   default(전체 허용)로 설정되어 있어도 놓쳤음(미탐) → 모든 com2sec 항목 점검
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local name source
        name=$(echo "$line"   | awk '{print $2}')
        source=$(echo "$line" | awk '{print $3}')

        # -Cn CONTEXT 옵션 사용 시 필드가 2칸 밀림
        if [[ "$name" == "-Cn" ]]; then
            name=$(echo "$line"   | awk '{print $4}')
            source=$(echo "$line" | awk '{print $5}')
        fi

        if [[ -z "$source" ]] || echo "$source" | grep -qE '^(default|0\.0\.0\.0(/0)?)$'; then
            issues+=("com2sec ${name}: 접근 제어 미설정 (전체 허용: ${source:-미지정})")
        fi
    done < <(echo "$clean_conf" | grep -iE '^\s*com2sec6?\s')

    # 접근 제어 설정 자체가 없는 경우
    if ! echo "$clean_conf" | grep -qE '^\s*(rocommunity|rwcommunity|com2sec)\b'; then
        result_fail "$id" "$title" "SNMP 접근 제어 설정 없음"
        return
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "SNMP 접근 제한 설정 양호"
    fi
}
# 26/6/14 완료

# ────────────────────────────────────────────────────────────
# U-62: 로그인 시 경고 메시지 설정
# 판단: 서버 및 각 서비스에 경고 메시지 설정 여부
# ────────────────────────────────────────────────────────────
check_U62() {
    local id="U-62" title="로그인 시 경고 메시지 설정"
    local issues=()

    # 경고 메시지 파일 내용 검사 함수
    # 시스템 정보 노출 이스케이프 코드만 있고 실제 경고 문구 없으면 취약
    check_banner_content() {
        local file="$1"
        local label="$2"

        if [[ ! -f "$file" ]] || [[ ! -s "$file" ]]; then
            issues+=("${label}: 파일 없음 또는 내용 없음")
            return
        fi

        # 시스템 정보 이스케이프 코드 제거 후 실질적인 경고 문구 여부 확인
        # ※ v2는 이스케이프 코드만 제거해, Rocky 기본 /etc/issue
        #   ("\S / Kernel \r on an \m")가 "Kernel on an" 이라는 잔여 문자열 때문에
        #   경고 문구가 있는 것으로 판정됐음(미탐)
        #   → OS 기본 배너 상용구까지 제거한 뒤 실질 문구 유무를 판정
        # ※ v2의 's/\\[Ss...]//g' 패턴은 GNU sed(BRE)에서 '\\' 뒤에 '['가 이어지면
        #   의도대로 해석되지 않아 \S \m 등 이스케이프 코드가 제거되지 않았음
        #   (실측: GNU sed 4.9에서 "\S" 미제거) → 문자클래스 [\\] 형태로 교정
        local stripped
        stripped=$(sed 's/[\\][SsRrMmOoLlBbDdTtUuVv]//g' "$file" \
                   | sed -E 's/\b(Kernel|on an|Welcome to|Rocky|Red Hat|Enterprise|Linux|release)\b//gI' \
                   | tr -d '[:space:]')
        if [[ -z "$stripped" ]]; then
            issues+=("${label}: 시스템 정보만 노출되고 경고 메시지 없음")
        fi
    }

    # ── 서버 공통 ──
    check_banner_content /etc/motd  "/etc/motd"
    check_banner_content /etc/issue "/etc/issue"

    # ── Telnet ──
    if ss -tlnp 2>/dev/null | grep -q ':23\b' || \
       systemctl is-active --quiet telnet 2>/dev/null || \
       systemctl is-active --quiet telnetd 2>/dev/null; then
        check_banner_content /etc/issue.net "Telnet(/etc/issue.net)"
    fi

    # ── SSH ──
    if systemctl is-active --quiet sshd 2>/dev/null; then
        local sshd_conf="/etc/ssh/sshd_config"
        if [[ -f "$sshd_conf" ]]; then
            local banner_val
            banner_val=$(grep -iE '^\s*Banner\s+' "$sshd_conf" 2>/dev/null | tail -1 | awk '{print $2}')
            if [[ -z "$banner_val" ]] || [[ "$banner_val" == "none" ]]; then
                issues+=("SSH: sshd_config Banner 미설정")
            else
                check_banner_content "$banner_val" "SSH Banner(${banner_val})"
            fi
        fi
    fi

    # ── Sendmail ──
    if systemctl is-active --quiet sendmail 2>/dev/null; then
        local sendmail_cf="/etc/mail/sendmail.cf"
        if [[ -f "$sendmail_cf" ]]; then
            local val
            val=$(grep -iE '^\s*SmtpGreetingMessage\s*=' "$sendmail_cf" 2>/dev/null | tail -1)
            if [[ -z "$val" ]]; then
                issues+=("Sendmail: SmtpGreetingMessage 미설정")
            fi
        fi
    fi

    # ── Postfix ──
    if systemctl is-active --quiet postfix 2>/dev/null; then
        local postfix_cf="/etc/postfix/main.cf"
        if [[ -f "$postfix_cf" ]]; then
            local val
            val=$(grep -iE '^\s*smtpd_banner\s*=' "$postfix_cf" 2>/dev/null | tail -1)
            if [[ -z "$val" ]]; then
                issues+=("Postfix: smtpd_banner 미설정")
            fi
        fi
    fi

    # ── Exim ──
    if systemctl is-active --quiet exim 2>/dev/null || \
       systemctl is-active --quiet exim4 2>/dev/null; then
        local exim_conf=""
        for f in /etc/exim/exim.conf /etc/exim4/exim4.conf; do
            [[ -f "$f" ]] && exim_conf="$f" && break
        done
        if [[ -n "$exim_conf" ]]; then
            local val
            val=$(grep -iE '^\s*smtp_banner\s*=' "$exim_conf" 2>/dev/null | tail -1)
            if [[ -z "$val" ]]; then
                issues+=("Exim: smtp_banner 미설정")
            fi
        fi
    fi

    # ── vsftpd ──
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
        local vsftpd_conf=""
        for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
            [[ -f "$f" ]] && vsftpd_conf="$f" && break
        done
        if [[ -n "$vsftpd_conf" ]]; then
            local val
            val=$(grep -iE '^\s*ftpd_banner\s*=' "$vsftpd_conf" 2>/dev/null | tail -1)
            if [[ -z "$val" ]]; then
                issues+=("vsftpd: ftpd_banner 미설정")
            fi
        fi
    fi

    # ── ProFTPd ──
    if systemctl is-active --quiet proftpd 2>/dev/null; then
        local proftpd_conf=""
        for f in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do
            [[ -f "$f" ]] && proftpd_conf="$f" && break
        done
        if [[ -n "$proftpd_conf" ]]; then
            local display_val
            display_val=$(grep -iE '^\s*DisplayLogin\s+' "$proftpd_conf" 2>/dev/null | tail -1 | awk '{print $2}')
            if [[ -z "$display_val" ]]; then
                issues+=("ProFTPd: DisplayLogin 미설정")
            elif [[ ! -f "$display_val" ]] || [[ ! -s "$display_val" ]]; then
                issues+=("ProFTPd: DisplayLogin 파일 없음 또는 내용 없음 (${display_val})")
            fi
        fi
    fi

    # ── DNS ──
    if systemctl is-active --quiet named 2>/dev/null; then
        local named_conf=""
        for f in /etc/named.conf /etc/bind/named.conf.options; do
            [[ -f "$f" ]] && named_conf="$f" && break
        done
        if [[ -n "$named_conf" ]]; then
            local val
            val=$(grep -iE '^\s*version\s+' "$named_conf" 2>/dev/null | tail -1)
            if [[ -z "$val" ]]; then
                issues+=("DNS: version 경고 메시지 미설정")
            fi
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "로그인 경고 메시지 설정 양호"
    fi
}

# ────────────────────────────────────────────────────────────
# U-63: /etc/sudoers 파일 권한 설정
# 판단: 소유자 root, 권한 640 이하이면 양호
# ────────────────────────────────────────────────────────────
check_U63() {
    local id="U-63" title="/etc/sudoers 파일 권한 설정"

    if [[ ! -f /etc/sudoers ]]; then
        result_pass "$id" "$title" "/etc/sudoers 파일 없음"
        return
    fi

    local issues=()
    local perm owner
    perm=$(get_perm /etc/sudoers)
    owner=$(get_owner /etc/sudoers)

    if [[ "$owner" != "root" ]]; then
        issues+=("소유자: ${owner}(root 아님)")
    fi

    if ! perm_le 640 "$perm"; then
        issues+=("권한: ${perm}(640 초과)")
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(join_by '; ' "${issues[@]}")"
    else
        result_pass "$id" "$title" "/etc/sudoers 권한: ${owner}/${perm} (양호)"
    fi
}
# 26/6/14 완료

# ────────────────────────────────────────────────────────────
# 서비스 관리 전체 실행
# ────────────────────────────────────────────────────────────
run_service_checks() {
    print_section "3. 서비스 관리 (U-34 ~ U-63)"

    check_U34
    check_U35
    check_U36
    check_U37
    check_U38
    check_U39
    check_U40
    check_U41
    check_U42
    check_U43
    check_U44
    check_U45
    check_U46
    check_U47
    check_U48
    check_U49
    check_U50
    check_U51
    check_U52
    check_U53
    check_U54
    check_U55
    check_U56
    check_U57
    check_U58
    check_U59
    check_U60
    check_U61
    check_U62
    check_U63
}
