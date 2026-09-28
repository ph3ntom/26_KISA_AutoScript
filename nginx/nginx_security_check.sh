#!/bin/bash

NGINX_CONF=""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULT_DIR="$SCRIPT_DIR/result"
RESULT_FILE=""

NGINX_CONF_DIR=""
NGINX_ALL_CONF=()      # 진단 대상 설정 파일 목록 (배열)
CONF_SOURCE=""         # 목록을 어떤 방식으로 수집했는지 기록

CNT_GOOD=0
CNT_VULN=0
CNT_MANUAL=0
CNT_NA=0

#==============================================================================
# 출력 함수
#==============================================================================
log() {
    printf '%s\n' "$*"
    [ -n "$RESULT_FILE" ] && printf '%s\n' "$*" >> "$RESULT_FILE"
    return 0
}

line() {
    log "------------------------------------------------------------------------"
}

# 진단 항목 머리말   head_item <항목ID> <항목명> <중요도>
head_item() {
    line
    log "[$1] $2 (중요도:$3 / 대상:Nginx)"
}

info() {
    log "       - $1"
}

info_lines() {
    local prefix="${1:-         }"
    local l
    while IFS= read -r l || [ -n "$l" ]; do
        log "${prefix}${l}"
    done
}

result_good() {
    log "  => 결과 : [양호] $1"
    CNT_GOOD=$((CNT_GOOD + 1))
}

result_vuln() {
    log "  => 결과 : [취약] $1"
    CNT_VULN=$((CNT_VULN + 1))
}

result_manual() {
    log "  => 결과 : [수동확인] $1"
    CNT_MANUAL=$((CNT_MANUAL + 1))
}

result_na() {
    log "  => 결과 : [N/A] $1"
    CNT_NA=$((CNT_NA + 1))
}

#==============================================================================
# 파일 권한 헬퍼
#==============================================================================
fperm()  { stat -c '%a' "$1" 2>/dev/null; }
fowner() { stat -c '%U:%G' "$1" 2>/dev/null; }
perm_other() { local p="$1"; printf '%s' "${p: -1}"; }

#==============================================================================
# 사전 조건 검사
#==============================================================================

# root 권한 필수
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        printf '%s\n' "[오류] root 권한이 필요합니다. sudo 로 실행하십시오." >&2
        printf '%s\n' "       예) sudo bash $0" >&2
        exit 1
    fi
}

init_result() {
    umask 077
    if ! mkdir -p "$RESULT_DIR" 2>/dev/null; then
        printf '%s\n' "[오류] 결과 디렉터리 생성 실패: $RESULT_DIR" >&2
        exit 1
    fi
    chmod 700 "$RESULT_DIR" 2>/dev/null      # 이전 실행이 만든 디렉터리에도 적용
    RESULT_FILE="$RESULT_DIR/nginx_check_$(date +%Y%m%d_%H%M%S).txt"
    if ! : > "$RESULT_FILE" 2>/dev/null; then
        printf '%s\n' "[오류] 결과 파일 생성 실패: $RESULT_FILE" >&2
        RESULT_FILE=""
        exit 1
    fi
}

# 설정 파일 목록이 비어 있으면 사유를 출력하고 즉시 종료한다.
require_conf() {
    if [ ${#NGINX_ALL_CONF[@]} -eq 0 ]; then
        log "[오류] 진단 대상 nginx 설정 파일을 찾지 못했습니다."
        log "       확인 사항"
        log "         1) nginx 가 설치되어 있는지          : command -v nginx"
        log "         2) nginx -T 가 정상 동작하는지       : nginx -T"
        log "            (설정에 문법 오류가 있으면 실패한다)"
        log "         3) 자동 탐지 실패 시 스크립트 상단 NGINX_CONF 변수에 경로를 직접 지정"
        log ""
        log "진단을 중단합니다."
        exit 1
    fi
}

#==============================================================================
# 환경 탐지
#==============================================================================

# 중복 없이 설정 파일 목록에 추가
append_conf() {
    local f="$1" e
    for e in "${NGINX_ALL_CONF[@]}"; do
        [ "$e" = "$f" ] && return 0
    done
    NGINX_ALL_CONF+=("$f")
}

# 기준 설정 파일 경로 탐지
#  ※ nginx -V 의 --conf-path 를 사용한다.
#    nginx -t 출력 파싱과 달리 설정 문법 오류와 무관하게 값을 얻을 수 있다.
detect_conf_path() {
    [ -n "$NGINX_CONF" ] && [ ! -f "$NGINX_CONF" ] && NGINX_CONF=""
    if [ -z "$NGINX_CONF" ] && command -v nginx >/dev/null 2>&1; then
        NGINX_CONF=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's/^--conf-path=//p' | head -1)
        [ -n "$NGINX_CONF" ] && [ ! -f "$NGINX_CONF" ] && NGINX_CONF=""
    fi
    [ -z "$NGINX_CONF" ] && [ -f /etc/nginx/nginx.conf ] && NGINX_CONF="/etc/nginx/nginx.conf"
    [ -n "$NGINX_CONF" ] && NGINX_CONF_DIR=$(dirname "$NGINX_CONF")
}

# 폴백 보강 : 지정 파일의 include 지시자를 1단계 따라간다.
collect_include_1depth() {
    local src="$1" inc f
    [ -f "$src" ] || return 0
    while IFS= read -r inc; do
        [ -n "$inc" ] || continue
        case "$inc" in
            /*) ;;                                  # 절대경로
            *)  inc="$NGINX_CONF_DIR/$inc" ;;       # 상대경로는 설정 디렉터리 기준
        esac

        for f in $inc; do
            [ -f "$f" ] && append_conf "$f"
        done
    done < <(sed -n 's/^[[:space:]]*include[[:space:]]\+\([^;]*\);.*/\1/p' "$src")
}

# 진단 대상 설정 파일 목록 수집
#  1순위) nginx -T : include 를 따라 실제 로드되는 파일만 정확히 열거한다.
#                    /etc/nginx 바깥을 include 하는 경우(모듈 설정 등)도 잡힌다.
#  2순위) 파일시스템 탐색 : nginx -T 가 실패한 경우에만 사용하는 폴백.

collect_conf_files() {
    NGINX_ALL_CONF=()
    CONF_SOURCE=""

    if command -v nginx >/dev/null 2>&1; then
        local tf
        while IFS= read -r tf; do
            [ -f "$tf" ] || continue
            append_conf "$tf"
        done < <(nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p')
        # sed -n 's/찾을패턴/바꿀문자/p' : 매칭 시 치환 후 출력 (-n 출력억제, p 매칭시출력)
        if [ ${#NGINX_ALL_CONF[@]} -gt 0 ]; then
            CONF_SOURCE="nginx -T (실제 로드되는 설정)"
            return
        fi
    fi

    if [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
        append_conf "$NGINX_CONF"
        local extra
        for extra in "$NGINX_CONF_DIR/conf.d"/*.conf \
                     "$NGINX_CONF_DIR/default.d"/*.conf \
                     "$NGINX_CONF_DIR/sites-enabled"/* ; do
            [ -f "$extra" ] && append_conf "$extra"
        done
        collect_include_1depth "$NGINX_CONF"
        CONF_SOURCE="파일시스템 탐색 (nginx -T 실패로 폴백 - 결과 신뢰도 확인 필요)"
    fi
}

detect_env() {
    detect_conf_path
    collect_conf_files
}

#==============================================================================
# 배너 / 요약
#==============================================================================
print_banner() {
    local ngver="(nginx 명령 없음)"
    command -v nginx >/dev/null 2>&1 && ngver=$(nginx -v 2>&1 | head -1)

    log "########################################################################"
    log "#  주요정보통신기반시설 웹 서비스(Nginx) 취약점 자동 진단"
    log "#  진단 일시 : $(date '+%Y-%m-%d %H:%M:%S')"
    log "#  호스트명  : $(hostname 2>/dev/null)"
    log "#  실행 계정 : $(id -un) (uid=$(id -u))"
    log "#  OS 정보   : $( (cat /etc/rocky-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || uname -a) | head -1)"
    log "#  Nginx     : $ngver"
    log "########################################################################"
    log "[탐지된 환경]"
    log "  - 기준 설정 파일 : ${NGINX_CONF:-(탐지 실패)}"
    log "  - 목록 수집 방식 : ${CONF_SOURCE:-(없음)}"
    log "  - 진단 대상 파일 : ${#NGINX_ALL_CONF[@]}개"
    local f
    for f in "${NGINX_ALL_CONF[@]}"; do
        log "        $f"
    done
    log ""
}

print_summary() {
    line
    local total=$((CNT_GOOD + CNT_VULN + CNT_MANUAL + CNT_NA))
    log "[ Nginx 진단 결과 요약 ]"
    log "  전체 항목        : $total"
    log "  양호(GOOD)       : $CNT_GOOD"
    log "  취약(VULN)       : $CNT_VULN"
    log "  수동확인(MANUAL) : $CNT_MANUAL"
    log "  해당없음(N/A)    : $CNT_NA"
    line
    log "결과 파일: $RESULT_FILE"
}

#------------------------------------------------------------------------------
# 1. 계정 관리
#------------------------------------------------------------------------------

# WEB-01 (상) Default 관리자 계정명 변경
web_01() {
    head_item "WEB-01" "Default 관리자 계정명 변경" "상"
    info "판단기준> 양호: 관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않은 경우"
    info "          취약: 계정명이 기본 계정명으로 설정되어 있거나, 추측하기 쉬운 계정명을 사용하는 경우"
    info "가이드 점검 대상: Tomcat, JEUS  (Nginx 미포함)"
    result_na "Nginx 비대상 - 관리자 콘솔 계정 기능이 없음"
}

# WEB-02 (상) 취약한 비밀번호 사용 제한
web_02() {
    head_item "WEB-02" "취약한 비밀번호 사용 제한" "상"
    info "판단기준> 양호: 관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
    info "          취약: 관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
    info "가이드 점검 대상: Tomcat, IIS, JEUS  (Nginx 미포함)"
    result_na "Nginx 비대상 - 관리자 계정/비밀번호 기능이 없음"
}

# WEB-03 (상) 비밀번호 파일 권한 관리
web_03() {
    head_item "WEB-03" "비밀번호 파일 권한 관리" "상"
    info "판단기준> 양호: 비밀번호 파일에 권한이 600 이하로 설정된 경우"
    info "          취약: 비밀번호 파일에 권한이 600 초과로 설정된 경우"
    info "가이드 점검 대상: Tomcat, IIS, JEUS  (Nginx 미포함)"
    result_na "Nginx 비대상 - 가이드가 지정한 비밀번호 파일(tomcat-users.xml, SAM, accounts.xml)이 없음"
}

#------------------------------------------------------------------------------
# 2. 서비스 관리
#------------------------------------------------------------------------------

# grep -nH 결과에서 "줄 전체가 주석" 인 항목을 걸러낸다.
#   입력 형식 : <파일>:<줄번호>:<원문>

drop_commented() {
    local nq='[^"'"'"']'      # 따옴표가 아닌 문자
    local q='["'"'"']'        # 따옴표
    grep -vE "^[^:]*:[0-9]+:[[:space:]]*#${nq}*(${q}${nq}*${q}${nq}*)*\$"
    return 0
}

# WEB-04 (상) 웹 서비스 디렉터리 리스팅 방지 설정
#   /etc/nginx/nginx.conf 내 autoindex 문자열 확인 후 값이 off/on인지 식별
web_04() {
    head_item "WEB-04" "웹 서비스 디렉터리 리스팅 방지 설정" "상"
    info "판단기준> 양호: 디렉터리 리스팅이 설정되지 않은 경우"
    info "          취약: 디렉터리 리스팅이 설정된 경우"

    local q='["'"'"']' 
    local on_hits off_hits split_hits
    # end = 지시자 값 뒤에 올 수 있는 것 : 세미콜론 / 인라인 주석 / 줄 끝
    local end='([[:space:]]*;|[[:space:]]*#|[[:space:]]*$)'
    # grep -n : 줄번호 출력, -H : 파일명 출력
    on_hits=$(grep -nHE  "(^|[{};])[[:space:]]*${q}?autoindex${q}?[[:space:]]+${q}?[Oo][Nn]${q}?${end}"     "${NGINX_ALL_CONF[@]}" | drop_commented)
    off_hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?autoindex${q}?[[:space:]]+${q}?[Oo][Ff][Ff]${q}?${end}" "${NGINX_ALL_CONF[@]}" | drop_commented)
    split_hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?autoindex${q}?([[:space:]]*#|[[:space:]]*$)"          "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -n "$on_hits" ]; then
        info "autoindex on 설정 (취약 근거)"
        printf '%s\n' "$on_hits" | info_lines
        if [ -n "$off_hits" ]; then
            info "참고> autoindex off 설정도 함께 존재 (블록별로 다르게 적용된 상태)"
            printf '%s\n' "$off_hits" | info_lines
        fi
        result_vuln "autoindex on 설정이 존재하여 디렉터리 리스팅이 활성화됨"
    elif [ -n "$split_hits" ]; then
        info "값이 다음 줄에 있는 autoindex 지시자 (자동 판별 불가)"
        printf '%s\n' "$split_hits" | info_lines
        result_manual "autoindex 지시자가 여러 줄에 걸쳐 있음 - 설정 파일 직접 확인 필요"
    elif [ -n "$off_hits" ]; then
        printf '%s\n' "$off_hits" | info_lines
        result_good "autoindex on 설정 없음 (명시적으로 off 설정됨)"
    else
        result_good "autoindex on 설정 없음 (기본값 off 적용)"
    fi
}

# WEB-05 (상) 지정하지 않은 CGI/ISAPI 실행 제한
#   Nginx 설정파일에서 CGI 실행은 fastcgi_pass(PHP) / scgi_pass(레거시) / uwsgi_pass(python) 로 이루어진다.

web_05() {
    head_item "WEB-05" "지정하지 않은 CGI/ISAPI 실행 제한" "상"
    info "판단기준> 양호: CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
    info "          취약: CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우"

    local q='["'"'"']'
    local cgi_hits loc_hits
    cgi_hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?(fastcgi_pass|scgi_pass|uwsgi_pass)${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -z "$cgi_hits" ]; then
        info "CGI 실행 지시자(fastcgi_pass / scgi_pass / uwsgi_pass) 설정 없음"
        result_good "CGI 스크립트를 사용하지 않음"
        return
    fi

    info "CGI 실행 지시자 설정"
    printf '%s\n' "$cgi_hits" | info_lines

    # 판단 근거로 설정된 location 헤더를 함께 제시한다.
    loc_hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?location${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)
    if [ -n "$loc_hits" ]; then
        info "설정된 location 블록 (어느 블록이 CGI 를 감싸는지 대조)"
        printf '%s\n' "$loc_hits" | info_lines
    fi
    result_manual "CGI 사용 중 - 실행 가능한 디렉터리 제한 여부를 설정 파일에서 확인 필요"
}

# WEB-06 (상) 웹 서비스 상위 디렉터리 접근 제한 설정
#   Nginx location 내 auth_basic이 off, on 확인 후 on 일경우 auth_basic_user_file 설정 여부 확인 필요.
web_06() {
    head_item "WEB-06" "웹 서비스 상위 디렉터리 접근 제한 설정" "상"
    info "판단기준> 양호: 상위 디렉터리 접근 기능을 제거한 경우"
    info "          취약: 상위 디렉터리 접근 기능을 제거하지 않은 경우"

    local q='["'"'"']'
    local ab_all ab_on ab_off ab_file loc_hits
    ab_all=$(grep -nHE  "(^|[{};])[[:space:]]*${q}?auth_basic${q}?([[:space:]]|\$)"            "${NGINX_ALL_CONF[@]}" | drop_commented)
    ab_file=$(grep -nHE "(^|[{};])[[:space:]]*${q}?auth_basic_user_file${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)
    loc_hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?location${q}?[[:space:]]"                  "${NGINX_ALL_CONF[@]}" | drop_commented)

    ab_on=""; ab_off=""
    if [ -n "$ab_all" ]; then
        ab_off=$(printf '%s\n' "$ab_all" | grep -E  "auth_basic${q}?[[:space:]]+${q}?[Oo][Ff][Ff]${q}?([[:space:]]*;|[[:space:]]*#|[[:space:]]*$)")
        ab_on=$(printf  '%s\n' "$ab_all" | grep -vE "auth_basic${q}?[[:space:]]+${q}?[Oo][Ff][Ff]${q}?([[:space:]]*;|[[:space:]]*#|[[:space:]]*$)")
    fi

    if [ -n "$ab_on" ]; then
        info "auth_basic 기본 인증 설정 (활성)"
        printf '%s\n' "$ab_on" | info_lines
    else
        info "auth_basic 기본 인증 설정 없음"
    fi

    if [ -n "$ab_off" ]; then
        info "auth_basic off 설정 (해당 블록은 인증 해제 - 예외 경로 여부 확인)"
        printf '%s\n' "$ab_off" | info_lines
    fi

    if [ -n "$ab_file" ]; then
        info "auth_basic_user_file 설정"
        printf '%s\n' "$ab_file" | info_lines
    else
        [ -n "$ab_on" ] && info "auth_basic_user_file 없음 - 인증이 동작하지 않는 상태(실측: 오류 없이 그대로 열림)"
    fi

    if [ -n "$loc_hits" ]; then
        info "설정된 location 블록 (보호 범위 대조용)"
        printf '%s\n' "$loc_hits" | info_lines
    fi

    result_manual "auth_basic 설정 위치와 보호 대상 디렉터리를 대조해 판정 필요"
}

# WEB-07 (중) 웹 서비스 경로 내 불필요한 파일 제거
#   Nginx 컴파일 시 설정된 기본 설치 경로(/user/share/nginx)를 prefix로 저장
#   Nginx 설정 파일에서 root, alias 설정되있는 경로 가져옴
#   mapfile -t roots 를 통해 roots[] 배열로 검색 된 경로 중복되지 않는 상위 경로저장  

web_07() {
    head_item "WEB-07" "웹 서비스 경로 내 불필요한 파일 제거" "중"
    info "판단기준> 양호: 기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
    info "          취약: 기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우"
    info "참고> 불필요한 파일 = 샘플, 매뉴얼, 임시, 테스트, 백업 파일 등"

    local q='["'"'"']'
    local d f n prefix vals root_vars out rc
    local dflt="" sym="" susp="" scan_cut=0
    local -a roots=()

    prefix=""
    command -v nginx >/dev/null 2>&1 && \
        prefix=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's/^--prefix=//p' | head -1)

    vals=$(grep -nHE "(^|[{};])[[:space:]]*${q}?(root|alias)${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" \
           | drop_commented \
           | sed -E "s/^[^:]*:[0-9]+://; s/.*(root|alias)[[:space:]]+//; s/[;#].*//; s/^${q}//; s/${q}\$//; s/[[:space:]]+\$//")
    root_vars=$(printf '%s\n' "$vals" | grep '\$' | grep -v '^$')

    mapfile -t roots < <(
        { printf '%s\n' "$vals" | grep -v '\$'
          [ -n "$prefix" ] && printf '%s\n' "$prefix/html"
          printf '%s\n' /usr/share/nginx/html
        } | while IFS= read -r d; do
                [ -n "$d" ] || continue
                case "$d" in /*) ;; *) d="${prefix:-/usr/share/nginx}/$d" ;; esac
                d="${d%/}"
                [ -d "$d" ] && printf '%s\n' "$d"
            done | sort -u | awk '{ for (k in seen) if (index($0"/", k"/") == 1) next; seen[$0]; print }'
    )

    for d in "${roots[@]}"; do
        f="$d/index.html"
        if [ -L "$f" ]; then
            sym="${sym}${f}  -> $(readlink "$f" 2>/dev/null)"$'\n'
        elif [ -f "$f" ] && \
             grep -qiE 'welcome to nginx|test page for the nginx http server|nginx\.(org|com)' "$f" 2>/dev/null; then
            dflt="${dflt}${f}   <- nginx 기본 페이지 (내용으로 확정)"$'\n'
        fi
    done

    # (2) 백업/임시/테스트/샘플/매뉴얼 의심 파일. 웹 루트 전체를 한 번에 훑는다.
    if [ ${#roots[@]} -gt 0 ]; then
        out=$(timeout 30 find "${roots[@]}" \( \
                -iname '*.bak'  -o -iname '*.old'     -o -iname '*.orig'  -o -iname '*.save' \
             -o -iname '*.swp'  -o -iname '*.tmp'     -o -iname '*~'      -o -iname '*.backup' \
             -o -iname 'test*'  -o -iname 'sample*'   -o -iname 'example*' -o -iname 'demo*' \
             -o -iname 'phpinfo*' -o -iname 'readme*' -o -iname 'manual*' -o -iname 'changelog*' \
             -o -name '.git' -o -name '.svn' -o -name '.hg' \
             \) 2>/dev/null)
        rc=$?
        #타임아웃 오류 코드는 124 $? 의미는 return 0같은 존재
        [ "$rc" -eq 124 ] && scan_cut=1
        susp=$(printf '%s\n' "$out" | grep -v '^$')
    fi

    if [ ${#roots[@]} -gt 0 ]; then
        info "점검한 웹 루트 (${#roots[@]}개)"
        printf '%s\n' "${roots[@]}" | info_lines
    else
        info "웹 루트 디렉터리를 확정하지 못함"
    fi
    [ -n "$root_vars" ] && { info "변수가 포함되어 경로를 확정할 수 없는 root/alias 설정"; printf '%s' "$root_vars" | info_lines; }
    [ -n "$dflt" ]      && { info "nginx 기본 설치 파일 (취약 근거)";                       printf '%s' "$dflt"      | info_lines; }
    [ -n "$sym" ]       && { info "index.html 이 심볼릭 링크 (링크를 따라가지 않음)";        printf '%s' "$sym"       | info_lines; }
    if [ -n "$susp" ]; then
        n=$(printf '%s\n' "$susp" | grep -c .)
        info "백업/임시/테스트/샘플/매뉴얼 의심 파일 ${n}건 (서비스에 필요한 파일인지 확인 필요)"
        printf '%s\n' "$susp" | head -20 | info_lines
        [ "$n" -gt 20 ] && info "(상위 20건만 표시 - 나머지 $((n - 20))건은 위 경로에서 직접 확인)"
    fi
    [ "$scan_cut" -eq 1 ] && info "탐색이 30초를 넘겨 중단됨 - 전체를 확인하지 못함"
    [ -n "$dflt$sym" ] && info "조치> 링크인 경우 nginx 경로의 링크만 제거한다. 링크 대상(예: /usr/share/testpage)은 다른 패키지 소유일 수 있으므로 건드리지 않는다."

    if   [ -n "$dflt" ]; then
        result_vuln "웹 서비스 경로에 nginx 기본 설치 파일이 남아 있음"
    elif [ -n "$sym" ]; then
        result_manual "index.html 이 심볼릭 링크 - 링크 대상이 기본 페이지인지 직접 확인 필요"
    elif [ -n "$susp" ]; then
        result_manual "의심 파일이 발견됨 - 서비스에 필요한 파일인지 확인 필요"
    elif [ ${#roots[@]} -eq 0 ] || [ -n "$root_vars" ] || [ "$scan_cut" -eq 1 ]; then
        result_manual "웹 루트 경로를 확정하지 못했거나 탐색이 완료되지 않음 - 직접 확인 필요"
    else
        result_good "웹 서비스 경로에 불필요한 기본 파일이 존재하지 않음"
    fi
}

# WEB-08 (하) 웹 서비스 파일 업로드 및 다운로드 용량 제한
#    nginx.conf 에 client_max_body_size 설정, 설정이 없으면 1m이지만 확인 필요
web_08() {
    head_item "WEB-08" "웹 서비스 파일 업로드 및 다운로드 용량 제한" "하"
    info "판단기준> 양호: 파일 업로드 및 다운로드 용량을 제한한 경우"
    info "          취약: 파일 업로드 및 다운로드 용량을 제한하지 않은 경우"

    local q='["'"'"']'
    local hits vals v num b
    local zero="" over="" okv="" bad=""
    local LIMIT=5242880                      # 5MB - 가이드 조치 사례 및 권고치

    hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?client_max_body_size${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -z "$hits" ]; then
        info "client_max_body_size 설정 없음"
        info "참고> 미설정 시 nginx 기본값 1m 이 적용된다(실측 확인). 제한 자체는 동작하나"
        info "      가이드가 요구하는 명시적 용량 제한 설정은 없는 상태"
        result_manual "client_max_body_size 미설정 - 기본값 1m 적용 여부와 내부 정책 확인 필요"
        return
    fi

    info "client_max_body_size 설정"
    printf '%s\n' "$hits" | info_lines

    vals=$(printf '%s\n' "$hits" \
           | sed -E "s/^[^:]*:[0-9]+://; s/.*client_max_body_size${q}?[[:space:]]+//; s/[;#].*//; s/^${q}//; s/${q}\$//; s/[[:space:]]+\$//")

    while IFS= read -r v; do
        [ -n "$v" ] || continue
        num="${v%[kKmMgG]}"
        case "$num" in
            ''|*[!0-9]*) bad="${bad}${v}"$'\n'; continue ;;   # 숫자로 해석 불가
        esac
        case "$v" in
            *[kK]) b=$((num * 1024)) ;;
            *[mM]) b=$((num * 1024 * 1024)) ;;
            *[gG]) b=$((num * 1024 * 1024 * 1024)) ;;
            *)     b="$num" ;;
        esac
        if   [ "$b" -eq 0 ];         then zero="${zero}${v}  (무제한)"$'\n'
        elif [ "$b" -gt "$LIMIT" ];  then over="${over}${v}  (${b} bytes - 권고치 5MB 초과)"$'\n'
        else                              okv="${okv}${v}  (${b} bytes)"$'\n'
        fi
    done <<< "$vals"

    if [ -n "$zero" ]; then
        printf '%s' "$zero" | info_lines
        result_vuln "client_max_body_size 가 0(무제한)으로 설정되어 업로드 용량이 제한되지 않음"
        return
    fi

    if [ -n "$bad" ]; then
        printf '%s' "$bad" | info_lines
        result_manual "client_max_body_size 값을 해석하지 못함 - 설정 파일 직접 확인 필요"
        return
    fi

    if [ -n "$over" ]; then
        printf '%s' "$over" | info_lines
        [ -n "$okv" ] && { info "참고> 권고치 이내인 값"; printf '%s' "$okv" | info_lines; }
        result_manual "제한은 설정되어 있으나 가이드 권고치 5MB 를 초과 - 내부 정책 확인 필요"
        return
    fi

    printf '%s' "$okv" | info_lines
    result_good "client_max_body_size 로 업로드 용량이 제한되어 있음"
}

# WEB-09 (상) 웹 서비스 프로세스 권한 제한
#    ps 로 nginx: worker 사용자 추출 후 getent로 사용자 uid, shell추출 , 구동중이 아닐 겨우 conf 파일에서 user의 계정, 그룹정보 확인
web_09() {
    head_item "WEB-09" "웹 서비스 프로세스 권한 제한" "상"
    info "판단기준> 양호: 웹 프로세스가 관리자 권한이 아닌 최소 권한의 별도 계정으로 구동되는 경우"
    info "          취약: 웹 프로세스가 관리자 권한이 부여된 계정으로 구동되는 경우"

    local q='["'"'"']'
    local ps_out mst wk u line uid sh val ud
    local root_acc="" ok_acc="" unk_acc=""

    acct_line() {
        local a="$1" u2 s2
        u2=$(id -u "$a" 2>/dev/null)
        
        [ -z "$u2" ] && case "$a" in ''|*[!0-9]*) ;; *) u2="$a" ;; esac
        s2=$(getent passwd "$a" 2>/dev/null | cut -d: -f7)
        if [ -n "$u2" ]; then
            printf '%s  (uid=%s, shell=%s)\n' "$a" "$u2" "${s2:-확인불가}"
        else
            printf '%s  (uid 확인 불가 - 시스템에 없는 계정명)\n' "$a"
        fi
    }
    # ps -e : 현재 실행 중인 시스템 내 모든 사용자의 프로세스 조회 -o:  출력 포맷 지정
    ps_out=$(ps -eo user:32,args 2>/dev/null | grep 'nginx:' | grep -v grep)
    mst=$(printf '%s\n' "$ps_out" | grep 'nginx: master')
    wk=$(printf  '%s\n' "$ps_out" | grep 'nginx: worker')

    [ -n "$mst" ] && {
        info "master 프로세스 (포트 바인딩 때문에 root 구동이 정상 - 판정 대상 아님)"
        printf '%s\n' "$mst" | info_lines
    }

    if [ -n "$wk" ]; then
        info "worker 프로세스 (판정 대상) - $(printf '%s\n' "$wk" | grep -c .)개"
        printf '%s\n' "$wk" | info_lines

        # worker 는 코어 수만큼 뜬다. 계정은 중복을 제거해 한 번씩만 조회·출력한다.
        while read -r u; do
            [ -n "$u" ] || continue
            line=$(acct_line "$u")
            case "$line" in
                *"(uid=0,"*)       root_acc="${root_acc}${line}"$'\n' ;;
                *"uid 확인 불가"*) unk_acc="${unk_acc}${line}"$'\n'  ;;
                *)                 ok_acc="${ok_acc}${line}"$'\n'    ;;
            esac
        done < <(printf '%s\n' "$wk" | awk '{print $1}' | sort -u)

        [ -n "$root_acc" ] && { info "관리자 권한(uid 0)으로 구동 중인 worker 계정 (취약 근거)"; printf '%s' "$root_acc" | info_lines; }
        [ -n "$unk_acc" ]  && { info "uid 를 확인할 수 없는 worker 계정";                        printf '%s' "$unk_acc"  | info_lines; }
        [ -n "$ok_acc" ]   && { info "worker 구동 계정";                                          printf '%s' "$ok_acc"   | info_lines; }

        if   [ -n "$root_acc" ]; then
            result_vuln "worker 프로세스가 관리자 권한 계정으로 구동되고 있음"
        elif [ -n "$unk_acc" ]; then
            result_manual "worker 계정의 uid 를 확인하지 못함 - 관리자 권한 여부 직접 확인 필요"
        else
            result_good "worker 프로세스가 관리자 권한이 아닌 별도 계정으로 구동되고 있음"
        fi
        return
    fi

    # ---- worker 미구동 : 설정의 user 지시자로 폴백 ----
    info "nginx worker 프로세스가 구동되어 있지 않음 - 설정의 user 지시자로 확인"
    ud=$(grep -nHE "(^|[{};])[[:space:]]*${q}?user${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -z "$ud" ]; then
        result_manual "worker 미구동 + user 지시자 미설정 - 실제 구동 계정 직접 확인 필요"
        return
    fi

    info "user 지시자 설정"
    printf '%s\n' "$ud" | info_lines

    # 값의 첫 토큰이 실행 계정이다 (user <계정> [그룹];)
    val=$(printf '%s\n' "$ud" \
          | sed -E "s/^[^:]*:[0-9]+://; s/.*${q}?user${q}?[[:space:]]+//; s/[;#].*//; s/^${q}//; s/${q}\$//" \
          | sed -E 's/[[:space:]].*//' | grep -v '^$' | head -1)
    info "설정된 실행 계정 : $(acct_line "${val:-확인불가}")"

    if [ "$(id -u "$val" 2>/dev/null)" = "0" ]; then
        result_vuln "user 지시자가 관리자 권한 계정($val)으로 설정되어 있음"
    else
        result_manual "설정상 별도 계정($val)이나 worker 미구동으로 실제 구동 계정 미확인"
    fi
}

# WEB-10 (상) 불필요한 프록시 설정 제한
#   nginx.conf 에서 proxy_pass, grpc_pass 설정 여부를 확인하고 해당 설정이 upstream, location 어디에 설정된 것인지 증적을 남김

web_10() {
    head_item "WEB-10" "불필요한 프록시 설정 제한" "상"
    info "판단기준> 양호: 불필요한 Proxy 설정을 제한한 경우"
    info "          취약: 불필요한 Proxy 설정을 제한하지 않은 경우"

    local q='["'"'"']'
    local px up loc

    px=$(grep -nHE "(^|[{};])[[:space:]]*${q}?(proxy_pass|grpc_pass)${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -z "$px" ]; then
        info "프록시 설정(proxy_pass / grpc_pass) 없음"
        result_good "프록시 설정이 없어 불필요한 프록시가 존재하지 않음"
        return
    fi

    info "프록시 설정 (증적)"
    printf '%s\n' "$px" | info_lines

    up=$(grep -nHE "(^|[{};])[[:space:]]*${q}?upstream${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)
    if [ -n "$up" ]; then
        info "upstream 블록 정의 (프록시 대상 백엔드 대조용)"
        printf '%s\n' "$up" | info_lines
    fi

    loc=$(grep -nHE "(^|[{};])[[:space:]]*${q}?location${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)
    if [ -n "$loc" ]; then
        info "설정된 location 블록 (어느 경로가 프록시되는지 대조용)"
        printf '%s\n' "$loc" | info_lines
    fi

    result_manual "프록시 설정이 존재함 - 서비스에 필요한 설정인지 직접 확인 필요"
}

# WEB-11 (중) 웹 서비스 경로 설정 
#   conf 파일들 내 root 설정을 가져와 /usr/share/nginx(웹 기본 서버: --prefix=) 경로 인지 확인
web_11() {
    head_item "WEB-11" "웹 서비스 경로 설정" "중"
    info "판단기준> 양호: 웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
    info "          취약: 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우"

    local q='["'"'"']'
    local hits prefix ln raw v p dflt
    local base="" sep="" undet=""

    prefix=""
    command -v nginx >/dev/null 2>&1 && \
        prefix=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's/^--prefix=//p' | head -1)
    dflt="${prefix:-/usr/share/nginx}/html"

    hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?root${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -z "$hits" ]; then
        result_vuln "root 미설정 - nginx 기본 경로($dflt)를 그대로 사용"
        return
    fi

    info "root 지시자 설정"
    printf '%s\n' "$hits" | info_lines

    # ${변수값%패턴} : 패턴에 검색되면 변수 값 끝에 슬래시가 있는 경우 제거
    while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        raw=$(printf '%s' "$ln" | sed -E 's/^[^:]*:[0-9]+://')
        if printf '%s' "$raw" | grep -qE "(^|[^A-Za-z0-9_])${q}?root${q}?[[:space:]]*\$"; then
            undet="${undet}${ln}  (값이 다음 줄에 있어 경로 확정 불가)"$'\n'; continue
        fi
        v=$(printf '%s' "$raw" \
            | sed -E "s/.*${q}?root${q}?[[:space:]]+//; s/[;#].*//; s/^[[:space:]]+//; s/^${q}//; s/${q}\$//; s/[[:space:]]+\$//")
        [ -n "$v" ] || continue
        case "$v" in
            *'$'*) undet="${undet}${ln}  (변수 포함 - 경로 확정 불가)"$'\n'; continue ;;
            /*)    p="${v%/}" ;;
            *)     p="${prefix:-/usr/share/nginx}/${v}"; p="${p%/}" ;;
        esac
        [ -z "$p" ] && p="/"

        case "$p" in
            "$dflt"|/usr/share/nginx/html) base="${base}${v}  ->  ${p}  (nginx 기본 경로)"$'\n' ;;
            *)                             sep="${sep}${v}  ->  ${p}"$'\n' ;;
        esac
    done <<< "$hits"

    [ -n "$base" ]  && { info "nginx 기본 경로를 그대로 사용 (취약 근거)"; printf '%s' "$base"  | sort -u | info_lines; }
    [ -n "$sep" ]   && { info "기본 경로와 분리된 경로";                   printf '%s' "$sep"   | sort -u | info_lines; }
    [ -n "$undet" ] && { info "경로를 확정할 수 없는 root 설정";            printf '%s' "$undet" | info_lines; }

    if [ -n "$base" ]; then
        result_vuln "웹 서비스 경로가 nginx 기본 경로와 분리되어 있지 않음"
    elif [ -n "$undet" ]; then
        result_manual "경로를 확정하지 못한 root 설정이 있음 - 위 파일·줄에서 직접 확인 필요"
    else
        result_manual "기본 경로와는 분리됨 - 불필요한 경로 존재 여부는 직접 확인 필요"
    fi
}

# WEB-12 (중) 웹 서비스 링크 사용 금지
#   nignx 설정파일에설 disable_symlinks 설정이 on 인지, alias 사용 확인. 
web_12() {
    head_item "WEB-12" "웹 서비스 링크 사용 금지" "중"
    info "판단기준> 양호: 심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
    info "          취약: 심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하는 경우"

    local q='["'"'"']'
    local ds als loc ln raw v
    local ds_on="" ds_off="" ds_ino="" ds_unk=""

    ds=$(grep -nHE  "(^|[{};])[[:space:]]*${q}?disable_symlinks${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)
    als=$(grep -nHE "(^|[{};])[[:space:]]*${q}?alias${q}?([[:space:]]|\$)"            "${NGINX_ALL_CONF[@]}" | drop_commented)
    loc=$(grep -nHE "(^|[{};])[[:space:]]*${q}?location${q}?[[:space:]]"              "${NGINX_ALL_CONF[@]}" | drop_commented)

    while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        raw="${ln#*:*:}"
        if printf '%s' "$raw" | grep -qE "(^|[^A-Za-z0-9_])${q}?disable_symlinks${q}?[[:space:]]*\$"; then
            ds_unk="${ds_unk}${ln}  (값이 다음 줄에 있어 확정 불가)"$'\n'; continue
        fi
        v=$(printf '%s' "$raw" \
            | sed -E "s/.*${q}?disable_symlinks${q}?[[:space:]]+//; s/[;#].*//; s/^[[:space:]]+//; s/^${q}//; s/${q}\$//" \
            | sed -E 's/[[:space:]].*//') 
        case "$v" in
            on)           ds_on="${ds_on}${ln}"$'\n' ;;
            off)          ds_off="${ds_off}${ln}"$'\n' ;;
            if_not_owner) ds_ino="${ds_ino}${ln}"$'\n' ;;
            *)            ds_unk="${ds_unk}${ln}  (값 해석 불가: ${v})"$'\n' ;;
        esac
    done <<< "$ds"

    [ -z "$ds" ] && {
        info "disable_symlinks 설정 없음"
    }
    [ -n "$ds_on" ]  && { info "disable_symlinks on (링크 차단)";                  printf '%s' "$ds_on"  | info_lines; }
    [ -n "$ds_ino" ] && { info "disable_symlinks if_not_owner (소유자가 같으면 서빙된다 - 실측 확인)"; printf '%s' "$ds_ino" | info_lines; }
    [ -n "$ds_off" ] && { info "disable_symlinks off (링크 허용 상태)";            printf '%s' "$ds_off" | info_lines; }
    [ -n "$ds_unk" ] && { info "값을 확정하지 못한 설정";                          printf '%s' "$ds_unk" | info_lines; }
    [ -n "$als" ]    && { info "alias 설정 (점검 내용의 aliases 에 해당 - 증적)";  printf '%s\n' "$als"  | info_lines; }
    [ -n "$ds_on$ds_ino$ds_unk" ] && [ -n "$loc" ] && {
        info "설정된 location 블록 (disable_symlinks 적용 범위 대조용)"
        printf '%s\n' "$loc" | info_lines
    }

    if [ -z "$ds_on$ds_ino$ds_unk" ]; then
        result_vuln "disable_symlinks 미설정 또는 off - 심볼릭 링크 사용이 허용된 상태"
    elif [ -n "$ds_unk" ]; then
        result_manual "disable_symlinks 값을 확정하지 못함 - 설정 파일 직접 확인 필요"
    elif [ -z "$ds_on" ]; then
        result_manual "disable_symlinks 가 if_not_owner 로만 설정됨 - 부분 제한 상태"
    else
        result_manual "disable_symlinks on 설정 확인 - 모든 디렉터리 적용 여부 직접 확인 필요"
    fi
}

# WEB-13 (상) 웹 서비스 설정 파일 노출 제한
web_13() {
    head_item "WEB-13" "웹 서비스 설정 파일 노출 제한" "상"
    info "판단기준> 양호: 일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우"
    info "          취약: DB 연결 파일 접근을 제한하지 않거나, 불필요한 스크립트 매핑이 제거되지 않은 경우"
    info "가이드 점검 대상: Tomcat, IIS, JEUS  (Nginx 미포함)"
    result_na "Nginx 비대상 - DB 연결 리소스 설정과 스크립트 매핑 기능이 없음"
}

# WEB-14 (상) 웹 서비스 경로 내 파일의 접근 통제
#   nignx 설정 파일들을 먼저 가져오고, 그 뒤 설정 파일의 디렉터리 및 /etc/nginx 및 하위 디렉터리 정보를 가져와 설정파일, 디렉터리 other 권한 검사 진행
web_14() {
    head_item "WEB-14" "웹 서비스 경로 내 파일의 접근 통제" "상"
    info "판단기준> 양호: 주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
    info "          취약: 주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우"
    info "대상> nginx 주요 설정 파일과 그 디렉터리 (가이드의 web.xml 은 Tomcat 파일이라 대체)"

    local f d p o owner e
    local -a targets=()
    local bad="" ok="" unk=""

    for f in "${NGINX_ALL_CONF[@]}"; do
        targets+=("$f")
    done
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        for e in "${targets[@]}"; do [ "$e" = "$d" ] && continue 2; done
        targets+=("$d")
    done < <( { for f in "${NGINX_ALL_CONF[@]}"; do dirname "$f"; done
                if [ -n "$NGINX_CONF_DIR" ]; then
                    for d in "$NGINX_CONF_DIR" "$NGINX_CONF_DIR/conf.d" \
                             "$NGINX_CONF_DIR/default.d" "$NGINX_CONF_DIR/sites-enabled"; do
                        [ -d "$d" ] && printf '%s\n' "$d"
                    done
                fi; } | sort -u )

    for f in "${targets[@]}"; do
        p=$(fperm "$f")
        owner=$(fowner "$f")
        if [ -z "$p" ]; then
            unk="${unk}${f}  (권한 확인 불가)"$'\n'
            continue
        fi
        o=$(perm_other "$p")
        case "$o" in
            ''|*[!0-9]*) unk="${unk}${f}  ${p}  (권한 해석 불가)"$'\n' ;;
            0)           ok="${ok}${f}  ${p}  ${owner}"$'\n' ;;
            *)           bad="${bad}${f}  ${p}  ${owner}  (other 권한 ${o})"$'\n' ;;
        esac
    done

    if [ -n "$bad" ]; then
        info "일반 사용자(other) 접근 권한이 남아 있는 대상 (취약 근거)"
        printf '%s' "$bad" | info_lines
        [ -n "$ok" ] && { info "참고> other 권한이 제거된 대상"; printf '%s' "$ok" | info_lines; }
        [ -n "$unk" ] && { info "참고> 권한을 확인하지 못한 대상"; printf '%s' "$unk" | info_lines; }
        result_vuln "주요 설정 파일/디렉터리에 일반 사용자 접근 권한이 부여되어 있음"
        return
    fi

    if [ -n "$unk" ]; then
        printf '%s' "$unk" | info_lines
        [ -n "$ok" ] && { info "참고> 확인된 대상"; printf '%s' "$ok" | info_lines; }
        result_manual "일부 대상의 권한을 확인하지 못함 - 직접 확인 필요"
        return
    fi

    printf '%s' "$ok" | info_lines
    result_good "주요 설정 파일/디렉터리에 일반 사용자 접근 권한이 없음"
}

# WEB-15 (상) 웹 서비스의 불필요한 스크립트 매핑 제거
web_15() {
    head_item "WEB-15" "웹 서비스의 불필요한 스크립트 매핑 제거" "상"
    info "판단기준> 양호: 불필요한 스크립트 매핑이 존재하지 않는 경우"
    info "          취약: 불필요한 스크립트 매핑이 존재하는 경우"
    info "가이드 점검 대상: Tomcat, IIS, JEUS  (Nginx 미포함)"
    result_na "Nginx 비대상 - servlet-mapping/처리기 매핑 기능이 없음"
}

# WEB-16 (중) 웹 서비스 헤더 정보 노출 제한
#   설정 파일 에서 server 나 location 내 server_tokens 설정이 off 인지 확인
web_16() {
    head_item "WEB-16" "웹 서비스 헤더 정보 노출 제한" "중"
    info "판단기준> 양호: HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
    info "          취약: HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우"

    local q='["'"'"']'
    local st loc ln raw v
    local st_off="" st_on="" st_unk=""

    st=$(grep -nHE  "(^|[{};])[[:space:]]*${q}?server_tokens${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)
    loc=$(grep -nHE "(^|[{};])[[:space:]]*${q}?(server|location)${q}?([[:space:]]|\{)" "${NGINX_ALL_CONF[@]}" | drop_commented)

    # 값별로 분류한다. 증거는 파일:줄 을 붙인 원본($ln)을 그대로 남긴다.
    while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        raw="${ln#*:*:}"
        if printf '%s' "$raw" | grep -qE "(^|[^A-Za-z0-9_])${q}?server_tokens${q}?[[:space:]]*\$"; then
            st_unk="${st_unk}${ln}  (값이 다음 줄에 있어 확정 불가)"$'\n'; continue
        fi
        v=$(printf '%s' "$raw" \
            | sed -E "s/.*${q}?server_tokens${q}?[[:space:]]+//; s/[;#].*//; s/^[[:space:]]+//; s/^${q}//; s/${q}\$//; s/[[:space:]]+\$//")
        case "$v" in
            [Oo][Ff][Ff])                    st_off="${st_off}${ln}"$'\n' ;;
            [Oo][Nn]|[Bb][Uu][Ii][Ll][Dd])   st_on="${st_on}${ln}  (버전 노출)"$'\n' ;;
            *)                               st_unk="${st_unk}${ln}  (값 해석 불가: ${v})"$'\n' ;;
        esac
    done <<< "$st"

    [ -n "$st_on" ]  && { info "버전을 노출하는 설정 (취약 근거)"; printf '%s' "$st_on"  | info_lines; }
    [ -n "$st_unk" ] && { info "값을 확정하지 못한 설정";          printf '%s' "$st_unk" | info_lines; }
    [ -n "$st_off" ] && { info "server_tokens off 설정";           printf '%s' "$st_off" | info_lines; }

    [ -z "$st_on$st_unk" ] && [ -n "$st_off" ] && [ -n "$loc" ] && {
        info "설정된 server / location 블록 (적용 범위 대조용)"
        printf '%s\n' "$loc" | info_lines
    }

    if [ -z "$st" ]; then
        result_vuln "server_tokens 미설정 - 응답 헤더에 웹 서버 버전이 노출됨"
    elif [ -n "$st_on" ]; then
        result_vuln "server_tokens 가 on/build 로 설정됨 - 응답 헤더에 웹 서버 버전이 노출됨"
    elif [ -n "$st_unk" ]; then
        result_manual "server_tokens 값을 확정하지 못함 - 설정 파일 직접 확인 필요"
    else
        result_manual "server_tokens off 설정은 있으나 적용 블록 범위 확인 필요 - 실제 응답 헤더 확인 필요"
    fi
}

# WEB-17 (중) 웹 서비스 가상 디렉터리 삭제
#   설정 파일들 에서 alias 존재 여부를 확인하고 있다면 값을 가져와서 비교
web_17() {
    head_item "WEB-17" "웹 서비스 가상 디렉터리 삭제" "중"
    info "판단기준> 양호: 불필요한 가상 디렉터리가 존재하지 않는 경우"
    info "          취약: 불필요한 가상 디렉터리가 존재하는 경우"
    info "참고> Nginx 의 가상 디렉터리는 location 블록의 alias 지시자로 만든다"

    local q='["'"'"']'
    local hits loc ln raw v note detail=""

    hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?alias${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -z "$hits" ]; then
        result_good "가상 디렉터리(alias) 설정이 존재하지 않음"
        return
    fi

    while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        raw="${ln#*:*:}"
        if printf '%s' "$raw" | grep -qE "(^|[^A-Za-z0-9_])${q}?alias${q}?[[:space:]]*\$"; then
            detail="${detail}${ln}   (경로가 다음 줄에 있어 확정 불가)"$'\n'; continue
        fi
        v=$(printf '%s' "$raw" \
            | sed -E "s/.*${q}?alias${q}?[[:space:]]+//; s/[;#].*//; s/^${q}//; s/${q}\$//; s/[[:space:]]+\$//")
        case "$v" in
            '')    note="(경로 확정 불가)" ;;
            *'$'*) note="-> $v  (변수 포함 - 실제 경로 직접 확인)" ;;
            *)     if   [ -d "$v" ]; then note="-> $v  (디렉터리 존재)"
                   elif [ -e "$v" ]; then note="-> $v  (파일 존재)"
                   else                   note="-> $v  (대상 없음 - 요청 시 404)"
                   fi ;;
        esac
        detail="${detail}${ln}   ${note}"$'\n'
    done <<< "$hits"

    info "alias 설정 (가상 디렉터리) - 대상 경로와 존재 여부 포함"
    printf '%s' "$detail" | info_lines

    loc=$(grep -nHE "(^|[{};])[[:space:]]*${q}?location${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)
    [ -n "$loc" ] && { info "설정된 location 블록 (가상 디렉터리 URL 대조용)"; printf '%s\n' "$loc" | info_lines; }

    result_manual "가상 디렉터리(alias) 설정이 존재함 - 서비스에 필요한 설정인지 직접 확인 필요"
}

# WEB-18 (상) 웹 서비스 WebDAV 비활성화   [가이드 점검 대상: Nginx 포함]
#   설정 파일들에서 dav_methods, dav_ext_methods 설정을 확인해서 선언이 없거나 off 인지 확인
web_18() {
    head_item "WEB-18" "웹 서비스 WebDAV 비활성화" "상"
    info "판단기준> 양호: WebDAV 서비스를 비활성화하고 있는 경우"
    info "          취약: WebDAV 서비스를 활성화하고 있는 경우"

    local q='["'"'"']'
    local hits ext ln raw v mod
    local on="" off="" unk=""

    hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?dav_methods${q}?([[:space:]]|\$)"     "${NGINX_ALL_CONF[@]}" | drop_commented)
    ext=$(grep -nHE  "(^|[{};])[[:space:]]*${q}?dav_ext_methods${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)

    if command -v nginx >/dev/null 2>&1; then
        if nginx -V 2>&1 | grep -q 'http_dav_module'; then mod="포함"; else mod="미포함"; fi
        info "빌드 모듈> ngx_http_dav_module ${mod}"
    fi

    while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        raw=$(printf '%s' "$ln" | sed -E 's/^[^:]*:[0-9]+://')
        if printf '%s' "$raw" | grep -qE "(^|[^A-Za-z0-9_])${q}?dav_methods${q}?[[:space:]]*\$"; then
            unk="${unk}${ln}  (값이 다음 줄에 있어 확정 불가)"$'\n'
            continue
        fi
        v=$(printf '%s' "$raw" \
            | sed -E "s/.*${q}?dav_methods${q}?[[:space:]]+//; s/[;#].*//; s/${q}//g; s/[[:space:]]+/ /g; s/^ //; s/ \$//")
        case "$(printf '%s' "$v" | tr 'A-Z' 'a-z')" in
            off) off="${off}${ln}"$'\n' ;;
            '')  unk="${unk}${ln}  (값 확정 불가)"$'\n' ;;
            *)   on="${on}${ln}  (허용 메서드: ${v})"$'\n' ;;
        esac
    done <<< "$hits"

    if [ -n "$on" ] || [ -n "$ext" ]; then
        [ -n "$on" ]  && printf '%s' "$on" | info_lines
        [ -n "$ext" ] && { info "dav_ext_methods (WebDAV 확장 메서드)"; printf '%s\n' "$ext" | info_lines; }
        [ -n "$off" ] && { info "참고> off 로 설정된 블록도 존재 (블록별로 다르게 적용된 상태)"; printf '%s' "$off" | info_lines; }
        result_vuln "WebDAV(dav_methods)가 활성화되어 있음 - PUT/DELETE 등 파일 조작이 가능"
        return
    fi

    if [ -n "$unk" ]; then
        printf '%s' "$unk" | info_lines
        result_manual "dav_methods 값을 확정하지 못함 - 설정 파일 직접 확인 필요"
        return
    fi

    if [ -n "$off" ]; then
        printf '%s' "$off" | info_lines
    else
        info "dav_methods 설정 없음 (기본값 off)"
    fi
    result_good "WebDAV 가 비활성화되어 있음"
}

#------------------------------------------------------------------------------
# 3. 보안 설정
#------------------------------------------------------------------------------

# WEB-19 (중) 웹 서비스 SSI(Server Side Includes) 사용 제한   [가이드 점검 대상: Nginx 포함]
#   설정 파일들에서 ssi 설정을 확인해서 off 확인(선언 없으면 default 값으로 off)
web_19() {
    head_item "WEB-19" "웹 서비스 SSI 사용 제한" "중"
    info "판단기준> 양호: 웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
    info "          취약: 웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"

    local q='["'"'"']'
    local hits ln raw v
    local on="" off="" unk=""

    hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?ssi${q}?([[:space:]]|\$)" "${NGINX_ALL_CONF[@]}" | drop_commented)

    while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        raw=$(printf '%s' "$ln" | sed -E 's/^[^:]*:[0-9]+://')
        if printf '%s' "$raw" | grep -qE "(^|[^A-Za-z0-9_])${q}?ssi${q}?[[:space:]]*\$"; then
            unk="${unk}${ln}  (값이 다음 줄에 있어 확정 불가)"$'\n'
            continue
        fi
        v=$(printf '%s' "$raw" \
            | sed -E "s/.*${q}?ssi${q}?[[:space:]]+//; s/[;#].*//; s/^${q}//; s/${q}\$//; s/[[:space:]]+\$//")
        case "$(printf '%s' "$v" | tr 'A-Z' 'a-z')" in
            on)  on="${on}${ln}"$'\n' ;;
            off) off="${off}${ln}"$'\n' ;;
            *)   unk="${unk}${ln}  (값 해석 불가: ${v})"$'\n' ;;
        esac
    done <<< "$hits"

    if [ -n "$on" ]; then
        printf '%s' "$on" | info_lines
        [ -n "$off" ] && { printf '%s' "$off" | info_lines; }
        result_vuln "SSI(ssi on)가 활성화되어 있음 - 서버 측 파일 삽입/변수 노출이 가능"
        return
    fi

    if [ -n "$unk" ]; then
        printf '%s' "$unk" | info_lines
        result_manual "ssi 값을 확정하지 못함 - 설정 파일 직접 확인 필요"
        return
    fi

    if [ -n "$off" ]; then
        printf '%s' "$off" | info_lines
    else
        info "ssi 설정 없음 (기본값 off)"
    fi

    result_good "SSI 가 비활성화되어 있음"
}

# WEB-20 (상) SSL/TLS 활성화   [가이드 점검 대상: Nginx 포함]
#   설정 파일 내 server에 listen 설정 내 "ssl" 이 선언 되어 있는가 확인하고 선언 되어 있을 경우 ssl_certificate, ssl_certificate 값이 있는지 확인
web_20() {
    head_item "WEB-20" "SSL/TLS 활성화" "상"
    info "판단기준> 양호: SSL/TLS 설정이 활성화되어 있는 경우"
    info "          취약: SSL/TLS 설정이 비활성화되어 있는 경우"

    local q='["'"'"']'
    local lis ssl_lis="" cert key prot ciph ln raw v detail=""

    lis=$(grep -nHE "(^|[{};])[[:space:]]*${q}?listen${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)
    while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        raw=$(printf '%s' "$ln" | sed -E 's/^[^:]*:[0-9]+://; s/#.*//')
        if printf '%s' "$raw" | grep -qE "[[:space:]]${q}?ssl${q}?([[:space:]]|;|\$)"; then
            ssl_lis="${ssl_lis}${ln}"$'\n'
        fi
    done <<< "$lis"
    ssl_lis=$(printf '%s' "$ssl_lis" | grep -v '^$')

    cert=$(grep -nHE "(^|[{};])[[:space:]]*${q}?ssl_certificate${q}?[[:space:]]"     "${NGINX_ALL_CONF[@]}" | drop_commented)
    key=$(grep -nHE  "(^|[{};])[[:space:]]*${q}?ssl_certificate_key${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)
    prot=$(grep -nHE "(^|[{};])[[:space:]]*${q}?ssl_protocols${q}?[[:space:]]"       "${NGINX_ALL_CONF[@]}" | drop_commented)
    ciph=$(grep -nHE "(^|[{};])[[:space:]]*${q}?(ssl_ciphers|ssl_prefer_server_ciphers)${q}?[[:space:]]" \
                     "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -n "$ssl_lis" ]; then
        info "SSL/TLS 가 활성화된 접점 (listen 의 ssl 파라미터)"
        printf '%s\n' "$ssl_lis" | info_lines

        # 인증서 경로와 파일 존재 여부를 증적으로 남긴다
        while IFS= read -r ln; do
            [ -n "$ln" ] || continue
            v=$(printf '%s' "$ln" | sed -E "s/^[^:]*:[0-9]+://; s/.*${q}?ssl_certificate(_key)?${q}?[[:space:]]+//; s/[;#].*//; s/^${q}//; s/${q}\$//; s/[[:space:]]+\$//")
            case "$v" in
                ''|*'$'*) detail="${detail}${ln}"$'\n' ;;
                *)        if [ -f "$v" ]; then detail="${detail}${ln}   -> 파일 존재"$'\n'
                          else detail="${detail}${ln}   -> 파일 없음"$'\n'; fi ;;
            esac
        done <<< "$(printf '%s\n%s\n' "$cert" "$key" | grep -v '^$')"
        [ -n "$detail" ] && { info "인증서 설정"; printf '%s' "$detail" | info_lines; }

        [ -n "$prot" ] && { info "참고> ssl_protocols 설정"; printf '%s\n' "$prot" | info_lines; }
        [ -n "$ciph" ] && { info "참고> 암호 스위트 설정"; printf '%s\n' "$ciph" | info_lines; }
        result_manual "SSL/TLS 는 활성화되어 있음 - 프로토콜/암호 스위트 적절성은 직접 확인 필요"
        return
    fi

    info "listen 에 ssl 파라미터가 있는 접점 없음 - SSL/TLS 미사용"
    [ -n "$lis" ] && { info "설정된 listen (ssl 없음)"; printf '%s\n' "$lis" | info_lines; }
    if [ -n "$cert" ] || [ -n "$key" ] || [ -n "$prot" ] || [ -n "$ciph" ]; then
        info "참고> SSL 관련 지시자는 있으나 listen 에 ssl 이 없어 HTTPS 로 동작하지 않음(실측 확인)"
        printf '%s\n' "$cert" "$key" "$prot" "$ciph" | grep -v '^$' | info_lines
    fi
    info "조치> 인증서/개인키를 준비하고 listen 443 ssl; 과 ssl_certificate(_key) 설정"
    result_vuln "SSL/TLS 가 비활성화되어 있음 - 데이터가 평문으로 전송됨"
}

# WEB-21 (중) HTTP 리디렉션
#     HTTP server 없으면 양호, HTTP server + https 리다이렉트 설정시 수동확인
#     HTTP server + 리다이렉트 없을 시 취약
#     설정 파일들에서 listen 값을 가져와서 ssl 설정이 있는가 확인 후 http 설정된 location에서 return 30[0] https:// 로 리다이 렉트 하는 가 확인
web_21() {
    head_item "WEB-21" "HTTP 리디렉션" "중"
    info "판단기준> 양호: HTTP 접근 시 HTTPS Redirection 이 활성화된 경우"
    info "          취약: HTTP 접근 시 HTTPS Redirection 이 비활성화된 경우"

    local q='["'"'"']'
    local lis ln raw
    local http_srv="" red="" red_unk=""

    lis=$(grep -nHE "(^|[{};])[[:space:]]*${q}?listen${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)

    while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        raw=$(printf '%s' "$ln" | sed -E 's/^[^:]*:[0-9]+://; s/#.*//')
        printf '%s' "$raw" | grep -qE "[[:space:]]${q}?ssl${q}?([[:space:]]|;|\$)" || http_srv="${http_srv}${ln}"$'\n'
    done <<< "$lis"
    http_srv=$(printf '%s' "$http_srv" | grep -v '^$')

    if [ -z "$http_srv" ]; then
        info "HTTP 로 접속되는 server 없음 (전부 https)"
        [ -n "$lis" ] && { info "설정된 listen"; printf '%s\n' "$lis" | info_lines; }
        result_good "HTTP 로 접속할 수 있는 server 가 없음"
        return
    fi

    info "HTTP 로 접속되는 server (listen 에 ssl 없음)"
    printf '%s\n' "$http_srv" | info_lines

    red=$(grep -nHE "(^|[{};])[[:space:]]*${q}?(return${q}?[[:space:]]+30[0-9]|rewrite${q}?[[:space:]])[^;]*${q}?https://" \
                    "${NGINX_ALL_CONF[@]}" | drop_commented)
    red_unk=$(grep -nHE "(^|[{};])[[:space:]]*${q}?return${q}?[[:space:]]+30[0-9][[:space:]]*\$" \
                        "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -n "$red" ]; then
        info "https:// 로 보내는 리다이렉션 설정"
        printf '%s\n' "$red" | info_lines
        [ -n "$red_unk" ] && { info "참고> 대상이 다음 줄에 있어 확정하지 못한 return"; printf '%s\n' "$red_unk" | info_lines; }
        result_manual "HTTPS 리다이렉션 설정 확인 - HTTP server 전부에 적용되는지 직접 확인 필요"
        return
    fi

    if [ -n "$red_unk" ]; then
        printf '%s\n' "$red_unk" | info_lines
        result_manual "리다이렉트 대상을 확정하지 못함 - 설정 파일 직접 확인 필요"
        return
    fi

    result_vuln "HTTP 로 접속되는 server 에 HTTPS 리다이렉션이 설정되어 있지 않음"
}

# WEB-22 (하) 에러 페이지 관리   [가이드 점검 대상: Nginx 포함]
#   설정 파일에서 error_page 값을 확인
web_22() {
    head_item "WEB-22" "에러 페이지 관리" "하"
    info "판단기준> 양호: 웹 서비스 에러 페이지가 별도로 지정된 경우"
    info "          취약: 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우"

    local q='["'"'"']'
    local hits

    hits=$(grep -nHE "(^|[{};])[[:space:]]*${q}?error_page${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" | drop_commented)

    if [ -z "$hits" ]; then
        result_vuln "에러 페이지가 별도로 지정되어 있지 않음"
        return
    fi

    printf '%s\n' "$hits" | info_lines
    result_manual "에러 페이지가 지정되어 있음 - 코드 범위와 페이지 내용은 직접 확인 필요"
}

# WEB-23 (중) LDAP 알고리즘 적절하게 구성 
web_23() {
    head_item "WEB-23" "LDAP 알고리즘 적절하게 구성" "중"
    info "판단기준> 양호: LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
    info "          취약: LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하지 않는 경우"
    info "가이드 점검 대상: Tomcat  (Nginx 미포함)"
    result_na "Nginx 비대상 - LDAP 연결 인증 기능이 없음"
}

#------------------------------------------------------------------------------
# 4. 패치 및 로그 관리
#------------------------------------------------------------------------------

# WEB-24 (중) 별도의 업로드 경로 사용 및 권한 설정   [가이드 점검 대상: Nginx 포함]
#   설정 파일들 중에 root, alias 설정 경로 확인 하고 해당 경로에 대하여 other 권한 제거 여부 확인
web_24() {
    head_item "WEB-24" "별도의 업로드 경로 사용 및 권한 설정" "중"
    info "판단기준> 양호: 별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
    info "          취약: 별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"

    local q='["'"'"']'
    local d p own o kind line
    local detail=""

    # 웹 서비스 경로(root / alias)와 권한
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        kind=${line%%$'\t'*}; d=${line#*$'\t'}
        case "$d" in
            *'$'*) detail="${detail}${kind}  ${d}  (변수 포함 - 실제 경로 직접 확인)"$'\n'; continue ;;
            /*)    ;;
            *)     detail="${detail}${kind}  ${d}  (상대경로 - 실제 경로 직접 확인)"$'\n'; continue ;;
        esac
        if [ -d "$d" ]; then
            p=$(fperm "$d"); own=$(fowner "$d"); o=$(perm_other "$p")
            case "$o" in
                ''|*[!0-9]*) detail="${detail}${kind}  ${d}  ${p}  ${own}  (권한 해석 불가)"$'\n' ;;
                0)           detail="${detail}${kind}  ${d}  ${p}  ${own}"$'\n' ;;
                *)           detail="${detail}${kind}  ${d}  ${p}  ${own}  (일반 사용자 접근 권한 ${o})"$'\n' ;;
            esac
        else
            detail="${detail}${kind}  ${d}  (경로 없음)"$'\n'
        fi
    done < <(grep -nHE "(^|[{};])[[:space:]]*${q}?(root|alias)${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" \
             | drop_commented \
             | sed -E "s/^[^:]*:[0-9]+://; s/#.*//" \
             | sed -E "s/.*${q}?(root|alias)${q}?[[:space:]]+/\1\t/; s/[;].*//; s/${q}//g; s/[[:space:]]+\$//" \
             | sort -u)

    if [ -n "$detail" ]; then
        printf '%s' "$detail" | info_lines
    else
        info "설정에서 웹 서비스 경로(root/alias)를 찾지 못함"
    fi

    result_manual "업로드 경로는 애플리케이션 구성이라 설정만으로 확정 불가 - 경로와 권한 직접 확인 필요"
}

# WEB-25 (상) 주기적 보안 패치 및 벤더 권고사항 적용
#   nginx -v 로 버전 정보 확인, 증적 정보를 위해 rpm -qa로 설치된 nginx 들을 출력.
web_25() {
    head_item "WEB-25" "주기적 보안 패치 및 벤더 권고사항 적용" "상"
    info "판단기준> 양호: 최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
    info "          취약: 최신 보안 패치가 적용되어 있지 않거나 패치 적용 정책 수립 및 주기적인 패치 관리를 하지 않는 경우"

    local ver pkg

    if command -v nginx >/dev/null 2>&1; then
        ver=$(nginx -v 2>&1 | head -1)
        if [ -n "$ver" ]; then
            info "설치된 버전"
            printf '%s\n' "$ver" | info_lines
        else
            info "nginx -v 로 버전을 확인하지 못함"
        fi
    else
        info "nginx 실행 파일을 찾지 못해 버전을 확인하지 못함"
    fi

    if command -v rpm >/dev/null 2>&1; then
        pkg=$(rpm -qa 'nginx*' --queryformat '%{NAME}-%{VERSION}-%{RELEASE}  설치일 %{INSTALLTIME:date}\n' 2>/dev/null)
        if [ -n "$pkg" ]; then
            info "설치된 패키지"
            printf '%s\n' "$pkg" | info_lines
        fi
    fi

    result_manual "설치 버전 확인 - 최신 패치 적용 여부와 패치 관리 정책은 직접 확인 필요"
}

# WEB-26 (중) 로그 디렉터리 및 파일 권한 설정   [가이드 점검 대상: Nginx 포함]
#   가이드 판단 기준 : 양호 = 로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우
#                      취약 = 로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우
#   가이드 조치 방법(Nginx)
#     Step 1) 로그 디렉터리 및 파일의 권한 확인   # ls -al /<Nginx 로그 디렉터리>
#     Step 2) 불필요 권한 삭제                    # chmod o-rwx /<Nginx 로그 디렉터리>
#
#   [실측으로 확인한 사실]
#     이 빌드의 컴파일 기본값
#       --http-log-path=/var/log/nginx/access.log
#       --error-log-path=stderr
#     access_log / error_log 가 가질 수 있는 값 (전부 문법 유효)
#       파일 경로 / off / stderr / syslog:server=... / memory:32m
#       레벨·포맷 인자 동반, 변수 포함 경로, 값 인용, 지시자 인용,
#       값이 다음 줄, 같은 블록에 여러 개
#     컨텍스트는 main(error_log) / http / server / location 모두 유효하다.
#     실제로 생성된 로그 파일은 644, /var/log/nginx 는 755 로
#     기본 상태에서 이미 일반 사용자가 읽을 수 있었다.
#
#   [판정]  WEB-14(설정 파일 권한)와 같은 구조다.
#     로그 파일과 그 디렉터리 중 other 권한이 남아 있는 것이 있음 -> 취약
#     전부 other 권한 없음                                        -> 양호
#     권한을 확인하지 못한 대상이 있음                            -> 수동확인
#         (경로에 변수가 있거나 로그 파일이 아직 생성되지 않은 경우)
#     off / stderr / syslog: / memory: 는 파일이 아니므로 대상에서 빼고
#     증적에만 남긴다.
web_26() {
    head_item "WEB-26" "로그 디렉터리 및 파일 권한 설정" "중"
    info "판단기준> 양호: 로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
    info "          취약: 로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우"

    local q='["'"'"']'
    local nginx_v="" prefix f p own o kind val line
    local -a targets=()
    local bad="" ok="" unk=""
    local has_access=0 has_error=0

    # nginx -V 는 한 번만 부르고 필요한 값을 여기서 뽑아 쓴다
    command -v nginx >/dev/null 2>&1 && nginx_v=$(nginx -V 2>&1 | tr ' ' '\n')
    prefix=$(printf '%s\n' "$nginx_v" | sed -n 's/^--prefix=//p' | head -1)

    # 설정에서 로그 경로를 모으고, 파일이 아닌 값은 걸러낸다
    #   중복은 아래 권한 점검 단계의 sort -u 가 처리하므로 여기서 따로 거르지 않는다
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        kind=${line%%$'\t'*}; f=${line#*$'\t'}
        [ "$kind" = "access_log" ] && has_access=1
        [ "$kind" = "error_log" ]  && has_error=1
        case "$f" in
            off|stderr|syslog:*|memory:*) continue ;;
            *'$'*) unk="${unk}${f}  (경로에 변수가 있어 확정 불가)"$'\n'; continue ;;
            /*) ;;
            *)  f="${prefix:-/usr/share/nginx}/${f}" ;;
        esac
        targets+=("$f")
    done < <(grep -nHE "(^|[{};])[[:space:]]*${q}?(access_log|error_log)${q}?[[:space:]]" "${NGINX_ALL_CONF[@]}" \
             | drop_commented \
             | sed -E "s/^[^:]*:[0-9]+://; s/#.*//" \
             | sed -E "s/.*${q}?(access_log|error_log)${q}?[[:space:]]+/\1\t/; s/[;].*//; s/${q}//g" \
             | awk -F'\t' 'NF==2 {split($2,a," "); print $1"\t"a[1]}' | grep -v '	$' | sort -u)

    # 컴파일 기본 로그 경로는 "해당 지시자가 설정에 전혀 없을 때만" 대상에 넣는다.
    #   설정에 access_log 가 있으면 --http-log-path 는 쓰이지 않는데도 대상에
    #   넣으면, 쓰이지도 않는 경로의 권한 때문에 취약으로 나온다(실측 확인).
    [ "$has_access" = 0 ] && {
        val=$(printf '%s\n' "$nginx_v" | sed -n 's/^--http-log-path=//p' | head -1)
        case "$val" in /*) targets+=("$val") ;; esac
    }
    [ "$has_error" = 0 ] && {
        val=$(printf '%s\n' "$nginx_v" | sed -n 's/^--error-log-path=//p' | head -1)
        case "$val" in /*) targets+=("$val") ;; esac
    }

    # 로그 파일과 그 디렉터리의 권한을 본다 (sort -u 로 중복 제거)
    if [ ${#targets[@]} -gt 0 ]; then
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            if [ ! -e "$f" ]; then
                unk="${unk}${f}  (대상이 존재하지 않음)"$'\n'; continue
            fi
            p=$(fperm "$f"); own=$(fowner "$f")
            if [ -z "$p" ]; then
                unk="${unk}${f}  (권한 확인 불가)"$'\n'; continue
            fi
            o=$(perm_other "$p")
            case "$o" in
                ''|*[!0-9]*) unk="${unk}${f}  ${p}  (권한 해석 불가)"$'\n' ;;
                0)           ok="${ok}${f}  ${p}  ${own}"$'\n' ;;
                *)           bad="${bad}${f}  ${p}  ${own}  (일반 사용자 접근 권한 ${o})"$'\n' ;;
            esac
        done < <( { printf '%s\n' "${targets[@]}"
                    for f in "${targets[@]}"; do printf '%s\n' "${f%/*}"; done; } | sort -u )
    fi

    [ -n "$bad" ] && { printf '%s' "$bad" | info_lines; }
    [ -n "$unk" ] && { printf '%s' "$unk" | info_lines; }
    [ -n "$ok" ]  && { printf '%s' "$ok"  | info_lines; }

    if [ ${#targets[@]} -eq 0 ] && [ -z "$unk" ]; then
        result_manual "로그 파일 경로를 확정하지 못함 - 직접 확인 필요"
    elif [ -n "$bad" ]; then
        result_vuln "로그 디렉터리/파일에 일반 사용자 접근 권한이 부여되어 있음"
    elif [ -n "$unk" ]; then
        result_manual "일부 로그 대상의 권한을 확인하지 못함 - 직접 확인 필요"
    else
        result_good "로그 디렉터리 및 파일에 일반 사용자 접근 권한이 없음"
    fi
}

#==============================================================================
# 메인
#==============================================================================
main() {
    require_root
    init_result
    detect_env
    print_banner          
    require_conf         

    #--------------------------------------------------------------------------
    # 진단 항목 함수 호출
    #   1. 계정 관리   : web_01 web_02 web_03                        (작성 완료)
    #   2. 서비스 관리 : web_04 web_05 web_06 web_07 web_08 web_09 web_10 web_11  (작성 완료)
    #                    web_12 web_13 web_14 web_15 web_16 web_17   (작성 완료)
    #                    web_18                                      (작성 완료)
    #   3. 보안 설정   : web_19 web_20 web_21 web_22 web_23          (작성 완료)
    #   4. 패치/로그   : web_24 web_25 web_26                        (작성 완료)
    #--------------------------------------------------------------------------
    web_01; web_02; web_03
    web_04; web_05; web_06; web_07; web_08; web_09; web_10; web_11; web_12; web_13
    web_14; web_15; web_16; web_17; web_18
    web_19; web_20; web_21; web_22; web_23
    web_24; web_25; web_26

    print_summary
}

main "$@"
