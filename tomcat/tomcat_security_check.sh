#!/bin/bash

TOMCAT_HOME=""          # 프로그램 본체 (lib/, bin/)
TOMCAT_BASE=""          # 설정과 데이터 (conf/, webapps/, logs/)
TOMCAT_SERVICE="tomcat" # systemd 유닛명

DEFAULT_ACCOUNT_WORDS="tomcat admin"

DEFAULT_WEBAPPS="docs examples manager host-manager"
DEFAULT_DOCFILES="BUILDING.txt RELEASE-NOTES.txt CHANGELOG.md RUNNING.txt README.md NOTICE LICENSE jndi-resources-howto.html"
BACKUP_PATTERNS="*.bak *.old *.orig *.backup *~ *.tmp *.swp"


SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULT_DIR="$SCRIPT_DIR/result"
RESULT_FILE=""

TC_SERVER_XML=""; TC_WEB_XML=""; TC_CONTEXT_XML=""; TC_USERS_XML=""

TC_WEB_XMLS=()          
TC_CONTEXT_XMLS=()      
TC_ALL_CONF=()          # 위 전체 + server.xml + tomcat-users.xml

TC_USER_FILES=""        # tc_user_elements 결과: 계정 파일 경로 (한 줄에 하나)
TC_USER_ELEMS=""        # tc_user_elements 결과: 활성 <user .../> 요소

CNT_GOOD=0; CNT_VULN=0; CNT_MANUAL=0; CNT_NA=0

#==============================================================================
# 출력
#==============================================================================

# ※ return 0 필수. 없으면 마지막 조건문 결과가 반환값이 되어 log "..." && ... 가 깨진다.
log() {
    printf '%s\n' "$*"
    [ -n "$RESULT_FILE" ] && printf '%s\n' "$*" >> "$RESULT_FILE"
    return 0
}
line()      { log "------------------------------------------------------------------------"; }

# head_item <항목> <제목> <중요도> [가이드 점검 대상]
head_item() { line; log "[$1] $2 (중요도:$3 / 대상:${4:-Tomcat})"; }

info()      { log "       - $1"; }

result_good()   { log "  => 결과 : [양호] $1";     CNT_GOOD=$((CNT_GOOD + 1)); }
result_vuln()   { log "  => 결과 : [취약] $1";     CNT_VULN=$((CNT_VULN + 1)); }
result_manual() { log "  => 결과 : [수동확인] $1"; CNT_MANUAL=$((CNT_MANUAL + 1)); }
result_na()     { log "  => 결과 : [N/A] $1";      CNT_NA=$((CNT_NA + 1)); }

# 권한 확인 stat -c 로 권한 정보를 가져올 수 있다.
#   -L 필수 : 심볼릭 링크의 원본파일을 가리킴.
fperm() {
    local p; p=$(stat -Lc '%a' "$1" 2>/dev/null) || return 1
    [ -n "$p" ] || return 1
    while [ ${#p} -lt 3 ]; do p="0$p"; done   
    printf '%s' "$p"
}
fowner() { stat -Lc '%U:%G' "$1" 2>/dev/null; }
perm_user()  { printf '%s' "${1: -3:1}"; }
perm_group() { printf '%s' "${1: -2:1}"; }
perm_other() { printf '%s' "${1: -1}"; }

#==============================================================================
# 사전 조건
#==============================================================================
require_root() {
    [ "$(id -u)" -eq 0 ] && return 0
    printf '%s\n' "[오류] root 권한이 필요합니다. 예) sudo bash $0" >&2
    exit 1
}

# 결과에 계정·권한 정보가 들어가므로 소유자 전용으로 만든다.
# -p 옵션의 역할: 생성하려는 목적지 폴더가 이미 존재하면 에러를 발생시키지 않고 그냥 성공(종료 상태 0)으로 간주하고 넘어갑니다.
# : (콜론): 셸 스크립트에서 "아무 일도 하지 마라(No-op)"라는 뜻의 내장 명령어입니다. 아무 일도 안 하므로 당연히 에러 없이 항상 '성공(0)'을 반환합니다.
# > (리다이렉션): 우측에 지정한 파일 경로($RESULT_FILE)를 열어서 내용을 새로 쓰겠다는 뜻입니다. (=touch [fileName])
init_result() {
    umask 077
    mkdir -p "$RESULT_DIR" 2>/dev/null || { printf '%s\n' "[오류] 결과 디렉터리 생성 실패: $RESULT_DIR" >&2; exit 1; }
    chmod 700 "$RESULT_DIR" 2>/dev/null
    RESULT_FILE="$RESULT_DIR/tomcat_check_$(date +%Y%m%d_%H%M%S).txt"
    : > "$RESULT_FILE" 2>/dev/null || { printf '%s\n' "[오류] 결과 파일 생성 실패: $RESULT_FILE" >&2; RESULT_FILE=""; exit 1; }
}

# 경로 미탐지 상태로 진행하면 모든 파일 검사가 "파일 없음"으로 흘러
# 취약한 설정이 전부 양호로 보고된다. 반드시 중단한다.
# -n : 파일 존재가 아니라 문자열이 있는가를 검증
require_tomcat() {
    [ -n "$TOMCAT_BASE" ] && [ -d "$TOMCAT_BASE/conf" ] && return 0
    log "[오류] 진단 대상 Tomcat 설치 경로를 찾지 못했습니다."
    log "       스크립트 상단 TOMCAT_HOME 을 직접 지정한 뒤 다시 실행하십시오."
    log "       (CATALINA_BASE 가 별도인 구성이면 TOMCAT_BASE 도 함께 지정)"
    log ""
    log "진단을 중단합니다."
    exit 1
}

#==============================================================================
# 환경 탐지   → 해설.md 4절
#==============================================================================

tc_prop() {
    ps -efww 2>/dev/null | grep -i 'catalina' | grep -v grep \
        | grep -o "catalina\.$1=[^ ]*" | head -1 | cut -d= -f2-
}

# systemd 유닛이 넘기는 환경변수. Environment= 와 EnvironmentFile= 둘 다 봐야 한다.
# (Rocky tomcat 패키지는 후자를 쓴다). 미구동 상태에서도 읽을 수 있는 것이 존재 이유.
tc_unit_env() {
    local unit f
    unit=$(systemctl cat "$TOMCAT_SERVICE" 2>/dev/null)
    [ -n "$unit" ] || return 0
    printf '%s\n' "$unit" \
        | sed -n "s/^[[:space:]]*Environment=[\"']\?$1=\([^\"']*\).*/\1/p" | tail -1 | grep . && return 0
    while IFS= read -r f; do
        f="${f#-}"                                   # '-' 는 "파일 없어도 무시" 표시
        [ -f "$f" ] || continue
        sed -n "s/^[[:space:]]*\(export[[:space:]]\+\)\?$1=[\"']\?\([^\"']*\).*/\2/p" "$f" \
            | tail -1 | grep . && return 0
    done < <(printf '%s\n' "$unit" | sed -n 's/^[[:space:]]*EnvironmentFile=//p')
    return 0
}

# 탐지 우선순위 ① 구동 중인 프로세스 ② systemd 유닛 ③ 표준 설치 경로
detect_env() {
    local d f
    [ -z "$TOMCAT_HOME" ] && TOMCAT_HOME=$(tc_prop home)
    [ -z "$TOMCAT_BASE" ] && TOMCAT_BASE=$(tc_prop base)
    [ -z "$TOMCAT_HOME" ] && TOMCAT_HOME=$(tc_unit_env CATALINA_HOME)
    [ -z "$TOMCAT_BASE" ] && TOMCAT_BASE=$(tc_unit_env CATALINA_BASE)

    # 실재하지 않는 경로는 버려야 다음 순위로 넘어간다.
    [ -n "$TOMCAT_HOME" ] && [ ! -d "$TOMCAT_HOME" ] && TOMCAT_HOME=""
    [ -n "$TOMCAT_BASE" ] && [ ! -d "$TOMCAT_BASE" ] && TOMCAT_BASE=""

    if [ -z "$TOMCAT_HOME" ]; then
        for d in /opt/tomcat* /usr/share/tomcat* /usr/local/tomcat* /var/lib/tomcat* ; do
            [ -d "$d/conf" ] && { TOMCAT_HOME="$d"; break; }
        done
    fi

    [ -z "$TOMCAT_BASE" ] && TOMCAT_BASE="$TOMCAT_HOME"

    TC_SERVER_XML="$TOMCAT_BASE/conf/server.xml"
    TC_WEB_XML="$TOMCAT_BASE/conf/web.xml"
    TC_CONTEXT_XML="$TOMCAT_BASE/conf/context.xml"
    TC_USERS_XML="$TOMCAT_BASE/conf/tomcat-users.xml"

    TC_WEB_XMLS=(); TC_CONTEXT_XMLS=(); TC_ALL_CONF=()
    [ -f "$TC_WEB_XML" ]     && TC_WEB_XMLS+=("$TC_WEB_XML")
    [ -f "$TC_CONTEXT_XML" ] && TC_CONTEXT_XMLS+=("$TC_CONTEXT_XML")

    while IFS= read -r f; do [ -n "$f" ] && TC_WEB_XMLS+=("$f"); done \
        < <(find "$TOMCAT_BASE/webapps" -maxdepth 3 -type f -path '*/WEB-INF/web.xml' 2>/dev/null)
    while IFS= read -r f; do [ -n "$f" ] && TC_CONTEXT_XMLS+=("$f"); done \
        < <(find "$TOMCAT_BASE/webapps" -maxdepth 3 -type f -path '*/META-INF/context.xml' 2>/dev/null
            find "$TOMCAT_BASE/conf/Catalina" -maxdepth 2 -type f -name '*.xml' 2>/dev/null)

    for f in "$TC_SERVER_XML" "$TC_USERS_XML" "${TC_WEB_XMLS[@]}" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$f" ] && TC_ALL_CONF+=("$f")
    done
}

#==============================================================================
# 배너 / 요약
#==============================================================================
# Tomcat 버전 문자열. 배너와 WEB-25 가 같은 값을 써야 하므로 한 곳에 둔다.
tc_version() {
    local jar="$TOMCAT_HOME/lib/catalina.jar" j ver=""
    j=$(command -v java 2>/dev/null)
    [ -n "$j" ] || j=$(ps -eww -o args= 2>/dev/null | grep 'catalina\.startup\.Bootstrap' \
                       | grep -v grep | awk '{print $1; exit}')
    [ -f "$jar" ] && [ -x "$j" ] && \
        ver=$("$j" -cp "$jar" org.apache.catalina.util.ServerInfo 2>/dev/null \
              | sed -n 's/^Server[[:space:]]*\(number\|version\):[[:space:]]*/\1=/p' | tr '\n' ' ')
    [ -n "$ver" ] || ver=$(grep -ohiE 'Apache Tomcat Version[[:space:]]+[0-9][0-9.]*' \
                           "$TOMCAT_HOME/RELEASE-NOTES" "$TOMCAT_BASE/RELEASE-NOTES" 2>/dev/null | head -1)
    printf '%s' "$ver"
}

print_banner() {
    local tcver f
    tcver=$(tc_version)
    log "########################################################################"
    log "#  주요정보통신기반시설 웹 서비스(Tomcat) 취약점 자동 진단"
    log "#  진단 일시 : $(date '+%Y-%m-%d %H:%M:%S')"
    log "#  호스트명  : $(hostname 2>/dev/null)"
    log "#  실행 계정 : $(id -un) (uid=$(id -u))"
    log "#  OS 정보   : $( (cat /etc/rocky-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || uname -a) | head -1)"
    log "#  Tomcat    : ${tcver:-(버전 확인 불가)}"
    log "########################################################################"
    log "[탐지된 환경]"
    log "  - CATALINA_HOME  : ${TOMCAT_HOME:-(탐지 실패)}"
    log "  - CATALINA_BASE  : ${TOMCAT_BASE:-(탐지 실패)}"
    log "  - 진단 대상 파일 : ${#TC_ALL_CONF[@]}개"
    for f in "${TC_ALL_CONF[@]}"; do log "        $f"; done
    log ""
}

print_summary() {
    line
    log "[ Tomcat 진단 결과 요약 ]"
    log "  전체 항목        : $((CNT_GOOD + CNT_VULN + CNT_MANUAL + CNT_NA))"
    log "  양호(GOOD)       : $CNT_GOOD"
    log "  취약(VULN)       : $CNT_VULN"
    log "  수동확인(MANUAL) : $CNT_MANUAL"
    log "  해당없음(N/A)    : $CNT_NA"
    line
    log "결과 파일: $RESULT_FILE"
    log ""
    log "[주의] 결과 파일에는 계정명·경로·권한과 평문 비밀번호가 그대로 기록됩니다."
    log "       (WEB-02 는 수동 확인용으로 비밀번호 설정값을 남깁니다)"
    log "       디렉터리는 700 으로 생성되나, 파일 전달 시 취급에 주의하십시오."
}

#------------------------------------------------------------------------------
# 1. 계정 관리   WEB-01 WEB-02 WEB-03
#------------------------------------------------------------------------------

# XML 주석을 걷어내고 활성 구간만 한 줄로 출력한다.
xml_active_flat() {
    [ -f "$1" ] || return 0
    tr '\n\t' '  ' < "$1" 2>/dev/null | awk 'BEGIN{RS="-->"} {sub(/<!--.*/,""); printf "%s", $0}'
}

# 요소에서 속성값 하나를 뽑는다.  attr_of <요소> <속성명>
attr_of() {
    printf '%s' "$1" | grep -oiE "$2[[:space:]]*=[[:space:]]*\"[^\"]*\"" \
        | head -1 | sed -E 's/^[^=]*=[[:space:]]*"//; s/"$//'
}

# 계정 파일에서 활성 <user> 요소를 모은다.  (WEB-01/02/03 공용)
# sed 사용시 s// 치환시 경로를 사용하면 문제가 발생가능하여 s##을 사용한다.
#done < <(명령어): 괄호 안의 명령어들(xml_active_flat, grep, sed, sort 등)을 복잡하게 실행해서 나온 결과물을 주입할 때 사용.
tc_user_elements() {
    TC_USER_FILES=""; TC_USER_ELEMS=""
    local f elems
    # $'\n' 은 ANSI-C 인용. 큰따옴표 안의 "\n" 은 개행이 아니라 글자 그대로라
    # 줄 단위 목록을 만들려면 이 형태가 필요하다.
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        TC_USER_FILES+="$f"$'\n'
        # 요소가 0건일 때 개행만 붙이면 "계정 없음" 분기를 지나쳐 버린다.
        elems=$(xml_active_flat "$f" | grep -oiE '<user[[:space:]][^<]*')
        [ -n "$elems" ] && TC_USER_ELEMS+="$elems"$'\n'
    done < <( { xml_active_flat "$TC_SERVER_XML" \
                  | grep -oiE 'pathname[[:space:]]*=[[:space:]]*"[^"]*"' \
                  | sed -E 's/^[^=]*=[[:space:]]*"//; s/"$//' \
                  | sed -E "s#^([^/])#$TOMCAT_BASE/\1#"
                printf '%s\n' "$TC_USERS_XML"; } | sort -u )
}

# 계정 파일 경로를 증거로 남긴다. (WEB-01/02 공용)
#done <<< "$변수": 명령어 실행 필요 없이, 이미 메모리 변수 안에 저장되어 있는 텍스트 데이터를 그대로 주입할 때 사용.
show_user_files() {
    local f
    while IFS= read -r f; do 
        [ -n "$f" ] && info "계정 파일: $f"; 
    done <<< "$TC_USER_FILES"
}

# WEB-01 (상) Default 관리자 계정명 변경
#   양호 : 관리자 페이지 미사용 또는 계정명이 기본 계정명이 아닌 경우
#   취약 : 기본 계정명이거나 추측하기 쉬운 문자 조합의 계정명
#   server.xml(pathname 정의된 경우 그 패스값(user 태그 줄) 추출) 후 tomcat-user.xml(pathname 경로) 에서 <user~> 
web_01() {
    head_item "WEB-01" "Default 관리자 계정명 변경" "상"
    info "판단기준> 양호: 관리자 페이지 미사용 또는 계정명이 기본 계정명이 아닌 경우"
    info "          취약: 기본 계정명이거나 추측하기 쉬운 문자 조합의 계정명"

    tc_user_elements
    show_user_files

    local admins vuln=0 manual=0 e name low w hit
    admins=$(printf '%s' "$TC_USER_ELEMS" \
             | grep -iE 'manager-gui|admin-gui|manager-script|manager-jmx|manager-status')
    [ -z "$admins" ] && { result_good "관리자 권한이 부여된 활성 계정 없음 (관리자 페이지 비활성)"; return; }

    while IFS= read -r e; do
        name=$(attr_of "$e" username); [ -n "$name" ] || continue
        low=$(printf '%s' "$name" | tr 'A-Z' 'a-z'); hit=""
        for w in $DEFAULT_ACCOUNT_WORDS; do 
            case "$low" in 
                *"$w"*) hit="$w"; break ;; 
            esac; 
        done
        if   [ -z "$hit" ];       then info "관리자 계정: username=\"$name\" (기본 계정명 아님)"; manual=1
        elif [ "$low" = "$hit" ]; then info "기본 계정명 사용: username=\"$name\"";               vuln=1
        else                           info "기본 계정명 변형: username=\"$name\" ('$hit' 포함)"; vuln=1
        fi
    done <<< "$admins"

    if [ "$vuln" -eq 1 ]; then
        result_vuln "기본 관리자 계정명 사용 - 위 계정 파일의 username 을 유추 어려운 값으로 변경"
    elif [ "$manual" -eq 1 ]; then
        result_manual "위 관리자 계정명이 추측하기 쉬운 문자 조합인지 수동 확인"
    else
        result_good "판별할 관리자 계정명 없음"
    fi
}

# WEB-02 (상) 취약한 비밀번호 사용 제한   [가이드 대상: Tomcat, IIS, JEUS]
#   양호 : 비밀번호가 암호화되어 있거나 유추하기 어려운 경우
#   취약 : 암호화되어 있지 않거나 유추하기 쉬운 경우
# Realm 정의는 server.xml 및 context.xml 에서 algo/degist로 암호 알고리즘 확인 후  
# server.xml(pathname 정의된 경우 그 패스값(user 태그 줄) 추출) 후 tomcat-user.xml(pathname 경로) 에서 <user~> password 을 가져와 server.xml, context.xml 들에 알고리즘 정의 여부 확인.
web_02() {
    head_item "WEB-02" "취약한 비밀번호 사용 제한" "상"
    info "판단기준> 양호: 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
    info "          취약: 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
    info "복잡도> 2종 조합 10자 이상 또는 3종 조합 8자 이상, 계정명과 상이"

    tc_user_elements
    show_user_files
    [ -z "$TC_USER_ELEMS" ] && {
        info "정의된 활성 계정 없음"
        result_pass "파일 내 정의된 로컬 계정 없음 (양호) - 단, 외부 인증(LDAP, DB 등) 사용 시 해당 시스템에서 별도 확인 필요"
        return
    }

    local algo="" c e name pw len
    for c in "$TC_SERVER_XML" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$c" ] || continue
        algo=$(xml_active_flat "$c" | tr "'" '"' \
               | grep -oiE '(digest|algorithm)[[:space:]]*=[[:space:]]*"[^"]*"' \
               | sed -E 's/^[^=]*=[[:space:]]*"//; s/"$//' | head -1)
        [ -n "$algo" ] && break
    done
    info "자격증명 저장 알고리즘 설정: ${algo:-(없음 - 평문 저장)}"

    while IFS= read -r e; do
        name=$(attr_of "$e" username); [ -n "$name" ] || continue
        pw=$(attr_of "$e" password); len=${#pw}

        # 알고리즘 설정만 믿으면 다른 용도의 digest 때문에 평문이 "암호화됨"으로 기록된다.
        # 저장값이 해시 모양(16진수 32/40/64/96/128자)일 때만 해시로 본다.
        if [ -n "$algo" ] && printf '%s' "$pw" \
             | grep -qE '^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{96}$|^[0-9a-fA-F]{128}$'; then
            info "해시 저장: username=\"$name\" 알고리즘=$algo 길이=${len}자"
            continue
        fi
        info "평문 저장: username=\"$name\" password=\"$pw\" (길이 ${len}자)"
    done <<< "$TC_USER_ELEMS"

    result_manual "비밀번호 적정성은 자동 판별 불가 - 위 설정값으로 수동 확인"
}

# WEB-03 (상) 비밀번호 파일 권한 관리   [가이드 대상: Tomcat, IIS, JEUS]
#   양호 : 권한 600 이하 / 취약 : 600 초과
# server.xml 에 설정된 tomcat-user.xml(pathname 경로) 의 파일 권환 확인
web_03() {
    head_item "WEB-03" "비밀번호 파일 권한 관리" "상"
    info "판단기준> 양호: 권한 600 이하 (소유자 6 이하, 그룹 0, 기타 0) / 취약: 600 초과"

    tc_user_elements                      # 계정 파일 목록을 TC_USER_FILES 에 채운다
    local vuln=0 n=0 f p
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        n=$((n+1)); p=$(fperm "$f")
        if [ -n "$p" ] && [ "$(perm_user "$p")" -le 6 ] \
           && [ "$(perm_group "$p")" -eq 0 ] && [ "$(perm_other "$p")" -eq 0 ]; then
            info "권한 적절: $f (권한 $p, 소유자 $(fowner "$f"))"
        else
            info "권한 600 초과: $f (권한 ${p:-확인불가}, 소유자 $(fowner "$f"))"; vuln=1
        fi
    done <<< "$TC_USER_FILES"

    [ "$n" -eq 0 ] && {
        info "비밀번호 파일 없음: $TC_USERS_XML"
        result_good "비밀번호 파일이 존재하지 않아 노출될 파일이 없음"
        return
    }
    [ "$vuln" -eq 1 ] \
        && result_vuln "비밀번호 파일 권한이 600 초과 - chmod 600 <위 파일> 로 조정" \
        || result_good "비밀번호 파일 권한이 600 이하"
}

#------------------------------------------------------------------------------
# 2. 서비스 관리   WEB-04 ~ WEB-18
#------------------------------------------------------------------------------

# WEB-04 (상) 디렉터리 리스팅 방지 설정   [가이드 대상: Apache, Tomcat, Nginx, IIS, JEUS, WebtoB]
#   양호 : 디렉터리 리스팅이 설정되지 않은 경우
#   취약 : 디렉터리 리스팅이 설정된 경우
# web.xml 내의 설정중 <param-name> 값이 listings 인걸 찾아 <param-value>가 false 이면 양호
web_04() {
    head_item "WEB-04" "디렉터리 리스팅 방지 설정" "상"
    info "판단기준> 양호: 디렉터리 리스팅 미설정 / 취약: 설정됨"

    if [ ${#TC_WEB_XMLS[@]} -eq 0 ]; then
        info "web.xml 없음: $TC_WEB_XML"
        result_good "web.xml 이 없어 리스팅 설정 없음 (Tomcat 기본값 false)"
        return
    fi

    local vuln=0 found=0 f v
    for f in "${TC_WEB_XMLS[@]}"; do
        while IFS= read -r v; do
            found=1
            if [ "$(printf '%s' "$v" | tr 'A-Z' 'a-z')" = "true" ]; then
                info "리스팅 활성: listings=$v ($f)"; vuln=1
            else
                info "리스팅 차단: listings=${v:-(빈 값)} ($f)"
            fi
        done < <(xml_active_flat "$f" \
                 | grep -oiE '<param-name>[[:space:]]*listings[[:space:]]*</param-name>[[:space:]]*<param-value>[^<]*</param-value>' \
                 | grep -oiE '<param-value>[^<]*</param-value>' \
                 | sed -E 's#^<[^>]*>##; s#</[^>]*>$##' | tr -d '[:blank:]')
    done

    [ "$found" -eq 0 ] && info "listings 설정 없음 (Tomcat 기본값 false)"
    [ "$vuln" -eq 1 ] \
        && result_vuln "디렉터리 리스팅 활성화 - 위 web.xml 의 listings 를 false 로 변경" \
        || result_good "디렉터리 리스팅이 설정되지 않음"
}

# WEB-05 (상) 지정하지 않은 CGI/ISAPI 실행 제한
#   양호 : CGI 를 사용하지 않거나, CGI 실행 가능 디렉터리를 제한한 경우
#   취약 : CGI 를 사용하고 실행 가능 디렉터리를 제한하지 않은 경우
# web.xml에서 CGIServlet 문자열을 찾아서 있으면 사용, 없으면  미사용. 
# 사용시 <param-name>이 cgiPathPrefix인 <param-value>를 가져와서 출력. default = WEB-INF/cgi
web_05() {
    head_item "WEB-05" "지정하지 않은 CGI/ISAPI 실행 제한" "상"
    info "판단기준> 양호: CGI 미사용 또는 실행 가능 디렉터리를 제한한 경우"
    info "          취약: CGI 를 사용하고 실행 가능 디렉터리를 제한하지 않은 경우"

    if [ ${#TC_WEB_XMLS[@]} -eq 0 ]; then
        info "web.xml 없음: $TC_WEB_XML"
        result_good "web.xml 이 없어 CGI 설정 없음"
        return
    fi

    local used=0 f flat prefix pat
    for f in "${TC_WEB_XMLS[@]}"; do
        flat=$(xml_active_flat "$f")
        printf '%s' "$flat" | grep -qi 'CGIServlet' || continue
        used=1
        info "CGI 서블릿(CGIServlet) 선언 활성: $f"

        # CGI 스크립트가 놓이는 디렉터리 (미지정 시 Tomcat 기본값 WEB-INF/cgi)
        prefix=$(printf '%s' "$flat" \
                 | grep -oiE '<param-name>[[:space:]]*cgiPathPrefix[[:space:]]*</param-name>[[:space:]]*<param-value>[^<]*</param-value>' \
                 | grep -oiE '<param-value>[^<]*</param-value>' \
                 | sed -E 's#^<[^>]*>##; s#</[^>]*>$##' | tr -d '[:blank:]' | head -1)
        info "  cgiPathPrefix=${prefix:-(미지정 - 기본값 WEB-INF/cgi)}"

        # 이 파일의 url-pattern 목록. 어느 것이 CGI 매핑인지는 파일에서 확인한다.
        while IFS= read -r pat; do
            [ -n "$pat" ] && info "  url-pattern: $pat"
        done < <(printf '%s' "$flat" | grep -oiE '<url-pattern>[^<]*</url-pattern>' \
                 | sed -E 's#<[^>]*>##g; s#[[:space:]]##g' | sort -u)
    done

    if [ "$used" -eq 0 ]; then
        info "CGIServlet 선언 없음 (Tomcat 기본 상태)"
        result_good "CGI 를 사용하지 않음"
        return
    fi
    result_manual "CGI 사용 중 - 실행 가능 디렉터리 제한 여부를 위 설정으로 수동 확인"
}

# WEB-06 (상) 웹 서비스 상위 디렉터리 접근 제한 설정
#   양호 : 상위 디렉터리 접근 기능을 제거한 경우
#   취약 : 상위 디렉터리 접근 기능을 제거하지 않은 경우
#
#   Tomcat 7 이하는 <Context allowLinking="true">, 8 이상은 <Resources allowLinking="true"/>
# server.xml, context.xml 들 내에 allowLinking 값을 검색 시 allowLinking 설정이 없거나 false 면 양호
web_06() {
    head_item "WEB-06" "웹 서비스 상위 디렉터리 접근 제한 설정" "상"
    info "판단기준> 양호: 상위 디렉터리 접근 기능을 제거한 경우"
    info "          취약: 상위 디렉터리 접근 기능을 제거하지 않은 경우"

    local vuln=0 found=0 checked=0 f v
    for f in "$TC_SERVER_XML" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$f" ] || continue
        checked=$((checked + 1))
  
        while IFS= read -r v; do
            found=1
            if [ "$(printf '%s' "$v" | tr 'A-Z' 'a-z')" = "true" ]; then
                info "상위 디렉터리 접근 허용: allowLinking=$v ($f)"; vuln=1
            else
                info "상위 디렉터리 접근 차단: allowLinking=${v:-(빈 값)} ($f)"
            fi
        done < <(xml_active_flat "$f" \
                 | grep -oiE "[[:space:]]allowLinking[[:space:]]*=[[:space:]]*[\"'][^\"']*[\"']" \
                 | sed -E "s#^[^=]*=[[:space:]]*[\"']##; s#[\"']\$##")
    done

    if [ "$checked" -eq 0 ]; then
        info "server.xml / context.xml 없음"
        result_good "Context 설정 파일이 없어 상위 디렉터리 접근 설정 없음"
        return
    fi
    [ "$found" -eq 0 ] && info "allowLinking 설정 없음 (Tomcat 기본값 false)"
    [ "$vuln" -eq 1 ] \
        && result_vuln "상위 디렉터리 접근 허용(allowLinking=true) - 위 파일에서 해당 옵션 제거" \
        || result_good "상위 디렉터리 접근 기능이 설정되지 않음"
}

# WEB-07 (중) 웹 서비스 경로 내 불필요한 파일 제거
#   양호 : 기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우
#   취약 : 기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우
# /webapp 내 디폴트 디렉터리 및 백업 임시 파일 검사, home/base 내 매뉴얼 파일 검사
web_07() {
    head_item "WEB-07" "웹 서비스 경로 내 불필요한 파일 제거" "중"
    info "판단기준> 양호: 기본 생성 불필요 파일·디렉터리가 없는 경우"
    info "          취약: 존재하는 경우 (샘플·매뉴얼·임시·테스트·백업 파일)"

    local vuln=0 d n p found prev=""

    for n in $DEFAULT_WEBAPPS; do
        [ -e "$TOMCAT_BASE/webapps/$n" ] || continue
        info "기본 생성 앱: webapps/$n ($TOMCAT_BASE/webapps/$n)"; vuln=1
    done

    for d in "$TOMCAT_HOME" "$TOMCAT_BASE"; do
        [ -d "$d" ] || continue
        [ "$d" = "$prev" ] && continue
        prev="$d"
        for n in $DEFAULT_DOCFILES; do
            [ -f "$d/$n" ] || continue
            info "매뉴얼 파일: $d/$n"; vuln=1
        done
    done

    found=0
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        found=$((found + 1))
        [ "$found" -le 10 ] && info "백업·임시 파일: $p"
        vuln=1
    done < <(for n in $BACKUP_PATTERNS; do
                 find "$TOMCAT_BASE/webapps" -maxdepth 4 -type f -name "$n" 2>/dev/null
             done | sort -u)
    [ "$found" -gt 10 ] && info "백업·임시 파일 외 $((found - 10))건 더 있음"

    if [ "$vuln" -eq 0 ]; then
        result_good "기본 생성 불필요 파일·디렉터리 없음"
        return
    fi
    result_manual "기본 생성 파일·디렉터리 발견 - 업무상 필요 여부를 수동 확인"
}

# WEB-08 (하) 웹 서비스 파일 업로드 및 다운로드 용량 제한
#   양호 : 파일 업로드 및 다운로드 용량을 제한한 경우
#   취약 : 파일 업로드 및 다운로드 용량을 제한하지 않은 경우
# server.xml 의 Connector 에 maxPostSize 설정 확인 후 web.xml 의 <multipart-config> 에 max-file-size / max-request-size 설정 확인 미설정 시 -1로 제한 없음
web_08() {
    head_item "WEB-08" "웹 서비스 파일 업로드 및 다운로드 용량 제한" "하"
    info "판단기준> 양호: 파일 업로드 및 다운로드 용량을 제한한 경우"
    info "          취약: 제한하지 않은 경우"

    local vuln=0 nconn=0 nmp=0 c f b n v port

    while IFS= read -r c; do
        [ -n "$c" ] || continue
        nconn=$((nconn + 1))
        port=$(attr_of "$c" "[[:space:]]port")
        v=$(attr_of "$c" "[[:space:]]maxPostSize" | tr -d '[:blank:]')
        case "$v" in
            ''|*[!0-9]*|0*) info "Connector(port=${port:-?}): maxPostSize=${v:-(미설정)} - 용량 제한 없음"; vuln=1 ;;
            *)              info "Connector(port=${port:-?}): maxPostSize=$v (제한)" ;;
        esac
    done < <(xml_active_flat "$TC_SERVER_XML" | tr "'" '"' \
             | grep -oiE '<Connector[[:space:]][^<]*')
    [ "$nconn" -eq 0 ] && info "server.xml 에 활성 Connector 없음: $TC_SERVER_XML"

    # ② web.xml 의 multipart-config
    for f in "${TC_WEB_XMLS[@]}"; do
        if xml_active_flat "$f" | grep -qiE '<multipart-config[[:space:]]*/>'; then
            nmp=$((nmp + 1)); vuln=1
            info "multipart-config: 빈 요소 <multipart-config/> - 전부 기본값 -1(무제한) ($f)"
        fi
        while IFS= read -r b; do
            nmp=$((nmp + 1))
            for n in max-file-size max-request-size; do
                while IFS= read -r v; do
                    case "$v" in
                        ''|*[!0-9]*|0*) info "multipart-config: $n=${v:-(미설정)} - 용량 제한 없음 ($f)"; vuln=1 ;;
                        *)              info "multipart-config: $n=$v (제한) ($f)" ;;
                    esac
                done <<< "$(printf '%s' "$b" | grep -oiE "<$n>[^<]*</$n>" \
                            | sed -E 's#<[^>]*>##g' | tr -d '[:blank:]')"
            done
        done < <(xml_active_flat "$f" \
                 | awk 'BEGIN{RS="</multipart-config>"} /<multipart-config>/{sub(/.*<multipart-config>/,""); print}')
    done
    [ "$nmp" -eq 0 ] && info "web.xml 에 multipart-config 선언 없음"

    [ "$vuln" -eq 1 ] \
        && result_vuln "업로드 용량 제한 미설정 - server.xml 의 maxPostSize, web.xml 의 multipart-config 설정" \
        || result_good "파일 업로드 용량이 제한되어 있음"
}

# WEB-09 (상) 웹 서비스 프로세스 권한 제한
#   양호 : 관리자 권한이 부여된 계정이 아닌 별도 계정으로 구동
#   취약 : 관리자 권한이 부여된 계정으로 구동
#   PS(실행 프로세서) 내에서 사용자 검색, 실행자가 없을 시 systemctl cat tomcat으로 User확인
#   찾은 user의 uid가 0이면 root
web_09() {
    head_item "WEB-09" "웹 서비스 프로세스 권한 제한" "상"
    info "판단기준> 양호: 관리자 권한이 아닌 별도 계정으로 구동"
    info "          취약: 관리자 권한이 부여된 계정으로 구동"

    local acct src uid
    # -e: 전체 프로세서 -o: 사용자 이름 컬럼(최대 32글자), args 컬럼 추출
    acct=$(ps -eww -o user:32=,args= 2>/dev/null \
           | grep 'catalina\.startup\.Bootstrap' | grep -v grep \
           | awk '{print $1}' | sort -u | head -1)
    src="실행 중 프로세스"

    # "User= 없음시 systemd 기본값이 root 다.
    if [ -z "$acct" ]; then
        src="${TOMCAT_SERVICE}.service 의 User="
        acct=$(systemctl cat "$TOMCAT_SERVICE" 2>/dev/null \
               | sed -n 's/^[[:space:]]*User=[[:space:]]*//p' | tr -d "\"'" | tail -1)
        if [ -z "$acct" ] && systemctl cat "$TOMCAT_SERVICE" >/dev/null 2>&1; then
            acct="root"; src="${TOMCAT_SERVICE}.service 에 User= 미지정 (systemd 기본값)"
        fi
    fi

    if [ -z "$acct" ]; then
        result_manual "구동 중인 프로세스와 ${TOMCAT_SERVICE}.service 를 모두 찾지 못함 - 기동 계정 수동 확인"
        return
    fi

    uid=$(id -u "$acct" 2>/dev/null)
    info "구동 계정: $acct (uid=${uid:-확인 불가}, 근거: $src)"
    if [ -z "$uid" ]; then
        result_manual "구동 계정($acct)이 /etc/passwd 에 없어 권한 확인 불가 - 수동 확인"
    elif [ "$uid" -eq 0 ]; then
        result_vuln "관리자 권한(uid 0) 계정으로 구동됨 - ${TOMCAT_SERVICE}.service 의 User/Group 변경"
    else
        result_good "관리자 권한이 없는 별도 계정($acct)으로 구동됨"
    fi
}

# WEB-10 (상) 불필요한 프록시 설정 제한
#   양호 : 불필요한 Proxy 설정을 제한한 경우
#   취약 : 불필요한 Proxy 설정을 제한하지 않은 경우
#   server.xml 의 Connector 요소에서 Proxy 설정(proxyName/proxyPort) 설정여부 확인
web_10() {
    head_item "WEB-10" "불필요한 프록시 설정 제한" "상"
    info "판단기준> 양호: 불필요한 Proxy 설정을 제한한 경우"
    info "          취약: 제한하지 않은 경우"

    local found=0 c port pn pp
    while IFS= read -r c; do
        printf '%s' "$c" | grep -qiE '[[:space:]]proxy(Name|Port)[[:space:]]*=' || continue
        port=$(attr_of "$c" "[[:space:]]port")
        pn=$(attr_of "$c" "[[:space:]]proxyName")
        pp=$(attr_of "$c" "[[:space:]]proxyPort")
        info "Connector(port=${port:-?}): proxyName=${pn:-(빈 값)} proxyPort=${pp:-(빈 값)}"
        found=1
    done < <(xml_active_flat "$TC_SERVER_XML" | tr "'" '"' \
             | grep -oiE '<Connector[[:space:]][^<]*')

    [ "$found" -eq 0 ] && { result_good "Connector 에 프록시 설정 없음"; return; }
    result_manual "프록시 설정 발견 - 업무상 필요한 구성인지 수동 확인 ($TC_SERVER_XML)"
}

# WEB-11 (중) 웹 서비스 경로 설정
#   양호 : 기타 업무와 영역이 분리된 경로로 설정, 불필요한 경로가 없는 경우
#   취약 : 영역이 분리되지 않은 경로이거나 불필요한 경로가 있는 경우
#   server.xml, context.xml 파일들을 확인해서 Host 태그 내 appBase 속성 확인 후 context 태그 내 docBase 설정 확인
web_11() {
    head_item "WEB-11" "웹 서비스 경로 설정" "중"
    info "판단기준> 양호: 기타 업무와 영역이 분리된 경로이고 불필요한 경로가 없는 경우"
    info "          취약: 분리되지 않은 경로이거나 불필요한 경로가 있는 경우"

    local n=0 ndoc=0 f e v abs base=""

    # ① Host appBase - docBase 가 없는 앱들이 실제로 놓이는 자리
    for f in "$TC_SERVER_XML" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$f" ] || continue
        while IFS= read -r e; do
            v=$(attr_of "$e" "[[:space:]]appBase"); [ -n "$v" ] || continue
            case "$v" in 
                /*) abs="$v" ;; 
                *) abs="$TOMCAT_BASE/$v" ;; 
            esac
            [ -n "$base" ] || base="$abs"
            n=$((n + 1))
            info "웹 서비스 경로: $abs"
            log  "         (Host appBase=\"$v\") ($f)"

            case "$abs" in
                "$TOMCAT_BASE"/*) log "         -> Tomcat 설치 경로($TOMCAT_BASE) 안. 기타 업무와 분리 여부는 진단자 판단" ;;
            esac
        done < <(xml_active_flat "$f" | tr "'" '"' | grep -oiE '<Host[[:space:]][^<]*')
    done

    # ② Context docBase - 절대경로면 appBase 를 무시하고 그 경로가 문서 루트가 된다
    for f in "$TC_SERVER_XML" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$f" ] || continue
        while IFS= read -r e; do
            v=$(attr_of "$e" "[[:space:]]docBase"); [ -n "$v" ] || continue
            n=$((n + 1)); ndoc=$((ndoc + 1))
            case "$v" in
                /*) info "웹 서비스 경로: $v"
                    log  "         (Context docBase=\"$v\" 절대경로 - appBase 무시) ($f)" ;;
                *)  info "웹 서비스 경로: ${base:-<appBase>}/$v"
                    log  "         (Context docBase=\"$v\" 상대경로 - appBase 기준) ($f)" ;;
            esac
        done < <(xml_active_flat "$f" | tr "'" '"' | grep -oiE '<Context[[:space:]][^<]*')
    done

    [ "$n" -eq 0 ] && { result_good "설정된 웹 서비스 경로 없음"; return; }

    [ "$ndoc" -eq 0 ] && log "         docBase 미설정 - 모든 앱이 위 appBase 아래에 자동 배포됨"
    result_manual "위 경로가 기타 업무와 영역이 분리되어 있는지, 불필요한 경로가 없는지 수동 확인"
}

# WEB-12 (중) 웹 서비스 링크 사용 금지
#   양호 : 심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우
#   취약 : 링크 사용을 허용하는 경우
#   server.xml과 context.xml들을 확이해서 allowLinking의 value를 추출하여 true면 링크사용으로 확인
web_12() {
    head_item "WEB-12" "웹 서비스 링크 사용 금지" "중"
    info "판단기준> 양호: 심볼릭 링크·aliases 등의 링크 사용을 허용하지 않는 경우"
    info "          취약: 링크 사용을 허용하는 경우"

    local vuln=0 found=0 f v
    for f in "$TC_SERVER_XML" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$f" ] || continue
        # 앞의 [[:space:]] 는 xallowLinking 같은 다른 속성에 걸리지 않게 하는 경계다.
        while IFS= read -r v; do
            found=1
            if [ "$(printf '%s' "$v" | tr 'A-Z' 'a-z')" = "true" ]; then
                info "링크 사용 허용: allowLinking=$v ($f)"; vuln=1
            else
                info "링크 사용 차단: allowLinking=${v:-(빈 값)} ($f)"
            fi
        done < <(xml_active_flat "$f" \
                 | grep -oiE "[[:space:]]allowLinking[[:space:]]*=[[:space:]]*[\"'][^\"']*[\"']" \
                 | sed -E "s#^[^=]*=[[:space:]]*[\"']##; s#[\"']\$##")
    done

    [ "$found" -eq 0 ] && info "allowLinking 설정 없음 (Tomcat 기본값 false)"
    [ "$vuln" -eq 1 ] \
        && result_vuln "링크 사용 허용(allowLinking=true) - 위 파일에서 해당 옵션 제거" \
        || result_good "링크 사용이 허용되어 있지 않음"
}

# WEB-13 (상) 웹 서비스 설정 파일 노출 제한
#   양호 : 일반 사용자의 DB 연결 파일 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우
#   취약 : 접근을 제한하지 않거나, 불필요한 스크립트 매핑이 제거되지 않은 경우
#   server.xml를 확인하고 Resource 태그를 확인 후 javax.sql.DataSource 또는 jdbc: 문자열을 찾고 해당 파일 권한 확인
web_13() {
    head_item "WEB-13" "웹 서비스 설정 파일 노출 제한" "상"
    info "판단기준> 양호: 일반 사용자의 DB 연결 파일 접근을 제한하고 불필요한 리소스가 없는 경우"
    info "          취약: 접근을 제한하지 않거나 불필요한 리소스가 있는 경우"

    local n=0 f e name p
    for f in "$TC_SERVER_XML" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$f" ] || continue
        while IFS= read -r e; do
            n=$((n + 1)); name=$(attr_of "$e" "[[:space:]]name"); p=$(fperm "$f")
            info "DB 연결 리소스: name=\"${name:-?}\" ($f, 권한 ${p:-확인불가}, 소유자 $(fowner "$f"))"
        done < <(xml_active_flat "$f" | tr "'" '"' \
                 | grep -oiE '<Resource[[:space:]][^<]*' | grep -iE 'javax\.sql\.DataSource|jdbc:')
    done

    [ "$n" -eq 0 ] && { result_good "DB 연결 리소스 설정 없음"; return; }
    result_manual "위 파일이 일반 사용자에게 열려 있는지, 해당 리소스가 업무상 필요한지 수동 확인"
}

# WEB-14 (상) 웹 서비스 경로 내 파일의 접근 통제
#   양호 : 주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우
#   취약 : 불필요한 접근 권한이 부여된 경우
#   /opt/tomcat/conf 및 모든 설정 파일들을 가져와 other 권한이 존재하는지 확인
web_14() {
    head_item "WEB-14" "웹 서비스 경로 내 파일의 접근 통제" "상"
    info "판단기준> 양호: 주요 설정 파일·디렉터리에 불필요한 접근 권한이 없는 경우"
    info "          취약: 일반 사용자(other)에게 접근 권한이 부여된 경우"

    local vuln=0 n=0 f p
    for f in "$TOMCAT_BASE/conf" "${TC_ALL_CONF[@]}"; do
        [ -e "$f" ] || continue
        n=$((n + 1)); p=$(fperm "$f")
        [ -n "$p" ] && [ "$(perm_other "$p")" -eq 0 ] && continue
        info "일반 사용자 접근 가능: $f (권한 ${p:-확인불가}, 소유자 $(fowner "$f"))"; vuln=1
    done

    [ "$n" -eq 0 ] && { result_good "확인할 설정 파일이 없음"; return; }
    [ "$vuln" -eq 1 ] \
        && result_vuln "일반 사용자에게 열린 설정 파일·디렉터리 존재 - 위 항목의 other 권한 제거" \
        || result_good "확인한 ${n}개 항목 모두 일반 사용자 접근 권한 없음"
}

# WEB-15 (상) 웹 서비스의 불필요한 스크립트 매핑 제거
#   양호 : 불필요한 스크립트 매핑이 존재하지 않는 경우
#   취약 : 불필요한 스크립트 매핑이 존재하는 경우
#   조치 : web.xml 의 불필요한 <servlet-mapping> 제거
#   web.xml 파일들 내 servlet-mapping 태그 내 servlet-name, url-pattern 태그를 가져와 식별
web_15() {
    head_item "WEB-15" "웹 서비스의 불필요한 스크립트 매핑 제거" "상"
    info "판단기준> 양호: 불필요한 스크립트 매핑이 없는 경우"
    info "          취약: 불필요한 스크립트 매핑이 존재하는 경우"

    local n=0 f b name pats pat
    for f in "${TC_WEB_XMLS[@]}"; do
        while IFS= read -r b; do
            name=$(printf '%s' "$b" | grep -oiE '<servlet-name>[^<]*</servlet-name>' \
                   | head -1 | sed -E 's#<[^>]*>##g' | tr -d '[:blank:]')
            pats=$(printf '%s' "$b" | grep -oiE '<url-pattern>[^<]*</url-pattern>' \
                   | sed -E 's#<[^>]*>##g' | tr -d '[:blank:]')
            # 한 매핑에 url-pattern 이 여럿일 수 있다. 없으면 빈 줄 하나가 들어와 그대로 센다.
            while IFS= read -r pat; do
                n=$((n + 1))
                [ "$n" -le 20 ] && info "매핑: servlet-name=\"${name:-?}\" url-pattern=\"${pat:-(없음)}\" ($f)"
            done <<< "$pats"
        done < <(xml_active_flat "$f" \
                 | awk 'BEGIN{RS="</servlet-mapping>"} /<servlet-mapping>/{sub(/.*<servlet-mapping>/,""); print}')
    done
    [ "$n" -gt 20 ] && info "그 외 매핑 $((n - 20))건 더 있음 - web.xml 을 직접 확인"

    [ "$n" -eq 0 ] && { result_good "선언된 스크립트 매핑 없음"; return; }
    result_manual "위 ${n}건의 매핑 중 업무상 불필요한 것이 있는지 수동 확인"
}

# WEB-16 (중) 웹 서비스 헤더 정보 노출 제한
#   양호 : HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우
#   취약 : 노출되는 경우
#   server.xml에서 connector 태그 내 server 속성 값을 가져와서 수동, value 태그에 ErrorReportValve 설정이 있을시 showServerInfo 값 가져와서 false 인지 확인
web_16() {
    head_item "WEB-16" "웹 서비스 헤더 정보 노출 제한" "중"
    info "판단기준> 양호: HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
    info "          취약: 노출되는 경우"

    local n=0 e v port
    while IFS= read -r e; do
        [ -n "$e" ] || continue
        n=$((n + 1)); port=$(attr_of "$e" "[[:space:]]port"); v=$(attr_of "$e" "[[:space:]]server")
        info "Connector(port=${port:-?}): server=${v:-(미설정)}"
    done < <(xml_active_flat "$TC_SERVER_XML" | tr "'" '"' | grep -oiE '<Connector[[:space:]][^<]*')
    [ "$n" -eq 0 ] && info "server.xml 에 활성 Connector 없음"

    n=0
    while IFS= read -r e; do
        n=$((n + 1)); v=$(attr_of "$e" "[[:space:]]showServerInfo")
        info "ErrorReportValve: showServerInfo=${v:-(미설정)}"
    done < <(xml_active_flat "$TC_SERVER_XML" | tr "'" '"' \
             | grep -oiE '<Valve[[:space:]][^<]*' | grep -i 'ErrorReportValve')
    [ "$n" -eq 0 ] && info "ErrorReportValve 선언 없음 (기본값 showServerInfo=true 로 동작)"

    result_manual "실제 HTTP 응답 헤더에 서버 정보가 나오는지 수동 확인 (위 설정값 참고)"
}

# WEB-17 (중) 웹 서비스 가상 디렉터리 삭제
#   양호 : 불필요한 가상 디렉터리가 존재하지 않는 경우
#   취약 : 불필요한 가상 디렉터리가 존재하는 경우
# server.xml, context.xml 파일들을 읽어 context 태그 내 path, docBase 속성 값을 가져와서 출력
web_17() {
    head_item "WEB-17" "웹 서비스 가상 디렉터리 삭제" "중"
    info "판단기준> 양호: 불필요한 가상 디렉터리가 없는 경우"
    info "          취약: 불필요한 가상 디렉터리가 존재하는 경우"

    local n=0 f e p doc
    for f in "$TC_SERVER_XML" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$f" ] || continue
        while IFS= read -r e; do
            p=$(attr_of "$e" "[[:space:]]path"); [ -n "$p" ] || continue
            n=$((n + 1)); doc=$(attr_of "$e" "[[:space:]]docBase")
            info "가상 디렉터리: path=\"$p\" docBase=\"${doc:-(미설정)}\" ($f)"
        done < <(xml_active_flat "$f" | tr "'" '"' | grep -oiE '<Context[[:space:]][^<]*')
    done

    [ "$n" -eq 0 ] && { result_good "설정된 가상 디렉터리(Context path) 없음"; return; }
    result_manual "위 ${n}건의 가상 디렉터리가 업무상 필요한지 수동 확인"
}

# WEB-18 (상) 
web_18() {
    head_item "WEB-18" "웹 서비스 WebDAV 비활성화" "상" "Apache, Nginx, IIS, WebtoB"
    info "판단기준> 양호: WebDAV 서비스를 비활성화하고 있는 경우 / 취약: 활성화하고 있는 경우"
    result_na "가이드 점검 대상에 Tomcat 이 포함되지 않음"
}

#------------------------------------------------------------------------------
# 3. 보안 설정   WEB-19 ~ WEB-24
#------------------------------------------------------------------------------

# WEB-19 (중) 웹 서비스 SSI 사용 제한   [가이드 대상: Apache, Tomcat, Nginx, IIS, WebtoB]
#   양호 : SSI 사용 설정이 비활성화되어 있는 경우
#   취약 : 활성화되어 있는 경우
#   web.xml 파일들 내 servlet-name, filter-name 태그 에 SSIServlet, SSIFilter 문자열 있는지 확인
web_19() {
    head_item "WEB-19" "웹 서비스 SSI(Server Side Includes) 사용 제한" "중"
    info "판단기준> 양호: SSI 사용 설정이 비활성화되어 있는 경우"
    info "          취약: 활성화되어 있는 경우"

    local vuln=0 f e
    for f in "${TC_WEB_XMLS[@]}"; do
        while IFS= read -r e; do
            [ -n "$e" ] || continue
            info "SSI 설정 활성: $e ($f)"; vuln=1
        done < <(xml_active_flat "$f" \
                 | grep -oiE '<(servlet|filter)-(name|class)>[^<]*(SSIServlet|SSIFilter)[^<]*</(servlet|filter)-(name|class)>' \
                 | sed -E 's#[[:space:]]+##g' | sort -u)
    done

    [ "$vuln" -eq 1 ] \
        && result_vuln "SSI 사용이 활성화되어 있음 - 위 설정과 관련 매핑을 삭제 또는 주석 처리" \
        || result_good "SSI 서블릿·필터 설정이 없음 (SSI 비활성)"
}

# WEB-20 (상) SSL/TLS 활성화
web_20() {
    head_item "WEB-20" "SSL/TLS 활성화" "상" "Apache, Nginx, IIS, WebtoB"
    info "판단기준> 양호: SSL/TLS 설정이 활성화되어 있는 경우 / 취약: 비활성화되어 있는 경우"
    result_na "가이드 점검 대상에 Tomcat 이 포함되지 않음"
}

# WEB-21 (중) HTTP 리디렉션
web_21() {
    head_item "WEB-21" "HTTP 리디렉션" "중" "Apache, Nginx, IIS, WebtoB"
    info "판단기준> 양호: HTTP 접근 시 HTTPS Redirection 이 활성화된 경우 / 취약: 비활성화된 경우"
    result_na "가이드 점검 대상에 Tomcat 이 포함되지 않음"
}

# WEB-22 (하) 에러 페이지 관리
#   양호 : 웹 서비스 에러 페이지가 별도로 지정된 경우
#   취약 : 지정되지 않았거나, 에러 발생 시 중요 정보가 노출되는 경우
#   web.xml에서 error=page 태그 검색헤서 그 내 error-code, location 태그를 검색 없으면 취약 있으면 수동진단
web_22() {
    head_item "WEB-22" "에러 페이지 관리" "하"
    info "판단기준> 양호: 웹 서비스 에러 페이지가 별도로 지정된 경우"
    info "          취약: 지정되지 않았거나 에러 발생 시 중요 정보가 노출되는 경우"

    local n=0 f b code loc
    for f in "${TC_WEB_XMLS[@]}"; do
        # RS 로 닫는 태그를 끊어 블록 단위로 본다. 코드와 위치의 짝이 어긋나지 않게. → 21절
        while IFS= read -r b; do
            n=$((n + 1))
            code=$(printf '%s' "$b" | grep -oiE '<(error-code|exception-type)>[^<]*</(error-code|exception-type)>' \
                   | head -1 | sed -E 's#<[^>]*>##g' | tr -d '[:blank:]')
            loc=$(printf '%s' "$b" | grep -oiE '<location>[^<]*</location>' \
                  | head -1 | sed -E 's#<[^>]*>##g' | tr -d '[:blank:]')
            info "에러 페이지: ${code:-(코드 없음)} -> ${loc:-(위치 없음)} ($f)"
        done < <(xml_active_flat "$f" \
                 | awk 'BEGIN{RS="</error-page>"} /<error-page>/{sub(/.*<error-page>/,""); print}')
    done

    [ "$n" -eq 0 ] && { result_vuln "일원화된 에러 페이지가 지정되지 않음 - web.xml 에 error-page 설정"; return; }
    result_manual "위 ${n}건에 중요 정보가 노출되는지, 필수 에러 코드가 모두 지정되었는지 수동 확인"
}

# WEB-23 (중) LDAP 알고리즘 적절하게 구성   [가이드 대상: Tomcat 단독]
#   양호 : LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우
#   취약 : 사용하지 않는 경우
#   server.xml, context.xml 파일들내 Realm 태그 내 ~JNDIRealm(classname) 가 선언되있으면 
#   digest 속성을 찾아서 진단. 
#   이 때 tomcat 7이하는 digest속성이지만 tomcat 8은 algorithm이라 digest가 없으면 수동진단으로...
web_23() {
    head_item "WEB-23" "LDAP 알고리즘 적절하게 구성" "중"
    info "판단기준> 양호: LDAP 연결 인증 시 안전한 다이제스트 알고리즘을 사용하는 경우"
    info "          취약: 사용하지 않는 경우 (가이드 조치 방법: SHA-256 이상)"

    local n=0 vuln=0 manual=0 f e alg
    for f in "$TC_SERVER_XML" "${TC_CONTEXT_XMLS[@]}"; do
        [ -f "$f" ] || continue
        while IFS= read -r e; do
            printf '%s' "$e" | grep -qi 'JNDIRealm' || continue
            n=$((n + 1)); alg=$(attr_of "$e" "[[:space:]]digest")
            if   [ -z "$alg" ]; then
                info "LDAP Realm: digest 미설정 ($f)"; manual=1
            elif printf '%s' "$alg" | grep -qiE 'SHA-?3?-?(256|384|512)'; then
                info "LDAP Realm: digest=\"$alg\" (SHA-256 이상) ($f)"
            else
                info "LDAP Realm: digest=\"$alg\" (SHA-256 미만) ($f)"; vuln=1
            fi
        done < <(xml_active_flat "$f" | tr "'" '"' | grep -oiE '<Realm[[:space:]][^<]*')
    done

    if   [ "$n" -eq 0 ];      then result_na "LDAP Realm(JNDIRealm) 설정이 없어 LDAP 인증을 사용하지 않음"
    elif [ "$vuln" -eq 1 ];   then result_vuln "LDAP 다이제스트가 SHA-256 미만 - digest 를 SHA-256 이상으로 변경"
    elif [ "$manual" -eq 1 ]; then result_manual "LDAP Realm 에 digest 가 없음 - bind 인증 여부와 CredentialHandler 설정을 수동 확인"
    else                           result_good "LDAP 다이제스트 알고리즘이 SHA-256 이상"
    fi
}

# WEB-24 (중) 별도의 업로드 경로 사용 및 권한 설정
#   양호 : 별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우
#   취약 : 별도 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우
#
#   가이드 예시 내용이 진단 항목에 맞지 않다고 판단.(별도 업로드 경로 설정은 multipart-config 태그로 해야한다고 생각.)
#   web.xml에서 multipart-config 태그 내 location 태그 에서 경로를 확인하고 권한을 확인한다.
web_24() {
    head_item "WEB-24" "별도의 업로드 경로 사용 및 권한 설정" "중"
    info "판단기준> 양호: 별도의 업로드 경로를 사용하고 일반 사용자 접근 권한이 없는 경우"
    info "          취약: 별도 경로를 사용하지 않거나 일반 사용자 접근 권한이 있는 경우"

    local n=0 f loc
    for f in "${TC_WEB_XMLS[@]}"; do
        while IFS= read -r loc; do
            [ -n "$loc" ] || continue
            n=$((n + 1))
            if [ -e "$loc" ]; then
                info "multipart 임시 저장 경로: $loc (권한 $(fperm "$loc"), 소유자 $(fowner "$loc")) ($f)"
            else
                info "multipart 임시 저장 경로: $loc (경로 없음) ($f)"
            fi
        done < <(xml_active_flat "$f" \
                 | awk 'BEGIN{RS="</multipart-config>"} /<multipart-config>/{sub(/.*<multipart-config>/,""); print}' \
                 | grep -oiE '<location>[^<]*</location>' | sed -E 's#<[^>]*>##g' | tr -d '[:blank:]')
    done
    [ "$n" -eq 0 ] && info "web.xml 에 multipart-config location 설정 없음"

    result_manual "실제 업로드 경로가 웹 서비스 경로(WEB-11 목록) 밖인지, 그 경로에 일반 사용자 접근 권한이 없는지 수동 확인"
}

#------------------------------------------------------------------------------
# 4. 패치/로그     WEB-25 WEB-26
#------------------------------------------------------------------------------

# WEB-25 (상) 주기적 보안 패치 및 벤더 권고사항 적용
#   양호 : 최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적으로 관리하는 경우
#   취약 : 미적용이거나, 정책 수립·주기적 관리를 하지 않는 경우
#   tc_version 함수 사용 /usr/lib/jvm/java-21-openjdk/bin/java(환경변수에 등록된 실제 실행파일 경로)
#   /opt/tomcat/lib/catalina.jar의 org.apache.catalina.util.ServerInfo 실행 server version/number 추출
web_25() {
    head_item "WEB-25" "주기적 보안 패치 및 벤더 권고사항 적용" "상"
    info "판단기준> 양호: 최신 보안 패치 적용 + 패치 정책 수립·주기적 관리"
    info "          취약: 미적용이거나 정책 수립·주기적 관리를 하지 않는 경우"

    local ver
    ver=$(tc_version)                 # 3단계 확인. 배너와 같은 값을 쓴다.
    info "Tomcat 버전: ${ver:-확인 불가}"

    result_manual "위 버전이 최신 보안 패치 적용 상태인지, 패치 정책 수립·주기적 관리 여부를 수동 확인 (벤더 공지: tomcat.apache.org)"
}

# WEB-26 (중) 로그 디렉터리 및 파일 권한 설정
#   양호 : 로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우
#   취약 : 일반 사용자의 접근 권한이 있는 경우
#   server.xml에서 Value  태그 옵션 내 AccessLogValue(className) 설정 있을 시 directory 속성의 폴더 경로 값을 가져와 해당 폴더 및 하위 파일들의 권한 확인
web_26() {
    head_item "WEB-26" "로그 디렉터리 및 파일 권한 설정" "중"
    info "판단기준> 양호: 로그 디렉터리·파일에 일반 사용자(other) 접근 권한이 없는 경우"
    info "          취약: 접근 권한이 있는 경우"

    local n=0 bad=0 d f p dirs
    dirs=$( { printf '%s\n' "$TOMCAT_BASE/logs" "$TOMCAT_HOME/logs"
              xml_active_flat "$TC_SERVER_XML" | tr "'" '"' \
                | grep -oiE '<Valve[[:space:]][^<]*' | grep -i 'AccessLogValve' \
                | grep -oiE '[[:space:]]directory[[:space:]]*=[[:space:]]*"[^"]*"' \
                | sed -E 's/^[^=]*=[[:space:]]*"//; s/"$//'; } \
            | grep . | sed -E "s#^([^/])#$TOMCAT_BASE/\1#" | sort -u )

    while IFS= read -r f; do
        [ -e "$f" ] || continue
        n=$((n + 1)); p=$(fperm "$f")
        [ -n "$p" ] && [ "$(perm_other "$p")" -eq 0 ] && continue
        bad=$((bad + 1))
        [ "$bad" -le 20 ] && info "일반 사용자 접근 가능: $f (권한 ${p:-확인불가}, 소유자 $(fowner "$f"))"
    done < <(while IFS= read -r d; do
                 [ -d "$d" ] && find "$d" -maxdepth 2 2>/dev/null
             done <<< "$dirs" | sort -u)
    [ "$bad" -gt 20 ] && info "그 외 $((bad - 20))건 더 있음"

    if [ "$n" -eq 0 ]; then
        info "확인한 경로: $(printf '%s' "$dirs" | tr '\n' ' ')"
        result_manual "로그 디렉터리를 찾지 못함 - 로그 위치와 권한을 수동 확인"
    elif [ "$bad" -eq 0 ]; then
        result_good "확인한 ${n}개 항목 모두 일반 사용자 접근 권한 없음"
    else
        result_vuln "로그 디렉터리·파일에 일반 사용자 접근 권한 존재 - chmod o-rwx <위 항목>"
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
    require_tomcat

    web_01; web_02; web_03
    web_04; web_05; web_06; web_07; web_08; web_09; web_10; web_11; web_12; web_13; web_14; web_15; web_16; web_17; web_18
    web_19; web_20; web_21; web_22; web_23; web_24
    web_25; web_26

    print_summary
}

main "$@"
