#!/bin/bash
# 02_access.sh - 접근 관리 진단 (D-10 ~ D-16)
# 대상 DBMS: MySQL 8.0 (Rocky Linux 10)

# ────────────────────────────────────────────────────────────
# D-10 (상) 원격에서 DB 서버로의 접속 제한
# 판단 기준:
#   - 양호: DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우
#   - 취약: 제한하지 않은 경우
# mysql.user에서 user@host 정보를 가져와서 출력 후 인터뷰 필요
check_D10() {
    local id="D-10" title="원격에서 DB 서버로의 접속 제한"
    local hosts rc

    hosts=$(mysql_query "SELECT IFNULL(GROUP_CONCAT(
                           CONCAT(IF(user='','(익명)',user), '@', host)
                           ORDER BY (host='%') DESC, user, host SEPARATOR ', '), '')
                         FROM mysql.user;")
    rc=$?

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "mysql.user 조회 실패 - 계정별 접속 허용 호스트 수동 확인 필요"
        return
    fi

    result_interview "$id" "$title" \
        "지정된 IP에서만 접속 가능한지 담당자 확인 필요 [계정@호스트: ${hosts}]"
}

# ────────────────────────────────────────────────────────────
# D-11 (상) DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# 판단 기준:
#   - 양호: 시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우
#   - 취약: DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우
# mysql.user 의 select_priv(조회), mysql.db (mysql, sys 데이터 베이스 접근), mysql.tables_priv(mysql, sys 테이블 접근) 여부 확인
check_D11() {
    local id="D-11" title="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
    local issues rc

    issues=$(mysql_query "SELECT IFNULL(GROUP_CONCAT(g SEPARATOR ', '), '') FROM (
               SELECT CONCAT(user,'@',host,'(전역 SELECT)') AS g FROM mysql.user
                WHERE Select_priv='Y' AND user != 'root' AND user NOT LIKE 'mysql.%'
               UNION ALL
               SELECT CONCAT(user,'@',host,'(db=',db,')') FROM mysql.db
                WHERE db IN ('mysql','sys') AND user != 'root' AND user NOT LIKE 'mysql.%'
               UNION ALL
               SELECT CONCAT(user,'@',host,'(table=',db,'.',table_name,')') FROM mysql.tables_priv
                WHERE db IN ('mysql','sys') AND user != 'root' AND user NOT LIKE 'mysql.%'
             ) AS t;")
    rc=$?

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "권한 테이블 조회 실패 - 시스템 테이블 접근 권한 수동 확인 필요"
    elif [[ -n "$issues" ]]; then
        result_fail "$id" "$title" "일반 계정이 시스템 테이블 접근 가능: ${issues}"
    else
        result_pass "$id" "$title" "DBA(root) 외 시스템 테이블 접근 가능 계정 없음"
    fi
}

# D-12 (상) 안전한 리스너 비밀번호 설정 및 사용
check_D12() {
    result_na "D-12" "안전한 리스너 비밀번호 설정 및 사용" \
        "점검 대상 아님(Oracle DB 전용)"
}

# D-13 (중) 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용
check_D13() {
    result_na "D-13" "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용" \
        "점검 대상 아님(Windows OS 전용)"
}

# ────────────────────────────────────────────────────────────
# D-14 (중) 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은
#           주요 파일들의 접근 권한이 적절하게 설정
# mysql 설정 파일(etc/my.cnf ...) 들 및 로그인 사용자 디렉터리내 설정파일 여부 확인 후 권한 검증 
# /etc/passwd에서 쉘 사용 가능한 사용자 검색의 home디렉토리 내 mysql 설정 파일 확인
list_home_my_cnf() {
    local passwd_file="${1:-/etc/passwd}"
    local home shell seen="|"

    [[ -r "$passwd_file" ]] || return 0

    while IFS=: read -r _ _ _ _ _ home shell; do
        # 로그인 불가 시스템 계정(bin, chrony, named 등)은 ~/.my.cnf 를 만들 수 없음
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        home="${home%/}"                   # 끝 슬래시 제거 (/run/sssd/ -> /run/sssd)
        [[ -n "$home" && "$home" != "/" && -d "$home" ]] || continue
        # 홈디렉터리를 공유하는 계정이 여러 개인 경우 중복 점검 방지
        case "$seen" in 
            *"|${home}|"*) continue ;; 
        esac
        seen="${seen}${home}|"
        printf '%s\n%s\n' "${home}/.my.cnf" "${home}/my.cnf"
    done < "$passwd_file"
}

check_D14() {
    local id="D-14" title="데이터베이스 주요 설정 파일, 비밀번호 파일 등의 접근 권한 설정"
    local f perm owner issues=() checked=()

    shopt -s nullglob
    local files=(/etc/my.cnf /etc/mysql/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf.d/*.cnf)
    shopt -u nullglob

    # mapfile -t : 개행문자 제거, -O : 배열 인덱스 저장
    mapfile -t -O "${#files[@]}" files < <(list_home_my_cnf)

    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        perm=$(get_perm "$f")
        owner=$(get_owner "$f")
        if perm_le 640 "$perm"; then
            checked+=("${f}(${perm},${owner})")
        else
            issues+=("${f}(${perm},${owner}) 기준 640 이하")
        fi
    done

    if [[ ${#issues[@]} -gt 0 ]]; then
        result_fail "$id" "$title" "$(IFS='|'; echo "${issues[*]}")"
    elif [[ ${#checked[@]} -gt 0 ]]; then
        result_pass "$id" "$title" "$(IFS='|'; echo "${checked[*]}")"
    else
        result_interview "$id" "$title" "설정 파일 미발견(설치 경로 수동 확인 필요)"
    fi
}

# D-15 (하) 관리자 이외의 사용자가 오라클 리스너의 접속을 통해
check_D15() {
    result_na "D-15" "관리자 외 사용자의 리스너 로그 및 trace 파일 변경 제한" \
        "점검 대상 아님(Oracle DB 전용)"
}

# D-16 (하) Windows 인증 모드 사용
check_D16() {
    result_na "D-16" "Windows 인증 모드 사용" \
        "점검 대상 아님(MSSQL 전용)"
}

# ────────────────────────────────────────────────────────────
# 섹션 실행
# ────────────────────────────────────────────────────────────
run_access_checks() {
    print_section "2. 접근 관리 (D-10 ~ D-16)"
    check_D10
    check_D11
    check_D12
    check_D13
    check_D14
    check_D15
    check_D16
}
