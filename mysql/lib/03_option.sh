#!/bin/bash

# D-17 (하) Audit Table은 데이터베이스 관리자 계정에 접근하도록 제한
check_D17() {
    result_na "D-17" "Audit Table은 데이터베이스 관리자 계정에 접근하도록 제한" \
        "점검 대상 아님(Oracle, Altibase, Tibero 전용)"
}

# D-18 (상) 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정
check_D18() {
    result_na "D-18" "응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정" \
        "점검 대상 아님(Oracle, Altibase, Tibero, Cubrid 전용)"
}

# D-19 (상) OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정
check_D19() {
    result_na "D-19" "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정" \
        "점검 대상 아님(Oracle DB 전용)"
}

# D-20 (하) 인가되지 않은 Object Owner의 제한
check_D20() {
    result_na "D-20" "인가되지 않은 Object Owner의 제한" \
        "점검 대상 아님(Oracle, Altibase, Tibero, PostgreSQL 전용)"
}

# D-21 (중) 인가되지 않은 GRANT OPTION 사용 제한
# 판단 기준:
#   - 양호: WITH GRANT OPTION이 ROLE에 의하여 설정된 경우
#   - 취약: WITH GRANT OPTION이 ROLE에 의하여 설정되지 않은 경우
# mysql.user에서 전역 범위로 권한을 넘길 수 있는 일반 사용자를 찾는다. mysql.db 에서 특정 db 범위 권한을 줄 수 있는 사용자를 찾는다.
# mysql.tables_priv 에서 특정 table 범위 권한을 줄 수 있는 사용자를 찾는다. mysql.procs_priv 에서 특정 프로시저 함수 범위 권한을 줄 수 있는 사용자를 찾는다.
# 이 넷중 하나라도 해당되면 조회
# ────────────────────────────────────────────────────────────
check_D21() {
    local id="D-21" title="인가되지 않은 GRANT OPTION 사용 제한"
    local issues rc

    issues=$(mysql_query "SELECT IFNULL(GROUP_CONCAT(g SEPARATOR ', '), '') FROM (
               SELECT CONCAT(user,'@',host,'(전역)') AS g FROM mysql.user
                WHERE Grant_priv='Y' AND user != 'root' AND user NOT LIKE 'mysql.%'
               UNION ALL
               SELECT CONCAT(user,'@',host,'(db=',db,')') FROM mysql.db
                WHERE Grant_priv='Y' AND user != 'root' AND user NOT LIKE 'mysql.%'
               UNION ALL
               SELECT CONCAT(user,'@',host,'(table=',db,'.',table_name,')') FROM mysql.tables_priv
                WHERE FIND_IN_SET('Grant',Table_priv) AND user != 'root' AND user NOT LIKE 'mysql.%'
               UNION ALL
               SELECT CONCAT(user,'@',host,'(routine=',db,'.',routine_name,')') FROM mysql.procs_priv
                WHERE FIND_IN_SET('Grant',Proc_priv) AND user != 'root' AND user NOT LIKE 'mysql.%'
             ) AS t;")
    rc=$?

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "권한 테이블 조회 실패 - GRANT OPTION 보유 계정 수동 확인 필요"
    elif [[ -n "$issues" ]]; then
        result_fail "$id" "$title" "일반 계정에 GRANT OPTION 부여됨: ${issues}"
    else
        result_pass "$id" "$title" "root 외 GRANT OPTION 보유 계정 없음"
    fi
}

# D-22 (하) 데이터베이스의 자원 제한 기능을 TRUE로 설정
check_D22() {
    result_na "D-22" "데이터베이스의 자원 제한 기능을 TRUE로 설정" \
        "점검 대상 아님(Oracle DB 전용)"
}

# D-23 (상) xp_cmdshell 사용 제한
check_D23() {
    result_na "D-23" "xp_cmdshell 사용 제한" \
        "점검 대상 아님(MSSQL 전용)"
}

# D-24 (상) Registry Procedure 권한 제한
check_D24() {
    result_na "D-24" "Registry Procedure 권한 제한" \
        "점검 대상 아님(MSSQL 전용)"
}

# ────────────────────────────────────────────────────────────
# 섹션 실행
# ────────────────────────────────────────────────────────────
run_option_checks() {
    print_section "3. 옵션 관리 (D-17 ~ D-24)"
    check_D17
    check_D18
    check_D19
    check_D20
    check_D21
    check_D22
    check_D23
    check_D24
}
