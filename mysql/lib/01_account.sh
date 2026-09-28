#!/bin/bash

# D-01 (상) 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# 판단 기준:
#   - 양호: 기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우
#   - 취약: 기본 계정의 초기 비밀번호를 변경하지 않거나 잠금설정을 하지 않은 경우
# root, mysql.sys, mysql.session, mysql.infoschema, ''(익명 계정), mariadb.sys, mysql, percona.telemetry, healthchecker
# 이 계정들을 조건으로 조회해서 사용자 명@호스트 와 계정 락 상태를 group_concat 으로 출력
check_D01() {
    local id="D-01" title="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    local rows rc

    # IFNULL: 매칭 행이 0건이면 GROUP_CONCAT 이 NULL 을 반환해 문자열 "NULL" 이 찍힘
    rows=$(mysql_query "SELECT IFNULL(GROUP_CONCAT(
                          CONCAT(IF(user='','(익명)',user), '@', host,
                                 '(lock=', account_locked, ')')
                          ORDER BY (user='root') DESC, user, host SEPARATOR ', '), '')
                        FROM mysql.user
                        WHERE user LIKE 'mysql.%'
                           OR user IN ('root','','mariadb.sys',
                                       'mysql','percona.telemetry','healthchecker');")
    # 바로 직전에 실행했던 명령어의 '종료 상태 코드(Exit Code)' 저장
    rc=$?

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "mysql.user 조회 실패(진단 계정의 SELECT 권한 부족 등) - 기본 계정 현황 수동 확인 필요"
    elif [[ -z "$rows" ]]; then
        result_interview "$id" "$title" \
            "기본 계정 미존재(계정명 변경 추정) - 기본 계정 관리 현황 담당자 확인 필요"
    else
        result_interview "$id" "$title" \
            "초기 비밀번호 변경 또는 잠금설정 여부 담당자 확인 필요 [기본계정: ${rows}]"
    fi
}

# D-02 (상) 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
# 판단 기준:
#   - 양호: 계정 정보를 확인하여 불필요한 계정이 없는 경우
#   - 취약: 인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 불필요한 계정이 존재하는 경우
# mysql 예약 계정 외 모든 계정 조회해서 조회 실패시 mysql 연결 에러외 익명계정 포함 모든 계정 정보는 인터뷰
check_D02() {
    local id="D-02" title="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
    local users anon rc=0

    # 전체 계정 목록 (MySQL 예약 계정 제외)
    users=$(mysql_query "SELECT IFNULL(GROUP_CONCAT(
                           CONCAT(IF(user='','(익명)',user), '@', host)
                           ORDER BY user, host SEPARATOR ', '), '')
                         FROM mysql.user
                         WHERE user NOT LIKE 'mysql.%';") || rc=1

    # 익명 계정: user 컬럼이 빈 문자열인 계정
    anon=$(mysql_query "SELECT IFNULL(GROUP_CONCAT(
                          CONCAT(IF(user='','(익명)',user), '@', host)
                          ORDER BY host SEPARATOR ', '), '')
                        FROM mysql.user
                        WHERE user='';") || rc=1

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "mysql.user 조회 실패 - 계정 현황 수동 확인 필요"
    elif [[ -n "$anon" ]]; then
        result_fail "$id" "$title" \
            "익명 계정 존재: ${anon} [전체 계정: ${users}]"
    else
        result_interview "$id" "$title" \
            "계정별 용도(퇴직자·미사용 계정 여부) 담당자 확인 필요 [전체 계정: ${users}]"
    fi
}

# D-03 (상) 비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정
# 판단 기준:
#   - 양호: 기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우
#   - 취약: 적용되지 않은 경우
#   SHOW VARIABLES LIKE 'validate_password%';        (복잡도 정책)
#   SHOW VARIABLES LIKE 'default_password_lifetime'; (사용 기간)
# 기준값(가이드 비밀번호 관리 방법/예시 참조):
#   - validate_password.length >= 8
#   - validate_password.policy MEDIUM 이상
#   - validate_password.mixed_case_count >= 1   (영문 대소문자 최소 개수)
#   - validate_password.number_count >= 1       (숫자 최소 개수)
#   - validate_password.special_char_count >= 1 (특수문자 최소 개수)
#   - default_password_lifetime 1~90일
check_D03() {
    local id="D-03" title="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
    local vp_vars vp_len vp_policy lifetime var_name val label
    local rc=0 fail_reasons=() pass_items=()
    local note="※ 사내/기관 정책에 맞게 확인 필요"

    vp_vars=$(mysql_query "SHOW VARIABLES LIKE 'validate_password%';") || rc=1

    # 비밀번호 사용 기간 (0 = 만료 없음)
    lifetime=$(mysql_query "SELECT @@global.default_password_lifetime;") || rc=1

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "비밀번호 정책 조회 실패 - 설정 현황 수동 확인 필요 ${note}"
        return
    fi

    if [[ -z "$vp_vars" ]]; then
        fail_reasons+=("validate_password 컴포넌트 미설치(복잡도 정책 미적용)")
    else
        #awk -F : 구분자로 필드 분리
        vp_len=$(awk -F'\t' '$1=="validate_password.length"{print $2}' <<< "$vp_vars")
        vp_policy=$(awk -F'\t' '$1=="validate_password.policy"{print $2}' <<< "$vp_vars")

        if [[ -n "$vp_len" && "$vp_len" -ge 8 ]]; then
            pass_items+=("length=${vp_len}")
        else
            fail_reasons+=("validate_password.length=${vp_len:-미설정} (기준 8 이상)")
        fi

        case "$vp_policy" in
            MEDIUM|STRONG) pass_items+=("policy=${vp_policy}") ;;
            *) fail_reasons+=("validate_password.policy=${vp_policy:-미설정} (기준 MEDIUM 이상)") ;;
        esac

        # 문자 조합 최소 개수: 영문 대소문자 / 숫자 / 특수문자 각 1개 이상
        for var_name in mixed_case_count number_count special_char_count; do
            case "$var_name" in
                mixed_case_count)   label="영문 대소문자" ;;
                number_count)       label="숫자" ;;
                special_char_count) label="특수문자" ;;
            esac
            val=$(awk -F'\t' -v v="validate_password.${var_name}" '$1==v{print $2}' <<< "$vp_vars")
            if [[ -n "$val" && "$val" -ge 1 ]]; then
                pass_items+=("${var_name}=${val}")
            else
                fail_reasons+=("validate_password.${var_name}=${val:-미설정} (기준 ${label} 1 이상)")
            fi
        done
    fi

    if [[ -n "$lifetime" && "$lifetime" -ge 1 && "$lifetime" -le 90 ]]; then
        pass_items+=("lifetime=${lifetime}일")
    else
        fail_reasons+=("default_password_lifetime=${lifetime:-확인불가} (기준 1~90일)")
    fi

    if [[ ${#fail_reasons[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "$(IFS='|'; echo "${pass_items[*]}")"
    elif [[ ${#pass_items[@]} -gt 0 ]]; then
        result_fail "$id" "$title" \
            "$(IFS='|'; echo "${fail_reasons[*]}") [충족: $(IFS='|'; echo "${pass_items[*]}")] ${note}"
    else
        result_fail "$id" "$title" "$(IFS='|'; echo "${fail_reasons[*]}") ${note}"
    fi
}

# D-04 (상) 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
# 판단 기준:
#   - 양호: 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우
#   - 취약: 관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우
# information_schema의 user_privileges에서 privilege_type 이 super인 계정의 grantee를 조회해서 만약 root 및 mysql 시스템 계정일 경우 제외 후 계정 검사진행
check_D04() {
    local id="D-04" title="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
    local super_users rc extra=()

    super_users=$(mysql_query "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES
                               WHERE PRIVILEGE_TYPE='SUPER';")
    rc=$?

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "USER_PRIVILEGES 조회 실패 - SUPER 권한 보유 계정 수동 확인 필요"
        return
    fi

    while IFS= read -r g; do
        [[ -z "$g" ]] && continue
        case "$g" in
            # root 및 MySQL 내부 시스템 계정은 관리자 권한 보유가 정상
            \'root\'@*|\'mysql.session\'@*|\'mysql.sys\'@*|\'mysql.infoschema\'@*) ;;
            *) extra+=("$g") ;;
        esac
    done <<< "$super_users"

    if [[ ${#extra[@]} -eq 0 ]]; then
        result_pass "$id" "$title" "SUPER 권한 보유 계정: root 및 시스템 계정만 존재"
    else
        result_interview "$id" "$title" \
            "root 외 SUPER 권한 계정 존재 - 권한 필요 여부 담당자 확인 필요 [$(IFS=','; echo "${extra[*]}")]"
    fi
}

# D-05 (중) 비밀번호 재사용에 대한 제약 설정
check_D05() {
    result_na "D-05" "비밀번호 재사용에 대한 제약 설정" \
        "점검 대상 아님(Oracle, Altibase, Tibero 전용)"
}

# D-06 (중) DB 사용자 계정을 개별적으로 부여하여 사용
# 판단 기준:
#   - 양호: 사용자별 계정을 사용하고 있는 경우
#   - 취약: 공용 계정을 사용하고 있는 경우
# mysql.user에서 mysql가 포함된 시스템 계정을 제외하고 나머지 계정 곗수와 계정정보를 가져온다.
check_D06() {
    local id="D-06" title="DB 사용자 계정을 개별적으로 부여하여 사용"
    local rows rc cnt users

    # 개수와 목록을 한 쿼리로 조회 (별도 조회 시 두 값이 어긋날 수 있음)
    rows=$(mysql_query "SELECT COUNT(*),
                               IFNULL(GROUP_CONCAT(
                                 CONCAT(IF(user='','(익명)',user), '@', host)
                                 ORDER BY user, host SEPARATOR ', '), '')
                        FROM mysql.user
                        WHERE user NOT LIKE 'mysql.%';")
    rc=$?

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "mysql.user 조회 실패 - 계정 현황 수동 확인 필요"
        return
    fi

    IFS=$'\t' read -r cnt users <<< "$rows"

    result_interview "$id" "$title" \
        "공용 계정 사용 여부 담당자 확인 필요 [계정 ${cnt}개: ${users}]"
}

# D-07 (중) root 권한으로 서비스 구동 제한
# 판단 기준:
#   - 양호: DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우
#   - 취약: DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우
#   실행중인 mysqld프로세서를 ps -eo user, comm으로 가져와서 실행 주체를 확인, 설정파일에서 [mysqld] 설정의 user 값 확인하기
check_D07() {
    local id="D-07" title="root 권한으로 서비스 구동 제한"
    local proc_users cfg_user

    proc_users=$(ps -eo user:32,comm --no-headers 2>/dev/null \
                 | awk '$2 == "mysqld" {print $1}' | sort -u | tr '\n' ' ')
    cfg_user=$(cat /etc/my.cnf /etc/my.cnf.d/*.cnf 2>/dev/null \
               | awk '/^[ \t]*\[/{s=$0} s~/^\[mysqld\]$/&&/^[ \t]*user[ \t]*=/{gsub(/[ \t]/,"");v=$0} END{print v}')

    if [[ -z "$proc_users" ]]; then
        result_interview "$id" "$title" \
            "mysqld 프로세스 미발견(원격 DB 또는 서비스 중지 상태) - 구동 계정 수동 확인 필요 [설정: ${cfg_user:-미설정}]"
    elif grep -qw 'root' <<< "$proc_users"; then
        result_fail "$id" "$title" \
            "mysqld가 root 권한으로 구동 중 [구동 계정: ${proc_users% } | 설정: ${cfg_user:-미설정}]"
    else
        result_pass "$id" "$title" \
            "mysqld 구동 계정: ${proc_users% } [설정: ${cfg_user:-미설정}]"
    fi
}

# D-08 (상) 안전한 암호화 알고리즘 사용
# 판단 기준:
#   - 양호: 해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우
#   - 취약: SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우
# mysql.user에서 mysql_navtive_password, mysql_old_password / caching_sha2_password, sha256_password 사용 여부를 위한 plugin 조회 확인
check_D08() {
    local id="D-08" title="안전한 암호화 알고리즘 사용"
    local rows rc weak others

    rows=$(mysql_query "SELECT CONCAT(
             IFNULL(GROUP_CONCAT(IF(plugin IN ('mysql_native_password','mysql_old_password'),
                     CONCAT(user,'@',host,'(',plugin,')'), NULL) SEPARATOR ', '), ''),
             '|',
             IFNULL(GROUP_CONCAT(IF(plugin NOT IN ('mysql_native_password','mysql_old_password',
                     'caching_sha2_password','sha256_password'),
                     CONCAT(user,'@',host,'(',plugin,')'), NULL) SEPARATOR ', '), ''))
           FROM mysql.user;")
    rc=$?

    if [[ $rc -ne 0 ]]; then
        result_interview "$id" "$title" \
            "mysql.user 조회 실패 - 계정별 암호화 알고리즘 수동 확인 필요"
        return
    fi

    IFS='|' read -r weak others <<< "$rows"

    if [[ -n "$weak" ]]; then
        result_fail "$id" "$title" "SHA-256 미만 알고리즘 사용 계정 존재: ${weak}"
    elif [[ -n "$others" ]]; then
        result_interview "$id" "$title" \
            "SHA-256 여부를 판별할 수 없는 인증 플러그인 사용 - 담당자 확인 필요: ${others}"
    else
        result_pass "$id" "$title" \
            "전 계정 SHA-256 이상 알고리즘(caching_sha2_password, sha256_password) 사용"
    fi
}

# D-09 (중) 일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정
check_D09() {
    result_na "D-09" "일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정" \
        "점검 대상 아님(Oracle, Altibase, Tibero 전용)"
}

run_account_checks() {
    print_section "1. 계정 관리 (D-01 ~ D-09)"
    check_D01
    check_D02
    check_D03
    check_D04
    check_D05
    check_D06
    check_D07
    check_D08
    check_D09
}
