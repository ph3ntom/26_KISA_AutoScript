#!/bin/bash

# D-25 (상) 주기적 보안 패치 및 벤더 권고 사항 적용
# 판단 기준:
#   - 양호: 보안 패치가 적용된 버전을 사용하는 경우
#   - 취약: 보안 패치가 적용되지 않는 버전을 사용하는 경우
# 로컬에 설치한 mysql(-community)-server 를 rpm으로 검색하고 dnf로 최신 패키지 확인해서 비교
check_D25() {
    local id="D-25" title="주기적 보안 패치 및 벤더 권고 사항 적용"
    local ver pkg="" pkg_ver="" avail="" notes=()

    ver=$(mysql_query "SELECT VERSION();")

    # 설치된 MySQL 패키지 확인 (Rocky 기본 저장소 / MySQL 공식 저장소)
    if rpm -q mysql-server >/dev/null 2>&1; then
        pkg="mysql-server"
    elif rpm -q mysql-community-server >/dev/null 2>&1; then
        pkg="mysql-community-server"
    fi
    [[ -n "$pkg" ]] && pkg_ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null)

    # 저장소에 상위 버전이 있을 때만 그 버전을 근거로 추가
    #   (상위 버전이 없거나 조회 실패 시 빈 값이 되어 출력에서 생략됨)
    [[ -n "$pkg" ]] && avail=$(dnf -q check-update "$pkg" 2>/dev/null \
                               | awk 'NF>=3 {printf "%s ", $2}' | sed 's/ $//')

    notes+=("현재 버전=${ver:-확인불가}")
    [[ -n "$pkg" ]]   && notes+=("패키지=${pkg}-${pkg_ver}")
    [[ -n "$avail" ]] && notes+=("저장소 상위 버전=${avail}")

    result_interview "$id" "$title" \
        "보안 패치 적용 여부 담당자 확인 필요 [$(IFS='|'; echo "${notes[*]}")]"
}


# D-26 (상) 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이
check_D26() {
    result_na "D-26" "데이터베이스의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정" \
        "점검 대상 아님(Oracle, MSSQL, Altibase, Tibero, PostgreSQL 전용)"
}

# ────────────────────────────────────────────────────────────
# 섹션 실행
# ────────────────────────────────────────────────────────────
run_patch_checks() {
    print_section "4. 패치 관리 (D-25 ~ D-26)"
    check_D25
    check_D26
}
