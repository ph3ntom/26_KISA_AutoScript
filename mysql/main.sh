#!/bin/bash

# set -e 는 사용하지 않음: mysql 쿼리 실패(권한 부족 등) 시에도 나머지 항목 진단을 계속 진행해야 하기 때문
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/01_account.sh"
source "${LIB_DIR}/02_access.sh"
source "${LIB_DIR}/03_option.sh"
source "${LIB_DIR}/04_patch.sh"

main() {
    if [[ $EUID -ne 0 ]]; then
        echo "[오류] root 권한으로 실행해야 합니다."
        exit 1
    fi

    mysql_setup_auth
    mysql_check_connection
    mysql_check_privilege

    echo ""
    echo "============================================================"
    echo "  MySQL DBMS 보안 진단 (주요정보통신기반시설 가이드 2026)"
    echo "============================================================"
    echo "  진단 일시  : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  호스트명   : $(hostname)"
    echo "  OS         : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
    echo "  MySQL 버전 : ${MYSQL_VERSION:-확인불가}"
    echo "============================================================"

    run_account_checks
    run_access_checks
    run_option_checks
    run_patch_checks

    echo ""
    echo "============================================================"
    printf "  전체: %d   양호: %d   취약: %d   인터뷰: %d   N/A: %d\n" \
        "$((PASS + FAIL + INTERVIEW + NA))" "$PASS" "$FAIL" "$INTERVIEW" "$NA"
    echo "============================================================"

    generate_report
}

main
