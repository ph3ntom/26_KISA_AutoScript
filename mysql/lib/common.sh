#!/bin/bash
# common.sh - 공통 함수 및 변수 정의 (MySQL DBMS 진단용)
# 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026) 08.DBMS

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASS=0
FAIL=0
INTERVIEW=0
NA=0
RESULTS=()

# ────────────────────────────────────────────────────────────
# 결과 출력
#   양호 / 취약 / 인터뷰(담당자 확인 필요) / N/A(해당 없음)
# ────────────────────────────────────────────────────────────
_result() {
    local status="$1" label="$2" id="$3" title="$4" detail="$5"
    printf "[%s] %-6s %s\n" "$label" "$id" "$title"
    [[ -n "$detail" ]] && printf "           %s\n" "$detail"
    RESULTS+=("${status}|${id}|${title}|${detail}")
}

result_pass()      { _result PASS      "양호  " "$1" "$2" "$3"; PASS=$((PASS + 1)); }
result_fail()      { _result FAIL      "취약  " "$1" "$2" "$3"; FAIL=$((FAIL + 1)); }
result_interview() { _result INTERVIEW "인터뷰" "$1" "$2" "$3"; INTERVIEW=$((INTERVIEW + 1)); }
result_na()        { _result NA        "N/A   " "$1" "$2" "$3"; NA=$((NA + 1)); }

print_section() {
    echo ""
    echo "── $1 ──────────────────────────────────────"
}

# ────────────────────────────────────────────────────────────
# 파일 권한/소유자 확인 (D-14에서 사용)
# ────────────────────────────────────────────────────────────
get_perm()  { stat -c "%a" "$1" 2>/dev/null; }   # %a : 권한을 8진수로 출력
get_owner() { stat -c "%U" "$1" 2>/dev/null; }   # %U : 소유자 이름

perm_le() {
    [[ $((8#$2)) -le $((8#$1)) ]]
}

# ────────────────────────────────────────────────────────────
# MySQL 접속 설정
#   계정/비밀번호를 입력받아 임시 옵션 파일(600)로 저장하여
#   명령행에 비밀번호가 노출되지 않도록 함
# ────────────────────────────────────────────────────────────
MYSQL_AUTH_FILE=""
MYSQL_VERSION=""

mysql_setup_auth() {
    local db_user db_pass db_host db_port

    echo "[MySQL 접속 정보 입력]"
    read -rp "  관리자 계정 [root]: " db_user
    db_user="${db_user:-root}"
    read -rsp "  비밀번호: " db_pass
    echo ""
    read -rp "  접속 호스트 [localhost]: " db_host
    db_host="${db_host:-localhost}"
    read -rp "  접속 포트 [3306]: " db_port
    db_port="${db_port:-3306}"

    MYSQL_AUTH_FILE=$(mktemp "${BASE_DIR}/.mysql_diag.XXXXXX") || {
        echo "[오류] 인증 파일을 생성할 수 없습니다: ${BASE_DIR}"
        exit 1
    }
    chmod 600 "$MYSQL_AUTH_FILE"
    # ※ 비밀번호에 큰따옴표(")가 포함된 경우 옵션 파일 문법상 접속에 실패할 수 있음
    cat > "$MYSQL_AUTH_FILE" <<EOF
[client]
user=${db_user}
password="${db_pass}"
host=${db_host}
port=${db_port}
EOF
    trap 'mysql_cleanup' EXIT
}

mysql_cleanup() {
    [[ -n "${MYSQL_AUTH_FILE:-}" && -f "$MYSQL_AUTH_FILE" ]] && rm -f "$MYSQL_AUTH_FILE"
}

# 쿼리 실행: 결과는 탭 구분, 헤더 없이 반환 (-N: 컬럼명, 테두리 생략, -B: batch 모드)
#   group_concat_max_len: 기본값 1024바이트라 계정이 많으면 GROUP_CONCAT 결과가
#   경고(1260)만 남기고 조용히 잘림. 근거 목록이 손실되지 않도록 세션 단위로 올림
mysql_query() {
    mysql --defaults-extra-file="$MYSQL_AUTH_FILE" -N -B \
          -e "SET SESSION group_concat_max_len = 1000000; $1" 2>/dev/null
}

mysql_check_connection() {
    if ! command -v mysql >/dev/null 2>&1; then
        echo "[오류] mysql 클라이언트가 설치되어 있지 않습니다."
        exit 1
    fi

    if ! mysql_query "SELECT 1;" >/dev/null; then
        echo "[오류] MySQL 접속에 실패했습니다."
        exit 1
    fi

    MYSQL_VERSION=$(mysql_query "SELECT VERSION();")
    if [[ "$MYSQL_VERSION" != 8.0* ]]; then
        echo "[경고] MySQL 8.0 기준 스크립트입니다. (현재: ${MYSQL_VERSION})"
    fi
}

# 진단 계정 권한 확인
#   전 항목이 mysql 스키마(user/db/tables_priv)와 information_schema 조회를
#   전제로 함. 권한이 없으면 쿼리가 빈 값을 반환해 "없음"으로 오판되므로,
#   실제 조회를 시도해 하나라도 실패하면 진단을 중단한다.
#   ※ 계정명이 아닌 권한으로 판정 -> root를 개명한 환경도 정상 동작
mysql_check_privilege() {
    local cur tbl failed=()

    cur=$(mysql_query "SELECT CURRENT_USER();")
    if [[ -z "$cur" ]]; then
        echo "[오류] 진단 계정을 확인할 수 없습니다."
        exit 1
    fi

    for tbl in mysql.user mysql.db mysql.tables_priv \
               information_schema.USER_PRIVILEGES information_schema.plugins; do
        mysql_query "SELECT 1 FROM ${tbl} LIMIT 1;" >/dev/null || failed+=("$tbl")
    done

    if [[ ${#failed[@]} -gt 0 ]]; then
        echo "[오류] 관리자 권한 계정으로 실행해야 합니다."
        echo "       현재 계정 : ${cur}"
        echo "       조회 불가 : $(IFS=', '; echo "${failed[*]}")"
        exit 1
    fi
}

# ────────────────────────────────────────────────────────────
# 결과 파일 생성
# ────────────────────────────────────────────────────────────
generate_report() {
    local report_dir out r status id title detail label
    report_dir="${BASE_DIR}/report"
    mkdir -p "$report_dir"
    out="${report_dir}/result_mysql_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "============================================================"
        echo "  MySQL DBMS 보안 진단 결과"
        echo "  주요정보통신기반시설 기술적 취약점 분석·평가 가이드 기준"
        echo "============================================================"
        echo "  진단 일시  : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  호스트명   : $(hostname)"
        echo "  OS 정보    : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
        echo "  MySQL 버전 : ${MYSQL_VERSION:-확인불가}"
        echo "  진단 계정  : $(whoami)"
        echo "------------------------------------------------------------"
        printf "  전체: %d   양호: %d   취약: %d   인터뷰: %d   N/A: %d\n" \
            "$((PASS + FAIL + INTERVIEW + NA))" "$PASS" "$FAIL" "$INTERVIEW" "$NA"
        echo "============================================================"
        echo ""
        for r in "${RESULTS[@]}"; do
            IFS='|' read -r status id title detail <<< "$r"
            case "$status" in
                PASS)      label="양호  " ;;
                FAIL)      label="취약  " ;;
                INTERVIEW) label="인터뷰" ;;
                *)         label="N/A   " ;;
            esac
            printf "[%s] %-6s %s\n" "$label" "$id" "$title"
            [[ -n "$detail" ]] && printf "           %s\n" "$detail"
        done
    } > "$out"

    echo ""
    echo "결과 파일: $out"
}
