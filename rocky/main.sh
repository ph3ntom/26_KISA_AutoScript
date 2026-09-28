#!/bin/bash
# main.sh - Rocky Linux 10.1 보안 진단 자동화 스크립트
# 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#
# 사용법: sudo bash main.sh [옵션]
#   옵션:
#     -a, --all       전체 항목 진단 (기본값)
#     -s, --section   특정 섹션만 진단 (예: -s account)
#     -h, --help      도움말
#
# 실행 예시:
#   sudo bash main.sh
#   sudo bash main.sh -s account

# set -e / pipefail 미사용:
#   진단 스크립트 특성상 "grep 매치 실패 = 설정 없음"이 정상 흐름이므로
#   -e/pipefail 사용 시 설정 미존재·SIGPIPE(rpm|head 등)에서 스크립트가 즉시 종료됨
set -u

# ────────────────────────────────────────────────────────────
# 스크립트 경로 기준 설정
# ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"

# ────────────────────────────────────────────────────────────
# 공통 함수 로드
# ────────────────────────────────────────────────────────────
# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"

# ────────────────────────────────────────────────────────────
# root 권한 확인
# ────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[오류] root 권한으로 실행해야 합니다.${NC}"
        echo "  실행 방법: sudo bash $0"
        exit 1
    fi
}

# ────────────────────────────────────────────────────────────
# OS 확인
# ────────────────────────────────────────────────────────────
check_os() {
    if ! grep -qi 'rocky' /etc/os-release 2>/dev/null; then
        echo -e "${YELLOW}[경고] Rocky Linux가 아닌 시스템입니다. 일부 항목이 부정확할 수 있습니다.${NC}"
        echo -e "  현재 OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
        echo ""
    fi
}

# ────────────────────────────────────────────────────────────
# 진단 섹션 모듈 로드 및 실행
# ────────────────────────────────────────────────────────────
run_section() {
    local section="$1"
    case "$section" in
        account)
            source "${LIB_DIR}/01_account.sh"
            run_account_checks
            ;;
        file)
            source "${LIB_DIR}/02_file.sh"
            run_file_checks
            ;;
        service)
            source "${LIB_DIR}/03_service.sh"
            run_service_checks
            ;;
        patch)
            source "${LIB_DIR}/04_patch.sh"
            run_patch_checks
            ;;
        log)
            source "${LIB_DIR}/05_log.sh"
            run_log_checks
            ;;
        *)
            echo -e "${RED}[오류] 알 수 없는 섹션: ${section}${NC}"
            echo "  사용 가능: account, file, service, patch, log"
            exit 1
            ;;
    esac
}

# ────────────────────────────────────────────────────────────
# 도움말
# ────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
사용법: sudo bash $(basename "$0") [옵션]

옵션:
  -a, --all           전체 항목 진단 (기본값)
  -s, --section SEC   특정 섹션만 진단
                      SEC: account, file, service, patch, log
  -h, --help          도움말 출력

예시:
  sudo bash main.sh
  sudo bash main.sh -s account
  sudo bash main.sh -s service
  sudo bash main.sh -s log
EOF
}

# ────────────────────────────────────────────────────────────
# 메인
# ────────────────────────────────────────────────────────────
main() {
    local section="all"

    # 인수 파싱
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -a|--all)     section="all" ;;
            -s|--section) section="${2:-}"; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            echo "알 수 없는 옵션: $1"; usage; exit 1 ;;
        esac
        shift
    done

    check_root
    check_os

    # 진단 시작 시각 기록
    # ※ 전체 파일시스템 탐색(U-15/23/25/26/33)으로 수 분이 소요되므로
    #   리포트에는 시작/종료 시각을 모두 기록한다 (v2는 종료 시각만 기록)
    DIAG_START_TIME="$(date '+%Y-%m-%d %H:%M:%S')"

    # 헤더 출력
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}  Rocky Linux 10.1 보안 진단 (${DIAG_VERSION})${NC}"
    echo -e "${BOLD}  기준: 주요정보통신기반시설 취약점 분석·평가 가이드 2026${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo "  진단 일시  : ${DIAG_START_TIME}"
    echo "  호스트명   : $(hostname)"
    echo "  OS         : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
    echo "  커널       : $(uname -r)"
    echo -e "${BOLD}============================================================${NC}"

    # 섹션 실행
    if [[ "$section" == "all" ]]; then
        run_section "account"
        run_section "file"
        run_section "service"
        run_section "patch"
        run_section "log"
    else
        run_section "$section"
    fi

    # 최종 요약 및 리포트
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}  진단 완료 요약${NC}"
    echo -e "${BOLD}============================================================${NC}"
    local total=$((PASS + FAIL + INTERVIEW + NA))
    printf "  전체: %-4d  " "$total"
    printf "${GREEN}양호: %-4d${NC}  " "$PASS"
    printf "${RED}취약: %-4d${NC}  " "$FAIL"
    printf "${YELLOW}인터뷰: %-4d${NC}  " "$INTERVIEW"
    printf "${CYAN}N/A: %-4d${NC}\n" "$NA"
    echo -e "${BOLD}============================================================${NC}"

    generate_report
}

main "$@"
