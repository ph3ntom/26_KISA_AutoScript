#!/bin/bash
# common.sh - 공통 함수 및 변수 정의

# ────────────────────────────────────────────────────────────
# 스크립트 버전 (v2 대비 수정 내역은 CHANGELOG.md 참조)
# ────────────────────────────────────────────────────────────
DIAG_VERSION="v3 (2026-08-01)"

# ────────────────────────────────────────────────────────────
# 색상
# ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'
# NC : No Color (색상 리셋). ${NC} 사용처가 많으므로 set -u 환경에서 반드시 정의 필요

# ────────────────────────────────────────────────────────────
# 카운터
# ────────────────────────────────────────────────────────────
PASS=0
FAIL=0
INTERVIEW=0
NA=0

# 결과 저장 (파이프 구분: STATUS|ID|TITLE|DETAIL)
declare -a RESULTS=()

# ────────────────────────────────────────────────────────────
# 상세 증적 저장 (파이프 구분: ID|LINE)
# ※ v2에서는 파일 목록 등 판정 근거를 echo로 콘솔에만 출력해
#   report/*.txt에는 "N개 발견"만 남아 증적으로 사용할 수 없었음
#   → print_evidence()로 콘솔 출력과 동시에 배열에 적재하고
#     generate_report()에서 별도 evidence 파일로 저장
# ────────────────────────────────────────────────────────────
declare -a EVIDENCE=()

# 리포트 본문에 인라인으로 포함할 항목별 최대 줄 수 (전체는 evidence 파일에 저장)
EVIDENCE_INLINE_MAX=20

# 사용: print_evidence <id> "라인1" "라인2" ...
#       print_evidence "$id" "${vuln_list[@]}"
print_evidence() {
    local id="$1"
    shift
    local line
    for line in "$@"; do
        [[ -z "$line" ]] && continue
        printf "         └─ %s\n" "$line"
        EVIDENCE+=("${id}|${line}")
    done
}

# ────────────────────────────────────────────────────────────
# 결과 출력 함수
# ※ 카운터 증가는 VAR=$((VAR + 1)) 형태 사용
#   ((VAR++))는 VAR가 0일 때 산술 결과 0 → exit code 1을 반환하므로
#   set -e 환경에서 스크립트가 종료되는 함정이 있음
# ────────────────────────────────────────────────────────────
result_pass() {
    local id="$1" title="$2" detail="$3"
    printf "[${GREEN}양호${NC}] %-6s %s\n" "$id" "$title"
    [[ -n "$detail" ]] && printf "       └─ %s\n" "$detail"
    RESULTS+=("PASS|${id}|${title}|${detail}")
    PASS=$((PASS + 1))
}

result_fail() {
    local id="$1" title="$2" detail="$3"
    printf "[${RED}취약${NC}] %-6s %s\n" "$id" "$title"
    [[ -n "$detail" ]] && printf "       └─ %s\n" "$detail"
    RESULTS+=("FAIL|${id}|${title}|${detail}")
    FAIL=$((FAIL + 1))
}

result_interview() {
    local id="$1" title="$2" detail="$3"
    printf "[${YELLOW}인터뷰${NC}] %-6s %s\n" "$id" "$title"
    [[ -n "$detail" ]] && printf "       └─ %s\n" "$detail"
    RESULTS+=("INTERVIEW|${id}|${title}|${detail}")
    INTERVIEW=$((INTERVIEW + 1))
}

result_na() {
    local id="$1" title="$2" detail="$3"
    printf "[${CYAN}N/A${NC}] %-6s %s\n" "$id" "$title"
    [[ -n "$detail" ]] && printf "       └─ %s\n" "$detail"
    RESULTS+=("NA|${id}|${title}|${detail}")
    NA=$((NA + 1))
}

# ────────────────────────────────────────────────────────────
# 배열 요소를 구분자로 연결
# 사용: join_by ', ' "${arr[@]}"
# ※ $(IFS=', '; echo "${arr[*]}") 방식은 IFS의 "첫 글자"만 구분자로 쓰기 때문에
#   ", "를 의도해도 ","로만 연결됨 → 이 헬퍼로 대체
# ────────────────────────────────────────────────────────────
join_by() {
    local sep="$1"
    shift
    local out="" first=1
    for x in "$@"; do
        if [[ $first -eq 1 ]]; then
            out="$x"
            first=0
        else
            out+="${sep}${x}"
        fi
    done
    printf '%s' "$out"
}

# ────────────────────────────────────────────────────────────
# 섹션 헤더 출력
# ────────────────────────────────────────────────────────────
print_section() {
    local title="$1"
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $title${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ────────────────────────────────────────────────────────────
# 파일 권한 숫자 변환 (stat --format=%a)
# ────────────────────────────────────────────────────────────
get_perm() {
    local p
    p=$(stat -c "%a" "$1" 2>/dev/null)
    #stat : 파일의 상태 정보를 출력하는 명령어
    # %a : 파일의 권한을 8진수로 출력 (예: 755, 644)
    # -c : 출력 형식 지정 옵션

    # ※ stat은 mode 000을 "0", 640을 "640"으로 출력하므로 3자리 미만은 0으로 채움
    #   (v2에서 /etc/shadow 권한이 "권한=0"으로 출력돼 오독 소지가 있었음)
    #   특수비트가 있는 경우(4755 등)는 4자리 그대로 유지
    [[ -z "$p" ]] && return 1
    while [[ ${#p} -lt 3 ]]; do p="0${p}"; done
    printf '%s' "$p"
}

get_owner() {
    stat -c "%U" "$1" 2>/dev/null
    # %U : 파일의 소유자 이름 출력
}

# ────────────────────────────────────────────────────────────
# 권한 비교: 실제 권한이 기준 이하인지 확인
# 예) perm_le 644 755 → false (755 > 644)
#     perm_le 644 644 → true
#     perm_le 644 600 → true
# ────────────────────────────────────────────────────────────
perm_le() {
    local max_perm="$1"
    local actual_perm="$2"

    [[ $((8#${actual_perm})) -le $((8#${max_perm})) ]]
    # 8# : 숫자를 8진수로 해석하여 비교 (예: 644 → 420, 755 → 493)
}

# ────────────────────────────────────────────────────────────
# 최종 요약 리포트 생성
# ────────────────────────────────────────────────────────────
generate_report() {
    local report_dir
    report_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/report"
    mkdir -p "$report_dir"

    # 파일명 타임스탬프와 리포트 헤더의 종료 시각을 동일 시점 값으로 통일
    # (date를 두 번 호출하면 초 경계에서 1초 차이가 발생함)
    local ts end_time
    ts=$(date +%Y%m%d_%H%M%S)
    end_time=$(date -d "${ts:0:8} ${ts:9:2}:${ts:11:2}:${ts:13:2}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null) \
        || end_time=$(date '+%Y-%m-%d %H:%M:%S')
    [[ -z "$end_time" ]] && end_time=$(date '+%Y-%m-%d %H:%M:%S')
    local out="${report_dir}/result_$(hostname)_${ts}.txt"
    local evidence_out="${report_dir}/evidence_$(hostname)_${ts}.txt"
    local total=$((PASS + FAIL + INTERVIEW + NA))

    # ── 상세 증적 파일 생성 (파일 목록 등 판정 근거 전체) ──
    if [[ ${#EVIDENCE[@]} -gt 0 ]]; then
        {
            echo "============================================================"
            echo "  Rocky Linux 보안 진단 상세 증적"
            echo "  진단 일시: ${DIAG_START_TIME:-확인불가} ~ ${end_time}  호스트: $(hostname)"
            echo "============================================================"
            local prev_id=""
            for e in "${EVIDENCE[@]}"; do
                local eid eline
                eid="${e%%|*}"
                eline="${e#*|}"
                if [[ "$eid" != "$prev_id" ]]; then
                    echo ""
                    echo "[${eid}]"
                    prev_id="$eid"
                fi
                echo "  $eline"
            done
        } > "$evidence_out"
    fi

    {
        echo "============================================================"
        echo "  Rocky Linux 10.1 보안 진단 결과"
        echo "  주요정보통신기반시설 기술적 취약점 분석·평가 가이드 기준"
        echo "  진단 스크립트 버전: ${DIAG_VERSION}"
        echo "============================================================"
        echo "  진단 시작  : ${DIAG_START_TIME:-확인불가}"
        echo "  진단 종료  : ${end_time}"
        echo "  호스트명   : $(hostname)"
        echo "  OS 정보    : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
        echo "  커널 버전  : $(uname -r)"
        echo "  진단 계정  : $(whoami)"
        echo "------------------------------------------------------------"
        printf "  [결과 요약]  전체: %d  양호: %d  취약: %d  인터뷰: %d  N/A: %d\n" \
            "$total" "$PASS" "$FAIL" "$INTERVIEW" "$NA"
        echo "============================================================"
        echo ""
        # ※ printf의 %-40s는 바이트 기준 패딩이라 한글 제목의 열이 어긋남
        #   → 고정폭 정렬 대신 콘솔 출력과 동일한 2행 형식(제목 행 + 상세 행)으로 출력
        for r in "${RESULTS[@]}"; do
            IFS='|' read -r status id title detail <<< "$r"
            printf "[%s] %s %s\n" "$status" "$id" "$title"
            [[ -n "$detail" ]] && printf "        └─ %s\n" "$detail"

            # 해당 항목의 상세 증적을 리포트 본문에도 일부 포함 (전체는 evidence 파일)
            local shown=0 hidden=0
            for e in "${EVIDENCE[@]}"; do
                [[ "${e%%|*}" == "$id" ]] || continue
                if [[ $shown -lt $EVIDENCE_INLINE_MAX ]]; then
                    printf "           · %s\n" "${e#*|}"
                    shown=$((shown + 1))
                else
                    hidden=$((hidden + 1))
                fi
            done
            [[ $hidden -gt 0 ]] && \
                printf "           · ... 외 %d건 (전체 목록: %s)\n" "$hidden" "$(basename "$evidence_out")"
        done
        echo ""
        echo "  * 보고서 파일: $out"
        [[ ${#EVIDENCE[@]} -gt 0 ]] && echo "  * 상세 증적 파일: $evidence_out"
        echo "============================================================"
    } | tee "$out"

    echo ""
    echo -e "${BOLD}리포트 저장 완료: ${out}${NC}"
    [[ ${#EVIDENCE[@]} -gt 0 ]] && \
        echo -e "${BOLD}상세 증적 저장 완료: ${evidence_out}${NC}"
}
