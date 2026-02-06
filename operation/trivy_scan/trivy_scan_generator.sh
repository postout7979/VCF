#!/bin/bash

# ==========================================
# 설정 (Settings)
# ==========================================
OUTPUT_FILE="trivy_full_report.json"
TARGET_DIR="/"  # 기본 스캔 대상 (전체 시스템)
TIMEOUT="30m"   # 스캔 타임아웃

# 스캔 제외 경로 (시스템 디렉토리 및 도커 내부 등)
SKIP_DIRS="/proc,/sys,/dev,/run,/var/lib/docker,/var/lib/containerd"

# 색상 코드
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ==========================================
# 함수 정의
# ==========================================
print_banner() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}    Trivy JSON Report Generator          ${NC}"
    echo -e "${BLUE}=========================================${NC}"
}

check_trivy() {
    if ! command -v trivy &> /dev/null; then
        echo -e "${RED}[Error] Trivy가 설치되어 있지 않습니다.${NC}"
        echo "설치 후 다시 실행해주세요."
        exit 1
    fi
}

run_scan() {
    local scanners=$1
    local mode_name=$2

    echo -e "${GREEN}[*] 스캔 모드: ${mode_name}${NC}"
    echo -e "${GREEN}[*] 대상 경로: ${TARGET_DIR}${NC}"
    echo -e "${GREEN}[*] 결과 파일: ${OUTPUT_FILE}${NC}"
    echo -e "스캔 진행 중... (Timeout: ${TIMEOUT})"

    # Trivy 실행 명령어
    trivy fs \
        --scanners "${scanners}" \
        --format json \
        --output "${OUTPUT_FILE}" \
        --timeout "${TIMEOUT}" \
        --skip-dirs "${SKIP_DIRS}" \
        "${TARGET_DIR}"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[Success] 스캔이 완료되었습니다!${NC}"
        echo -e "생성된 파일: $(ls -lh ${OUTPUT_FILE})"
    else
        echo -e "${RED}[Fail] 스캔 중 오류가 발생했습니다.${NC}"
    fi
}

show_menu() {
    echo "스캔할 옵션을 선택하세요:"
    echo "1) 전체 스캔 (Vuln + Misconfig + Secret + License) - 권장"
    echo "2) 보안 취약점 (Vulnerability)만"
    echo "3) 설정 오류 (Misconfiguration)만"
    echo "4) 비밀 키/패스워드 (Secret)만"
    echo "5) 라이선스 (License)만"
    echo "-----------------------------------------"
    read -p "번호 입력 [1-5]: " choice

    case $choice in
        1) run_scan "vuln,misconfig,secret,license" "FULL SCAN (All)" ;;
        2) run_scan "vuln" "Vulnerability Only" ;;
        3) run_scan "misconfig" "Misconfiguration Only" ;;
        4) run_scan "secret" "Secret Only" ;;
        5) run_scan "license" "License Only" ;;
        *) echo -e "${RED}잘못된 선택입니다.${NC}"; exit 1 ;;
    esac
}

# ==========================================
# 메인 실행 로직
# ==========================================
print_banner
check_trivy

# 인자가 없으면 대화형 메뉴 실행
if [ -z "$1" ]; then
    show_menu
else
    # 인자가 있으면 자동 모드 (예: ./script.sh --vuln)
    case "$1" in
        --full)    run_scan "vuln,misconfig,secret,license" "FULL SCAN" ;;
        --vuln)    run_scan "vuln" "Vulnerability Only" ;;
        --misconf) run_scan "misconfig" "Misconfiguration Only" ;;
        --secret)  run_scan "secret" "Secret Only" ;;
        --license) run_scan "license" "License Only" ;;
        *) 
            echo "사용법: $0 [옵션]"
            echo "옵션:"
            echo "  (없음)    : 대화형 메뉴 실행"
            echo "  --full    : 전체 스캔"
            echo "  --vuln    : 취약점만"
            echo "  --misconf : 설정오류만"
            echo "  --secret  : 시크릿만"
            exit 1 
            ;;
    esac
fi
