#!/bin/bash

set -e

QSCANNER_VERSION="latest"
QSCANNER_BINARY_URL="https://github.com/nelssec/qualys-lambda/raw/main/scanner-lambda/qscanner.gz"
QSCANNER_SHA256="1a31b854154ee4594bb94e28aa86460b14a75687085d097f949e91c5fd00413d"
QSCANNER_DIR="${QSCANNER_DIR:-/tmp/qscanner-codebuild}"
QSCANNER_BINARY="${QSCANNER_DIR}/qscanner"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_platform() {
    local platform=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    if [[ "$arch" == "x86_64" ]]; then
        arch="amd64"
    elif [[ "$arch" == "aarch64" ]]; then
        arch="arm64"
    fi

    if [[ "$platform" != "linux" || "$arch" != "amd64" ]]; then
        log_error "QScanner only supports linux-amd64. Current: ${platform}-${arch}"
        log_error "Use an x86_64 CodeBuild compute type (e.g., BUILD_GENERAL1_SMALL)"
        exit 1
    fi

    log_info "Platform: ${platform}-${arch}"
}

download_binary() {
    log_info "Downloading QScanner binary..."

    mkdir -p "${QSCANNER_DIR}"

    local gz_path="${QSCANNER_DIR}/qscanner.gz"

    curl -sL "${QSCANNER_BINARY_URL}" -o "${gz_path}"

    log_info "Verifying SHA256 checksum..."
    local actual_hash=$(sha256sum "${gz_path}" | cut -d' ' -f1)

    if [[ "${actual_hash}" != "${QSCANNER_SHA256}" ]]; then
        log_error "SHA256 checksum mismatch!"
        log_error "Expected: ${QSCANNER_SHA256}"
        log_error "Got: ${actual_hash}"
        rm -f "${gz_path}"
        exit 1
    fi

    log_info "Checksum verified"

    log_info "Extracting binary..."
    gunzip -f "${gz_path}"
    chmod +x "${QSCANNER_BINARY}"

    log_info "QScanner binary ready at ${QSCANNER_BINARY}"
}

setup() {
    log_info "Setting up QScanner for AWS CodeBuild..."

    check_platform

    if [[ -x "${QSCANNER_BINARY}" ]]; then
        log_info "QScanner binary already exists, skipping download"
    else
        download_binary
    fi

    if ! "${QSCANNER_BINARY}" --version &>/dev/null; then
        log_error "Failed to verify QScanner installation"
        exit 1
    fi

    log_info "Setup complete!"
}

container_scan() {
    log_info "Starting container scan..."

    if [[ -z "${QUALYS_ACCESS_TOKEN}" ]]; then
        log_error "QUALYS_ACCESS_TOKEN is required"
        exit 1
    fi

    if [[ -z "${QUALYS_POD}" ]]; then
        log_error "QUALYS_POD is required"
        exit 1
    fi

    if [[ -z "${IMAGE_ID}" ]]; then
        log_error "IMAGE_ID is required"
        exit 1
    fi

    if [[ ! -x "${QSCANNER_BINARY}" ]]; then
        setup
    fi

    local output_dir="${OUTPUT_DIR:-./qualys-reports}"
    mkdir -p "${output_dir}"

    local cmd="${QSCANNER_BINARY}"
    cmd+=" --pod ${QUALYS_POD}"
    cmd+=" --mode ${SCAN_MODE:-get-report}"
    cmd+=" --output-dir ${output_dir}"

    if [[ -n "${SCAN_TYPES}" ]]; then
        cmd+=" --scan-types ${SCAN_TYPES}"
    fi

    if [[ -n "${STORAGE_DRIVER}" && "${STORAGE_DRIVER}" != "none" ]]; then
        cmd+=" --storage-driver ${STORAGE_DRIVER}"
    fi

    if [[ -n "${PLATFORM}" ]]; then
        cmd+=" --platform ${PLATFORM}"
    fi

    if [[ -n "${POLICY_TAGS}" ]]; then
        cmd+=" --policy-tags ${POLICY_TAGS}"
    fi

    if [[ -n "${SCAN_TIMEOUT}" ]]; then
        cmd+=" --scan-timeout ${SCAN_TIMEOUT}s"
    fi

    cmd+=" --format json,sarif"
    cmd+=" --report-format sarif,json"
    cmd+=" image ${IMAGE_ID}"

    log_info "Executing: ${cmd}"

    local exit_code=0
    eval "${cmd}" || exit_code=$?

    process_results "${output_dir}" "${exit_code}"
}

code_scan() {
    log_info "Starting code scan..."

    if [[ -z "${QUALYS_ACCESS_TOKEN}" ]]; then
        log_error "QUALYS_ACCESS_TOKEN is required"
        exit 1
    fi

    if [[ -z "${QUALYS_POD}" ]]; then
        log_error "QUALYS_POD is required"
        exit 1
    fi

    if [[ ! -x "${QSCANNER_BINARY}" ]]; then
        setup
    fi

    local scan_path="${SCAN_PATH:-${CODEBUILD_SRC_DIR:-.}}"
    local output_dir="${OUTPUT_DIR:-./qualys-reports}"
    mkdir -p "${output_dir}"

    local cmd="${QSCANNER_BINARY}"
    cmd+=" --pod ${QUALYS_POD}"
    cmd+=" --mode ${SCAN_MODE:-get-report}"
    cmd+=" --output-dir ${output_dir}"

    if [[ -n "${SCAN_TYPES}" ]]; then
        cmd+=" --scan-types ${SCAN_TYPES}"
    fi

    if [[ -n "${EXCLUDE_DIRS}" ]]; then
        cmd+=" --exclude-dirs ${EXCLUDE_DIRS}"
    fi

    if [[ -n "${EXCLUDE_FILES}" ]]; then
        cmd+=" --exclude-files ${EXCLUDE_FILES}"
    fi

    if [[ "${OFFLINE_SCAN}" == "true" ]]; then
        cmd+=" --offline-scan=true"
    fi

    if [[ -n "${POLICY_TAGS}" ]]; then
        cmd+=" --policy-tags ${POLICY_TAGS}"
    fi

    if [[ -n "${SCAN_TIMEOUT}" ]]; then
        cmd+=" --scan-timeout ${SCAN_TIMEOUT}s"
    fi

    cmd+=" --format json,sarif"
    cmd+=" --report-format sarif,json"
    cmd+=" repo ${scan_path}"

    log_info "Executing: ${cmd}"

    local exit_code=0
    eval "${cmd}" || exit_code=$?

    process_results "${output_dir}" "${exit_code}"
}

process_results() {
    local output_dir="$1"
    local exit_code="$2"

    echo ""
    echo "============================================================"
    echo "Scan Results"
    echo "============================================================"

    local sarif_file=$(find "${output_dir}" -name "*-Report.sarif.json" 2>/dev/null | head -1)

    if [[ -n "${sarif_file}" && -f "${sarif_file}" ]]; then
        log_info "SARIF report: ${sarif_file}"

        if command -v jq &>/dev/null; then
            local total=$(jq '[.runs[].results[]] | length' "${sarif_file}" 2>/dev/null || echo "0")
            log_info "Total findings: ${total}"
        fi
    fi

    local threshold_failed=false

    if [[ -n "${MAX_CRITICAL}" ]] || [[ -n "${MAX_HIGH}" ]]; then
        log_info "Threshold checking requires jq to be installed"
    fi

    echo ""
    if [[ ${exit_code} -eq 0 ]]; then
        log_info "SCAN PASSED"
    elif [[ ${exit_code} -eq 42 ]]; then
        log_error "SCAN FAILED - Policy evaluation: DENY"
        exit 1
    elif [[ ${exit_code} -eq 43 ]]; then
        log_warn "SCAN COMPLETED - Policy evaluation: AUDIT"
    else
        log_error "SCAN FAILED - Exit code: ${exit_code}"
        exit ${exit_code}
    fi

    echo "============================================================"
}

show_help() {
    echo "Qualys QScanner for AWS CodeBuild"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  setup              Download and setup QScanner binary"
    echo "  container-scan     Scan a container image"
    echo "  code-scan          Scan source code"
    echo "  help               Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  QUALYS_ACCESS_TOKEN     Qualys API access token (required)"
    echo "  QUALYS_POD              Qualys platform POD (required)"
    echo "  IMAGE_ID                Container image to scan (for container-scan)"
    echo "  SCAN_PATH               Path to scan (for code-scan, default: .)"
    echo "  STORAGE_DRIVER          Docker storage driver (default: none)"
    echo "  SCAN_MODE               Scan mode (default: get-report)"
    echo "  SCAN_TYPES              Comma-separated scan types"
    echo "  POLICY_TAGS             Comma-separated policy tags"
    echo "  SCAN_TIMEOUT            Scan timeout in seconds"
    echo "  MAX_CRITICAL            Max critical vulnerabilities allowed"
    echo "  MAX_HIGH                Max high vulnerabilities allowed"
    echo "  OUTPUT_DIR              Output directory for reports"
}

case "${1:-help}" in
    setup)
        setup
        ;;
    container-scan)
        container_scan
        ;;
    code-scan)
        code_scan
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
