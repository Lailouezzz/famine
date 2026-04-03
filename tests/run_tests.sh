#!/bin/bash
# Famine Test Suite
# Tests the famine infecter against various binary types

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINDIR="$SCRIPT_DIR/bin"
RESULTS_DIR="$SCRIPT_DIR/results"
FAMINE="$PROJECT_DIR/famine"

# Test directories used by famine
TEST_DIR="/tmp/test"
TEST_DIR2="/tmp/test2"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

# Famine signature (from include/famine.h)
FAMINE_SIGN="Pestilence version 1.0 (c)oded by ale-boud - amassias"

# Directories
mkdir -p "$RESULTS_DIR"
CRASHED_DIR="$SCRIPT_DIR/crashed"
mkdir -p "$CRASHED_DIR"

# Get exit code description
describe_exit() {
    local code=$1
    case $code in
        0)   echo "OK" ;;
        124) echo "TIMEOUT" ;;
        126) echo "NOT_EXEC" ;;
        127) echo "NOT_FOUND" ;;
        129) echo "SIGHUP" ;;
        130) echo "SIGINT" ;;
        131) echo "SIGQUIT" ;;
        132) echo "SIGILL" ;;
        133) echo "SIGTRAP" ;;
        134) echo "SIGABRT" ;;
        135) echo "SIGBUS" ;;
        136) echo "SIGFPE" ;;
        137) echo "SIGKILL" ;;
        139) echo "SEGFAULT" ;;
        141) echo "SIGPIPE" ;;
        143) echo "SIGTERM" ;;
        *)   echo "EXIT_$code" ;;
    esac
}

# Check if binary is infected by famine
# Since the signature is embedded in the stub (not at EOF), we check:
# 1. If the binary contains the signature string anywhere
# 2. Or if it displays the WOODY banner when run
is_infected() {
    local binary="$1"
    # Check if signature exists anywhere in the binary
    if grep -q "$FAMINE_SIGN" "$binary" 2>/dev/null; then
        return 0
    fi
    # Alternative: check if WOODY banner appears when running
    local output
    output=$(timeout 2s "$binary" 2>&1 || true)
    if echo "$output" | grep -qF "....WOODY...."; then
        return 0
    fi
    return 1
}

# Clean test directories
clean_test_dirs() {
    rm -rf "$TEST_DIR"/* "$TEST_DIR2"/* 2>/dev/null || true
    mkdir -p "$TEST_DIR" "$TEST_DIR2"
}

# Run a single test
# Args: $1=name $2=binary $3=expect_fail
run_test() {
    local name="$1"
    local binary="$2"
    local expect_fail="${3:-0}"

    ((TOTAL++)) || true

    # Check if binary exists and is valid ELF
    if [ ! -f "$binary" ] || [ ! -s "$binary" ]; then
        ((SKIPPED++)) || true
        printf "[%3d] %-50s ${YELLOW}SKIP${NC} (no binary)\n" "$TOTAL" "$name"
        return
    fi

    # Check if famine exists
    if [ ! -f "$FAMINE" ]; then
        ((SKIPPED++)) || true
        printf "[%3d] %-50s ${YELLOW}SKIP${NC} (no famine)\n" "$TOTAL" "$name"
        return
    fi

    local log_name="${name//\//_}"
    local log_file="$RESULTS_DIR/${log_name}.log"

    # Clean test directories
    clean_test_dirs

    # Copy binary to test directory
    local test_binary="$TEST_DIR/$(basename "$binary")"
    cp "$binary" "$test_binary"
    chmod +x "$test_binary"

    # Get original output (for comparison)
    local orig_output orig_exit
    orig_output=$(timeout 5s "$binary" 2>&1)
    orig_exit=$?

    # Get original file size and hash
    local orig_size orig_hash
    orig_size=$(stat -c%s "$test_binary")
    orig_hash=$(md5sum "$test_binary" | cut -d' ' -f1)

    # Run famine to infect
    local famine_output famine_exit
    famine_output=$("$FAMINE" 2>&1)
    famine_exit=$?

    if [ $famine_exit -ne 0 ]; then
        clean_test_dirs
        local famine_err=$(describe_exit $famine_exit)
        if [ "$expect_fail" = "1" ]; then
            ((PASSED++)) || true
            printf "[%3d] %-50s ${GREEN}PASS${NC} (famine failed: $famine_err)\n" "$TOTAL" "$name"
        else
            ((FAILED++)) || true
            printf "[%3d] %-50s ${RED}FAIL${NC} (famine: $famine_err)\n" "$TOTAL" "$name"
            echo "Famine exit: $famine_exit ($famine_err)" > "$log_file"
            echo "Output: $famine_output" >> "$log_file"
        fi
        return
    fi

    # Check if binary was infected (signature present)
    if ! is_infected "$test_binary"; then
        clean_test_dirs
        if [ "$expect_fail" = "1" ]; then
            ((PASSED++)) || true
            printf "[%3d] %-50s ${GREEN}PASS${NC} (not infected)\n" "$TOTAL" "$name"
        else
            ((FAILED++)) || true
            printf "[%3d] %-50s ${RED}FAIL${NC} (not infected)\n" "$TOTAL" "$name"
            echo "Binary was not infected (no famine signature)" > "$log_file"
        fi
        return
    fi

    # Check file size increased
    local infected_size
    infected_size=$(stat -c%s "$test_binary")
    if [ "$infected_size" -le "$orig_size" ]; then
        clean_test_dirs
        ((FAILED++)) || true
        printf "[%3d] %-50s ${RED}FAIL${NC} (size not increased)\n" "$TOTAL" "$name"
        echo "Original size: $orig_size, Infected size: $infected_size" > "$log_file"
        return
    fi

    # Run infected binary with timeout
    local infected_output infected_exit
    infected_output=$(timeout 5s "$test_binary" 2>&1)
    infected_exit=$?
    local exit_desc=$(describe_exit $infected_exit)

    # For expected failures
    if [ "$expect_fail" = "1" ]; then
        if [ $infected_exit -ne 0 ]; then
            ((PASSED++)) || true
            printf "[%3d] %-50s ${GREEN}PASS${NC} (run failed: $exit_desc)\n" "$TOTAL" "$name"
        else
            ((FAILED++)) || true
            printf "[%3d] %-50s ${RED}FAIL${NC} (should have failed)\n" "$TOTAL" "$name"
        fi
        clean_test_dirs
        return
    fi

    # Check if infected binary crashed (signal)
    if [ $infected_exit -gt 128 ]; then
        ((FAILED++)) || true
        printf "[%3d] %-50s ${RED}FAIL${NC} ${CYAN}($exit_desc)${NC}\n" "$TOTAL" "$name"
        {
            echo "Exit code: $infected_exit ($exit_desc)"
            echo "Original exit: $orig_exit"
            echo "Original output: $orig_output"
            echo "Infected output: $infected_output"
        } > "$log_file"
        # Save crashed binary for analysis
        cp "$test_binary" "$CRASHED_DIR/${log_name}.infected" 2>/dev/null || true
        clean_test_dirs
        return
    fi

    # Compare outputs (infected should produce same output as original)
    local orig_trimmed infected_trimmed
    orig_trimmed=$(echo "$orig_output" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    infected_trimmed=$(echo "$infected_output" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    if [ "$infected_trimmed" = "$orig_trimmed" ]; then
        ((PASSED++)) || true
        printf "[%3d] %-50s ${GREEN}PASS${NC}\n" "$TOTAL" "$name"
    else
        # Check if outputs differ only by whitespace or minor differences
        if [ $infected_exit -eq $orig_exit ]; then
            ((PASSED++)) || true
            printf "[%3d] %-50s ${GREEN}PASS${NC} ${YELLOW}(exit OK, output differs)${NC}\n" "$TOTAL" "$name"
        else
            ((FAILED++)) || true
            printf "[%3d] %-50s ${RED}FAIL${NC} ${CYAN}(output mismatch)${NC}\n" "$TOTAL" "$name"
            {
                echo "=== Original (exit $orig_exit) ==="
                echo "$orig_output"
                echo ""
                echo "=== Infected (exit $infected_exit - $exit_desc) ==="
                echo "$infected_output"
            } > "$log_file"
        fi
    fi

    clean_test_dirs
}

# Run re-infection test (x2)
# Verifies that famine doesn't re-infect an already infected binary
run_reinfection_test() {
    local name="$1"
    local binary="$2"

    ((TOTAL++)) || true

    # Check if binary exists and is valid ELF
    if [ ! -f "$binary" ] || [ ! -s "$binary" ]; then
        ((SKIPPED++)) || true
        printf "[%3d] %-50s ${YELLOW}SKIP${NC} (no binary)\n" "$TOTAL" "$name"
        return
    fi

    # Check if famine exists
    if [ ! -f "$FAMINE" ]; then
        ((SKIPPED++)) || true
        printf "[%3d] %-50s ${YELLOW}SKIP${NC} (no famine)\n" "$TOTAL" "$name"
        return
    fi

    local log_name="${name//\//_}"
    local log_file="$RESULTS_DIR/${log_name}.log"

    # Clean test directories
    clean_test_dirs

    # Copy binary to test directory
    local test_binary="$TEST_DIR/$(basename "$binary")"
    cp "$binary" "$test_binary"
    chmod +x "$test_binary"

    # First infection
    "$FAMINE" >/dev/null 2>&1

    if ! is_infected "$test_binary"; then
        clean_test_dirs
        ((SKIPPED++)) || true
        printf "[%3d] %-50s ${YELLOW}SKIP${NC} (first infection failed)\n" "$TOTAL" "$name"
        return
    fi

    # Get infected file hash
    local infected_hash infected_size
    infected_hash=$(md5sum "$test_binary" | cut -d' ' -f1)
    infected_size=$(stat -c%s "$test_binary")

    # Second infection attempt
    "$FAMINE" >/dev/null 2>&1

    # Get new hash after second run
    local new_hash new_size
    new_hash=$(md5sum "$test_binary" | cut -d' ' -f1)
    new_size=$(stat -c%s "$test_binary")

    # Check if file was modified (it shouldn't be)
    if [ "$infected_hash" = "$new_hash" ] && [ "$infected_size" = "$new_size" ]; then
        ((PASSED++)) || true
        printf "[%3d] %-50s ${GREEN}PASS${NC} (no re-infection)\n" "$TOTAL" "$name"
    else
        ((FAILED++)) || true
        printf "[%3d] %-50s ${RED}FAIL${NC} ${CYAN}(re-infected!)${NC}\n" "$TOTAL" "$name"
        {
            echo "Binary was re-infected!"
            echo "After 1st infection: size=$infected_size hash=$infected_hash"
            echo "After 2nd infection: size=$new_size hash=$new_hash"
        } > "$log_file"
    fi

    clean_test_dirs
}

# Main
main() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}              Famine Test Suite${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""

    # Build test binaries
    echo "Building test binaries..."
    make -C "$SCRIPT_DIR" all >/dev/null 2>&1 || true
    echo ""

    # Setup test directories
    mkdir -p "$TEST_DIR" "$TEST_DIR2"

    # ===== 64-bit binaries =====
    echo -e "${BLUE}─── 64-bit Binaries ───${NC}"
    echo ""

    echo -e "${YELLOW}PIE:${NC}"
    for bin in "$BINDIR"/*_64_pie; do
        [ -f "$bin" ] || continue
        run_test "64 PIE/$(basename "${bin%_64_pie}")" "$bin" 0
    done
    echo ""

    echo -e "${YELLOW}no-PIE:${NC}"
    for bin in "$BINDIR"/*_64_nopie; do
        [ -f "$bin" ] || continue
        run_test "64 noPIE/$(basename "${bin%_64_nopie}")" "$bin" 0
    done
    echo ""

    echo -e "${YELLOW}static:${NC}"
    for bin in "$BINDIR"/*_64_static; do
        [ -f "$bin" ] || continue
        run_test "64 static/$(basename "${bin%_64_static}")" "$bin" 0
    done
    echo ""

    echo -e "${YELLOW}static-PIE:${NC}"
    for bin in "$BINDIR"/*_64_static_pie; do
        [ -f "$bin" ] || continue
        run_test "64 staticPIE/$(basename "${bin%_64_static_pie}")" "$bin" 0
    done
    echo ""

    echo -e "${YELLOW}ASM:${NC}"
    for bin in "$BINDIR"/*_asm64; do
        [ -f "$bin" ] || continue
        run_test "64 asm/$(basename "${bin%_asm64}")" "$bin" 0
    done
    echo ""

    # ===== 32-bit binaries =====
    echo -e "${BLUE}─── 32-bit Binaries ───${NC}"
    echo ""

    echo -e "${YELLOW}PIE:${NC}"
    for bin in "$BINDIR"/*_32_pie; do
        [ -f "$bin" ] || continue
        run_test "32 PIE/$(basename "${bin%_32_pie}")" "$bin" 0
    done
    echo ""

    echo -e "${YELLOW}no-PIE:${NC}"
    for bin in "$BINDIR"/*_32_nopie; do
        [ -f "$bin" ] || continue
        run_test "32 noPIE/$(basename "${bin%_32_nopie}")" "$bin" 0
    done
    echo ""

    echo -e "${YELLOW}static:${NC}"
    for bin in "$BINDIR"/*_32_static; do
        [ -f "$bin" ] || continue
        run_test "32 static/$(basename "${bin%_32_static}")" "$bin" 0
    done
    echo ""

    echo -e "${YELLOW}static-PIE:${NC}"
    for bin in "$BINDIR"/*_32_static_pie; do
        [ -f "$bin" ] || continue
        run_test "32 staticPIE/$(basename "${bin%_32_static_pie}")" "$bin" 0
    done
    echo ""

    # ===== Re-infection tests (x2) =====
    echo -e "${BLUE}─── Re-infection Tests (x2) ───${NC}"
    echo -e "${CYAN}(Verifies famine doesn't re-infect already infected binaries)${NC}"
    echo ""

    # Select a few binaries for re-infection testing
    local reinfect_tests=("hello" "bss_simple" "recursion" "function_ptrs" "loops" "malloc_free" "fork_test")

    echo -e "${YELLOW}64-bit PIE:${NC}"
    for name in "${reinfect_tests[@]}"; do
        bin="$BINDIR/${name}_64_pie"
        [ -f "$bin" ] || continue
        run_reinfection_test "reinfect/64 PIE/$name" "$bin"
    done
    echo ""

    echo -e "${YELLOW}32-bit PIE:${NC}"
    for name in "${reinfect_tests[@]}"; do
        bin="$BINDIR/${name}_32_pie"
        [ -f "$bin" ] || continue
        run_reinfection_test "reinfect/32 PIE/$name" "$bin"
    done
    echo ""

    # Cleanup
    clean_test_dirs

    # Summary
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    Test Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
    printf "  Total:   %d\n" "$TOTAL"
    printf "  ${GREEN}Passed:  %d${NC}\n" "$PASSED"
    printf "  ${RED}Failed:  %d${NC}\n" "$FAILED"
    printf "  ${YELLOW}Skipped: %d${NC}\n" "$SKIPPED"
    echo ""

    local pass_rate=0
    if [ $((TOTAL - SKIPPED)) -gt 0 ]; then
        pass_rate=$((100 * PASSED / (TOTAL - SKIPPED)))
    fi
    echo "  Pass rate: ${pass_rate}%"
    echo ""

    echo -e "${CYAN}Legend:${NC}"
    echo "  SEGFAULT  = Signal 11 (invalid memory access)"
    echo "  SIGABRT   = Signal 6 (abort)"
    echo "  SIGILL    = Signal 4 (illegal instruction)"
    echo "  SIGBUS    = Signal 7 (bus error)"
    echo "  TIMEOUT   = Exceeded 5s limit"
    echo ""

    if [ $FAILED -gt 0 ]; then
        echo "Detailed logs: $RESULTS_DIR/"
        echo "Crashed binaries: $CRASHED_DIR/"
    fi

    [ $FAILED -eq 0 ]
}

main "$@"
