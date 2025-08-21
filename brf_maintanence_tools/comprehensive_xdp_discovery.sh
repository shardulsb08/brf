#!/bin/bash
# Comprehensive XDP Function Discovery Script
# This script finds ALL XDP-related BPF functions in the kernel source
# with minimal assumptions and maximum coverage

set -euo pipefail

# Configuration - modify these paths as needed
KERNEL_SRC_DIR="${1:-kernel}"
BRF_TYPES_FILE="${2:-brf/prog/brf_types.go}"
OUTPUT_FILE="xdp_function_analysis_$(date +%Y%m%d_%H%M%S).txt"
TEMP_DIR=$(mktemp -d)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Function to safely search files
safe_grep() {
    local pattern="$1"
    local file="$2"
    local description="$3"
    
    if [[ -f "$file" ]]; then
        log_debug "Searching $description in $file"
        grep -h "$pattern" "$file" 2>/dev/null || true
    else
        log_warn "File not found: $file"
    fi
}

# Function to search multiple files with a pattern
multi_file_search() {
    local pattern="$1"
    local description="$2"
    local files=("${@:3}")
    
    log_info "Searching for $description across ${#files[@]} files"
    
    local results=""
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            local file_results=$(grep -h "$pattern" "$file" 2>/dev/null || true)
            if [[ -n "$file_results" ]]; then
                results+="$file_results"$'\n'
                log_debug "Found results in $file"
            fi
        fi
    done
    
    echo "$results"
}

# Step 1: Find all files that might contain XDP-related content
find_xdp_related_files() {
    log_info "=== Step 1: Discovering XDP-related files ==="
    
    cd "$KERNEL_SRC_DIR"
    
    # Find all files containing "xdp" (case-insensitive)
    log_info "Searching for files containing 'xdp'..."
    find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.S" -o -name "*.asm" \) 2>/dev/null | \
    xargs -I {} grep -l -i "xdp" {} 2>/dev/null | \
    sort -u > "$TEMP_DIR/xdp_related_files.txt"
    
    log_info "Found $(wc -l < "$TEMP_DIR/xdp_related_files.txt") files with XDP content"
    
    # Also find files containing "bpf" that might have XDP functions
    log_info "Searching for files containing 'bpf'..."
    find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.S" -o -name "*.asm" \) 2>/dev/null | \
    xargs -I {} grep -l -i "bpf" {} 2>/dev/null | \
    sort -u > "$TEMP_DIR/bpf_related_files.txt"
    
    log_info "Found $(wc -l < "$TEMP_DIR/bpf_related_files.txt") files with BPF content"
    
    # Combine and deduplicate
    cat "$TEMP_DIR/xdp_related_files.txt" "$TEMP_DIR/bpf_related_files.txt" | \
    sort -u > "$TEMP_DIR/all_relevant_files.txt"
    
    log_info "Total unique relevant files: $(wc -l < "$TEMP_DIR/all_relevant_files.txt")"
    
    cd "$SCRIPT_DIR"
}

# Step 2: Extract all XDP-related function patterns
extract_xdp_function_patterns() {
    log_info "=== Step 2: Extracting XDP function patterns ==="
    
    cd "$KERNEL_SRC_DIR"
    
    # Pattern 1: bpf_xdp_*_proto definitions
    log_info "Searching for bpf_xdp_*_proto patterns..."
    cat "$TEMP_DIR/all_relevant_files.txt" | \
    xargs -I {} grep -h "bpf_xdp.*_proto" {} 2>/dev/null | \
    sed 's/.*bpf_xdp_\([a-zA-Z_]*\)_proto.*/bpf_xdp_\1_proto/' | \
    sort -u > "$TEMP_DIR/xdp_proto_patterns.txt"
    
    # Pattern 2: BPF_FUNC_xdp_* constants
    log_info "Searching for BPF_FUNC_xdp_* patterns..."
    cat "$TEMP_DIR/all_relevant_files.txt" | \
    xargs -I {} grep -h "BPF_FUNC_xdp" {} 2>/dev/null | \
    sed 's/.*BPF_FUNC_xdp_\([a-zA-Z_]*\).*/BPF_FUNC_xdp_\1/' | \
    sort -u > "$TEMP_DIR/xdp_func_constants.txt"
    
    # Pattern 3: __bpf_kfunc xdp functions
    log_info "Searching for __bpf_kfunc xdp patterns..."
    cat "$TEMP_DIR/all_relevant_files.txt" | \
    xargs -I {} grep -h "__bpf_kfunc.*xdp" {} 2>/dev/null | \
    sed 's/.*__bpf_kfunc.*\(bpf_xdp_[a-zA-Z_]*\).*/\1/' | \
    sort -u > "$TEMP_DIR/xdp_kfunc_patterns.txt"
    
    # Pattern 4: BTF_ID_FLAGS for xdp functions
    log_info "Searching for BTF_ID_FLAGS xdp patterns..."
    cat "$TEMP_DIR/all_relevant_files.txt" | \
    xargs -I {} grep -h "BTF_ID_FLAGS.*xdp" {} 2>/dev/null | \
    sed 's/.*BTF_ID_FLAGS.*\(bpf_xdp_[a-zA-Z_]*\).*/\1/' | \
    sort -u > "$TEMP_DIR/xdp_btf_patterns.txt"
    
    # Pattern 5: Generic xdp function references
    log_info "Searching for generic xdp function references..."
    cat "$TEMP_DIR/all_relevant_files.txt" | \
    xargs -I {} grep -h "bpf_xdp_[a-zA-Z_]*" {} 2>/dev/null | \
    grep -v "_proto" | grep -v "BTF_ID" | grep -v "__bpf_kfunc" | \
    sed 's/.*bpf_xdp_\([a-zA-Z_]*\).*/bpf_xdp_\1/' | \
    sort -u > "$TEMP_DIR/xdp_generic_patterns.txt"
    
    cd "$SCRIPT_DIR"
}

# Step 3: Extract function usage in xdp_func_proto
extract_xdp_func_proto_usage() {
    log_info "=== Step 3: Extracting xdp_func_proto usage ==="
    
    cd "$KERNEL_SRC_DIR"
    
    # Find all files that might contain xdp_func_proto
    local xdp_func_files=$(grep -l "xdp_func_proto" "$TEMP_DIR/all_relevant_files.txt" 2>/dev/null || true)
    
    if [[ -n "$xdp_func_files" ]]; then
        log_info "Found xdp_func_proto in $(echo "$xdp_func_files" | wc -l) files"
        
        # Extract function names returned by xdp_func_proto
        echo "$xdp_func_files" | \
        xargs -I {} grep -h "xdp_func_proto" {} 2>/dev/null | \
        grep -A 50 "xdp_func_proto" | grep -B 50 "^}" | \
        grep "return &" | \
        sed 's/.*return &\([^;]*\);/\1/' | \
        sort -u > "$TEMP_DIR/xdp_func_proto_returns.txt"
        
        log_info "Found $(wc -l < "$TEMP_DIR/xdp_func_proto_returns.txt") functions returned by xdp_func_proto"
    else
        log_warn "No xdp_func_proto found in any files"
        touch "$TEMP_DIR/xdp_func_proto_returns.txt"
    fi
    
    cd "$SCRIPT_DIR"
}

# Step 4: Extract kfunc definitions
extract_xdp_kfuncs() {
    log_info "=== Step 4: Extracting XDP kfuncs ==="
    
    cd "$KERNEL_SRC_DIR"
    
    # Find kfunc set definitions
    local kfunc_set_files=$(grep -l "bpf_kfunc_check_set_xdp" "$TEMP_DIR/all_relevant_files.txt" 2>/dev/null || true)
    
    if [[ -n "$kfunc_set_files" ]]; then
        log_info "Found bpf_kfunc_check_set_xdp in $(echo "$kfunc_set_files" | wc -l) files"
        
        # Extract kfuncs between start and end markers
        echo "$kfunc_set_files" | \
        xargs -I {} sed -n '/BTF_SET.*START.*bpf_kfunc_check_set_xdp/,/BTF_SET.*END.*bpf_kfunc_check_set_xdp/p' {} 2>/dev/null | \
        grep "BTF_ID_FLAGS" | \
        sed 's/.*BTF_ID_FLAGS(func, \([^,]*\).*/\1/' | \
        sort -u > "$TEMP_DIR/xdp_kfuncs.txt"
        
        log_info "Found $(wc -l < "$TEMP_DIR/xdp_kfuncs.txt") XDP kfuncs"
    else
        log_warn "No bpf_kfunc_check_set_xdp found"
        touch "$TEMP_DIR/xdp_kfuncs.txt"
    fi
    
    cd "$SCRIPT_DIR"
}

# Step 5: Extract base function paths
extract_base_function_paths() {
    log_info "=== Step 5: Extracting base function paths ==="
    
    cd "$KERNEL_SRC_DIR"
    
    # Find bpf_sk_base_func_proto
    local sk_base_files=$(grep -l "bpf_sk_base_func_proto" "$TEMP_DIR/all_relevant_files.txt" 2>/dev/null || true)
    
    if [[ -n "$sk_base_files" ]]; then
        log_info "Found bpf_sk_base_func_proto in $(echo "$sk_base_files" | wc -l) files"
        
        # Extract functions from bpf_sk_base_func_proto
        echo "$sk_base_files" | \
        xargs -I {} sed -n '/bpf_sk_base_func_proto/,/^}/p' {} 2>/dev/null | \
        grep "case BPF_FUNC_" | \
        sed 's/.*case BPF_FUNC_\([^:]*\):/\1/' | \
        sort -u > "$TEMP_DIR/sk_base_functions.txt"
        
        log_info "Found $(wc -l < "$TEMP_DIR/sk_base_functions.txt") sk_base functions"
    else
        log_warn "No bpf_sk_base_func_proto found"
        touch "$TEMP_DIR/sk_base_functions.txt"
    fi
    
    # Find bpf_base_func_proto (if it exists)
    local base_func_files=$(grep -l "bpf_base_func_proto" "$TEMP_DIR/all_relevant_files.txt" 2>/dev/null || true)
    
    if [[ -n "$base_func_files" ]]; then
        log_info "Found bpf_base_func_proto in $(echo "$base_func_files" | wc -l) files"
        
        # Extract functions from bpf_base_func_proto
        echo "$base_func_files" | \
        xargs -I {} sed -n '/bpf_base_func_proto/,/^}/p' {} 2>/dev/null | \
        grep "case BPF_FUNC_" | \
        sed 's/.*case BPF_FUNC_\([^:]*\):/\1/' | \
        sort -u > "$TEMP_DIR/base_functions.txt"
        
        log_info "Found $(wc -l < "$TEMP_DIR/base_functions.txt") base functions"
    else
        log_warn "No bpf_base_func_proto found"
        touch "$TEMP_DIR/base_functions.txt"
    fi
    
    cd "$SCRIPT_DIR"
}

# Step 6: Analyze BRF coverage
analyze_brf_coverage() {
    log_info "=== Step 6: Analyzing BRF Coverage ==="
    
    if [[ -f "$BRF_TYPES_FILE" ]]; then
        # Extract XDP functions from BRF HelperFuncMap
        grep -h "bpf_xdp.*_proto.*&BpfHelper" "$BRF_TYPES_FILE" 2>/dev/null | \
        sed 's/.*"\([^"]*\)".*/\1/' | \
        sort -u > "$TEMP_DIR/brf_xdp_functions.txt"
        
        # Also extract from BpfProgType XDP definition
        sed -n '/BPF_PROG_TYPE_XDP/,/^}/p' "$BRF_TYPES_FILE" 2>/dev/null | \
        grep "bpf_xdp.*_proto" | \
        sed 's/.*"\([^"]*\)".*/\1/' | \
        sort -u > "$TEMP_DIR/brf_xdp_progtype.txt"
        
        # Combine BRF functions
        cat "$TEMP_DIR/brf_xdp_functions.txt" "$TEMP_DIR/brf_xdp_progtype.txt" 2>/dev/null | \
        sort -u > "$TEMP_DIR/brf_all_xdp_functions.txt"
        
        log_info "BRF has $(wc -l < "$TEMP_DIR/brf_all_xdp_functions.txt") XDP functions"
    else
        log_warn "BRF types file not found: $BRF_TYPES_FILE"
        touch "$TEMP_DIR/brf_all_xdp_functions.txt"
    fi
}

# Step 7: Generate comprehensive report
generate_report() {
    log_info "=== Step 7: Generating Comprehensive Report ==="
    
    # Combine all discovered patterns
    cat "$TEMP_DIR"/xdp_*_patterns.txt "$TEMP_DIR"/xdp_*functions.txt 2>/dev/null | \
    grep -v '^$' | sort -u > "$TEMP_DIR/all_discovered_xdp_functions.txt"
    
    # Remove duplicates and clean up
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' "$TEMP_DIR/all_discovered_xdp_functions.txt" | \
    grep -v '^$' | sort -u > "$TEMP_DIR/clean_xdp_functions.txt"
    
    local total_kernel=$(wc -l < "$TEMP_DIR/clean_xdp_functions.txt")
    local total_brf=$(wc -l < "$TEMP_DIR/brf_all_xdp_functions.txt" 2>/dev/null || echo "0")
    local missing=$((total_kernel - total_brf))
    
    # Generate comprehensive report
    cat > "$OUTPUT_FILE" << EOF
COMPREHENSIVE XDP FUNCTION ANALYSIS REPORT
==========================================
Generated: $(date)
Kernel Source: $KERNEL_SRC_DIR
BRF Types: $BRF_TYPES_FILE
Script: $0

EXECUTION SUMMARY
================
- Files with XDP content: $(wc -l < "$TEMP_DIR/xdp_related_files.txt")
- Files with BPF content: $(wc -l < "$TEMP_DIR/bpf_related_files.txt")
- Total relevant files: $(wc -l < "$TEMP_DIR/all_relevant_files.txt")

FUNCTION DISCOVERY SUMMARY
==========================
Total XDP functions discovered in kernel: $total_kernel
Total XDP functions in BRF: $total_brf
Missing functions: $missing

DETAILED BREAKDOWN
==================

1. XDP PROTO PATTERNS (bpf_xdp_*_proto)
----------------------------------------
EOF

    if [[ -f "$TEMP_DIR/xdp_proto_patterns.txt" ]]; then
        cat "$TEMP_DIR/xdp_proto_patterns.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

2. XDP FUNCTION CONSTANTS (BPF_FUNC_xdp_*)
-------------------------------------------
EOF

    if [[ -f "$TEMP_DIR/xdp_func_constants.txt" ]]; then
        cat "$TEMP_DIR/xdp_func_constants.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

3. XDP KFUNCS (__bpf_kfunc xdp_*)
-----------------------------------
EOF

    if [[ -f "$TEMP_DIR/xdp_kfuncs.txt" ]]; then
        cat "$TEMP_DIR/xdp_kfuncs.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

4. XDP BTF PATTERNS (BTF_ID_FLAGS xdp_*)
------------------------------------------
EOF

    if [[ -f "$TEMP_DIR/xdp_btf_patterns.txt" ]]; then
        cat "$TEMP_DIR/xdp_btf_patterns.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

5. GENERIC XDP PATTERNS (bpf_xdp_*)
-------------------------------------
EOF

    if [[ -f "$TEMP_DIR/xdp_generic_patterns.txt" ]]; then
        cat "$TEMP_DIR/xdp_generic_patterns.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

6. XDP FUNC PROTO RETURNS
--------------------------
EOF

    if [[ -f "$TEMP_DIR/xdp_func_proto_returns.txt" ]]; then
        cat "$TEMP_DIR/xdp_func_proto_returns.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

7. SK BASE FUNCTIONS (Available to XDP)
---------------------------------------
EOF

    if [[ -f "$TEMP_DIR/sk_base_functions.txt" ]]; then
        cat "$TEMP_DIR/sk_base_functions.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

8. BASE FUNCTIONS (Available to XDP)
------------------------------------
EOF

    if [[ -f "$TEMP_DIR/base_functions.txt" ]]; then
        cat "$TEMP_DIR/base_functions.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

9. BRF COVERAGE
---------------
EOF

    if [[ -f "$TEMP_DIR/brf_all_xdp_functions.txt" ]]; then
        cat "$TEMP_DIR/brf_all_xdp_functions.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

10. MISSING FUNCTIONS (Need to be added to BRF)
===============================================
EOF

    # Find missing functions
    if [[ -f "$TEMP_DIR/clean_xdp_functions.txt" ]] && [[ -f "$TEMP_DIR/brf_all_xdp_functions.txt" ]]; then
        comm -23 <(sort "$TEMP_DIR/clean_xdp_functions.txt") <(sort "$TEMP_DIR/brf_all_xdp_functions.txt") >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

11. RAW DISCOVERY DATA
======================

All discovered XDP functions (raw):
EOF

    cat "$TEMP_DIR/clean_xdp_functions.txt" >> "$OUTPUT_FILE"

    cat >> "$OUTPUT_FILE" << EOF

BRF XDP functions (raw):
EOF

    cat "$TEMP_DIR/brf_all_xdp_functions.txt" >> "$OUTPUT_FILE"

    log_info "Comprehensive report generated: $OUTPUT_FILE"
}

# Step 8: Cleanup and final summary
cleanup_and_summary() {
    log_info "=== Step 8: Cleanup and Summary ==="
    
    # Show final statistics
    local total_kernel=$(wc -l < "$TEMP_DIR/clean_xdp_functions.txt")
    local total_brf=$(wc -l < "$TEMP_DIR/brf_all_xdp_functions.txt" 2>/dev/null || echo "0")
    local missing=$((total_kernel - total_brf))
    
    log_info "=== FINAL RESULTS ==="
    log_info "Total XDP functions in kernel: $total_kernel"
    log_info "Total XDP functions in BRF: $total_brf"
    log_info "Missing functions: $missing"
    log_info "Report saved to: $OUTPUT_FILE"
    
    # Cleanup temporary files
    rm -rf "$TEMP_DIR"
    
    log_info "Analysis complete! Check $OUTPUT_FILE for comprehensive results"
}

# Main execution function
main() {
    log_info "Starting Comprehensive XDP Function Analysis"
    log_info "This may take a while - completeness over speed!"
    
    # Check if kernel source directory exists
    if [[ ! -d "$KERNEL_SRC_DIR" ]]; then
        log_error "Kernel source directory not found: $KERNEL_SRC_DIR"
        log_info "Usage: $0 <kernel_source_dir> [brf_types_file]"
        exit 1
    fi
    
    # Execute all steps
    find_xdp_related_files
    extract_xdp_function_patterns
    extract_xdp_func_proto_usage
    extract_xdp_kfuncs
    extract_base_function_paths
    analyze_brf_coverage
    generate_report
    cleanup_and_summary
}

# Run main function with error handling
trap 'log_error "Script interrupted. Cleaning up..."; rm -rf "$TEMP_DIR"; exit 1' INT TERM
main "$@"
