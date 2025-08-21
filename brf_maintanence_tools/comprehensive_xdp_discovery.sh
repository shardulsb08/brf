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
    log_info "Current directory: $(pwd)"

    # Step 1: Just find files
    log_info "Step 1.1: Running find command..."
    find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.S" -o -name "*.asm" \) 2>/dev/null > "$TEMP_DIR/all_files.txt"
    log_info "Step 1.1 completed: $(wc -l < "$TEMP_DIR/all_files.txt") files found"

    # Step 2: Find XDP files
    log_info "Step 1.2: Finding XDP files..."
    while IFS= read -r file; do
        if grep -l -i "xdp" "$file" >/dev/null 2>/dev/null; then
            echo "$file"
        fi
    done < "$TEMP_DIR/all_files.txt" > "$TEMP_DIR/xdp_related_files.txt"
    log_info "Step 1.2 completed: $(wc -l < "$TEMP_DIR/xdp_related_files.txt") XDP files found"

    # Step 3: Sort and deduplicate
    log_info "Step 1.3: Sorting and deduplicating..."
    sort -u "$TEMP_DIR/xdp_related_files.txt" > "$TEMP_DIR/xdp_related_files_sorted.txt"
    mv "$TEMP_DIR/xdp_related_files_sorted.txt" "$TEMP_DIR/xdp_related_files.txt"
    log_info "Step 1.3 completed"

    # Step 4: Create all_relevant_files.txt (this was missing!)
    log_info "Step 1.4: Creating all_relevant_files.txt..."
    cat "$TEMP_DIR/xdp_related_files.txt" > "$TEMP_DIR/all_relevant_files.txt"
    log_info "Step 1.4 completed: $(wc -l < "$TEMP_DIR/all_relevant_files.txt") relevant files"

    log_info "Found $(wc -l < "$TEMP_DIR/xdp_related_files.txt") files with XDP content"
    log_info "xdp find done"
}

# Step 2: Extract all XDP-related function patterns
# Step 2: Extract all XDP-related function patterns
extract_xdp_function_patterns() {
    log_info "=== Step 2: Extracting XDP function patterns ==="
    
    cd "$KERNEL_SRC_DIR"
    
    # Debug: Check if we're in the right directory
    log_info "Current directory: $(pwd)"
    
    # Debug: Check if the temp file exists and has content
    log_info "Checking all_relevant_files.txt..."
    if [[ -f "$TEMP_DIR/all_relevant_files.txt" ]]; then
        log_info "all_relevant_files.txt exists with $(wc -l < "$TEMP_DIR/all_relevant_files.txt") lines"
        log_info "First few files:"
        head -5 "$TEMP_DIR/all_relevant_files.txt"
    else
        log_error "all_relevant_files.txt not found!"
        return 1
    fi
    
    # Pattern 1: bpf_xdp_*_proto definitions
    log_info "Step 2.1: Searching for bpf_xdp_*_proto patterns..."
    log_info "Running grep command on $(wc -l < "$TEMP_DIR/all_relevant_files.txt") files..."
    
    # Use a safer approach - process files in smaller batches
    local batch_size=100
    local total_files=$(wc -l < "$TEMP_DIR/all_relevant_files.txt")
    local processed=0
    
    > "$TEMP_DIR/xdp_proto_patterns.txt"  # Clear the file
    
    while [[ $processed -lt $total_files ]]; do
        local end_line=$((processed + batch_size))
        log_info "Processing batch: $((processed + 1)) to $end_line of $total_files"
        
        sed -n "$((processed + 1)),${end_line}p" "$TEMP_DIR/all_relevant_files.txt" | \
        while IFS= read -r file; do
            if [[ -r "$file" ]]; then
                grep -h "bpf_xdp.*_proto" "$file" 2>/dev/null | \
                sed 's/.*bpf_xdp_\([a-zA-Z_]*\)_proto.*/bpf_xdp_\1_proto/' >> "$TEMP_DIR/xdp_proto_patterns.txt" || true
            fi
        done
        
        processed=$end_line
    done
    
    log_info "Step 2.1 completed: $(wc -l < "$TEMP_DIR/xdp_proto_patterns.txt") proto patterns found"
    
    # Pattern 2: BPF_FUNC_xdp_* constants
    log_info "Step 2.2: Searching for BPF_FUNC_xdp_* patterns..."
    > "$TEMP_DIR/xdp_func_constants.txt"  # Clear the file
    
    processed=0
    while [[ $processed -lt $total_files ]]; do
        local end_line=$((processed + batch_size))
        log_info "Processing batch: $((processed + 1)) to $end_line of $total_files"
        
        sed -n "$((processed + 1)),${end_line}p" "$TEMP_DIR/all_relevant_files.txt" | \
        while IFS= read -r file; do
            if [[ -r "$file" ]]; then
                grep -h "BPF_FUNC_xdp" "$file" 2>/dev/null | \
                sed 's/.*BPF_FUNC_xdp_\([a-zA-Z_]*\).*/BPF_FUNC_xdp_\1/' >> "$TEMP_DIR/xdp_func_constants.txt" || true
            fi
        done
        
        processed=$end_line
    done
    
    log_info "Step 2.2 completed: $(wc -l < "$TEMP_DIR/xdp_func_constants.txt") func constants found"
    
    # Continue with other patterns...
    log_info "Step 2 completed successfully"
    
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
    
    # Debug: Check what files we have
    log_info "Checking available temp files:"
    ls -la "$TEMP_DIR"/
    
    # Debug: Check file contents
    log_info "Contents of xdp_proto_patterns.txt:"
    if [[ -f "$TEMP_DIR/xdp_proto_patterns.txt" ]]; then
        wc -l "$TEMP_DIR/xdp_proto_patterns.txt"
        head -5 "$TEMP_DIR/xdp_proto_patterns.txt"
    else
        log_warn "xdp_proto_patterns.txt not found"
    fi
    
    log_info "Contents of xdp_func_constants.txt:"
    if [[ -f "$TEMP_DIR/xdp_func_constants.txt" ]]; then
        wc -l "$TEMP_DIR/xdp_func_constants.txt"
        head -5 "$TEMP_DIR/xdp_func_constants.txt"
    else
        log_warn "xdp_func_constants.txt not found"
    fi
    
    # Combine all discovered patterns - FIXED VERSION
    log_info "Step 7.1: Combining all discovered patterns..."
    
    # Clear the output file first
    > "$TEMP_DIR/all_discovered_xdp_functions.txt"
    
    # Add proto patterns
    if [[ -f "$TEMP_DIR/xdp_proto_patterns.txt" ]]; then
        log_info "Adding proto patterns..."
        cat "$TEMP_DIR/xdp_proto_patterns.txt" >> "$TEMP_DIR/all_discovered_xdp_functions.txt"
    fi
    
    # Add function constants
    if [[ -f "$TEMP_DIR/xdp_func_constants.txt" ]]; then
        log_info "Adding function constants..."
        cat "$TEMP_DIR/xdp_func_constants.txt" >> "$TEMP_DIR/all_discovered_xdp_functions.txt"
    fi
    
    # Add other pattern files if they exist
    for pattern_file in "$TEMP_DIR"/xdp_*_patterns.txt "$TEMP_DIR"/xdp_*functions.txt; do
        if [[ -f "$pattern_file" ]] && [[ "$pattern_file" != "$TEMP_DIR/xdp_proto_patterns.txt" ]] && [[ "$pattern_file" != "$TEMP_DIR/xdp_func_constants.txt" ]]; then
            log_info "Adding $(basename "$pattern_file")..."
            cat "$pattern_file" >> "$TEMP_DIR/all_discovered_xdp_functions.txt"
        fi
    done
    
    log_info "Step 7.1 completed: $(wc -l < "$TEMP_DIR/all_discovered_xdp_functions.txt") total functions"
    
    # Remove duplicates and clean up
    log_info "Step 7.2: Cleaning up function list..."
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' "$TEMP_DIR/all_discovered_xdp_functions.txt" | \
    grep -v '^$' | sort -u > "$TEMP_DIR/clean_xdp_functions.txt"
    log_info "Step 7.2 completed: $(wc -l < "$TEMP_DIR/clean_xdp_functions.txt") clean functions"
    
    local total_kernel=$(wc -l < "$TEMP_DIR/clean_xdp_functions.txt")
    local total_brf=$(wc -l < "$TEMP_DIR/brf_all_xdp_functions.txt" 2>/dev/null || echo "0")
    local missing=$((total_kernel - total_brf))
    
    log_info "Step 7.3: Calculating statistics..."
    log_info "Total kernel functions: $total_kernel"
    log_info "Total BRF functions: $total_brf"
    log_info "Missing functions: $missing"
    
    # Generate comprehensive report
    log_info "Step 7.4: Writing report to $OUTPUT_FILE..."
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

    log_info "Step 7.5: Writing proto patterns to report..."
    if [[ -f "$TEMP_DIR/xdp_proto_patterns.txt" ]]; then
        cat "$TEMP_DIR/xdp_proto_patterns.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

2. XDP FUNCTION CONSTANTS (BPF_FUNC_xdp_*)
-------------------------------------------
EOF

    log_info "Step 7.6: Writing function constants to report..."
    if [[ -f "$TEMP_DIR/xdp_func_constants.txt" ]]; then
        cat "$TEMP_DIR/xdp_func_constants.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

3. BRF COVERAGE
---------------
EOF

    log_info "Step 7.7: Writing BRF coverage to report..."
    if [[ -f "$TEMP_DIR/brf_all_xdp_functions.txt" ]]; then
        cat "$TEMP_DIR/brf_all_xdp_functions.txt" >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

4. MISSING FUNCTIONS (Need to be added to BRF)
===============================================
EOF

    log_info "Step 7.8: Calculating missing functions..."
    # Find missing functions
    if [[ -f "$TEMP_DIR/clean_xdp_functions.txt" ]] && [[ -f "$TEMP_DIR/brf_all_xdp_functions.txt" ]]; then
        comm -23 <(sort "$TEMP_DIR/clean_xdp_functions.txt") <(sort "$TEMP_DIR/brf_all_xdp_functions.txt") >> "$OUTPUT_FILE"
    fi

    cat >> "$OUTPUT_FILE" << EOF

5. RAW DISCOVERY DATA
======================

All discovered XDP functions (raw):
EOF

    log_info "Step 7.9: Writing raw data to report..."
    cat "$TEMP_DIR/clean_xdp_functions.txt" >> "$OUTPUT_FILE"

    cat >> "$OUTPUT_FILE" << EOF

BRF XDP functions (raw):
EOF

    cat "$TEMP_DIR/brf_all_xdp_functions.txt" >> "$OUTPUT_FILE"

    log_info "Step 7 completed: Report written to $OUTPUT_FILE"
    log_info "Report size: $(wc -l < "$OUTPUT_FILE") lines"
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
    
    # Show report location
    log_info "Report absolute path: $(readlink -f "$OUTPUT_FILE")"
    
    # Cleanup temporary files
    log_info "Cleaning up temporary files..."
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
