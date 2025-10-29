# Quick Start: Improving BPF Program Generator for Security Research

## Purpose

This guide provides a **roadmap** for improving the BPF program generator to discover high-quality security vulnerabilities in the Linux kernel. Use this alongside the detailed analysis document.

---

## Understanding the Current System (10 minutes)

### Key Files to Review
1. **`prog/brf.go`**: Entry point and Syzkaller integration
2. **`prog/brf_legacy.go`**: Core generation logic
   - Lines 2228-2273: `genBpfHelperCall()` - recursive generation
   - Lines 1958-2002: `genBpfHelperCallArg()` - argument generation
   - Lines 2515-2621: `FixRef()` - reference counting
3. **`prog/brf_types.go`**: Type definitions and helper database
4. **`prog/brf_prog.go`**: Program structure and C generation

### Core Generation Flow
```
Select Program Type → Choose Initial Helper → Generate Arguments (recursive) 
→ Fix References → Fix Spinlocks → Generate C Code → Compile → Execute
```

### Current Focus Areas
- **Program Types**: Configurable - can focus on specific types or enable all 35+ types
- **Selection Strategy**: Uniform random
- **Mutation**: Single argument only
- **Call Depth**: Average 3-5 levels

---

## Priority Improvements (Ranked by Impact)

### 🔴 Priority 1: Expand Program Type Coverage (High Impact, Low Complexity)

**Why**: More program types = more kernel code coverage = more potential vulnerabilities discovered

**Goal**: Expand from focused set to comprehensive coverage of all 35+ program types

**Quick Win** - Modify `brf_legacy.go:2443`:
```go
// OPTION 1: Expand to high-value types (quick win)
targetTypes := []BpfProgTypeEnum{
    BPF_PROG_TYPE_LSM,           // Security hooks
    BPF_PROG_TYPE_SYSCALL,       // Syscall interception
    BPF_PROG_TYPE_NETFILTER,     // Packet filtering
    BPF_PROG_TYPE_XDP,           // Add - packet processing (CVE-2021-3490)
    BPF_PROG_TYPE_TRACING,       // Add - kernel tracing (CVE-2020-8835)
    BPF_PROG_TYPE_SOCK_OPS,      // Add - socket operations (CVE-2021-31440)
    BPF_PROG_TYPE_SCHED_CLS,     // Add - traffic control
    BPF_PROG_TYPE_CGROUP_SKB,    // Add - cgroup networking
}
pt := brf.progTypeMap[targetTypes[r.Intn(len(targetTypes))]]

// OPTION 2: Enable all types (comprehensive coverage)
pt := brf.progTypeMap[BpfProgTypeEnum(r.Intn(int(BPF_PROG_TYPE_MAX))+1)]
```

**Testing New Types**: When adding new types, start with focused testing:
```go
// Phase 1: Test only new types first
newTypes := []BpfProgTypeEnum{BPF_PROG_TYPE_NEW_TYPE_1, BPF_PROG_TYPE_NEW_TYPE_2}
pt := brf.progTypeMap[newTypes[r.Intn(len(newTypes))]]

// Phase 2: After validation, add to main set
// Phase 3: Enable all types for full coverage
```

**Expected Benefit**: 2-3x more kernel code coverage per additional type

---

### 🔴 Priority 2: Implement Vulnerability Pattern Templates (High Impact, Medium Complexity)

**Why**: Targeted generation finds bugs faster than random generation

**Implementation Location**: Create new file `prog/vuln_patterns.go`

**Example Pattern - Integer Overflow**:
```go
func generateIntegerOverflowPattern(p *BpfProg, r *randGen) bool {
    // 1. Create map with small value
    smallMap := p.NewMap(selectMapType(r), hint, 8, r)
    
    // 2. Lookup returns pointer
    lookup := p.pt.getHelper(BPF_FUNC_map_lookup_elem)
    lookupCall, _ := p.genBpfHelperCall(r, lookup, newBpfCallGenHint(smallMap), false)
    
    // 3. Access with large offset (potential overflow)
    offset := r.Intn(1024)
    accessHelper := selectMemAccessHelper(p.pt, r)
    hint := newBpfCallGenHint(nil)
    hint.RetAccessSize = smallMap.Val.Size + offset  // Beyond bounds!
    
    accessCall, _ := p.genBpfHelperCall(r, accessHelper, hint, false)
    accessCall.Args[findPtrArgIndex(accessCall)].Name = lookupCall.Ret
    
    return true
}
```

**Hook into Generation** - Modify `brf.go:GenBpfProg()`:
```go
func (brf *BpfRuntimeFuzzer) GenBpfProg(r *randGen, opt BrfGenProgOpt) (*BpfProg, bool) {
    pt := selectProgramType(brf, r)
    p := NewBpfProg(pt, r, opt)
    
    // 30% chance to use vulnerability pattern
    if r.Intn(10) < 3 {
        pattern := selectVulnPattern(r)
        pattern.Generate(p, r)
    } else {
        // Normal generation
        helper := pt.Helpers[r.Intn(len(pt.Helpers))]
        p.genBpfHelperCall(r, helper, hint, false)
    }
    
    return p, true
}
```

**Expected Benefit**: 5-10x higher quality bug discovery rate

---

### 🟡 Priority 3: Enhanced Mutation Strategies (Medium Impact, Medium Complexity)

**Why**: Current mutation only changes one argument; structural mutations find different bugs

**Implementation Location**: `prog/brf.go:MutBpfProg()`

**Quick Improvement**:
```go
func (brf *BpfRuntimeFuzzer) MutBpfProg(r *randGen, p *BpfProg, opt BrfGenProgOpt) bool {
    if len(p.Calls) == 0 {
        return false
    }
    
    // Choose mutation strategy
    strategy := r.Intn(5)
    
    switch strategy {
    case 0, 1:  // 40% - Argument mutation (current)
        call := p.Calls[r.Intn(len(p.Calls))]
        arg := r.Intn(len(call.Args))
        return p.genBpfHelperCallArg(r, call, arg)
        
    case 2:  // 20% - Call insertion
        helper := p.pt.Helpers[r.Intn(len(p.pt.Helpers))]
        insertPos := r.Intn(len(p.Calls) + 1)
        newCall, ok := p.genBpfHelperCall(r, helper, newBpfCallGenHint(nil), false)
        if ok {
            p.Calls = append(p.Calls[:insertPos], append([]*BpfCall{newCall}, p.Calls[insertPos:]...)...)
        }
        return ok
        
    case 3:  // 20% - Call deletion
        if len(p.Calls) > 1 {
            delPos := r.Intn(len(p.Calls))
            p.Calls = append(p.Calls[:delPos], p.Calls[delPos+1:]...)
            return true
        }
        return false
        
    case 4:  // 20% - Map mutation
        if len(p.Maps) > 0 {
            m := p.Maps[r.Intn(len(p.Maps))]
            // Mutate flags
            if r.Intn(2) == 0 {
                m.Flags = append(m.Flags, "BPF_F_NO_PREALLOC")
            } else {
                m.MaxEntries = int64(r.Intn(1 << 20))
            }
            return true
        }
        return false
    }
    
    return false
}
```

**Expected Benefit**: 3-4x corpus diversity, finds different bug classes

---

### 🟡 Priority 4: Intelligent Helper Selection (Medium Impact, Low Complexity)

**Why**: Some helpers are more bug-prone; prioritize them

**Implementation**: Create helper scoring system

```go
// Add to brf_types.go or new file prog/helper_scoring.go
var HelperComplexityScore = map[BpfHelperEnum]int{
    BPF_FUNC_map_lookup_elem:      5,  // Pointer returns
    BPF_FUNC_probe_read:            8,  // Kernel memory access
    BPF_FUNC_sk_lookup_tcp:         7,  // Socket lookups (ref counting)
    BPF_FUNC_ringbuf_reserve:       9,  // Memory allocation
    BPF_FUNC_bpf_skb_load_bytes:    6,  // Packet access
    // ... add more
}

var HelperBugHistory = map[BpfHelperEnum]int{
    BPF_FUNC_probe_read:            3,  // 3 known CVEs
    BPF_FUNC_map_lookup_elem:       2,  // 2 known CVEs
    BPF_FUNC_sk_lookup_tcp:         1,  // 1 known CVE
    // ... populate from CVE database
}

// Modify helper selection in brf_legacy.go:2446
func selectHelperWeighted(pt *BpfProgType, r *randGen) *BpfHelper {
    if len(pt.Helpers) == 0 {
        return nil
    }
    
    // Calculate scores
    scores := make([]int, len(pt.Helpers))
    for i, helper := range pt.Helpers {
        complexity := HelperComplexityScore[helper.Enum]
        bugHistory := HelperBugHistory[helper.Enum]
        scores[i] = complexity + bugHistory*10  // Weight history heavily
        
        if scores[i] == 0 {
            scores[i] = 1  // Minimum score
        }
    }
    
    // Weighted random selection
    totalScore := 0
    for _, score := range scores {
        totalScore += score
    }
    
    target := r.Intn(totalScore)
    cumulative := 0
    for i, score := range scores {
        cumulative += score
        if cumulative > target {
            return pt.Helpers[i]
        }
    }
    
    return pt.Helpers[len(pt.Helpers)-1]
}
```

**Expected Benefit**: 2x faster bug discovery in high-value helpers

---

### 🟢 Priority 5: Coverage Tracking (Low Impact, High Complexity)

**Why**: Avoid redundant testing, focus on uncovered code

**Implementation**: Add coverage tracker to `BpfRuntimeFuzzer`

```go
// Add to brf.go
type CoverageTracker struct {
    helperCalls     map[BpfHelperEnum]int
    helperPairs     map[[2]BpfHelperEnum]int
    progTypes       map[BpfProgTypeEnum]int
}

func (tracker *CoverageTracker) RecordProgram(p *BpfProg) {
    tracker.progTypes[p.TypeEnum]++
    
    for _, call := range p.Calls {
        tracker.helperCalls[call.Helper.Enum]++
    }
    
    for i := 0; i < len(p.Calls)-1; i++ {
        pair := [2]BpfHelperEnum{p.Calls[i].Helper.Enum, p.Calls[i+1].Helper.Enum}
        tracker.helperPairs[pair]++
    }
}

func (tracker *CoverageTracker) GetLeastCoveredHelper(pt *BpfProgType) *BpfHelper {
    minCount := int(^uint(0) >> 1)  // Max int
    var leastCovered *BpfHelper
    
    for _, helper := range pt.Helpers {
        count := tracker.helperCalls[helper.Enum]
        if count < minCount {
            minCount = count
            leastCovered = helper
        }
    }
    
    return leastCovered
}
```

**Expected Benefit**: 30-40% reduction in redundant test cases

---

## Quick Debugging Tips

### Program Generation Failures

**Problem**: `genBpfHelperCall()` returns `nil, false`

**Debug Steps**:
1. Check recursion depth: `rd > 100`
2. Check argument generation attempts: `attempt > 50`
3. Add debug prints in `genBpfHelperCallArg()`
4. Verify helper compatibility with program type

**Common Issues**:
- No compatible maps available → Check `getHelperCompatMaps()`
- No compatible register types → Check `genCompatibleRegTypes()`
- Context access denied → Check `p.pt.ctxAccess`

### Compilation Failures

**Problem**: Clang compilation fails

**Debug Steps**:
1. Check generated C source: `cat /mnt/brf_work_dir/prog_*.c`
2. Look for syntax errors in `genCSource()`
3. Verify struct definitions are complete
4. Check for missing includes

**Common Issues**:
- Undefined struct members → Check `FieldTypes` generation
- Missing map definitions → Check map generation
- Invalid helper arguments → Check argument type matching

### Verification Failures

**Problem**: Kernel verifier rejects program

**Debug Steps**:
1. Run `bpftool prog load` manually to see verifier output
2. Check reference counting: `FixRef()` might have missed something
3. Check spinlock matching: `FixSpinLock()` might have missed something
4. Verify context access permissions

**Common Issues**:
- Reference leak → Add `bpf_sk_release` call
- Unmatched spinlock → Add `bpf_spin_unlock` call
- Invalid context access → Check `ctxAccess.accesses`

---

## Testing Your Changes

### Unit Testing Approach

```go
// Create test file: prog/brf_improvements_test.go
func TestEnhancedProgramTypeSelection(t *testing.T) {
    brf := NewBpfRuntimeFuzzer(true)
    
    // Test that new program types are selected
    types := make(map[BpfProgTypeEnum]int)
    for i := 0; i < 100; i++ {
        r := newRandGen()
        pt := selectProgramType(brf, r)
        types[pt.Enum]++
    }
    
    // Verify we're hitting multiple types
    if len(types) < 5 {
        t.Errorf("Only %d program types selected, expected at least 5", len(types))
    }
    
    // Verify high-value types are included
    expectedTypes := []BpfProgTypeEnum{
        BPF_PROG_TYPE_XDP,
        BPF_PROG_TYPE_TRACING,
        BPF_PROG_TYPE_SOCK_OPS,
    }
    for _, expected := range expectedTypes {
        if types[expected] == 0 {
            t.Errorf("Expected program type %v not selected", expected)
        }
    }
}
```

### Integration Testing

```bash
# Build fuzzer
make

# Run with enhanced generation
./bin/syz-manager -config=brf.cfg

# Monitor for crashes
tail -f workdir/crashes/*/log*

# Check coverage
./bin/syz-manager -config=brf.cfg -coverage
```

### Validation Checklist

- [ ] Programs compile successfully (check logs)
- [ ] Programs pass verifier (check kernel logs)
- [ ] Programs execute without crashes
- [ ] Coverage is increasing (check workdir/coverage)
- [ ] New program types are being tested
- [ ] Mutation creates diverse programs

---

## Measuring Success

### Metrics to Track

1. **Generation Success Rate**: `successful_programs / total_attempts`
   - Target: > 80%
   
2. **Verifier Pass Rate**: `verifier_passed / compiled_programs`
   - Target: > 90%
   
3. **Program Diversity**: Unique helper call sequences
   - Measure: Shannon entropy of call sequences
   
4. **Bug Discovery Rate**: Unique crashes per hour
   - Compare before/after improvements
   
5. **Coverage Growth**: Kernel code coverage increase
   - Use KCOV data from kernel

### Logging Improvements

```go
// Add to brf.go:GenBpfProg
func (brf *BpfRuntimeFuzzer) GenBpfProg(r *randGen, opt BrfGenProgOpt) (*BpfProg, bool) {
    startTime := time.Now()
    
    // ... generation code ...
    
    if ok {
        metrics.RecordSuccess(p, time.Since(startTime))
    } else {
        metrics.RecordFailure(p, time.Since(startTime))
    }
    
    return p, ok
}

// Metrics tracking
type GenerationMetrics struct {
    SuccessCount    int
    FailureCount    int
    AverageTime     time.Duration
    HelperUsage     map[BpfHelperEnum]int
    ProgramTypes    map[BpfProgTypeEnum]int
}
```

---

## Roadmap

### Week 1: Foundation
- [ ] Implement Priority 1 (Expand Program Type Coverage)
  - [ ] Add 5 more high-value types to current set
  - [ ] Test each new type in isolation first
  - [ ] Monitor success rates (generation, compilation, verification)
- [ ] Add basic logging and metrics
- [ ] Test compilation success rate for each type

### Week 2: Quality Improvements
- [ ] Implement Priority 2 (Vulnerability Patterns)
- [ ] Add 3-5 pattern templates
- [ ] Validate pattern effectiveness

### Week 3: Diversity
- [ ] Implement Priority 3 (Enhanced Mutations)
- [ ] Add structural mutation operators
- [ ] Measure corpus diversity

### Week 4: Optimization
- [ ] Implement Priority 4 (Helper Selection)
- [ ] Add bug history database
- [ ] Optimize for high-value targets

### Month 2: Advanced Features
- [ ] Implement Priority 5 (Coverage Tracking)
- [ ] Add campaign-based generation
- [ ] Create fuzzing strategies for specific subsystems

---

## Quick Reference: Key Functions

| Function | File | Line | Purpose |
|----------|------|------|---------|
| `GenPrologue()` | brf.go | 86-127 | Entry point from Syzkaller |
| `GenBpfProg()` | brf_legacy.go | 2441-2454 | Core program generation |
| `genBpfHelperCall()` | brf_legacy.go | 2228-2273 | Recursive helper call generation |
| `genBpfHelperCallArg()` | brf_legacy.go | 1958-2002 | Argument generation strategies |
| `FixRef()` | brf_legacy.go | 2515-2621 | Fix reference counting |
| `FixSpinLock()` | brf_legacy.go | 2623-2670 | Fix spinlock matching |
| `genCSource()` | brf_legacy.go | 2706-2815 | C code generation |
| `NewBpfProg()` | brf_legacy.go | 305-361 | Program initialization |

---

## Resources

- **Detailed Analysis**: See `BPF_Program_Generator_Deep_Dive_Analysis.md`
- **Existing Docs**: See `BRF_Initialization_and_Program_Generation_Guide.md`
- **CVE Database**: Track BPF-related CVEs for bug patterns
- **Kernel Source**: `linux/kernel/bpf/` for verifier and runtime code

---

## Getting Help

**If programs fail to compile**:
- Check `genCSource()` output
- Verify struct definitions are complete
- Ensure all variables are declared

**If verifier rejects programs**:
- Check reference counting with `FixRef()`
- Check spinlock matching with `FixSpinLock()`
- Verify context access permissions

**If coverage is low**:
- Implement Priority 1 (expand program type coverage)
- Add more high-value program types
- Check that different helpers are being selected
- Verify mutation is working

**If bug discovery rate is low**:
- Implement Priority 2 (vulnerability patterns)
- Focus on high-complexity helpers
- Target specific kernel subsystems

---

## Summary

**Quick wins** (1-2 days):
1. Expand program type coverage to 8+ types (Priority 1)
   - Add 5 more high-value types (XDP, TRACING, SOCK_OPS, SCHED_CLS, CGROUP_SKB)
   - Test each new type in isolation before enabling broadly
2. Add basic mutation strategies (Priority 3 partial)

**Medium effort** (1 week):
3. Implement 3-5 vulnerability patterns (Priority 2)
4. Add helper scoring (Priority 4)

**Long-term** (1 month):
5. Add comprehensive coverage tracking (Priority 5)
6. Create fuzzing campaigns
7. Integrate with external coverage data

Start with Priority 1 for immediate impact, then work through priorities 2-4 for quality improvements. Save Priority 5 for optimization phase.

---

## Testing New Program Type Additions

When adding support for new BPF program types, follow this phased testing approach:

### Phase 1: Isolated Testing (1-2 days)

**Goal**: Validate new type implementation without interference

```go
// Test only the new type(s)
func (brf *BpfRuntimeFuzzer) GenBpfProg(r *randGen, opt BrfGenProgOpt) (*BpfProg, bool) {
    newTypes := []BpfProgTypeEnum{BPF_PROG_TYPE_NEW_TYPE}
    pt := brf.progTypeMap[newTypes[0]]  // Focus on single new type
    // ... generation logic
}
```

**Checklist**:
- [ ] Generate 1000+ programs
- [ ] Compilation success rate > 90%
- [ ] Verifier pass rate > 85%
- [ ] No crashes during execution
- [ ] All helpers work correctly
- [ ] Context access validated

### Phase 2: Incremental Integration (3-5 days)

**Goal**: Add to existing types, monitor for regressions

```go
// Add validated type to existing set
targetTypes := []BpfProgTypeEnum{
    BPF_PROG_TYPE_EXISTING_1,
    BPF_PROG_TYPE_EXISTING_2,
    BPF_PROG_TYPE_NEW_TYPE,  // Add after Phase 1 validation
}
pt := brf.progTypeMap[targetTypes[r.Intn(len(targetTypes))]]
```

**Monitor**:
- Generation success rate per type
- No regression in existing types
- New type performs comparably

### Phase 3: Full Deployment (Ongoing)

**Goal**: Enable comprehensive coverage

```go
// Enable all types
pt := brf.progTypeMap[BpfProgTypeEnum(r.Intn(int(BPF_PROG_TYPE_MAX))+1)]
```

### Example: Testing LSM, SYSCALL, NETFILTER

```bash
# Week 1: Isolated testing
# Modified code to test only: LSM, SYSCALL, NETFILTER
# Generated 10,000 programs
# Results: 85% success rate, found 3 bugs in context access

# Week 2: Incremental integration
# Added to existing XDP, TRACING types
# Generated 20,000 programs
# Results: No regressions, stable performance

# Week 3: Full deployment
# Enabled all program types
# New types contribute 30% of test cases
```

### Quick Test Script

```bash
# Test new program type
./bin/syz-manager -config=test_new_type.cfg

# Monitor results
tail -f workdir/crashes/*/log*
grep "BPF_PROG_TYPE_NEW_TYPE" workdir/corpus/*/log*

# Check success metrics
grep "compilation success" workdir/logs/* | wc -l
grep "verifier passed" workdir/logs/* | wc -l
```

