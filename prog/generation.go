// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	fmt.Printf("🔍 BRF Debug: Generate() called with ncalls=%d\n", ncalls)
	fmt.Printf("🔍 BRF Debug: target.Brf = %v\n", target.Brf)

	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)

	if target.Brf != nil {
		fmt.Printf("✅ BRF Debug: Calling target.Brf.GenPrologue()\n")
		target.Brf.GenPrologue(r, s, p)
		fmt.Printf("✅ BRF Debug: GenPrologue completed, prog has %d calls\n", len(p.Calls))
	} else {
		fmt.Printf("❌ BRF Debug: target.Brf is nil, skipping GenPrologue\n")
	}

	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()

	fmt.Printf("🔍 BRF Debug: Generate() completed, final prog has %d calls\n", len(p.Calls))
	return p
}
