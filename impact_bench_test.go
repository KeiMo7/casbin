// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v3/model"
)

func benchmarkPolicyPair(b *testing.B, roles, usersPerRole, domains int) (ImpactSnapshot, ImpactSnapshot) {
	b.Helper()
	m, err := model.NewModelFromFile(filepath.Join("testdata", "impact", "domain_model.conf"))
	if err != nil {
		b.Fatal(err)
	}
	cur := ImpactSnapshot{Model: m.Copy()}
	cand := ImpactSnapshot{Model: m.Copy()}
	for d := 0; d < domains; d++ {
		domain := fmt.Sprintf("domain%d", d)
		for r := 0; r < roles; r++ {
			role := fmt.Sprintf("role:%d", r)
			cur.Policy = append(cur.Policy, ImpactRule{PType: "p", Rule: []string{role, domain, fmt.Sprintf("obj:%d", r), "read"}})
			cand.Policy = append(cand.Policy, ImpactRule{PType: "p", Rule: []string{role, domain, fmt.Sprintf("obj:%d", r), "read"}})
			for u := 0; u < usersPerRole; u++ {
				user := fmt.Sprintf("user:%d:%d", r, u)
				cur.Policy = append(cur.Policy, ImpactRule{PType: "g", Rule: []string{user, role, domain}})
				cand.Policy = append(cand.Policy, ImpactRule{PType: "g", Rule: []string{user, role, domain}})
			}
		}
	}
	cand.Policy = append(cand.Policy, ImpactRule{PType: "p", Rule: []string{"role:0", "domain0", "obj:new", "write"}})
	return cur, cand
}

// BenchmarkImpactLargePolicySet measures a preview over a several-thousand-rule
// policy set, the size the change window actually sees.
func BenchmarkImpactLargePolicySet(b *testing.B) {
	cur, cand := benchmarkPolicyPair(b, 40, 25, 6)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report, err := ComputeImpact(cur, cand, ImpactOptions{})
		if err != nil {
			b.Fatal(err)
		}
		if err := report.Verify(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkImpactWideRoleTree measures a preview where a single link change is
// visible to a wide role closure.
func BenchmarkImpactWideRoleTree(b *testing.B) {
	m, err := model.NewModelFromFile(filepath.Join("testdata", "impact", "rbac_model.conf"))
	if err != nil {
		b.Fatal(err)
	}
	cur := ImpactSnapshot{Model: m.Copy()}
	cand := ImpactSnapshot{Model: m.Copy()}
	cur.Policy = append(cur.Policy, ImpactRule{PType: "p", Rule: []string{"role:root", "data1", "read"}})
	cand.Policy = append(cand.Policy, ImpactRule{PType: "p", Rule: []string{"role:root", "data1", "read"}})
	for i := 0; i < 200; i++ {
		child := fmt.Sprintf("role:%d", i)
		cur.Policy = append(cur.Policy, ImpactRule{PType: "g", Rule: []string{child, "role:root"}})
		for j := 0; j < 10; j++ {
			user := fmt.Sprintf("user:%d:%d", i, j)
			cur.Policy = append(cur.Policy, ImpactRule{PType: "g", Rule: []string{user, child}})
			cand.Policy = append(cand.Policy, ImpactRule{PType: "g", Rule: []string{user, child}})
		}
	}
	// The candidate keeps every link except one mid-tree link, which it omits.
	for _, r := range cur.Policy {
		if r.PType == "g" && len(r.Rule) == 2 && r.Rule[0] == "role:0" && r.Rule[1] == "role:root" {
			continue
		}
		if r.PType == "g" {
			cand.Policy = append(cand.Policy, r)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report, err := ComputeImpact(cur, cand, ImpactOptions{})
		if err != nil {
			b.Fatal(err)
		}
		if err := report.Verify(); err != nil {
			b.Fatal(err)
		}
	}
}
