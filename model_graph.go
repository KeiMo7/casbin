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
	"sort"
	"strings"

	"github.com/casbin/casbin/v3/model"
)

// ModelGraphFormat selects a text graph representation.
type ModelGraphFormat string

const (
	ModelGraphMermaid ModelGraphFormat = "mermaid"
	ModelGraphDOT     ModelGraphFormat = "dot"
)

// GetModelVisualization returns a Mermaid graph of role inheritance and
// resource grouping.
func (e *Enforcer) GetModelVisualization() string {
	graph, _ := e.ExportModelGraph(ModelGraphMermaid)
	return graph
}

// ExportModelGraph renders role inheritance and resource grouping from the
// current model. Grouping types named g are treated as role groups, g2 and
// other grouping definitions are retained as resource/group edges.
func (e *Enforcer) ExportModelGraph(format ModelGraphFormat) (string, error) {
	return RenderModelGraph(e.currentState().model, format)
}

// RenderModelGraph renders a model without mutating the enforcer.
func RenderModelGraph(m model.Model, format ModelGraphFormat) (string, error) {
	switch format {
	case ModelGraphMermaid, "":
		return renderMermaidGraph(m), nil
	case ModelGraphDOT:
		return renderDOTGraph(m), nil
	default:
		return "", fmt.Errorf("unsupported model graph format %q", format)
	}
}

func sortedGroupingTypes(m model.Model) []string {
	ptypes := make([]string, 0, len(m["g"]))
	for ptype := range m["g"] {
		ptypes = append(ptypes, ptype)
	}
	sort.Strings(ptypes)
	return ptypes
}

func renderMermaidGraph(m model.Model) string {
	var builder strings.Builder
	builder.WriteString("%% Casbin model ")
	builder.WriteString(modelDefinitionVersion(m))
	builder.WriteString("\nflowchart LR\n")
	nodeID := 0
	for _, ptype := range sortedGroupingTypes(m) {
		assertion := m["g"][ptype]
		label := "Resource groups (" + ptype + ")"
		if ptype == "g" {
			label = "Role inheritance (g)"
		}
		fmt.Fprintf(&builder, "  subgraph %s[%q]\n", mermaidID(ptype), label)

		direct := make([]int, 0, len(assertion.Policy))
		for i, rule := range assertion.Policy {
			if len(rule) >= 2 {
				direct = append(direct, i)
			}
		}
		sort.SliceStable(direct, func(i, j int) bool {
			return strings.Join(assertion.Policy[direct[i]], "\x00") <
				strings.Join(assertion.Policy[direct[j]], "\x00")
		})
		for _, index := range direct {
			rule := assertion.Policy[index]
			nodeID++
			fromID := fmt.Sprintf("n%d", nodeID)
			nodeID++
			toID := fmt.Sprintf("n%d", nodeID)
			fmt.Fprintf(&builder, "    %s[%q] --> %s[%q]\n",
				fromID, rule[0], toID, rule[1])
		}
		builder.WriteString("  end\n")
	}
	return builder.String()
}

func renderDOTGraph(m model.Model) string {
	var builder strings.Builder
	builder.WriteString("digraph casbin_model {\n")
	builder.WriteString("  rankdir=LR;\n")
	nodeID := 0
	for _, ptype := range sortedGroupingTypes(m) {
		assertion := m["g"][ptype]
		label := "Resource groups (" + ptype + ")"
		if ptype == "g" {
			label = "Role inheritance (g)"
		}
		fmt.Fprintf(&builder, "  subgraph cluster_%s {\n", dotID(ptype))
		fmt.Fprintf(&builder, "    label=%q;\n", label)

		direct := make([]int, 0, len(assertion.Policy))
		for i, rule := range assertion.Policy {
			if len(rule) >= 2 {
				direct = append(direct, i)
			}
		}
		sort.SliceStable(direct, func(i, j int) bool {
			return strings.Join(assertion.Policy[direct[i]], "\x00") <
				strings.Join(assertion.Policy[direct[j]], "\x00")
		})
		for _, index := range direct {
			rule := assertion.Policy[index]
			nodeID++
			fromID := fmt.Sprintf("n%d", nodeID)
			nodeID++
			toID := fmt.Sprintf("n%d", nodeID)
			fmt.Fprintf(&builder, "    %s [label=%q];\n", fromID, rule[0])
			fmt.Fprintf(&builder, "    %s [label=%q];\n", toID, rule[1])
			fmt.Fprintf(&builder, "    %s -> %s;\n", fromID, toID)
		}
		builder.WriteString("  }\n")
	}
	builder.WriteString("}\n")
	return builder.String()
}

func mermaidID(value string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_", ":", "_")
	return "g_" + replacer.Replace(value)
}

func dotID(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	return builder.String()
}
