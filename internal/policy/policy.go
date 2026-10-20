package policy

import (
	"fmt"
	"strings"
)

type DecisionKind string

const (
	DecisionDeny     DecisionKind = "deny"
	DecisionAllow    DecisionKind = "allow"
	DecisionApproval DecisionKind = "approval_required"
)

type Request struct {
	Who      string
	Provider string
	Profile  string
}

type Rule struct {
	Effect   string
	Who      string
	Provider string
	Profile  string
	Approval string
}

type Policy struct {
	Version int
	Rules   []Rule
}

type Decision struct {
	Kind     DecisionKind
	Approval string
	Reason   string
}

// Validate rejects unsupported or ambiguous policy data.
func Validate(p Policy) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}

	for i, rule := range p.Rules {
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return fmt.Errorf("rule %d: effect must be allow or deny", i)
		}
		if strings.TrimSpace(rule.Who) == "" {
			return fmt.Errorf("rule %d: who is required", i)
		}
		if strings.TrimSpace(rule.Provider) == "" || rule.Provider == "*" {
			return fmt.Errorf("rule %d: a specific provider is required", i)
		}
		if rule.Approval != "" &&
			rule.Approval != "none" &&
			rule.Approval != "session" &&
			rule.Approval != "each" {
			return fmt.Errorf("rule %d: invalid approval mode", i)
		}
		if rule.Effect == "deny" && rule.Approval != "" {
			return fmt.Errorf("rule %d: deny rules cannot set approval", i)
		}
		if rule.Effect == "allow" && rule.Approval == "" {
			return fmt.Errorf("rule %d: allow rules must set approval", i)
		}
	}

	return nil
}

// Evaluate returns a decision for a trusted caller classification and request.
// Caller identity must be obtained by the platform layer, not from client input.
func Evaluate(p Policy, req Request) Decision {
	if err := Validate(p); err != nil {
		return Decision{Kind: DecisionDeny, Reason: "invalid policy: " + err.Error()}
	}
	if strings.TrimSpace(req.Who) == "" || strings.TrimSpace(req.Provider) == "" {
		return Decision{Kind: DecisionDeny, Reason: "incomplete request identity"}
	}

	for _, rule := range p.Rules {
		if rule.Effect == "deny" && matches(rule, req) {
			return Decision{Kind: DecisionDeny, Reason: "matched deny rule"}
		}
	}

	for _, rule := range p.Rules {
		if rule.Effect == "allow" && matches(rule, req) {
			if rule.Approval == "none" {
				return Decision{Kind: DecisionAllow, Reason: "matched allow rule"}
			}
			return Decision{
				Kind:     DecisionApproval,
				Approval: rule.Approval,
				Reason:   "matched allow rule; approval required",
			}
		}
	}

	return Decision{Kind: DecisionDeny, Reason: "no matching allow rule"}
}

func matches(rule Rule, req Request) bool {
	return (rule.Who == "*" || rule.Who == req.Who) &&
		rule.Provider == req.Provider &&
		(rule.Profile == "*" || rule.Profile == req.Profile)
}
