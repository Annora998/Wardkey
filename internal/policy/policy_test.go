package policy

import "testing"

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name         string
		policy       Policy
		request      Request
		wantKind     DecisionKind
		wantApproval string
	}{
		{
			name:     "no matching rule denies",
			policy:   Policy{Version: 1},
			request:  Request{Who: "interactive", Provider: "aws", Profile: "dev"},
			wantKind: DecisionDeny,
		},
		{
			name: "none approval allows",
			policy: Policy{
				Version: 1,
				Rules: []Rule{{
					Effect: "allow", Who: "interactive",
					Provider: "aws", Profile: "dev", Approval: "none",
				}},
			},
			request:  Request{Who: "interactive", Provider: "aws", Profile: "dev"},
			wantKind: DecisionAllow,
		},
		{
			name: "session approval is required",
			policy: Policy{
				Version: 1,
				Rules: []Rule{{
					Effect: "allow", Who: "interactive",
					Provider: "aws", Profile: "*", Approval: "session",
				}},
			},
			request:      Request{Who: "interactive", Provider: "aws", Profile: "dev"},
			wantKind:     DecisionApproval,
			wantApproval: "session",
		},
		{
			name: "matching deny overrides allow",
			policy: Policy{
				Version: 1,
				Rules: []Rule{
					{Effect: "allow", Who: "*", Provider: "aws", Profile: "*", Approval: "none"},
					{Effect: "deny", Who: "installer", Provider: "aws", Profile: "*"},
				},
			},
			request:  Request{Who: "installer", Provider: "aws", Profile: "dev"},
			wantKind: DecisionDeny,
		},
		{
			name: "incomplete request denies",
			policy: Policy{
				Version: 1,
				Rules: []Rule{{
					Effect: "allow", Who: "*",
					Provider: "aws", Profile: "*", Approval: "none",
				}},
			},
			request:  Request{Provider: "aws", Profile: "dev"},
			wantKind: DecisionDeny,
		},
		{
			name: "invalid policy denies",
			policy: Policy{
				Version: 2,
				Rules: []Rule{{
					Effect: "allow", Who: "interactive",
					Provider: "aws", Profile: "dev", Approval: "none",
				}},
			},
			request:  Request{Who: "interactive", Provider: "aws", Profile: "dev"},
			wantKind: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.policy, tt.request)
			if got.Kind != tt.wantKind {
				t.Fatalf("Evaluate().Kind = %q, want %q (reason: %s)", got.Kind, tt.wantKind, got.Reason)
			}
			if got.Approval != tt.wantApproval {
				t.Errorf("Evaluate().Approval = %q, want %q", got.Approval, tt.wantApproval)
			}
		})
	}
}

func TestValidateRejectsWildcardProvider(t *testing.T) {
	p := Policy{
		Version: 1,
		Rules: []Rule{{
			Effect: "allow", Who: "*",
			Provider: "*", Profile: "*", Approval: "each",
		}},
	}

	if err := Validate(p); err == nil {
		t.Fatal("Validate() error = nil, want wildcard provider to be rejected")
	}
}
