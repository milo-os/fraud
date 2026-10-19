// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
)

// testLowScore is a composite score string shared by the risk assessment tests.
const testLowScore = "0.10"

func TestRiskAssessmentFor(t *testing.T) {
	at := metav1.NewTime(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	// Sub-second precision is lost when the time round-trips through the API
	// server, so it must not take part in comparisons.
	precise := metav1.NewTime(at.Add(250 * time.Millisecond))

	tests := []struct {
		name   string
		status fraudv1alpha1.FraudEvaluationStatus
		want   *iamv1alpha1.RiskAssessment
	}{
		{
			name: "completed evaluation",
			status: fraudv1alpha1.FraudEvaluationStatus{
				Phase: fraudv1alpha1.PhaseCompleted, CompositeScore: testLowScore,
				Decision: fraudv1alpha1.DecisionAccepted, LastEvaluationTime: &precise,
			},
			want: &iamv1alpha1.RiskAssessment{
				Score: testLowScore, Decision: fraudv1alpha1.DecisionAccepted, EvaluatedAt: &at, EvaluationName: "eval-a",
			},
		},
		{
			name: "not completed",
			status: fraudv1alpha1.FraudEvaluationStatus{
				Phase: fraudv1alpha1.PhaseRunning, CompositeScore: testLowScore,
				Decision: fraudv1alpha1.DecisionAccepted, LastEvaluationTime: &at,
			},
		},
		{
			name: "no decision yet",
			status: fraudv1alpha1.FraudEvaluationStatus{
				Phase: fraudv1alpha1.PhaseCompleted, CompositeScore: testLowScore, LastEvaluationTime: &at,
			},
		},
		{
			name: "no evaluation time",
			status: fraudv1alpha1.FraudEvaluationStatus{
				Phase: fraudv1alpha1.PhaseCompleted, CompositeScore: testLowScore, Decision: fraudv1alpha1.DecisionAccepted,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval := &fraudv1alpha1.FraudEvaluation{ObjectMeta: metav1.ObjectMeta{Name: "eval-a"}, Status: tt.status}
			got := riskAssessmentFor(eval)

			if (got == nil) != (tt.want == nil) {
				t.Fatalf("riskAssessmentFor() = %+v, want %+v", got, tt.want)
			}
			if got == nil {
				return
			}
			if got.Score != tt.want.Score || got.Decision != tt.want.Decision ||
				got.EvaluationName != tt.want.EvaluationName || !got.EvaluatedAt.Equal(tt.want.EvaluatedAt) {
				t.Errorf("riskAssessmentFor() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRiskAssessmentShouldReplace(t *testing.T) {
	t0 := metav1.NewTime(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	t1 := metav1.NewTime(t0.Add(time.Minute))

	ra := func(name, score string, at *metav1.Time) *iamv1alpha1.RiskAssessment {
		return &iamv1alpha1.RiskAssessment{Score: score, Decision: fraudv1alpha1.DecisionAccepted, EvaluatedAt: at, EvaluationName: name}
	}

	tests := []struct {
		name     string
		existing *iamv1alpha1.RiskAssessment
		desired  *iamv1alpha1.RiskAssessment
		want     bool
	}{
		{name: "nothing to write", existing: ra("a", testLowScore, &t0), desired: nil, want: false},
		{name: "existing missing", existing: nil, desired: ra("a", testLowScore, &t0), want: true},
		{name: "existing has no time", existing: ra("a", testLowScore, nil), desired: ra("b", testLowScore, &t0), want: true},
		{name: "existing older", existing: ra("a", testLowScore, &t0), desired: ra("b", "0.20", &t1), want: true},
		{name: "existing newer", existing: ra("b", "0.20", &t1), desired: ra("a", testLowScore, &t0), want: false},
		{name: "identical", existing: ra("a", testLowScore, &t0), desired: ra("a", testLowScore, &t0), want: false},
		{name: "same evaluation, changed", existing: ra("a", testLowScore, &t0), desired: ra("a", "0.30", &t0), want: true},
		// Two evaluations finishing in the same second must not take turns
		// overwriting each other; the greater name wins deterministically.
		{name: "same time, greater name wins", existing: ra("a", testLowScore, &t0), desired: ra("b", "0.30", &t0), want: true},
		{name: "same time, lesser name loses", existing: ra("b", "0.30", &t0), desired: ra("a", testLowScore, &t0), want: false},
		{name: "desired has no time, existing has one", existing: ra("a", testLowScore, &t0), desired: ra("b", testLowScore, nil), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := riskAssessmentShouldReplace(tt.existing, tt.desired); got != tt.want {
				t.Errorf("riskAssessmentShouldReplace() = %v, want %v", got, tt.want)
			}
		})
	}
}
