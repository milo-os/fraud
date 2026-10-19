// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
)

// riskAssessmentFor summarizes a completed evaluation for PlatformAccess.spec.riskAssessment,
// which milo copies onto User.status so user lists carry the latest score without reading
// every evaluation. It returns nil when the evaluation has nothing to summarize yet.
func riskAssessmentFor(eval *fraudv1alpha1.FraudEvaluation) *iamv1alpha1.RiskAssessment {
	if eval.Status.Phase != fraudv1alpha1.PhaseCompleted ||
		eval.Status.Decision == "" ||
		eval.Status.LastEvaluationTime == nil {
		return nil
	}

	// The API server stores times at second precision. Truncating here keeps the
	// in-memory value written right after a pipeline run identical to the one read
	// back later, so the sync sees them as equal instead of patching again.
	evaluatedAt := metav1.NewTime(eval.Status.LastEvaluationTime.Rfc3339Copy().Time)

	return &iamv1alpha1.RiskAssessment{
		// Copied as-is: the composite score is already a decimal string.
		Score:          eval.Status.CompositeScore,
		Decision:       eval.Status.Decision,
		EvaluatedAt:    &evaluatedAt,
		EvaluationName: eval.Name,
	}
}

// riskAssessmentShouldReplace reports whether desired should overwrite existing. The
// newer evaluation wins so that evaluations reconciled out of order cannot roll the
// summary back. Two evaluations from the same second are ordered by name so they never
// take turns overwriting each other across resyncs.
func riskAssessmentShouldReplace(existing, desired *iamv1alpha1.RiskAssessment) bool {
	switch {
	case desired == nil:
		return false
	case existing == nil:
		return true
	case desired.EvaluatedAt == nil:
		// Without a time the desired value cannot be shown to be newer than
		// anything already recorded.
		return false
	case existing.EvaluatedAt == nil:
		return true
	}

	existingAt := existing.EvaluatedAt.Rfc3339Copy()
	desiredAt := desired.EvaluatedAt.Rfc3339Copy()

	switch {
	case existingAt.Before(&desiredAt):
		return true
	case desiredAt.Before(&existingAt):
		return false
	case existing.EvaluationName != desired.EvaluationName:
		return desired.EvaluationName > existing.EvaluationName
	default:
		return !equality.Semantic.DeepEqual(existing, desired)
	}
}

// syncRiskAssessment records a completed evaluation's risk assessment on the user's
// existing PlatformAccess. It runs on every reconcile of a completed evaluation,
// independent of whether enforcement has already been applied, which is how
// evaluations enforced before this field existed get backfilled when the controller
// starts. It never creates a PlatformAccess, since that would change the user's
// access, and it patches only spec.riskAssessment so state and reason set by staff
// are left alone. It is a no-op when the recorded assessment is already current.
func (r *FraudEvaluationReconciler) syncRiskAssessment(ctx context.Context, eval *fraudv1alpha1.FraudEvaluation) error {
	desired := riskAssessmentFor(eval)
	if desired == nil {
		return nil
	}

	userName := eval.Spec.UserRef.Name

	var pa iamv1alpha1.PlatformAccess
	if err := r.Get(ctx, types.NamespacedName{Name: userName}, &pa); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get PlatformAccess for user %q: %w", userName, err)
	}

	if !riskAssessmentShouldReplace(pa.Spec.RiskAssessment, desired) {
		return nil
	}

	base := pa.DeepCopy()
	pa.Spec.RiskAssessment = desired
	if err := r.Patch(ctx, &pa, client.MergeFrom(base), client.FieldOwner(controllerFieldOwner)); err != nil {
		return fmt.Errorf("failed to patch risk assessment on PlatformAccess for user %q: %w", userName, err)
	}

	logf.FromContext(ctx).Info("PlatformAccess risk assessment updated",
		"user", userName, "score", desired.Score, "decision", desired.Decision)

	return nil
}
