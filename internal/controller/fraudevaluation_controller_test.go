// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
	"go.miloapis.com/fraud/internal/provider"
)

// mockProvider is a test implementation of provider.Provider.
type mockProvider struct {
	name   string
	result provider.Result
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Evaluate(_ context.Context, _ provider.Input) provider.Result {
	return m.result
}

var _ = Describe("FraudEvaluation Controller", func() {
	ctx := context.Background()

	Context("Full pipeline evaluation", func() {
		var (
			reconciler *FraudEvaluationReconciler
			registry   *provider.Registry
			policyName string
			provName   string
		)

		BeforeEach(func() {
			provName = "maxmind-test"
			policyName = "test-policy"
			registry = provider.NewRegistry()
		})

		AfterEach(func() {
			// Clean up all resources. Ignore not-found errors.
			evalList := &fraudv1alpha1.FraudEvaluationList{}
			Expect(k8sClient.List(ctx, evalList)).To(Succeed())
			for i := range evalList.Items {
				_ = k8sClient.Delete(ctx, &evalList.Items[i])
			}

			policyList := &fraudv1alpha1.FraudPolicyList{}
			Expect(k8sClient.List(ctx, policyList)).To(Succeed())
			for i := range policyList.Items {
				_ = k8sClient.Delete(ctx, &policyList.Items[i])
			}

			providerList := &fraudv1alpha1.FraudProviderList{}
			Expect(k8sClient.List(ctx, providerList)).To(Succeed())
			for i := range providerList.Items {
				_ = k8sClient.Delete(ctx, &providerList.Items[i])
			}

			deactivationList := &iamv1alpha1.PlatformAccessList{}
			Expect(k8sClient.List(ctx, deactivationList)).To(Succeed())
			for i := range deactivationList.Items {
				_ = k8sClient.Delete(ctx, &deactivationList.Items[i])
			}

			approvalList := &iamv1alpha1.PlatformAccessList{}
			Expect(k8sClient.List(ctx, approvalList)).To(Succeed())
			for i := range approvalList.Items {
				_ = k8sClient.Delete(ctx, &approvalList.Items[i])
			}

			rejectionList := &iamv1alpha1.PlatformAccessList{}
			Expect(k8sClient.List(ctx, rejectionList)).To(Succeed())
			for i := range rejectionList.Items {
				_ = k8sClient.Delete(ctx, &rejectionList.Items[i])
			}
		})

		createResources := func(score float64, failurePolicy string, mode string) {
			// Create FraudProvider CR.
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: failurePolicy,
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			// Create FraudPolicy CR.
			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "risk-analysis",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
								{MinScore: 90, Action: "DEACTIVATE"},
							},
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: mode},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Register the mock provider in the registry under the CR name.
			registry.Register(provName, &mockProvider{
				name:   "maxmind",
				result: provider.Result{Score: score, RawResponse: `{"risk_score": 50}`},
			})

			// Set up reconciler with the registry.
			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}
		}

		It("should complete with ACCEPTED decision for low score", func() {
			createResources(15, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-low"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-1"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-low"},
			})
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch to see status.
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-low"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.CompositeScore).To(Equal("15.00"))
			Expect(eval.Status.Decision).To(Equal("ACCEPTED"))
			Expect(eval.Status.EnforcementAction).To(Equal("OBSERVED"))
			Expect(eval.Status.StageResults).To(HaveLen(1))
			Expect(eval.Status.StageResults[0].ProviderResults).To(HaveLen(1))
			Expect(eval.Status.StageResults[0].ProviderResults[0].Score).To(Equal("15.00"))
			Expect(eval.Status.History).To(HaveLen(1))
		})

		It("should trigger REVIEW for score above 70", func() {
			createResources(75, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-review"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-2"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-review"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-review"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.CompositeScore).To(Equal("75.00"))
			Expect(eval.Status.Decision).To(Equal("REVIEW"))
			Expect(eval.Status.EnforcementAction).To(Equal("OBSERVED"))
		})

		It("should trigger DEACTIVATE for score above 90 and create UserDeactivation", func() {
			createResources(95, "FailOpen", "AUTO")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-deactivate"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-3"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-deactivate"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-deactivate"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal(fraudv1alpha1.PhaseCompleted))
			Expect(eval.Status.Decision).To(Equal(fraudv1alpha1.DecisionDeactivate))
			Expect(eval.Status.EnforcementAction).To(Equal("ENFORCED"))

			// Verify the PlatformAccess resource was created.
			deactivation := &iamv1alpha1.PlatformAccess{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "user-3"}, deactivation)).To(Succeed())
			Expect(deactivation.Spec.UserRef.Name).To(Equal("user-3"))
			Expect(deactivation.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateSuspended))
			Expect(deactivation.Spec.Reason).To(ContainSubstring("Automated deactivation from FraudEvaluation"))

			// Verify EnforcementApplied condition is set.
			Expect(eval.Status.Conditions).To(ContainElement(
				HaveField("Type", conditionEnforcementApplied),
			))
		})

		It("should use OBSERVED enforcement in OBSERVE mode even for high scores", func() {
			createResources(95, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-observe"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-4"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-observe"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-observe"}, eval)).To(Succeed())
			Expect(eval.Status.Decision).To(Equal("DEACTIVATE"))
			Expect(eval.Status.EnforcementAction).To(Equal("OBSERVED"))
		})

		It("should handle provider failure with FailOpen", func() {
			// Create resources but use an error-returning provider.
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailOpen",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "risk-analysis",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
							},
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			registry.Register(provName, &mockProvider{
				name: "maxmind",
				result: provider.Result{
					Error: fmt.Errorf("connection refused"),
				},
			})

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-failopen"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-5"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-failopen"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-failopen"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.CompositeScore).To(Equal("0.00"))
			Expect(eval.Status.Decision).To(Equal("ACCEPTED"))
			Expect(eval.Status.StageResults[0].ProviderResults[0].Error).To(ContainSubstring("connection refused"))
			Expect(eval.Status.StageResults[0].ProviderResults[0].FailurePolicyApplied).To(Equal("FailOpen"))
		})

		It("should set Error phase on provider failure with FailClosed", func() {
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailClosed",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "risk-analysis",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
							},
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			registry.Register(provName, &mockProvider{
				name: "maxmind",
				result: provider.Result{
					Error: fmt.Errorf("connection refused"),
				},
			})

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-failclosed"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-6"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-failclosed"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-failclosed"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Error"))
		})

		It("should skip stages when short-circuit is active", func() {
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailOpen",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			// Two stages: first with short-circuit at 30, second is not required.
			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "stage-1",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
							},
							ShortCircuit: &fraudv1alpha1.ShortCircuitConfig{
								SkipWhenBelow: 30,
							},
						},
						{
							Name: "stage-2",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 80, Action: "DEACTIVATE"},
							},
							Required: false,
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Score of 10 is below short-circuit threshold of 30.
			registry.Register(provName, &mockProvider{
				name:   "maxmind",
				result: provider.Result{Score: 10},
			})

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-shortcircuit"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-7"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-shortcircuit"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-shortcircuit"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.StageResults).To(HaveLen(2))
			Expect(eval.Status.StageResults[0].Skipped).To(BeFalse())
			Expect(eval.Status.StageResults[1].Skipped).To(BeTrue())
		})

		It("should not skip required stages even when short-circuit is active", func() {
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailOpen",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "stage-1",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
							},
							ShortCircuit: &fraudv1alpha1.ShortCircuitConfig{
								SkipWhenBelow: 30,
							},
						},
						{
							Name: "stage-2-required",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 80, Action: "DEACTIVATE"},
							},
							Required: true,
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			registry.Register(provName, &mockProvider{
				name:   "maxmind",
				result: provider.Result{Score: 10},
			})

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-required"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-8"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-required"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-required"}, eval)).To(Succeed())
			Expect(eval.Status.StageResults).To(HaveLen(2))
			Expect(eval.Status.StageResults[0].Skipped).To(BeFalse())
			Expect(eval.Status.StageResults[1].Skipped).To(BeFalse())
		})

		It("should not re-process completed evaluations", func() {
			createResources(50, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-completed"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-9"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			// First reconcile: should complete.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-completed"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-completed"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))

			// Second reconcile: should be a no-op.
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-completed"},
			})
			Expect(err).NotTo(HaveOccurred())

			// History should still have only 1 entry.
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-completed"}, eval)).To(Succeed())
			Expect(eval.Status.History).To(HaveLen(1))
		})

		It("AUTO mode REVIEW decision should defer enforcement, creating a PlatformAccess with Pending state", func() {
			createResources(75, "FailOpen", "AUTO")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-review-auto"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-review"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-review-auto"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-review-auto"}, eval)).To(Succeed())
			Expect(eval.Status.Decision).To(Equal(fraudv1alpha1.DecisionReview))

			// Verify PlatformAccess with Pending state is created.
			pa := &iamv1alpha1.PlatformAccess{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "user-review"}, pa)).To(Succeed())
			Expect(pa.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStatePending))

			// EnforcementApplied condition should reflect the deferral.
			cond := meta.FindStatusCondition(eval.Status.Conditions, conditionEnforcementApplied)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("ReviewRequired"))
		})

		It("AUTO mode ACCEPTED decision should create PlatformAccessApproval", func() {
			createResources(15, "FailOpen", "AUTO")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-accepted-auto"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-accepted"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-accepted-auto"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-accepted-auto"}, eval)).To(Succeed())
			Expect(eval.Status.Decision).To(Equal(fraudv1alpha1.DecisionAccepted))

			approval := &iamv1alpha1.PlatformAccess{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "user-accepted"}, approval)).To(Succeed())
			Expect(approval.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateApproved))
			Expect(approval.Spec.UserRef.Name).To(Equal("user-accepted"))
		})

		It("OBSERVE mode should approve the user and not create any deactivation resources", func() {
			createResources(95, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-observe-noiam"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-observe"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-observe-noiam"},
			})
			Expect(err).NotTo(HaveOccurred())

			// A PlatformAccess should be created with state Approved.
			approval := &iamv1alpha1.PlatformAccess{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "user-observe"}, approval)).To(Succeed())
			Expect(approval.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateApproved))
			Expect(approval.Annotations).To(HaveKeyWithValue("fraud.miloapis.com/observe-mode", "true"))
			Expect(approval.Annotations).To(HaveKeyWithValue("fraud.miloapis.com/observed-decision", fraudv1alpha1.DecisionDeactivate))

			// EnforcementApplied condition should be set with ObserveMode reason.
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-observe-noiam"}, eval)).To(Succeed())
			cond := meta.FindStatusCondition(eval.Status.Conditions, conditionEnforcementApplied)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Reason).To(Equal("ObserveMode"))
		})

		It("enforcement should be idempotent on repeated reconciles", func() {
			createResources(95, "FailOpen", "AUTO")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-idempotent"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-idempotent"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "eval-idempotent"}}

			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile should also succeed without error (AlreadyExists is handled).
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			// Still only one UserDeactivation.
			deactivationList := &iamv1alpha1.PlatformAccessList{}
			Expect(k8sClient.List(ctx, deactivationList)).To(Succeed())
			Expect(deactivationList.Items).To(HaveLen(1))
		})

		It("should not create a duplicate PlatformAccessApproval on re-reconcile", func() {
			createResources(15, "FailOpen", "AUTO")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-paa-idem"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-paa-idem"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "eval-paa-idem"}}

			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile: EnforcementApplied short-circuits; no second create attempted.
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			paaList := &iamv1alpha1.PlatformAccessList{}
			Expect(k8sClient.List(ctx, paaList)).To(Succeed())
			Expect(paaList.Items).To(HaveLen(1))
		})

		It("should update PlatformAccess if user already has an approval from a prior evaluation", func() {
			createResources(15, "FailOpen", "AUTO")

			prior := &iamv1alpha1.PlatformAccess{
				ObjectMeta: metav1.ObjectMeta{Name: "user-preapproved"},
				Spec: iamv1alpha1.PlatformAccessSpec{
					UserRef: iamv1alpha1.UserReference{Name: "user-preapproved"},
					State:   iamv1alpha1.PlatformAccessStateApproved,
					Reason:  "prior-reason",
				},
			}
			Expect(k8sClient.Create(ctx, prior)).To(Succeed())

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-preapproved"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-preapproved"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-preapproved"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-preapproved"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal(fraudv1alpha1.PhaseCompleted))
			Expect(eval.Status.Decision).To(Equal(fraudv1alpha1.DecisionAccepted))

			pa := &iamv1alpha1.PlatformAccess{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "user-preapproved"}, pa)).To(Succeed())
			Expect(pa.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateApproved))
			Expect(pa.Spec.Reason).To(ContainSubstring("Automated approval from FraudEvaluation \"eval-preapproved\""))

			// Only one PlatformAccess should be present.
			paList := &iamv1alpha1.PlatformAccessList{}
			Expect(k8sClient.List(ctx, paList)).To(Succeed())
			Expect(paList.Items).To(HaveLen(1))

			// EnforcementApplied condition should still be set.
			cond := meta.FindStatusCondition(eval.Status.Conditions, conditionEnforcementApplied)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		})

		It("should update PlatformAccess to Approved even if user already has a PlatformAccess rejection", func() {
			createResources(15, "FailOpen", "AUTO")

			prior := &iamv1alpha1.PlatformAccess{
				ObjectMeta: metav1.ObjectMeta{Name: "user-prerejected"},
				Spec: iamv1alpha1.PlatformAccessSpec{
					UserRef: iamv1alpha1.UserReference{Name: "user-prerejected"},
					State:   iamv1alpha1.PlatformAccessStateRejected,
					Reason:  "prior-rejection",
				},
			}
			Expect(k8sClient.Create(ctx, prior)).To(Succeed())

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-prerejected"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-prerejected"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-prerejected"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-prerejected"}, eval)).To(Succeed())
			Expect(eval.Status.Decision).To(Equal(fraudv1alpha1.DecisionAccepted))

			// The PlatformAccess should be updated to Approved.
			pa := &iamv1alpha1.PlatformAccess{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "user-prerejected"}, pa)).To(Succeed())
			Expect(pa.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateApproved))

			// EnforcementApplied condition should be set with EnforcementApplied reason.
			cond := meta.FindStatusCondition(eval.Status.Conditions, conditionEnforcementApplied)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("EnforcementApplied"))
		})

		// Regression: in prod we observed evaluations stuck with status.decision=ACCEPTED
		// but EnforcementApplied=True with reason="SkippedUnknownDecision" and
		// message=`unrecognised decision ""`. Same reconcileID logged "evaluation
		// completed decision: ACCEPTED" then immediately "skipping enforcement for
		// unrecognised decision decision: ''". Root cause: Reconcile re-fetches the
		// eval via the cached client after Status().Update, the cache hasn't seen
		// the update yet, the stale read has decision="", applyEnforcement's default
		// branch sets EnforcementApplied=True permanently, and the short-circuit at
		// the top of applyEnforcement blocks any future retry.
		//
		// This test exercises the same observable state by calling applyEnforcement
		// directly with an eval whose status.decision is empty. With the fix
		// (default branch returns without setting the condition when decision==""),
		// no PAA is created and no terminal condition is set, so the next reconcile
		// can recover. Without the fix, the eval is permanently locked.
		It("should not permanently lock an eval when applyEnforcement is called with an empty decision (cache-lag race regression)", func() {
			createResources(15, "FailOpen", "AUTO")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-empty-decision"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-empty-decision"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			// Storage state: pipeline already ran, decision is ACCEPTED, phase is
			// Completed. This is what the API server would have after the
			// Status().Update at fraudevaluation_controller.go:187.
			eval.Status.Phase = fraudv1alpha1.PhaseCompleted
			eval.Status.Decision = fraudv1alpha1.DecisionAccepted
			eval.Status.EnforcementAction = "ENFORCED"
			Expect(k8sClient.Status().Update(ctx, eval)).To(Succeed())

			var policy fraudv1alpha1.FraudPolicy
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, &policy)).To(Succeed())

			// Stale snapshot: this is what r.Get returns from the cache before
			// the watch event for the Update above has been delivered. Same name
			// (so the patch in setEnforcementAppliedCondition targets the live
			// object) but decision="".
			stale := eval.DeepCopy()
			stale.Status.Decision = ""

			_, err := reconciler.applyEnforcement(ctx, stale, &policy)
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch the live object: it should NOT have been permanently
			// marked EnforcementApplied=SkippedUnknownDecision based on the
			// stale empty decision.
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-empty-decision"}, eval)).To(Succeed())
			cond := meta.FindStatusCondition(eval.Status.Conditions, conditionEnforcementApplied)
			if cond != nil {
				Expect(cond.Reason).NotTo(Equal("SkippedUnknownDecision"),
					"applyEnforcement must not lock the eval with SkippedUnknownDecision when decision is empty — that prevents the next reconcile (which sees the real ACCEPTED decision) from creating the PAA")
			}
		})

		It("should set Error phase when provider is not registered", func() {
			// Create resources but do NOT register anything in the registry.
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailOpen",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "risk-analysis",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
							},
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry, // empty registry
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-no-provider"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-10"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-no-provider"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-no-provider"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Error"))
		})

		// completedEval creates a FraudEvaluation that has already been through the
		// pipeline, which is the state the ~266 evaluations enforced before risk
		// assessments existed are in when the controller restarts.
		completedEval := func(name, user, score, decision string, evaluatedAt time.Time, enforced bool) *fraudv1alpha1.FraudEvaluation {
			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: user},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			at := metav1.NewTime(evaluatedAt)
			eval.Status.Phase = fraudv1alpha1.PhaseCompleted
			eval.Status.CompositeScore = score
			eval.Status.Decision = decision
			eval.Status.EnforcementAction = fraudv1alpha1.EnforcementActionEnforced
			eval.Status.LastEvaluationTime = &at
			if enforced {
				meta.SetStatusCondition(&eval.Status.Conditions, metav1.Condition{
					Type:    conditionEnforcementApplied,
					Status:  metav1.ConditionTrue,
					Reason:  "EnforcementApplied",
					Message: "applied before risk assessments existed",
				})
			}
			Expect(k8sClient.Status().Update(ctx, eval)).To(Succeed())

			return eval
		}

		existingAccess := func(user string, state iamv1alpha1.PlatformAccessState, reason string, assessment *iamv1alpha1.RiskAssessment) *iamv1alpha1.PlatformAccess {
			pa := &iamv1alpha1.PlatformAccess{
				ObjectMeta: metav1.ObjectMeta{Name: user},
				Spec: iamv1alpha1.PlatformAccessSpec{
					UserRef:        iamv1alpha1.UserReference{Name: user},
					State:          state,
					Reason:         reason,
					RiskAssessment: assessment,
				},
			}
			Expect(k8sClient.Create(ctx, pa)).To(Succeed())

			return pa
		}

		reconcileEval := func(name string) {
			res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
			Expect(err).NotTo(HaveOccurred())
			Expect(res).To(Equal(reconcile.Result{}), "the risk assessment sync must never requeue")
		}

		getAccess := func(user string) *iamv1alpha1.PlatformAccess {
			pa := &iamv1alpha1.PlatformAccess{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: user}, pa)).To(Succeed())

			return pa
		}

		evalTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

		It("enforcement that creates the PlatformAccess includes the risk assessment", func() {
			createResources(15, "FailOpen", "AUTO")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-ra-create"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-ra-create"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())
			reconcileEval("eval-ra-create")

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-ra-create"}, eval)).To(Succeed())
			pa := getAccess("user-ra-create")
			Expect(pa.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateApproved))
			Expect(pa.Spec.RiskAssessment).NotTo(BeNil())
			Expect(pa.Spec.RiskAssessment.Score).To(Equal(eval.Status.CompositeScore))
			Expect(pa.Spec.RiskAssessment.Score).To(Equal("15.00"))
			Expect(pa.Spec.RiskAssessment.Decision).To(Equal(fraudv1alpha1.DecisionAccepted))
			Expect(pa.Spec.RiskAssessment.EvaluationName).To(Equal("eval-ra-create"))
			Expect(pa.Spec.RiskAssessment.EvaluatedAt).NotTo(BeNil())
			Expect(pa.Spec.RiskAssessment.EvaluatedAt.Equal(eval.Status.LastEvaluationTime)).To(BeTrue())
		})

		It("enforcement that patches an existing PlatformAccess includes the risk assessment", func() {
			createResources(95, "FailOpen", "AUTO")
			existingAccess("user-ra-patch", iamv1alpha1.PlatformAccessStateApproved, "prior-reason", nil)

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-ra-patch"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-ra-patch"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())
			reconcileEval("eval-ra-patch")

			pa := getAccess("user-ra-patch")
			Expect(pa.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateSuspended))
			Expect(pa.Spec.RiskAssessment).NotTo(BeNil())
			Expect(pa.Spec.RiskAssessment.Score).To(Equal("95.00"))
			Expect(pa.Spec.RiskAssessment.Decision).To(Equal(fraudv1alpha1.DecisionDeactivate))
			Expect(pa.Spec.RiskAssessment.EvaluationName).To(Equal("eval-ra-patch"))
		})

		It("backfills an already-enforced evaluation without touching state or reason", func() {
			createResources(15, "FailOpen", "AUTO")
			// An admin has since overridden the automated decision.
			existingAccess("user-ra-backfill", iamv1alpha1.PlatformAccessStateRejected, "rejected by staff", nil)
			completedEval("eval-ra-backfill", "user-ra-backfill", testLowScore, fraudv1alpha1.DecisionAccepted, evalTime, true)

			reconcileEval("eval-ra-backfill")

			pa := getAccess("user-ra-backfill")
			Expect(pa.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateRejected))
			Expect(pa.Spec.Reason).To(Equal("rejected by staff"))
			Expect(pa.Spec.RiskAssessment).NotTo(BeNil())
			Expect(pa.Spec.RiskAssessment.Score).To(Equal(testLowScore), "score is copied as-is, never rescaled")
			Expect(pa.Spec.RiskAssessment.Decision).To(Equal(fraudv1alpha1.DecisionAccepted))
			Expect(pa.Spec.RiskAssessment.EvaluationName).To(Equal("eval-ra-backfill"))
			Expect(pa.Spec.RiskAssessment.EvaluatedAt.Time.Equal(evalTime)).To(BeTrue())
		})

		It("backfills even when the referenced policy no longer exists", func() {
			// No createResources: the policy is missing, which makes the
			// enforcement path return an error. The sync runs before that.
			reconciler = &FraudEvaluationReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), Registry: registry}
			existingAccess("user-ra-nopolicy", iamv1alpha1.PlatformAccessStateApproved, "approved", nil)
			completedEval("eval-ra-nopolicy", "user-ra-nopolicy", "0.20", fraudv1alpha1.DecisionAccepted, evalTime, true)

			// The missing policy still fails the reconcile, as it did before;
			// the assessment must have been written regardless.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "eval-ra-nopolicy"}})
			Expect(err).To(HaveOccurred())

			pa := getAccess("user-ra-nopolicy")
			Expect(pa.Spec.RiskAssessment).NotTo(BeNil())
			Expect(pa.Spec.RiskAssessment.EvaluationName).To(Equal("eval-ra-nopolicy"))
		})

		It("still enforces, and returns the error, when the summary patch fails", func() {
			createResources(15, "FailOpen", "AUTO")
			existingAccess("user-ra-patchfail", iamv1alpha1.PlatformAccessStateRejected, "pending", nil)
			completedEval("eval-ra-patchfail", "user-ra-patchfail", testLowScore, fraudv1alpha1.DecisionAccepted, evalTime, false)

			// Fail only the first PlatformAccess patch, which is the summary sync.
			failed := false
			watchClient, err := client.NewWithWatch(cfg, client.Options{Scheme: k8sClient.Scheme()})
			Expect(err).NotTo(HaveOccurred())
			reconciler.Client = interceptor.NewClient(watchClient, interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					if _, ok := obj.(*iamv1alpha1.PlatformAccess); ok && !failed {
						failed = true
						return fmt.Errorf("injected patch failure")
					}

					return c.Patch(ctx, obj, patch, opts...)
				},
			})

			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "eval-ra-patchfail"}})
			Expect(err).To(MatchError(ContainSubstring("injected patch failure")), "sync error must still surface so the backfill retries")
			Expect(failed).To(BeTrue())

			pa := getAccess("user-ra-patchfail")
			Expect(pa.Spec.State).To(Equal(iamv1alpha1.PlatformAccessStateApproved), "enforcement must not wait on the sync")

			eval := &fraudv1alpha1.FraudEvaluation{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-ra-patchfail"}, eval)).To(Succeed())
			Expect(meta.FindStatusCondition(eval.Status.Conditions, conditionEnforcementApplied)).NotTo(BeNil())
		})

		It("does not create a PlatformAccess when backfilling", func() {
			createResources(15, "FailOpen", "AUTO")
			completedEval("eval-ra-missing", "user-ra-missing", testLowScore, fraudv1alpha1.DecisionAccepted, evalTime, true)

			reconcileEval("eval-ra-missing")

			pa := &iamv1alpha1.PlatformAccess{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: "user-ra-missing"}, pa)
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "expected no PlatformAccess, got err=%v", err)
		})

		It("does not let an older evaluation overwrite a newer assessment", func() {
			createResources(15, "FailOpen", "AUTO")
			newer := metav1.NewTime(evalTime.Add(time.Hour))
			existingAccess("user-ra-newer", iamv1alpha1.PlatformAccessStateApproved, "approved", &iamv1alpha1.RiskAssessment{
				Score: "0.05", Decision: fraudv1alpha1.DecisionAccepted, EvaluatedAt: &newer, EvaluationName: "eval-ra-newest",
			})
			completedEval("eval-ra-older", "user-ra-newer", "0.90", fraudv1alpha1.DecisionReview, evalTime, true)

			reconcileEval("eval-ra-older")

			pa := getAccess("user-ra-newer")
			Expect(pa.Spec.RiskAssessment.EvaluationName).To(Equal("eval-ra-newest"))
			Expect(pa.Spec.RiskAssessment.Score).To(Equal("0.05"))
		})

		It("replaces an older assessment with a newer evaluation", func() {
			createResources(15, "FailOpen", "AUTO")
			older := metav1.NewTime(evalTime.Add(-time.Hour))
			existingAccess("user-ra-older", iamv1alpha1.PlatformAccessStateApproved, "approved", &iamv1alpha1.RiskAssessment{
				Score: "0.05", Decision: fraudv1alpha1.DecisionAccepted, EvaluatedAt: &older, EvaluationName: "eval-ra-stale",
			})
			completedEval("eval-ra-fresh", "user-ra-older", "0.30", fraudv1alpha1.DecisionReview, evalTime, true)

			reconcileEval("eval-ra-fresh")

			pa := getAccess("user-ra-older")
			Expect(pa.Spec.RiskAssessment.EvaluationName).To(Equal("eval-ra-fresh"))
			Expect(pa.Spec.RiskAssessment.Score).To(Equal("0.30"))
			Expect(pa.Spec.RiskAssessment.Decision).To(Equal(fraudv1alpha1.DecisionReview))
		})

		It("does not write when the assessment is already current", func() {
			createResources(15, "FailOpen", "AUTO")
			at := metav1.NewTime(evalTime)
			existingAccess("user-ra-equal", iamv1alpha1.PlatformAccessStateApproved, "approved", &iamv1alpha1.RiskAssessment{
				Score: testLowScore, Decision: fraudv1alpha1.DecisionAccepted, EvaluatedAt: &at, EvaluationName: "eval-ra-equal",
			})
			completedEval("eval-ra-equal", "user-ra-equal", testLowScore, fraudv1alpha1.DecisionAccepted, evalTime, true)
			before := getAccess("user-ra-equal").ResourceVersion

			reconcileEval("eval-ra-equal")
			reconcileEval("eval-ra-equal")

			Expect(getAccess("user-ra-equal").ResourceVersion).To(Equal(before))
		})
	})
})
