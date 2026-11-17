/-
AttestFlow V4 concrete-to-abstract bridge model.

This file deliberately proves a typed abstract bridge only.  Cryptographic
verification, JSON decoding, process isolation, operating-system mediation,
and completeness of concrete event capture remain executable conformance
obligations outside this Lean model.
-/

namespace AttestFlowBridgeV4

inductive Decision where
  | allow
  | deny
  | indeterminate
deriving DecidableEq, Repr

inductive Verdict where
  | pass
  | fail
  | indeterminate
deriving DecidableEq, Repr

/-
The trace-only checker receives exactly this type.  Runtime effect counts,
receipt signatures, mutation labels, and ground truth are intentionally absent.
In the concrete P0 mapping, traceComplete is only a declared pinned-driver
capture-profile marker, not raw/native or V2 typed-trace completeness.
-/
structure Projection where
  schemaVersion : String
  evidenceKind : String
  configuredPolicy : Decision
  observedDecision : Decision
  expectedDecision : Decision
  resourcePath : String
  resourceUri : String
  resourcePolicyDigest : String
  attestationPolicyDigest : String
  dummyResourceDigest : String
  resourceDigest : Option String
  resourceErrorClass : Option String
  resourceErrorDetail : Option String
  publicInterfaces : List String
  traceComplete : Bool
deriving DecidableEq, Repr

inductive EffectRequirement where
  | forbidden
  | exactly (count : Nat)
deriving DecidableEq, Repr

structure EffectSpec where
  expectedDecision : Decision
  resource : String
  operation : String
  requirement : EffectRequirement
deriving DecidableEq, Repr

/-
Only an executable verifier may promote a raw signed envelope to this type.
The fields state the abstract payload that survives signature, correlation,
causal-order, uniqueness, and closed-window validation.
-/
structure VerifiedReceipt (specification : EffectSpec) where
  resource : String
  operation : String
  resourceBound : resource = specification.resource
  operationBound : operation = specification.operation
  windowId : String
  nonceDigest : String
  transactionId : String
  observedEffectCount : Nat
deriving DecidableEq, Repr

inductive ReceiptView (specification : EffectSpec) where
  | missing
  | invalid
  | verified (receipt : VerifiedReceipt specification)
deriving DecidableEq, Repr

structure ConcreteExecution where
  projection : Projection
  specification : EffectSpec
  receipt : ReceiptView specification

def projectionSpecBound (projection : Projection) (specification : EffectSpec) : Bool :=
  decide (projection.configuredPolicy = specification.expectedDecision) &&
    decide (projection.observedDecision = specification.expectedDecision) &&
    decide (projection.expectedDecision = specification.expectedDecision) &&
    projection.traceComplete

def effectConforms : EffectRequirement → Nat → Bool
  | .forbidden, 0 => true
  | .forbidden, Nat.succ _ => false
  | .exactly expected, observed => decide (expected = observed)

def requiredVerdict
    (projection : Projection)
    (specification : EffectSpec)
    (view : ReceiptView specification) : Verdict :=
  match projectionSpecBound projection specification with
  | false => .indeterminate
  | true =>
      match view with
      | .missing => .indeterminate
      | .invalid => .indeterminate
      | .verified receipt =>
          if effectConforms specification.requirement receipt.observedEffectCount then
            .pass
          else
            .fail

def executionRequiredVerdict (execution : ConcreteExecution) : Verdict :=
  requiredVerdict execution.projection execution.specification execution.receipt

structure TraceOnlyChecker where
  decide : Projection → Verdict

/-
A randomized trace-only checker is represented by making its internal seed
explicit.  The seed distribution must not depend on the hidden execution; that
independence condition is part of what "trace-only" means here.
-/
structure SeededTraceOnlyChecker (Seed : Type) where
  decide : Projection → Seed → Verdict

def runTraceOnly
    (checker : TraceOnlyChecker)
    (execution : ConcreteExecution) : Verdict :=
  checker.decide execution.projection

def FactorsThroughProjection
    (oracle : ConcreteExecution → Verdict) : Prop :=
  ∃ checker : Projection → Verdict,
    ∀ execution : ConcreteExecution,
      oracle execution = checker execution.projection

/- B1: the typed trace-only runner factors through Projection by construction. -/
theorem trace_only_runner_factors
    (checker : TraceOnlyChecker) :
    FactorsThroughProjection (runTraceOnly checker) := by
  exact ⟨checker.decide, fun _ => rfl⟩

/- B2: every factorized oracle is constant on a projection equivalence class. -/
theorem factorized_equal_on_equal_projection
    (oracle : ConcreteExecution → Verdict)
    (factors : FactorsThroughProjection oracle)
    (left right : ConcreteExecution)
    (projectionEqual : left.projection = right.projection) :
    oracle left = oracle right := by
  rcases factors with ⟨checker, correct⟩
  exact (correct left).trans ((congrArg checker projectionEqual).trans (correct right).symm)

/-
B2R: under a common internal seed, equal projections also force equal outputs
for a randomized trace-only checker.  Consequently, any execution-independent
distribution over Seed induces the same output distribution for the pair.
-/
theorem seeded_trace_only_equal_on_equal_projection
    {Seed : Type}
    (checker : SeededTraceOnlyChecker Seed)
    (left right : ConcreteExecution)
    (projectionEqual : left.projection = right.projection)
    (seed : Seed) :
    checker.decide left.projection seed = checker.decide right.projection seed := by
  exact congrArg (fun projection => checker.decide projection seed) projectionEqual

/-
B3: equal projection plus different required labels rules out simultaneous
correctness.  Effect difference alone is deliberately not a premise that can
replace requiredVerdictDiverges.
-/
theorem factorized_joint_correctness_impossible
    (oracle : ConcreteExecution → Verdict)
    (factors : FactorsThroughProjection oracle)
    (left right : ConcreteExecution)
    (projectionEqual : left.projection = right.projection)
    (requiredVerdictDiverges :
      executionRequiredVerdict left ≠ executionRequiredVerdict right)
    (correctLeft : oracle left = executionRequiredVerdict left)
    (correctRight : oracle right = executionRequiredVerdict right) :
    False := by
  have oracleEqual : oracle left = oracle right :=
    factorized_equal_on_equal_projection oracle factors left right projectionEqual
  have requiredEqual :
      executionRequiredVerdict left = executionRequiredVerdict right :=
    correctLeft.symm.trans (oracleEqual.trans correctRight)
  exact requiredVerdictDiverges requiredEqual

def receiptWithCount
    (specification : EffectSpec)
    (count : Nat) : VerifiedReceipt specification where
  resource := specification.resource
  operation := specification.operation
  resourceBound := rfl
  operationBound := rfl
  windowId := "window"
  nonceDigest := "nonce-digest"
  transactionId := "transaction"
  observedEffectCount := count

/- B4: a closed, valid zero-effect receipt satisfies a forbidden-effect spec. -/
theorem forbidden_zero_effect_passes
    (projection : Projection)
    (specification : EffectSpec)
    (bound : projectionSpecBound projection specification = true)
    (forbidden : specification.requirement = .forbidden) :
    requiredVerdict projection specification
      (.verified (receiptWithCount specification 0)) = .pass := by
  unfold requiredVerdict
  rw [bound]
  rw [forbidden]
  rfl

/- B5: a closed, valid one-effect receipt violates a forbidden-effect spec. -/
theorem forbidden_one_effect_fails
    (projection : Projection)
    (specification : EffectSpec)
    (bound : projectionSpecBound projection specification = true)
    (forbidden : specification.requirement = .forbidden) :
    requiredVerdict projection specification
      (.verified (receiptWithCount specification 1)) = .fail := by
  unfold requiredVerdict
  rw [bound]
  rw [forbidden]
  rfl

/- B6: the zero/one receipts require distinct labels under the same bound spec. -/
theorem forbidden_zero_one_required_verdicts_diverge
    (projection : Projection)
    (specification : EffectSpec)
    (bound : projectionSpecBound projection specification = true)
    (forbidden : specification.requirement = .forbidden) :
    requiredVerdict projection specification
        (.verified (receiptWithCount specification 0)) ≠
      requiredVerdict projection specification
        (.verified (receiptWithCount specification 1)) := by
  intro requiredEqual
  have zeroPass :=
    forbidden_zero_effect_passes projection specification bound forbidden
  have oneFail :=
    forbidden_one_effect_fails projection specification bound forbidden
  have passEqualsFail : Verdict.pass = Verdict.fail :=
    zeroPass.symm.trans (requiredEqual.trans oneFail)
  cases passEqualsFail

/-
B6N: different effect counts do not, by themselves, force different required
labels.  Under an exactly-two specification, both zero and one effects fail.
-/
theorem effect_divergence_alone_not_sufficient
    (projection : Projection)
    (specification : EffectSpec)
    (bound : projectionSpecBound projection specification = true)
    (exactTwo : specification.requirement = .exactly 2) :
    (0 : Nat) ≠ 1 ∧
      requiredVerdict projection specification
          (.verified (receiptWithCount specification 0)) =
        requiredVerdict projection specification
          (.verified (receiptWithCount specification 1)) := by
  constructor
  · decide
  · unfold requiredVerdict
    rw [bound]
    rw [exactTwo]
    rfl

/- B7: a trace-only checker cannot be correct on both members of this pair. -/
theorem trace_only_forbidden_zero_one_impossible
    (checker : TraceOnlyChecker)
    (projection : Projection)
    (specification : EffectSpec)
    (bound : projectionSpecBound projection specification = true)
    (forbidden : specification.requirement = .forbidden)
    (correctZero :
      checker.decide projection =
        requiredVerdict projection specification
          (.verified (receiptWithCount specification 0)))
    (correctOne :
      checker.decide projection =
        requiredVerdict projection specification
          (.verified (receiptWithCount specification 1))) :
    False := by
  have requiredDiverges :=
    forbidden_zero_one_required_verdicts_diverge
      projection specification bound forbidden
  exact requiredDiverges (correctZero.symm.trans correctOne)

theorem indeterminate_ne_pass : Verdict.indeterminate ≠ Verdict.pass := by
  intro impossible
  cases impossible

/- B8: unavailable or invalid effect evidence cannot be promoted to PASS. -/
theorem missing_or_invalid_not_pass
    (projection : Projection)
    (specification : EffectSpec)
    (view : ReceiptView specification)
    (unavailable : view = .missing ∨ view = .invalid) :
    requiredVerdict projection specification view ≠ .pass := by
  cases unavailable with
  | inl isMissing =>
      cases isMissing
      unfold requiredVerdict
      cases projectionSpecBound projection specification <;>
        exact indeterminate_ne_pass
  | inr isInvalid =>
      cases isInvalid
      unfold requiredVerdict
      cases projectionSpecBound projection specification <;>
        exact indeterminate_ne_pass

#check trace_only_runner_factors
#check factorized_equal_on_equal_projection
#check seeded_trace_only_equal_on_equal_projection
#check factorized_joint_correctness_impossible
#check forbidden_zero_effect_passes
#check forbidden_one_effect_fails
#check forbidden_zero_one_required_verdicts_diverge
#check effect_divergence_alone_not_sufficient
#check trace_only_forbidden_zero_one_impossible
#check missing_or_invalid_not_pass

#print axioms trace_only_runner_factors
#print axioms factorized_equal_on_equal_projection
#print axioms seeded_trace_only_equal_on_equal_projection
#print axioms factorized_joint_correctness_impossible
#print axioms forbidden_zero_effect_passes
#print axioms forbidden_one_effect_fails
#print axioms forbidden_zero_one_required_verdicts_diverge
#print axioms effect_divergence_alone_not_sufficient
#print axioms trace_only_forbidden_zero_one_impossible
#print axioms missing_or_invalid_not_pass

end AttestFlowBridgeV4
