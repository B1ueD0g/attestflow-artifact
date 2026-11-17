/-
AttestFlow trace-only information-barrier theorems.

This file uses only Lean 4 core.  Its statements are abstract: they do not prove
that concrete trace extraction, effect observation, or oracle code refines the
types and functions below.
-/

namespace AttestFlowFormal

inductive Verdict where
  | pass
  | fail
  | indeterminate
deriving DecidableEq, Repr

structure Projection (Decision Trace : Type) where
  decision : Decision
  trace : Trace

structure Execution (P Effect : Type) where
  projection : P
  effect : Effect

inductive EffectView (Effect : Type) where
  | missing
  | invalid
  | observed (effect : Effect)

/- T1: deterministic extensionality over the declared projection. -/
theorem projection_congruence
    {P V : Type}
    (oracle : P → V)
    (p₁ p₂ : P)
    (projectionEqual : p₁ = p₂) :
    oracle p₁ = oracle p₂ := by
  cases projectionEqual
  rfl

/-
T1 proper: a specification factors through project exactly when it is constant
on every projection fiber.  The reverse direction selects one preimage for an
inhabited fiber and therefore explicitly uses Classical.choice/propComplete.
The supplied default handles projections outside the image.
-/
noncomputable def factorOracle
    {X P V : Type}
    (project : X → P)
    (specification : X → V)
    (default : V) :
    P → V := by
  classical
  exact fun projection =>
    if hasPreimage : ∃ execution, project execution = projection then
      specification (Classical.choose hasPreimage)
    else
      default

theorem trace_only_factorization_iff
    {X P V : Type}
    (project : X → P)
    (specification : X → V)
    (default : V) :
    (∃ oracle : P → V, ∀ execution : X,
      oracle (project execution) = specification execution) ↔
    (∀ left right : X, project left = project right →
      specification left = specification right) := by
  constructor
  · intro factorization
    cases factorization with
    | intro oracle correct =>
        intro left right projectionEqual
        exact
          (correct left).symm.trans
            ((congrArg oracle projectionEqual).trans (correct right))
  · intro fiberConstant
    classical
    refine ⟨factorOracle project specification default, ?_⟩
    intro execution
    unfold factorOracle
    split
    · next hasPreimage =>
        exact
          fiberConstant (Classical.choose hasPreimage) execution
            (Classical.choose_spec hasPreimage)
    · next noPreimage =>
        exact False.elim (noPreimage ⟨execution, rfl⟩)

/- T2: equal inputs cannot satisfy two different required outputs perfectly. -/
theorem trace_only_joint_correctness_impossible
    {P Effect : Type}
    (specification : P → Effect → Verdict)
    (oracle : P → Verdict)
    (p₁ p₂ : P)
    (e₁ e₂ : Effect)
    (projectionEqual : p₁ = p₂)
    (_effectDiverges : e₁ ≠ e₂)
    (requiredVerdictDiverges : specification p₁ e₁ ≠ specification p₂ e₂)
    (correctLeft : oracle p₁ = specification p₁ e₁)
    (correctRight : oracle p₂ = specification p₂ e₂) :
    False := by
  have oracleEqual : oracle p₁ = oracle p₂ :=
    congrArg oracle projectionEqual
  have requiredEqual : specification p₁ e₁ = specification p₂ e₂ :=
    correctLeft.symm.trans (oracleEqual.trans correctRight)
  exact requiredVerdictDiverges requiredEqual

/- Randomized algorithms are ordinary functions once all coins are explicit. -/
theorem randomized_oracle_same_coin_congruence
    {P Coins V : Type}
    (oracle : P → Coins → V)
    (p₁ p₂ : P)
    (c₁ c₂ : Coins)
    (projectionEqual : p₁ = p₂)
    (coinsEqual : c₁ = c₂) :
    oracle p₁ c₁ = oracle p₂ c₂ := by
  cases projectionEqual
  cases coinsEqual
  rfl

/- T3: when Spec factors over (Projection, Effect), this lambda is a witness. -/
def constructedExtendedOracle
    {P Effect V : Type}
    (specification : P → Effect → V) :
    P → Effect → V :=
  fun projection effect => specification projection effect

theorem effect_complete_separability
    {P Effect V : Type}
    (specification : P → Effect → V) :
    ∀ (projection : P) (effect : Effect),
      constructedExtendedOracle specification projection effect =
        specification projection effect := by
  intro projection effect
  rfl

/- T4: the defined three-valued rule is fail-closed for unavailable evidence. -/
def safeEffectOracle
    {P Effect : Type}
    (specification : P → Effect → Verdict) :
    P → EffectView Effect → Verdict
  | _, .missing => .indeterminate
  | _, .invalid => .indeterminate
  | projection, .observed effect => specification projection effect

theorem indeterminate_ne_pass : Verdict.indeterminate ≠ Verdict.pass := by
  intro impossible
  cases impossible

theorem missing_effect_cannot_pass
    {P Effect : Type}
    (specification : P → Effect → Verdict)
    (projection : P)
    (view : EffectView Effect)
    (unavailable : view = .missing ∨ view = .invalid) :
    safeEffectOracle specification projection view = Verdict.indeterminate ∧
      safeEffectOracle specification projection view ≠ Verdict.pass := by
  cases unavailable with
  | inl isMissing =>
      cases isMissing
      constructor
      · rfl
      · exact indeterminate_ne_pass
  | inr isInvalid =>
      cases isInvalid
      constructor
      · rfl
      · exact indeterminate_ne_pass

/- Non-vacuity witness for equal projection, divergent effect, and divergent Spec. -/
inductive WitnessEffect where
  | noRelease
  | release
deriving DecidableEq, Repr

def witnessSpecification (_ : Unit) : WitnessEffect → Verdict
  | .noRelease => .pass
  | .release => .fail

theorem nonvacuity_effects_distinct :
    WitnessEffect.noRelease ≠ WitnessEffect.release := by
  intro impossible
  cases impossible

theorem nonvacuity_required_verdicts_diverge :
    witnessSpecification () .noRelease ≠ witnessSpecification () .release := by
  decide

/- Controls: relaxing a required assumption admits the corresponding behavior. -/
def distinguishableProjectionOracle : Bool → Verdict
  | false => .pass
  | true => .fail

theorem control_distinguishable_projection :
    distinguishableProjectionOracle false = Verdict.pass ∧
      distinguishableProjectionOracle true = Verdict.fail := by
  constructor <;> rfl

def constantSpecification (_ : Unit) (_ : WitnessEffect) : Verdict := .pass

theorem control_no_required_verdict_divergence :
    constantSpecification () .noRelease = constantSpecification () .release := by
  rfl

theorem control_effect_aware_oracle :
    constructedExtendedOracle witnessSpecification () .noRelease = Verdict.pass ∧
      constructedExtendedOracle witnessSpecification () .release = Verdict.fail := by
  constructor <;> rfl

def randomizedWitnessOracle (_ : Unit) : Bool → Verdict
  | false => .pass
  | true => .fail

theorem control_different_random_coins :
    randomizedWitnessOracle () false ≠ randomizedWitnessOracle () true := by
  decide

def uncheckedEffectOracle
    {P Effect : Type}
    (_ : P)
    (_ : EffectView Effect) : Verdict :=
  .pass

theorem control_unchecked_missing_effect_can_fail_open :
    uncheckedEffectOracle () (EffectView.missing : EffectView WitnessEffect) =
      Verdict.pass := by
  rfl

#check projection_congruence
#check trace_only_factorization_iff
#check trace_only_joint_correctness_impossible
#check randomized_oracle_same_coin_congruence
#check effect_complete_separability
#check missing_effect_cannot_pass
#check nonvacuity_effects_distinct
#check nonvacuity_required_verdicts_diverge
#check control_distinguishable_projection
#check control_no_required_verdict_divergence
#check control_effect_aware_oracle
#check control_different_random_coins
#check control_unchecked_missing_effect_can_fail_open

#print axioms projection_congruence
#print axioms trace_only_factorization_iff
#print axioms trace_only_joint_correctness_impossible
#print axioms randomized_oracle_same_coin_congruence
#print axioms effect_complete_separability
#print axioms missing_effect_cannot_pass

end AttestFlowFormal
