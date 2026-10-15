from __future__ import annotations

from shroodler.attack_chain import AttackChain, ChainStep
from shroodler.models import Finding
from shroodler.workflow import mutate_workflow, run_workflow_mutations


def _chain() -> AttackChain:
    return AttackChain(
        name="checkout",
        description="cart -> pay -> confirm",
        finding_id="checkout-chain",
        steps=[
            ChainStep(id="cart", url="http://t/cart", method="POST"),
            ChainStep(id="pay", url="http://t/pay", method="POST"),
            ChainStep(id="confirm", url="http://t/confirm", method="POST"),
        ],
    )


def _ok():
    return {
        "findings": [
            Finding(
                id="x",
                severity="high",
                category="payload",
                url="http://t/confirm",
                description="chain succeeded",
            )
        ]
    }


def _fail(where="confirm"):
    return {"findings": [], "stopped_at": where, "reason": "blocked"}


def test_mutate_workflow_generates_skips_and_replay():
    variants = mutate_workflow(_chain())
    labels = [label for label, _ in variants]
    assert "skip-step:cart" in labels
    assert "skip-step:pay" in labels
    assert "skip-step:confirm" not in labels  # never skip the target step
    assert "replay-target" in labels


def test_single_step_workflow_has_no_mutations():
    chain = AttackChain(name="x", description="", finding_id="x",
                        steps=[ChainStep(id="only", url="http://t/x")])
    assert mutate_workflow(chain) == []


def test_flags_step_skip_and_replay_bypass():
    # Fake app: works with a cart; 'pay' is NOT enforced (confirm succeeds
    # without it); replay of confirm also succeeds.
    def fake_run(chain, **kw):
        ids = [s.id for s in chain.steps]
        if "cart" not in ids:
            return _fail()  # cart token genuinely required
        return _ok()

    findings = run_workflow_mutations(_chain(), run=fake_run)
    ids = {f.id for f in findings}
    assert "workflow-step-skip" in ids
    assert "workflow-replay" in ids
    skip = next(f for f in findings if f.id == "workflow-step-skip")
    # The missing-enforcement is 'pay' (skipping cart failed, so not flagged).
    assert "pay" in skip.evidence
    assert all("cart" not in f.evidence for f in findings if f.id == "workflow-step-skip")


def test_no_findings_when_baseline_does_not_complete():
    # If the legitimate flow doesn't work, there's nothing to bypass.
    findings = run_workflow_mutations(_chain(), run=lambda chain, **kw: _fail("cart"))
    assert findings == []


def test_no_findings_when_mutations_are_blocked():
    # Baseline works, but every mutation is properly blocked -> no bug.
    def fake_run(chain, **kw):
        ids = [s.id for s in chain.steps]
        # Only the exact 3-step baseline succeeds; any mutation is blocked.
        return _ok() if ids == ["cart", "pay", "confirm"] else _fail()

    assert run_workflow_mutations(_chain(), run=fake_run) == []
