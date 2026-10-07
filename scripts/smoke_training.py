"""Tiny, explicitly synthetic CPU run of baseline, rules, fusion and both GRUs."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import torch

from vtguard.evaluation.experiment import write_comparison
from vtguard.training.baseline import train_baseline
from vtguard.training.hybrid import train_hybrid
from vtguard.training.sequence import train_sequence
from vtguard.training.sequence_hybrid import fit_sequence_hybrid
from vtguard.training.synthetic_fixture import make_fixture


def main() -> None:
    torch.set_num_threads(1)
    root = ROOT / "artifacts/training_smoke"
    manifest = make_fixture(root / "input", events_per_run=2)
    train_baseline(manifest, root / "logistic", allow_synthetic=True)
    hybrid = train_hybrid(manifest, root / "hybrid_logistic", allow_synthetic=True,
                          min_rule_support=1, min_validation_matches=1)
    models = {}
    for kind in ("gru", "gru_attention"):
        models[kind] = train_sequence(manifest, root / kind, model_kind=kind,
                                      hidden_size=8, epochs=2, batch_size=7,
                                      allow_synthetic=True, device="cpu")
    combined = fit_sequence_hybrid(manifest, root / "gru_attention",
                                   root / "hybrid_gru_attention",
                                   allow_synthetic=True, min_rule_support=1,
                                   min_validation_matches=1)
    comparison = write_comparison(root, root / "experiment_report.json")
    print(json.dumps({"status": "synthetic_smoke", "hybrid_rules": hybrid["rules"],
                      "gru_hybrid_rules": combined["rules"],
                      "compared_models": list(comparison["results"]),
                      "models": {name: value["bundle_dir"] for name, value in models.items()},
                      "warning": "Synthetic repeated events; no real detection result"},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
