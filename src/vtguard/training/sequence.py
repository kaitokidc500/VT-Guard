"""Reviewed multi-task GRU training with durable resume checkpoint."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import copy
from dataclasses import asdict
from pathlib import Path

import torch
from torch import nn

from vtguard import SCHEMA_VERSION
from vtguard.data.schema import TARGET_TTPS
from vtguard.evaluation.metrics import binary_metrics, choose_threshold
from vtguard.features.event import fit_vocabulary
from vtguard.features.sequence import SequenceConfig, offline_windows
from vtguard.features.sequence_encoding import encode_window
from vtguard.inference.sequence import SequenceBundle
from vtguard.models.gru import GRUDetector
from vtguard.training.reviewed import SPLITS, load_reviewed


HEADS = ("attack",) + TARGET_TTPS


def _target(row) -> list[float]:
    return [float(row.event.labels.activity == "attack")] + [
        float(ttp in row.event.labels.ttps) for ttp in TARGET_TTPS]


def _batch(samples: list[tuple[list[list[float]], list[float]]], device: torch.device):
    width = len(samples[0][0][0])
    maximum = max(len(encoded) for encoded, _ in samples)
    values = torch.zeros((len(samples), maximum, width), dtype=torch.float32)
    lengths = torch.tensor([len(encoded) for encoded, _ in samples], dtype=torch.long)
    targets = torch.tensor([target for _, target in samples], dtype=torch.float32)
    for index, (encoded, _) in enumerate(samples):
        values[index, :len(encoded)] = torch.tensor(encoded, dtype=torch.float32)
    return values.to(device), lengths.to(device), targets.to(device)


def _scores(model: GRUDetector, samples, batch_size: int, device: torch.device) -> list[list[float]]:
    model.eval()
    output: list[list[float]] = []
    with torch.no_grad():
        for start in range(0, len(samples), batch_size):
            values, lengths, _ = _batch(samples[start:start + batch_size], device)
            output.extend(torch.sigmoid(model(values, lengths)).cpu().tolist())
    return output


def train_sequence(manifest_path: Path, output_dir: Path, *, model_kind: str = "gru_attention",
                   sequence_config: SequenceConfig = SequenceConfig(), hidden_size: int = 32,
                   epochs: int = 30, batch_size: int = 32, learning_rate: float = 0.001,
                   patience: int = 6, checkpoint_dir: Path | None = None,
                   resume: bool = False, allow_synthetic: bool = False,
                   device: str = "auto") -> dict:
    if model_kind not in ("gru", "gru_attention") or min(hidden_size, epochs, batch_size, patience) < 1:
        raise ValueError("Invalid GRU training configuration")
    if device not in ("auto", "cpu", "cuda") or (device == "cuda" and not torch.cuda.is_available()):
        raise ValueError("Requested training device is unavailable")
    chosen_device = torch.device("cuda" if (device == "cuda" or device == "auto" and torch.cuda.is_available())
                                 else "cpu")
    manifest_path = Path(manifest_path)
    output_dir = Path(output_dir)
    checkpoint_dir = Path(checkpoint_dir) if checkpoint_dir else output_dir.parent / f"{output_dir.name}_checkpoints"
    rows, report = load_reviewed(manifest_path, allow_synthetic=allow_synthetic)
    by_split = {split: [row for row in rows if row.split == split] for split in SPLITS}
    vocabulary = fit_vocabulary([row.event for row in by_split["train"]])
    if not vocabulary:
        raise ValueError("Train vocabulary is empty")
    samples = {}
    window_lengths = {}
    for split in SPLITS:
        ordered = sorted(by_split[split], key=lambda row: (row.event.event_time_utc, row.event.event_uid))
        windows = offline_windows([row.event for row in ordered], sequence_config)
        samples[split] = [(encode_window(window, vocabulary, sequence_config), _target(row))
                          for window, row in zip(windows, ordered)]
        window_lengths[split] = [len(window) for window in windows]
    if not report["synthetic"] and max(window_lengths["train"]) < 2:
        raise ValueError("Real sequence training needs verified multi-event run windows")
    for head_index, head in enumerate(HEADS):
        for split in ("train", "validation"):
            positives = sum(target[head_index] for _, target in samples[split])
            if not 0 < positives < len(samples[split]):
                raise ValueError(f"{split} lacks both classes for {head}")
    torch.manual_seed(17)
    randomizer = random.Random(17)
    model = GRUDetector(len(vocabulary) + 1, hidden_size,
                        attention=model_kind == "gru_attention").to(chosen_device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.BCEWithLogitsLoss()
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    config_digest = hashlib.sha256(json.dumps({"manifest": manifest_digest,
        "model_kind": model_kind, "hidden_size": hidden_size,
        "sequence": asdict(sequence_config), "vocabulary": vocabulary,
        "batch_size": batch_size, "learning_rate": learning_rate, "seed": 17},
        sort_keys=True).encode("utf-8")).hexdigest()
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = checkpoint_dir / "checkpoint.pt"
    first_epoch = 0
    best_loss = float("inf")
    stale = 0
    best_state = copy.deepcopy(model.state_dict())
    best_epoch = -1
    if resume:
        if not checkpoint_path.is_file():
            raise FileNotFoundError("Resume checkpoint is missing")
        saved = torch.load(checkpoint_path, map_location=chosen_device, weights_only=True)
        if saved["config_digest"] != config_digest:
            raise ValueError("Resume checkpoint data/model configuration mismatch")
        model.load_state_dict(saved["model_state"])
        optimizer.load_state_dict(saved["optimizer_state"])
        first_epoch, best_loss = saved["epoch"] + 1, saved["best_loss"]
        best_state, best_epoch, stale = saved["best_model_state"], saved["best_epoch"], saved["stale"]
        randomizer.setstate(saved["random_state"])
        torch.set_rng_state(saved["torch_rng_state"].cpu())
        if chosen_device.type == "cuda" and saved.get("cuda_rng_state") is not None:
            torch.cuda.set_rng_state_all(saved["cuda_rng_state"])
    for epoch in range(first_epoch, epochs):
        model.train()
        order = list(range(len(samples["train"])))
        randomizer.shuffle(order)
        for start in range(0, len(order), batch_size):
            batch = [samples["train"][index] for index in order[start:start + batch_size]]
            values, lengths, targets = _batch(batch, chosen_device)
            optimizer.zero_grad()
            loss = loss_fn(model(values, lengths), targets)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
        model.eval()
        with torch.no_grad():
            val_loss = 0.0
            for start in range(0, len(samples["validation"]), batch_size):
                batch = samples["validation"][start:start + batch_size]
                values, lengths, targets = _batch(batch, chosen_device)
                val_loss += loss_fn(model(values, lengths), targets).item() * len(batch)
            val_loss /= len(samples["validation"])
        if val_loss < best_loss - 1e-6:
            best_loss, stale = val_loss, 0
            best_state, best_epoch = copy.deepcopy(model.state_dict()), epoch
        else:
            stale += 1
        checkpoint = {"config_digest": config_digest, "epoch": epoch,
                      "best_loss": best_loss, "best_epoch": best_epoch, "stale": stale,
                      "model_state": model.state_dict(), "best_model_state": best_state,
                      "optimizer_state": optimizer.state_dict(),
                      "random_state": randomizer.getstate(),
                      "torch_rng_state": torch.get_rng_state(),
                      "cuda_rng_state": torch.cuda.get_rng_state_all() if chosen_device.type == "cuda" else None}
        temporary = checkpoint_path.with_suffix(".partial")
        torch.save(checkpoint, temporary)
        temporary.replace(checkpoint_path)
        if stale >= patience:
            break
    saved = torch.load(checkpoint_path, map_location=chosen_device, weights_only=True)
    model.load_state_dict(saved["best_model_state"])
    val_scores = _scores(model, samples["validation"], batch_size, chosen_device)
    test_scores = _scores(model, samples["test"], batch_size, chosen_device)
    thresholds = {}
    metrics = {}
    for index, head in enumerate(HEADS):
        val_y = [int(target[index]) for _, target in samples["validation"]]
        test_y = [int(target[index]) for _, target in samples["test"]]
        thresholds[head] = choose_threshold(val_y, [row[index] for row in val_scores])
        metrics[head] = {"validation": binary_metrics(val_y, [row[index] for row in val_scores], thresholds[head]),
                         "test": binary_metrics(test_y, [row[index] for row in test_scores], thresholds[head])}
    output_dir.mkdir(parents=True, exist_ok=True)
    model.cpu().eval()
    weights_path = output_dir / "weights.pt"
    torch.save(model.state_dict(), weights_path)
    references = []
    for encoded, _ in samples["validation"][:3]:
        values, lengths, _ = _batch([(encoded, [0.0] * len(HEADS))], torch.device("cpu"))
        with torch.no_grad():
            scores = torch.sigmoid(model(values, lengths))[0].tolist()
        references.append({"encoded": encoded, "scores": dict(zip(HEADS, scores))})
    content = {
        "bundle_kind": "cpu_gru_sequence", "bundle_version": "0.1",
        "schema_version": SCHEMA_VERSION, "attack_version": "19.2",
        "detector_status": "synthetic_smoke" if report["synthetic"] else "experimental_sequence",
        "deployable": False, "labels": list(HEADS),
        "model_config": {"kind": model_kind, "hidden_size": hidden_size,
                         "attention": model_kind == "gru_attention"},
        "sequence_config": asdict(sequence_config), "feature_version": "event_allowlist_time_v1",
        "vocabulary": vocabulary, "thresholds": thresholds,
        "weights_sha256": hashlib.sha256(weights_path.read_bytes()).hexdigest(),
        "reference_inference": references,
        "training_config": {"epochs_requested": epochs, "best_epoch": saved["best_epoch"],
                            "batch_size": batch_size, "learning_rate": learning_rate,
                            "seed": 17, "device": str(chosen_device)},
        "data_provenance": report, "reviewed_manifest_sha256": manifest_digest,
        "code_commit": os.environ.get("VTGUARD_CODE_COMMIT"),
        "dependency_versions": {"python": platform.python_version(), "torch": torch.__version__},
        "metrics": {"by_head": metrics,
                    "counts": {split: {"events": len(samples[split]),
                                       "multi_event_windows": sum(length > 1 for length in window_lengths[split]),
                                       "runs": report["run_counts"][split]}
                               for split in SPLITS},
                    "evaluation_unit": "reviewed_event_window",
                    "session_detection": None, "end_to_end_latency": None,
                    "alerts_per_benign_hour": None},
    }
    raw = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    (output_dir / "bundle.json").write_bytes(raw)
    (output_dir / "bundle.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n", encoding="ascii")
    SequenceBundle.load(output_dir)
    return {"status": content["detector_status"], "model_kind": model_kind,
            "best_epoch": saved["best_epoch"], "counts": content["metrics"]["counts"],
            "bundle_dir": str(output_dir)}
