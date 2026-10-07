from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.features.sequence import SequenceConfig
from vtguard.training.sequence import train_sequence


def main() -> None:
    parser = argparse.ArgumentParser(description="Train reviewed multi-task GRU on Colab/CPU")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checkpoint-dir", type=Path)
    parser.add_argument("--model-kind", choices=("gru", "gru_attention"), default="gru_attention")
    parser.add_argument("--max-events", type=int, default=64)
    parser.add_argument("--horizon-seconds", type=int, default=300)
    parser.add_argument("--hidden-size", type=int, default=32)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--patience", type=int, default=6)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--allow-synthetic", action="store_true", help="Fixture smoke only")
    args = parser.parse_args()
    result = train_sequence(args.manifest, args.output, model_kind=args.model_kind,
        sequence_config=SequenceConfig(args.max_events, args.horizon_seconds),
        hidden_size=args.hidden_size, epochs=args.epochs, batch_size=args.batch_size,
        patience=args.patience, checkpoint_dir=args.checkpoint_dir,
        resume=args.resume, allow_synthetic=args.allow_synthetic, device=args.device)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
