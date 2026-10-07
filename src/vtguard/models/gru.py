"""GRU baseline and customized causal attention model."""

from __future__ import annotations

import torch
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence


class GRUDetector(nn.Module):
    def __init__(self, input_size: int, hidden_size: int = 32, *, attention: bool = False) -> None:
        super().__init__()
        if input_size < 2 or hidden_size < 1:
            raise ValueError("Invalid GRU dimensions")
        self.attention_enabled = attention
        self.gru = nn.GRU(input_size, hidden_size, batch_first=True)
        self.attention = nn.Linear(hidden_size, 1) if attention else None
        self.heads = nn.Linear(hidden_size, 6)

    def forward(self, values: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        if values.ndim != 3 or lengths.ndim != 1 or values.size(0) != lengths.numel():
            raise ValueError("Expected padded batch and matching lengths")
        packed = pack_padded_sequence(values, lengths.cpu(), batch_first=True,
                                      enforce_sorted=False)
        packed_output, hidden = self.gru(packed)
        if self.attention_enabled:
            output, _ = pad_packed_sequence(packed_output, batch_first=True,
                                            total_length=values.size(1))
            mask = torch.arange(values.size(1), device=values.device)[None, :] < lengths[:, None]
            logits = self.attention(output).squeeze(-1).masked_fill(~mask, -1e9)
            weights = torch.softmax(logits, dim=1)
            context = (output * weights.unsqueeze(-1)).sum(dim=1)
        else:
            context = hidden[-1]
        return self.heads(context)
