"""Bounded audio summaries and parameterized FSK decoding for file challenges."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import numpy as np
import soundfile as sf

from tools.flags import extract_flag


AudioOperation = Literal["summary", "fsk_decode"]
_OPERATIONS = {"summary", "fsk_decode"}
MAX_AUDIO_BYTES = 64 * 1024 * 1024
MAX_DECODED_BITS = 4_096


def _samples(path: Path) -> tuple[np.ndarray, int]:
    if not path.is_file():
        raise FileNotFoundError(f"Audio file does not exist or is not a file: {path}")
    if path.stat().st_size > MAX_AUDIO_BYTES:
        raise ValueError(f"Audio artifact exceeds the {MAX_AUDIO_BYTES}-byte analysis limit")
    samples, sample_rate = sf.read(path, always_2d=False)
    values = np.asarray(samples, dtype=float)
    if values.ndim == 2:
        values = values.mean(axis=1)
    if values.ndim != 1 or values.size < 2:
        raise ValueError("Audio artifact must contain at least two mono or stereo samples")
    return values, int(sample_rate)


def _summary(samples: np.ndarray, sample_rate: int) -> dict[str, Any]:
    window = samples[: min(samples.size, 65_536)]
    transformed = np.abs(np.fft.rfft(window * np.hanning(window.size)))
    frequencies = np.fft.rfftfreq(window.size, 1 / sample_rate)
    indices = np.argsort(transformed)[-12:][::-1]
    return {
        "sample_rate": sample_rate,
        "sample_count": int(samples.size),
        "duration_seconds": samples.size / sample_rate,
        "peak_amplitude": float(np.max(np.abs(samples))),
        "rms_amplitude": float(np.sqrt(np.mean(np.square(samples)))),
        "dominant_frequencies_hz": [round(float(frequencies[index]), 3) for index in indices],
    }


def _fsk_decode(
    samples: np.ndarray,
    sample_rate: int,
    *,
    symbol_rate: float,
    zero_frequency: float,
    one_frequency: float,
) -> dict[str, Any]:
    if not all(isinstance(value, (int, float)) and value > 0 for value in (symbol_rate, zero_frequency, one_frequency)):
        raise ValueError("fsk_decode requires positive symbol_rate, zero_frequency, and one_frequency")
    samples_per_symbol = round(sample_rate / float(symbol_rate))
    if samples_per_symbol < 4:
        raise ValueError("symbol_rate is too high for this audio sample rate")
    symbol_count = min(samples.size // samples_per_symbol, MAX_DECODED_BITS)
    if symbol_count < 8:
        raise ValueError("Audio artifact does not contain enough full symbols")

    time_axis = np.arange(samples_per_symbol) / sample_rate
    zero_reference = np.exp(-2j * np.pi * float(zero_frequency) * time_axis)
    one_reference = np.exp(-2j * np.pi * float(one_frequency) * time_axis)
    bits: list[str] = []
    for index in range(symbol_count):
        segment = samples[index * samples_per_symbol : (index + 1) * samples_per_symbol]
        zero_power = abs(np.vdot(segment, zero_reference))
        one_power = abs(np.vdot(segment, one_reference))
        bits.append("1" if one_power > zero_power else "0")
    bitstring = "".join(bits)
    byte_count = len(bitstring) // 8
    payload = bytes(int(bitstring[index : index + 8], 2) for index in range(0, byte_count * 8, 8))
    text = payload.decode("utf-8", errors="replace")
    return {
        "symbol_rate": symbol_rate,
        "zero_frequency": zero_frequency,
        "one_frequency": one_frequency,
        "bits": bitstring,
        "decoded_text": text,
        "decoded_hex": payload.hex(),
        "flag": extract_flag(text),
    }


def run_audio_analysis(
    audio_path: str | Path,
    *,
    operation: AudioOperation,
    symbol_rate: float | None = None,
    zero_frequency: float | None = None,
    one_frequency: float | None = None,
) -> dict[str, Any]:
    """Return a spectral summary or a parameterized binary FSK decode."""
    if operation not in _OPERATIONS:
        raise ValueError(f"Unsupported audio operation: {operation}")
    samples, sample_rate = _samples(Path(audio_path).resolve())
    if operation == "summary":
        return _summary(samples, sample_rate)
    if any(value is None for value in (symbol_rate, zero_frequency, one_frequency)):
        raise ValueError("fsk_decode requires symbol_rate, zero_frequency, and one_frequency")
    return _fsk_decode(
        samples,
        sample_rate,
        symbol_rate=float(symbol_rate),
        zero_frequency=float(zero_frequency),
        one_frequency=float(one_frequency),
    )
