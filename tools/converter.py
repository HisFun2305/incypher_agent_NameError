"""Local file-conversion helpers for challenge assets."""

from __future__ import annotations

import gzip
import shutil
import stat
import zipfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Literal

from tools.context import store_artifact_paths


AudioConversionType = Literal[1, 2]
SPECTROGRAM = 1
WAVEFORM = 2


def _output_path(audio_path: Path, conversion_type: AudioConversionType) -> Path:
    """Return the default PNG path for an audio conversion."""
    suffix = "spectrogram" if conversion_type == SPECTROGRAM else "waveform"
    return audio_path.with_name(f"{audio_path.stem}_{suffix}.png")


def _mono_samples(audio_path: Path) -> tuple[Any, int]:
    """Load mono audio or down-mix stereo audio to mono."""
    import numpy as np
    import soundfile as sf

    samples, sample_rate = sf.read(audio_path, always_2d=False)
    if samples.size < 2:
        raise ValueError("audio file must contain at least two samples")
    if samples.ndim == 2:
        if samples.shape[1] != 2:
            raise ValueError("audio file must be mono or stereo")
        samples = samples.mean(axis=1)
    elif samples.ndim != 1:
        raise ValueError("audio file must be mono or stereo")
    return np.asarray(samples, dtype=float), sample_rate


def _spectrogram_nfft(sample_count: int) -> int:
    """Choose a bounded, power-of-two FFT size for Matplotlib's specgram.

    ``Axes.specgram`` performs the FFT internally. A power-of-two NFFT lets its
    NumPy-backed FFT implementation run efficiently. The value is capped at
    1024 samples to retain useful time resolution, and reduced for short clips.
    """
    return 1 << (min(1024, sample_count).bit_length() - 1)


def _store_converted_files(output_paths: list[Path], chal_ID: int) -> None:
    """Add generated file paths to a challenge's JSON context."""
    store_artifact_paths([str(output_path.resolve()) for output_path in output_paths], chal_ID)


def convert_audio_file(
    audio_path: str | Path,
    conversion_type: AudioConversionType,
    output_path: str | Path | None = None,
    *,
    chal_ID: int,
) -> Path:
    """Convert audio to a PNG spectrogram (``1``) or waveform (``2``).

    The source format must be readable by SoundFile. When ``output_path`` is
    omitted, the PNG is written beside the audio file with a descriptive name.
    The returned absolute path is added to ``converted_file_paths`` in the
    challenge's JSON context.
    """
    source = Path(audio_path)
    if not source.is_file():
        raise FileNotFoundError(f"Audio file does not exist: {source}")
    if conversion_type not in {SPECTROGRAM, WAVEFORM}:
        raise ValueError("conversion_type must be 1 (spectrogram) or 2 (waveform)")

    destination = Path(output_path) if output_path is not None else _output_path(
        source, conversion_type
    )
    if destination.suffix.lower() != ".png":
        raise ValueError("output_path must use a .png extension")
    destination.parent.mkdir(parents=True, exist_ok=True)

    import matplotlib
    import numpy as np

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    samples, sample_rate = _mono_samples(source)
    figure, axis = plt.subplots(figsize=(12, 4), layout="constrained")
    try:
        if conversion_type == SPECTROGRAM:
            nfft = _spectrogram_nfft(samples.size)
            axis.specgram(samples, Fs=sample_rate, NFFT=nfft, noverlap=nfft // 2)
            axis.set_ylabel("Frequency (Hz)")
            axis.set_title(f"Spectrogram: {source.name}")
        else:
            time_axis = np.arange(samples.size) / sample_rate
            axis.plot(time_axis, samples, linewidth=0.5)
            axis.set_ylabel("Amplitude")
            axis.set_title(f"Waveform: {source.name}")

        axis.set_xlabel("Time (seconds)")
        figure.savefig(destination, dpi=150)
    finally:
        plt.close(figure)

    resolved_destination = destination.resolve()
    _store_converted_files([resolved_destination], chal_ID)
    return resolved_destination


def extract_gzip_archive(
    archive_path: str | Path,
    *,
    chal_ID: int,
    output_path: str | Path | None = None,
    max_output_size: int = 512 * 1024 * 1024,
) -> Path:
    """Safely expand one gzip artifact and record the resulting file path."""
    source = Path(archive_path)
    if not source.is_file():
        raise FileNotFoundError(f"gzip archive does not exist: {source}")
    if source.suffix.lower() != ".gz":
        raise ValueError("extract_gzip requires a .gz artifact")
    if max_output_size < 1:
        raise ValueError("max_output_size must be positive")
    destination = Path(output_path) if output_path is not None else source.with_suffix("")
    if destination.exists():
        raise FileExistsError(f"gzip output already exists: {destination}")

    written = 0
    try:
        with gzip.open(source, "rb") as compressed, destination.open("xb") as output:
            while chunk := compressed.read(64 * 1024):
                written += len(chunk)
                if written > max_output_size:
                    raise ValueError(f"gzip archive exceeds the {max_output_size}-byte extraction limit")
                output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise

    resolved_destination = destination.resolve()
    _store_converted_files([resolved_destination], chal_ID)
    return resolved_destination


def extract_zip_archive(
    archive_path: str | Path,
    *,
    chal_ID: int,
    output_directory: str | Path | None = None,
    max_files: int = 1000,
    max_total_size: int = 512 * 1024 * 1024,
) -> list[Path]:
    """Safely extract a ZIP archive and record all output files in context.

    The default output directory is ``<archive_name>_extracted`` beside the
    archive. Absolute paths, parent-directory traversal, symbolic links,
    excessive file counts, and excessive uncompressed sizes are rejected.
    Existing output files are never overwritten.
    """
    source = Path(archive_path)
    if not source.is_file():
        raise FileNotFoundError(f"ZIP archive does not exist: {source}")
    if not zipfile.is_zipfile(source):
        raise ValueError(f"File is not a valid ZIP archive: {source}")
    if max_files < 1 or max_total_size < 1:
        raise ValueError("ZIP extraction limits must be positive")

    destination = (
        Path(output_directory)
        if output_directory is not None
        else source.with_name(f"{source.stem}_extracted")
    ).resolve()

    extracted_files: list[Path] = []
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        file_members = [member for member in members if not member.is_dir()]
        if len(file_members) > max_files:
            raise ValueError(f"ZIP archive exceeds the {max_files}-file limit")
        if sum(member.file_size for member in file_members) > max_total_size:
            raise ValueError(
                f"ZIP archive exceeds the {max_total_size}-byte extraction limit"
            )

        planned_outputs: list[tuple[zipfile.ZipInfo, Path]] = []
        planned_targets: set[Path] = set()
        for member in members:
            normalized_name = member.filename.replace("\\", "/")
            relative_path = PurePosixPath(normalized_name)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise ValueError(f"Unsafe ZIP member path: {member.filename}")
            if not relative_path.parts:
                continue
            if member.flag_bits & 0x1:
                raise ValueError(f"Encrypted ZIP members are not supported: {member.filename}")
            if stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError(f"ZIP symbolic links are not supported: {member.filename}")

            target = destination.joinpath(*relative_path.parts).resolve()
            try:
                target.relative_to(destination)
            except ValueError as exc:
                raise ValueError(f"Unsafe ZIP member path: {member.filename}") from exc
            if target in planned_targets:
                raise ValueError(f"Duplicate ZIP output path: {member.filename}")
            if not member.is_dir() and target.exists():
                raise FileExistsError(f"ZIP output already exists: {target}")
            planned_targets.add(target)
            planned_outputs.append((member, target))

        for member, target in planned_outputs:
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source_file, target.open("xb") as output_file:
                shutil.copyfileobj(source_file, output_file)
            extracted_files.append(target)

    _store_converted_files(extracted_files, chal_ID)
    return extracted_files
