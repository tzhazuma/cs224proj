"""Dataset loading and validation for the two SecVulEval subsets.

Only fields needed for evaluation are retained.  Ground-truth fields are kept
out of the prompt-building path: prompt builders receive ``func_body`` and a
sanitised context object, never the sample record itself.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable


class DatasetError(ValueError):
    """Raised when an evaluation file is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class FunctionSample:
    sample_id: str
    unit_id: str
    idx: int
    label: bool
    func_body: str
    func_name: str
    project: str
    filepath: str
    context_raw: str | None
    fixed_func_idx: int | None
    pair_id: str | None
    side: str | None

    @property
    def code_sha256(self) -> str:
        return hashlib.sha256(self.func_body.encode("utf-8")).hexdigest()

    def prompt_metadata(self) -> dict[str, Any]:
        """Metadata safe to put in a request/log: no label or pair identity."""
        return {
            "function_chars": len(self.func_body),
            "function_lines": self.func_body.count("\n") + 1,
            "code_sha256": self.code_sha256,
        }


@dataclass(frozen=True)
class PairRecord:
    pair_id: str
    vulnerable: FunctionSample
    fixed: FunctionSample


@dataclass(frozen=True)
class LoadedDataset:
    dataset_type: str
    path: Path
    sha256: str
    metadata: dict[str, Any]
    units: tuple[FunctionSample, ...] | tuple[PairRecord, ...]

    @property
    def is_pairs(self) -> bool:
        return self.dataset_type == "pairs"

    @property
    def all_samples(self) -> tuple[FunctionSample, ...]:
        if self.is_pairs:
            out: list[FunctionSample] = []
            for pair in self.units:
                assert isinstance(pair, PairRecord)
                out.extend((pair.vulnerable, pair.fixed))
            return tuple(out)
        return tuple(self.units)  # type: ignore[arg-type]

    @property
    def unit_count(self) -> int:
        return len(self.units)

    def limited(self, limit: int) -> "LoadedDataset":
        if limit <= 0 or limit >= len(self.units):
            return self
        return replace(self, units=tuple(self.units[:limit]))

    def expected_counts(self, task: str) -> dict[str, int]:
        """Number of requests expected for a task on the selected units."""
        if task == "detection":
            return {"requests": self.unit_count if not self.is_pairs else self.unit_count * 2}
        if task == "repair":
            vuln = sum(
                1
                for unit in self.units
                if (unit.vulnerable.label if isinstance(unit, PairRecord) else unit.label)
            )
            return {"requests": vuln}
        if task == "both":
            detection = self.expected_counts("detection")["requests"]
            repair = self.expected_counts("repair")["requests"]
            return {"requests": detection + repair, "detection": detection, "repair": repair}
        raise ValueError(f"unknown task {task!r}")

    def units_for_task(self, task: str) -> Iterable[tuple[FunctionSample, str]]:
        """Yield (function, task) pairs in a deterministic order.

        Pair order is vulnerable then fixed for detection, matching the source
        pair order.  Repair requests are generated only for vulnerable
        functions (the original buggy versions).
        """
        if task not in {"detection", "repair", "both"}:
            raise ValueError(f"unknown task {task!r}")
        for unit in self.units:
            if isinstance(unit, PairRecord):
                if task in {"detection", "both"}:
                    yield unit.vulnerable, "detection"
                    yield unit.fixed, "detection"
                if task in {"repair", "both"}:
                    yield unit.vulnerable, "repair"
            else:
                if task in {"detection", "both"}:
                    yield unit, "detection"
                if task in {"repair", "both"} and unit.label:
                    yield unit, "repair"


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise DatasetError(message)


def _get_str(record: dict[str, Any], key: str, where: str, allow_empty: bool = False) -> str:
    value = record.get(key)
    _need(isinstance(value, str), f"{where}: field {key!r} must be a string")
    if not allow_empty:
        _need(bool(value.strip()), f"{where}: field {key!r} must not be empty")
    return value  # type: ignore[return-value]


def _get_int(record: dict[str, Any], key: str, where: str, nullable: bool = False) -> int | None:
    value = record.get(key)
    if value is None and nullable:
        return None
    _need(isinstance(value, int) and not isinstance(value, bool), f"{where}: field {key!r} must be an integer")
    return value  # type: ignore[return-value]


def _get_label(record: dict[str, Any], where: str) -> bool:
    value = record.get("is_vulnerable")
    _need(isinstance(value, bool), f"{where}: field 'is_vulnerable' must be a boolean")
    return value  # type: ignore[return-value]


def _get_context(record: dict[str, Any], where: str) -> str | None:
    value = record.get("context")
    if value is not None:
        _need(isinstance(value, str), f"{where}: field 'context' must be a string or null")
    return value  # type: ignore[return-value]


def _make_sample(
    record: dict[str, Any],
    *,
    where: str,
    sample_id: str,
    unit_id: str,
    pair_id: str | None = None,
    side: str | None = None,
) -> FunctionSample:
    idx = _get_int(record, "idx", where)
    assert idx is not None
    body = _get_str(record, "func_body", where)
    return FunctionSample(
        sample_id=sample_id,
        unit_id=unit_id,
        idx=idx,
        label=_get_label(record, where),
        func_body=body,
        func_name=_get_str(record, "func_name", where),
        project=_get_str(record, "project", where),
        filepath=_get_str(record, "filepath", where),
        context_raw=_get_context(record, where),
        fixed_func_idx=_get_int(record, "fixed_func_idx", where, nullable=True),
        pair_id=pair_id,
        side=side,
    )


def _read_json(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise DatasetError(f"cannot read dataset {path}: {exc}") from exc
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DatasetError(f"dataset {path} is not valid UTF-8: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DatasetError(f"dataset {path} is not valid JSON: {exc}") from exc
    _need(isinstance(data, dict), f"dataset {path}: top-level value must be an object")
    return data, hashlib.sha256(raw_bytes).hexdigest()


def load_dataset(path: str | Path, dataset_type: str) -> LoadedDataset:
    """Load and strictly validate one of the two supported datasets."""
    path = Path(path)
    _need(dataset_type in {"independent", "pairs"}, f"unsupported dataset type {dataset_type!r}")
    data, digest = _read_json(path)
    metadata = data.get("metadata", {})
    _need(isinstance(metadata, dict), f"{path}: metadata must be an object")

    if dataset_type == "independent":
        samples_raw = data.get("samples")
        _need(isinstance(samples_raw, list), f"{path}: 'samples' must be an array")
        _need(bool(samples_raw), f"{path}: 'samples' must not be empty")
        seen_idx: set[int] = set()
        samples: list[FunctionSample] = []
        for pos, record in enumerate(samples_raw):
            where = f"{path}: samples[{pos}]"
            _need(isinstance(record, dict), f"{where} must be an object")
            idx = _get_int(record, "idx", where)
            assert idx is not None
            _need(idx not in seen_idx, f"{where}: duplicate idx {idx}")
            seen_idx.add(idx)
            sample = _make_sample(record, where=where, sample_id=f"idx:{idx}", unit_id=str(idx))
            samples.append(sample)

        declared_vuln = metadata.get("vulnerable_count")
        declared_non = metadata.get("non_vulnerable_count")
        actual_vuln = sum(1 for sample in samples if sample.label)
        actual_non = len(samples) - actual_vuln
        if isinstance(declared_vuln, int):
            _need(declared_vuln == actual_vuln, f"{path}: metadata.vulnerable_count={declared_vuln} but data has {actual_vuln}")
        if isinstance(declared_non, int):
            _need(declared_non == actual_non, f"{path}: metadata.non_vulnerable_count={declared_non} but data has {actual_non}")
        if "sample_count" in metadata:
            _need(metadata["sample_count"] == len(samples), f"{path}: metadata.sample_count does not match data")
        return LoadedDataset(
            dataset_type="independent",
            path=path,
            sha256=digest,
            metadata=metadata,
            units=tuple(samples),
        )

    pairs_raw = data.get("pairs")
    _need(isinstance(pairs_raw, list), f"{path}: 'pairs' must be an array")
    _need(bool(pairs_raw), f"{path}: 'pairs' must not be empty")
    seen_pair_ids: set[str] = set()
    seen_idx: set[int] = set()
    pairs: list[PairRecord] = []
    for pos, record in enumerate(pairs_raw):
        where = f"{path}: pairs[{pos}]"
        _need(isinstance(record, dict), f"{where} must be an object")
        pair_id = _get_str(record, "pair_id", where)
        _need(pair_id not in seen_pair_ids, f"{where}: duplicate pair_id {pair_id!r}")
        seen_pair_ids.add(pair_id)
        vuln_raw = record.get("vulnerable")
        fixed_raw = record.get("fixed")
        _need(isinstance(vuln_raw, dict), f"{where}.vulnerable must be an object")
        _need(isinstance(fixed_raw, dict), f"{where}.fixed must be an object")
        vuln = _make_sample(
            vuln_raw,
            where=f"{where}.vulnerable",
            sample_id=f"pair:{pair_id}:vulnerable",
            unit_id=pair_id,
            pair_id=pair_id,
            side="vulnerable",
        )
        fixed = _make_sample(
            fixed_raw,
            where=f"{where}.fixed",
            sample_id=f"pair:{pair_id}:fixed",
            unit_id=pair_id,
            pair_id=pair_id,
            side="fixed",
        )
        _need(vuln.label is True, f"{where}: vulnerable side must be labelled true")
        _need(fixed.label is False, f"{where}: fixed side must be labelled false")
        for side_name, sample in (("vulnerable", vuln), ("fixed", fixed)):
            _need(sample.idx not in seen_idx, f"{where}.{side_name}: duplicate idx {sample.idx}")
            seen_idx.add(sample.idx)
        _need(vuln.idx != fixed.idx, f"{where}: pair sides must have distinct idx values")
        _need(vuln.project == fixed.project, f"{where}: project differs between pair sides")
        _need(vuln.filepath == fixed.filepath, f"{where}: filepath differs between pair sides")
        _need(vuln.func_name == fixed.func_name, f"{where}: func_name differs between pair sides")
        _need(vuln.func_body != fixed.func_body, f"{where}: pair sides have identical function bodies")
        if vuln.fixed_func_idx is not None:
            _need(vuln.fixed_func_idx == fixed.idx, f"{where}: vulnerable.fixed_func_idx must equal fixed.idx")
        if fixed.fixed_func_idx is not None:
            _need(fixed.fixed_func_idx == fixed.idx, f"{where}: fixed.fixed_func_idx must equal fixed.idx")
        pairs.append(PairRecord(pair_id=pair_id, vulnerable=vuln, fixed=fixed))

    if "pair_count" in metadata:
        _need(metadata["pair_count"] == len(pairs), f"{path}: metadata.pair_count does not match data")
    if "function_count" in metadata:
        _need(metadata["function_count"] == len(pairs) * 2, f"{path}: metadata.function_count does not match data")
    return LoadedDataset(
        dataset_type="pairs",
        path=path,
        sha256=digest,
        metadata=metadata,
        units=tuple(pairs),
    )


def dataset_label_counts(dataset: LoadedDataset) -> dict[str, int]:
    samples = dataset.all_samples
    vulnerable = sum(1 for sample in samples if sample.label)
    return {
        "functions": len(samples),
        "units": dataset.unit_count,
        "vulnerable": vulnerable,
        "non_vulnerable": len(samples) - vulnerable,
    }
