"""Load real runner artifacts, join them to the pairs dataset, and sample cases."""

from __future__ import annotations

import json
import random
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .util import (
    RepairEvalError,
    read_json,
    read_jsonl,
    salted_id,
    sha256_file,
    sha256_text,
)

KNOWN_STRATEGIES = ("direct", "few-shot", "context")
MIN_PAIRS = 20
MAX_PAIRS = 30

CWE_FAMILY_MAP = {
    20: "input_validation",
    22: "path_traversal",
    78: "command_injection",
    79: "injection",
    89: "injection",
    94: "injection",
    119: "memory_buffer",
    120: "memory_buffer",
    121: "memory_buffer",
    122: "memory_buffer",
    123: "memory_buffer",
    124: "memory_buffer",
    125: "memory_buffer",
    126: "memory_buffer",
    127: "memory_buffer",
    128: "memory_buffer",
    129: "memory_buffer",
    131: "memory_buffer",
    134: "injection",
    189: "integer",
    190: "integer",
    191: "integer",
    194: "integer",
    195: "integer",
    196: "integer",
    197: "integer",
    200: "information_exposure",
    209: "information_exposure",
    250: "access_control",
    264: "access_control",
    269: "access_control",
    276: "access_control",
    284: "access_control",
    285: "access_control",
    287: "access_control",
    306: "access_control",
    310: "cryptography",
    311: "cryptography",
    319: "cryptography",
    320: "cryptography",
    321: "cryptography",
    322: "cryptography",
    323: "cryptography",
    324: "cryptography",
    325: "cryptography",
    326: "cryptography",
    327: "cryptography",
    328: "cryptography",
    329: "cryptography",
    330: "cryptography",
    331: "cryptography",
    332: "cryptography",
    335: "cryptography",
    336: "cryptography",
    337: "cryptography",
    338: "cryptography",
    340: "cryptography",
    347: "cryptography",
    362: "race",
    364: "race",
    366: "race",
    367: "race",
    368: "race",
    369: "integer",
    370: "race",
    371: "race",
    372: "race",
    399: "resource",
    400: "resource",
    401: "memory_lifecycle",
    404: "memory_lifecycle",
    415: "memory_lifecycle",
    416: "memory_lifecycle",
    457: "memory_lifecycle",
    476: "memory_lifecycle",
    502: "injection",
    522: "information_exposure",
    532: "information_exposure",
    538: "information_exposure",
    590: "memory_lifecycle",
    601: "path_traversal",
    611: "injection",
    617: "resource",
    639: "access_control",
    662: "race",
    663: "race",
    665: "race",
    667: "resource",
    674: "resource",
    680: "integer",
    681: "integer",
    732: "access_control",
    761: "memory_lifecycle",
    770: "resource",
    772: "memory_lifecycle",
    775: "memory_lifecycle",
    787: "memory_buffer",
    824: "memory_lifecycle",
    834: "resource",
    835: "resource",
    862: "access_control",
    863: "access_control",
    908: "memory_lifecycle",
    916: "cryptography",
    918: "injection",
}

LENGTH_BINS = ("<=400", "401-800", "801-1600", "1601-4000")
CWE_PATTERN = re.compile(r"^CWE-(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class PairInfo:
    pair_id: str
    project: str
    filepath: str
    func_name: str
    vulnerable_idx: int
    fixed_idx: int
    vulnerable_code: str
    fixed_code: str
    cwe: tuple[str, ...]
    cwe_family: str
    length_bin: str
    function_chars: int


@dataclass(frozen=True)
class DatasetInfo:
    path: Path
    sha256: str
    pairs: dict[str, PairInfo]
    metadata: dict[str, Any]


@dataclass
class ResultsFileInfo:
    path: Path
    sha256: str
    manifest_path: Path | None
    manifest_sha256: str | None
    run_id: str | None
    status: str | None
    model: str | None
    endpoint: str | None
    records_total: int = 0
    repair_records: int = 0
    http_200_repair: int = 0
    valid_candidates: int = 0
    provenance_unverified: bool = False


@dataclass(frozen=True)
class RepairCandidate:
    pair_id: str
    strategy: str
    sample_id: str
    model: str
    fixed_function: str
    explanation: str
    validation: dict[str, Any]
    source_path: Path
    source_index: int


@dataclass(frozen=True)
class CaseInfo:
    pair: PairInfo
    candidates: tuple[RepairCandidate, ...]

    @property
    def stratum(self) -> tuple[str, str]:
        return (self.pair.cwe_family, self.pair.length_bin)


@dataclass
class SamplingResult:
    selected: list[CaseInfo]
    requested_pairs: int
    target_pairs: int
    strata: list[dict[str, Any]]
    allocation: dict[str, int]
    project_cap_used: int | None
    warnings: list[str]
    frame_exclusions: dict[str, int]
    frame_size: int


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RepairEvalError(message)


def _get_str(record: dict[str, Any], key: str, where: str) -> str:
    value = record.get(key)
    _need(isinstance(value, str) and bool(value.strip()), f"{where}: {key!r} must be a non-empty string")
    return value.strip()


def _get_code(record: dict[str, Any], key: str, where: str) -> str:
    value = record.get(key)
    _need(
        isinstance(value, str) and bool(value.strip()),
        f"{where}: {key!r} must be a non-empty string",
    )
    return value


def _get_int(record: dict[str, Any], key: str, where: str) -> int:
    value = record.get(key)
    _need(
        isinstance(value, int) and not isinstance(value, bool),
        f"{where}: {key!r} must be an integer",
    )
    return value


def _normalise_cwe_list(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ("UNKNOWN",)
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = [value]
    _need(isinstance(value, list), f"{where}: cwe_list must be a list or JSON list string")
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            result.append(item.strip())
    return tuple(result) if result else ("UNKNOWN",)


def cwe_family(cwe: str) -> str:
    match = CWE_PATTERN.match(cwe.strip())
    if match:
        return CWE_FAMILY_MAP.get(int(match.group(1)), "other")
    if cwe.upper().startswith("NVD-"):
        return "unknown"
    return "other"


def length_bin(characters: int) -> str:
    if characters <= 400:
        return LENGTH_BINS[0]
    if characters <= 800:
        return LENGTH_BINS[1]
    if characters <= 1600:
        return LENGTH_BINS[2]
    return LENGTH_BINS[3]


def load_pairs_dataset(path: str | Path) -> DatasetInfo:
    dataset_path = Path(path)
    data = read_json(dataset_path)
    _need(isinstance(data, dict), f"{dataset_path}: top level must be an object")
    raw_pairs = data.get("pairs")
    _need(isinstance(raw_pairs, list) and bool(raw_pairs), f"{dataset_path}: 'pairs' must be a non-empty list")
    metadata = data.get("metadata", {})
    _need(isinstance(metadata, dict), f"{dataset_path}: metadata must be an object")
    pairs: dict[str, PairInfo] = {}
    for position, record in enumerate(raw_pairs):
        where = f"{dataset_path}: pairs[{position}]"
        _need(isinstance(record, dict), f"{where} must be an object")
        pair_id = _get_str(record, "pair_id", where)
        _need(pair_id not in pairs, f"{where}: duplicate pair_id {pair_id!r}")
        vulnerable = record.get("vulnerable")
        fixed = record.get("fixed")
        _need(isinstance(vulnerable, dict), f"{where}.vulnerable must be an object")
        _need(isinstance(fixed, dict), f"{where}.fixed must be an object")
        vulnerable_code = _get_code(vulnerable, "func_body", f"{where}.vulnerable")
        fixed_code = _get_code(fixed, "func_body", f"{where}.fixed")
        _need(
            vulnerable_code != fixed_code,
            f"{where}: vulnerable and fixed function bodies must differ",
        )
        _need(
            vulnerable.get("is_vulnerable") is True,
            f"{where}.vulnerable: is_vulnerable must be true",
        )
        _need(
            fixed.get("is_vulnerable") is False,
            f"{where}.fixed: is_vulnerable must be false",
        )
        project = _get_str(vulnerable, "project", f"{where}.vulnerable")
        _need(
            fixed.get("project") == project,
            f"{where}: project differs between vulnerable and fixed",
        )
        func_name = _get_str(vulnerable, "func_name", f"{where}.vulnerable")
        _need(
            fixed.get("func_name") == func_name,
            f"{where}: func_name differs between vulnerable and fixed",
        )
        filepath = _get_str(vulnerable, "filepath", f"{where}.vulnerable")
        vulnerable_idx = _get_int(vulnerable, "idx", f"{where}.vulnerable")
        fixed_idx = _get_int(fixed, "idx", f"{where}.fixed")
        _need(
            vulnerable_idx != fixed_idx,
            f"{where}: vulnerable and fixed idx must differ",
        )
        cwe = _normalise_cwe_list(vulnerable.get("cwe_list"), f"{where}.vulnerable")
        pairs[pair_id] = PairInfo(
            pair_id=pair_id,
            project=project,
            filepath=filepath,
            func_name=func_name,
            vulnerable_idx=vulnerable_idx,
            fixed_idx=fixed_idx,
            vulnerable_code=vulnerable_code,
            fixed_code=fixed_code,
            cwe=cwe,
            cwe_family=cwe_family(cwe[0]),
            length_bin=length_bin(len(vulnerable_code)),
            function_chars=len(vulnerable_code),
        )
    declared = metadata.get("pair_count")
    if isinstance(declared, int):
        _need(
            declared == len(pairs),
            f"{dataset_path}: metadata.pair_count={declared} but data has {len(pairs)}",
        )
    return DatasetInfo(
        path=dataset_path.resolve(),
        sha256=sha256_file(dataset_path),
        pairs=pairs,
        metadata=metadata,
    )


def _is_local_endpoint(endpoint: str) -> bool:
    host = (urlsplit(endpoint).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _dataset_sha_from_manifest(manifest: dict[str, Any]) -> str | None:
    dataset = manifest.get("dataset")
    if isinstance(dataset, dict) and isinstance(dataset.get("sha256"), str):
        return dataset["sha256"]
    config = manifest.get("config")
    if isinstance(config, dict) and isinstance(config.get("dataset_sha256"), str):
        return config["dataset_sha256"]
    return None


def _check_manifest(
    results_path: Path,
    dataset: DatasetInfo,
    *,
    allow_missing_manifest: bool,
    allow_incomplete_runs: bool,
    allow_local_endpoint: bool,
) -> tuple[Path | None, str | None, dict[str, Any] | None]:
    manifest_path = results_path.parent / "manifest.json"
    if not manifest_path.exists():
        if not allow_missing_manifest:
            raise RepairEvalError(
                f"missing run manifest next to {results_path}: {manifest_path}. "
                "A formal blind package requires runner provenance. Use "
                "--allow-missing-manifest only for archived real results."
            )
        return None, None, None
    manifest = read_json(manifest_path)
    _need(isinstance(manifest, dict), f"{manifest_path}: manifest must be an object")
    status = manifest.get("status")
    if status != "completed" and not allow_incomplete_runs:
        raise RepairEvalError(
            f"{manifest_path}: run status is {status!r}, not 'completed'. "
            "Use --allow-incomplete-runs only if the partial run is understood."
        )
    manifest_dataset_sha = _dataset_sha_from_manifest(manifest)
    _need(
        manifest_dataset_sha is not None,
        f"{manifest_path}: no dataset SHA-256 recorded; refusing provenance check",
    )
    _need(
        manifest_dataset_sha == dataset.sha256,
        f"{manifest_path}: dataset SHA-256 does not match {dataset.path}",
    )
    config = manifest.get("config")
    _need(isinstance(config, dict), f"{manifest_path}: config block is missing")
    task = config.get("task")
    _need(
        task in {"repair", "both"},
        f"{manifest_path}: task={task!r}; this tool needs repair output",
    )
    strategy = config.get("strategy")
    _need(
        strategy in KNOWN_STRATEGIES,
        f"{manifest_path}: unsupported or missing config.strategy {strategy!r}",
    )
    config_sha = config.get("dataset_sha256")
    if isinstance(config_sha, str):
        _need(
            config_sha == dataset.sha256,
            f"{manifest_path}: config.dataset_sha256 does not match the dataset",
        )
    api = manifest.get("api")
    _need(isinstance(api, dict), f"{manifest_path}: api block is missing")
    _need(
        isinstance(api.get("model"), str) and bool(api["model"].strip()),
        f"{manifest_path}: api.model is missing",
    )
    endpoint = api.get("endpoint")
    _need(
        isinstance(endpoint, str) and bool(endpoint.strip()),
        f"{manifest_path}: api.endpoint is missing",
    )
    if _is_local_endpoint(endpoint) and not allow_local_endpoint:
        raise RepairEvalError(
            f"{manifest_path}: endpoint {endpoint!r} is local. A formal blind package "
            "refuses mock/local endpoints; use --allow-local-endpoint only for a "
            "verified local deployment, never for mock results."
        )
    return manifest_path, sha256_file(manifest_path), manifest


def load_results(
    paths: Iterable[str | Path],
    dataset: DatasetInfo,
    *,
    allow_missing_manifest: bool = False,
    allow_incomplete_runs: bool = False,
    allow_local_endpoint: bool = False,
) -> tuple[dict[str, dict[str, RepairCandidate]], list[ResultsFileInfo], Counter[str], list[str]]:
    result_paths = [Path(path) for path in paths]
    _need(bool(result_paths), "at least one --results file is required")
    by_pair: dict[str, dict[str, RepairCandidate]] = {}
    files: list[ResultsFileInfo] = []
    excluded: Counter[str] = Counter()
    models: list[str] = []
    seen_locations: dict[tuple[str, str], str] = {}

    for results_path in result_paths:
        _need(results_path.exists(), f"results file does not exist: {results_path}")
        _need(results_path.is_file(), f"results path is not a file: {results_path}")
        manifest_path, manifest_sha, manifest = _check_manifest(
            results_path,
            dataset,
            allow_missing_manifest=allow_missing_manifest,
            allow_incomplete_runs=allow_incomplete_runs,
            allow_local_endpoint=allow_local_endpoint,
        )
        info = ResultsFileInfo(
            path=results_path.resolve(),
            sha256=sha256_file(results_path),
            manifest_path=manifest_path.resolve() if manifest_path else None,
            manifest_sha256=manifest_sha,
            run_id=None if manifest is None else manifest.get("run_id"),
            status=None if manifest is None else manifest.get("status"),
            model=None if manifest is None else manifest.get("api", {}).get("model"),
            endpoint=None if manifest is None else manifest.get("api", {}).get("endpoint"),
            provenance_unverified=manifest is None,
        )
        manifest_strategy = None
        manifest_model = info.model
        if manifest is not None:
            config = manifest.get("config")
            if isinstance(config, dict):
                manifest_strategy = config.get("strategy")
                _need(
                    manifest_strategy in KNOWN_STRATEGIES,
                    f"{manifest_path}: unsupported strategy {manifest_strategy!r}",
                )
        rows = read_jsonl(results_path)
        info.records_total = len(rows)
        for index, record in enumerate(rows, start=1):
            if record.get("task") != "repair":
                continue
            info.repair_records += 1
            where = f"{results_path}: record {index}"
            status = record.get("status")
            response = record.get("response")
            if status != "ok":
                excluded[f"status_{status}"] += 1
                continue
            if not isinstance(response, dict):
                excluded["missing_response"] += 1
                continue
            if response.get("status") != "ok":
                excluded["response_not_ok"] += 1
                continue
            if response.get("http_status") != 200:
                excluded["http_status_not_200"] += 1
                continue
            info.http_200_repair += 1
            parsed = record.get("parsed")
            validation = record.get("validation")
            if not isinstance(parsed, dict) or not isinstance(parsed.get("fixed_function"), str):
                excluded["missing_parsed_fixed_function"] += 1
                continue
            if not isinstance(validation, dict) or validation.get("schema_valid") is not True:
                excluded["schema_invalid"] += 1
                continue
            fixed_function = parsed["fixed_function"]
            explanation = parsed.get("explanation")
            if not fixed_function.strip():
                excluded["empty_fixed_function"] += 1
                continue
            if not isinstance(explanation, str):
                excluded["missing_explanation"] += 1
                continue
            sample_id = record.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id:
                raise RepairEvalError(f"{where}: missing sample_id")
            pair_id = record.get("pair_id")
            if not isinstance(pair_id, str) or not pair_id:
                match = re.match(r"^pair:(.+):vulnerable$", sample_id)
                _need(
                    match is not None,
                    f"{where}: cannot derive pair_id from sample_id {sample_id!r}",
                )
                pair_id = match.group(1)
            pair = dataset.pairs.get(pair_id)
            if pair is None:
                raise RepairEvalError(
                    f"{where}: pair_id {pair_id!r} / sample_id {sample_id!r} is not in "
                    f"{dataset.path}; results and dataset do not match"
                )
            expected_sample_id = f"pair:{pair_id}:vulnerable"
            _need(
                sample_id == expected_sample_id,
                f"{where}: sample_id {sample_id!r} does not match {expected_sample_id!r}",
            )
            if "idx" in record:
                _need(
                    record["idx"] == pair.vulnerable_idx,
                    f"{where}: idx does not match the vulnerable function",
                )
            if "side" in record:
                _need(
                    record["side"] == "vulnerable",
                    f"{where}: repair records must be the vulnerable side",
                )
            if "label" in record:
                _need(record["label"] is True, f"{where}: repair record must be labelled true")
            prompt = record.get("prompt")
            if isinstance(prompt, dict):
                function = prompt.get("function")
                if isinstance(function, dict) and isinstance(function.get("code_sha256"), str):
                    expected_code_sha = sha256_text(pair.vulnerable_code)
                    _need(
                        function["code_sha256"] == expected_code_sha,
                        f"{where}: prompt function SHA-256 does not match the dataset "
                        "vulnerable function (stale or different dataset)",
                    )
            strategy = record.get("strategy")
            _need(
                strategy in KNOWN_STRATEGIES,
                f"{where}: unsupported strategy {strategy!r}",
            )
            if manifest_strategy is not None:
                _need(
                    strategy == manifest_strategy,
                    f"{where}: strategy {strategy!r} does not match manifest "
                    f"strategy {manifest_strategy!r}",
                )
            request = record.get("request")
            record_model = None
            record_endpoint = None
            if isinstance(request, dict):
                record_model = request.get("model")
                record_endpoint = request.get("endpoint")
                if isinstance(record_endpoint, str) and _is_local_endpoint(record_endpoint):
                    _need(
                        allow_local_endpoint,
                        f"{where}: local endpoint {record_endpoint!r} is not allowed for a "
                        "formal blind package",
                    )
            if (
                info.endpoint
                and isinstance(record_endpoint, str)
                and record_endpoint
                and record_endpoint != info.endpoint
            ):
                raise RepairEvalError(
                    f"{where}: record endpoint {record_endpoint!r} does not match "
                    f"manifest endpoint {info.endpoint!r}"
                )
            model = record_model if isinstance(record_model, str) and record_model.strip() else manifest_model
            _need(
                isinstance(model, str) and bool(model.strip()),
                f"{where}: no model ID recorded; refusing unverifiable result",
            )
            if manifest_model and record_model and manifest_model != record_model:
                raise RepairEvalError(
                    f"{where}: record model {record_model!r} does not match manifest "
                    f"model {manifest_model!r}"
                )
            expected_fixed_sha = sha256_text(fixed_function)
            recorded_fixed_sha = validation.get("fixed_code_sha256")
            if isinstance(recorded_fixed_sha, str):
                _need(
                    recorded_fixed_sha == expected_fixed_sha,
                    f"{where}: validation.fixed_code_sha256 does not match parsed output",
                )
            location = f"{results_path}:{index}"
            key = (pair_id, strategy)
            if key in seen_locations:
                raise RepairEvalError(
                    f"duplicate repair candidate for pair {pair_id!r} and strategy "
                    f"{strategy!r}: {seen_locations[key]} and {location}. "
                    "Supply exactly one results file per strategy/run."
                )
            seen_locations[key] = location
            candidate = RepairCandidate(
                pair_id=pair_id,
                strategy=strategy,
                sample_id=sample_id,
                model=model,
                fixed_function=fixed_function,
                explanation=explanation,
                validation=dict(validation),
                source_path=results_path.resolve(),
                source_index=index,
            )
            by_pair.setdefault(pair_id, {})[strategy] = candidate
            info.valid_candidates += 1
            models.append(model)
        files.append(info)

    if not any(by_pair.values()):
        raise RepairEvalError(
            "no schema-valid repair candidates were found. If the run ended with 401/API "
            "errors, do not build a blind package; fix credentials and rerun the real "
            "experiment first."
        )
    return by_pair, files, excluded, sorted(set(models))


def build_frame(
    dataset: DatasetInfo,
    by_pair: dict[str, dict[str, RepairCandidate]],
    *,
    strategies: tuple[str, ...] | None,
    min_candidates_per_case: int,
    max_function_chars: int,
) -> tuple[list[CaseInfo], dict[str, int], tuple[str, ...], int]:
    observed = tuple(
        sorted({candidate.strategy for candidates in by_pair.values() for candidate in candidates.values()})
    )
    if strategies is None:
        selected_strategies = observed
    else:
        selected_strategies = tuple(dict.fromkeys(strategies))
        missing = [strategy for strategy in selected_strategies if strategy not in observed]
        _need(not missing, f"requested strategies have no valid repair output: {missing}")
    _need(
        len(selected_strategies) >= 2,
        "at least two strategies with valid repair output are required for a blind comparison",
    )
    _need(
        1 <= min_candidates_per_case <= len(selected_strategies),
        f"min_candidates_per_case must be between 1 and {len(selected_strategies)}",
    )
    frame: list[CaseInfo] = []
    exclusions: Counter[str] = Counter()
    for pair_id in sorted(dataset.pairs):
        pair = dataset.pairs[pair_id]
        if len(pair.vulnerable_code) > max_function_chars:
            exclusions["function_too_long"] += 1
            continue
        available = by_pair.get(pair_id, {})
        candidates = tuple(
            available[strategy]
            for strategy in selected_strategies
            if strategy in available
        )
        if not candidates:
            exclusions["no_valid_candidate"] += 1
            continue
        if len(candidates) < min_candidates_per_case:
            exclusions["insufficient_valid_candidates"] += 1
            continue
        frame.append(CaseInfo(pair=pair, candidates=candidates))
    return frame, dict(sorted(exclusions.items())), selected_strategies, len(frame)


def _stratum_key(case: CaseInfo) -> str:
    return f"{case.pair.cwe_family}|{case.pair.length_bin}"


def _allocation(
    strata: dict[str, list[CaseInfo]], target: int, seed: int
) -> dict[str, int]:
    keys = sorted(strata, key=lambda key: (-len(strata[key]), key))
    allocation = {key: 0 for key in keys}
    remaining = target
    for key in keys:
        if remaining <= 0:
            break
        allocation[key] = 1
        remaining -= 1
    while remaining > 0:
        available = [key for key in keys if allocation[key] < len(strata[key])]
        if not available:
            break
        key = max(
            available,
            key=lambda item: (
                (len(strata[item]) - allocation[item]) / (allocation[item] + 1),
                salted_id(str(seed), "allocation", item),
            ),
        )
        allocation[key] += 1
        remaining -= 1
    return allocation


def _select_with_cap(
    strata: dict[str, list[CaseInfo]],
    allocation: dict[str, int],
    *,
    cap: int | None,
    seed: int,
    target: int,
) -> list[CaseInfo]:
    keys = sorted(strata, key=lambda key: (-len(strata[key]), key))
    ordered: dict[str, list[CaseInfo]] = {}
    ranks: dict[str, dict[str, int]] = {}
    for key in keys:
        cases = sorted(strata[key], key=lambda case: case.pair.pair_id)
        rng = random.Random(int(salted_id(str(seed), "order", key)[:16], 16))
        rng.shuffle(cases)
        ordered[key] = cases
        ranks[key] = {case.pair.pair_id: position for position, case in enumerate(cases)}
    remaining = {key: allocation.get(key, 0) for key in keys}
    selected: list[CaseInfo] = []
    selected_ids: set[str] = set()
    project_counts: Counter[str] = Counter()
    while sum(remaining.values()) > 0:
        progress = False
        for key in keys:
            if remaining[key] <= 0:
                continue
            pool = [
                case
                for case in ordered[key]
                if case.pair.pair_id not in selected_ids
                and (cap is None or project_counts[case.pair.project] < cap)
            ]
            if not pool:
                continue
            case = min(
                pool,
                key=lambda item: (
                    project_counts[item.pair.project],
                    ranks[key][item.pair.pair_id],
                ),
            )
            selected.append(case)
            selected_ids.add(case.pair.pair_id)
            project_counts[case.pair.project] += 1
            remaining[key] -= 1
            progress = True
        if not progress:
            break
    while len(selected) < target:
        global_pool: list[tuple[int, int, str, CaseInfo]] = []
        for key in keys:
            for case in ordered[key]:
                if case.pair.pair_id in selected_ids:
                    continue
                if cap is not None and project_counts[case.pair.project] >= cap:
                    continue
                global_pool.append(
                    (
                        project_counts[case.pair.project],
                        ranks[key][case.pair.pair_id],
                        key,
                        case,
                    )
                )
        if not global_pool:
            break
        _, _, _, case = min(global_pool, key=lambda item: (item[0], item[1], item[2]))
        selected.append(case)
        selected_ids.add(case.pair.pair_id)
        project_counts[case.pair.project] += 1
    return selected


def sample_cases(
    frame: list[CaseInfo],
    *,
    requested_pairs: int,
    seed: int,
    max_per_project: int,
) -> SamplingResult:
    _need(
        MIN_PAIRS <= requested_pairs <= MAX_PAIRS,
        f"--pairs must be between {MIN_PAIRS} and {MAX_PAIRS}",
    )
    _need(
        len(frame) >= MIN_PAIRS,
        f"only {len(frame)} eligible pairs with valid repairs; a blind package needs "
        f"at least {MIN_PAIRS}. Do not lower this threshold with synthetic data.",
    )
    warnings: list[str] = []
    target = min(requested_pairs, len(frame))
    if target < requested_pairs:
        warnings.append(
            f"requested_pairs_reduced_from_{requested_pairs}_to_{target}_eligible"
        )
    strata: dict[str, list[CaseInfo]] = {}
    for case in frame:
        strata.setdefault(_stratum_key(case), []).append(case)
    allocation = _allocation(strata, target, seed)
    cap_sequence: list[int | None] = []
    if max_per_project > 0:
        cap_sequence.append(max_per_project)
        cap_sequence.append(max_per_project + 1)
        cap_sequence.append(None)
    else:
        cap_sequence.append(None)
    selected: list[CaseInfo] = []
    cap_used: int | None = None
    for cap in cap_sequence:
        selected = _select_with_cap(
            strata, allocation, cap=cap, seed=seed, target=target
        )
        cap_used = cap
        if len(selected) >= target:
            break
    if len(selected) < target:
        raise RepairEvalError(
            f"could not select {target} cases even after relaxing the project cap; "
            f"selected {len(selected)}"
        )
    selected = selected[:target]
    if max_per_project > 0 and cap_used != max_per_project:
        warnings.append(
            "project_cap_relaxed_from_%s_to_%s"
            % (max_per_project, cap_used if cap_used is not None else "unlimited")
        )
    order_rng = random.Random(int(salted_id(str(seed), "case-display-order")[:16], 16))
    selected.sort(key=lambda case: case.pair.pair_id)
    order_rng.shuffle(selected)
    stratum_rows: list[dict[str, Any]] = []
    selected_counts = Counter(_stratum_key(case) for case in selected)
    for key in sorted(strata):
        family, bin_name = key.split("|", 1)
        stratum_rows.append(
            {
                "cwe_family": family,
                "length_bin": bin_name,
                "available": len(strata[key]),
                "allocated": allocation.get(key, 0),
                "selected": selected_counts.get(key, 0),
            }
        )
    return SamplingResult(
        selected=selected,
        requested_pairs=requested_pairs,
        target_pairs=target,
        strata=stratum_rows,
        allocation=allocation,
        project_cap_used=cap_used,
        warnings=warnings,
        frame_exclusions={},
        frame_size=len(frame),
    )
