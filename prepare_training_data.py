#!/usr/bin/env python3
"""
Prepare Training Data for Spatial GNN

This script:
1. Extracts CPG structures from Java files using Joern
2. Labels them as vulnerable/safe with vulnerability types
3. Creates PyTorch Geometric Data objects
4. Splits into train/val/test sets

Usage:
    # Directory mode (scan a folder of .java files)
    python prepare_training_data.py --dataset dir --input tests/samples --output training_data/samples \
      --train-split 0.7 --val-split 0.15 --test-split 0.15

    # Vul4J mode (real CVEs; clones upstream repos and creates paired vulnerable/fixed samples)
    python prepare_training_data.py --dataset vul4j --output training_data/vul4j \
      --vul4j-limit-vulns 50 --vul4j-max-files-per-vuln 2
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import subprocess
import tempfile
import re
import torch
from torch_geometric.data import Data
import pickle
from tqdm import tqdm
import random
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
LOG = logging.getLogger(__name__)


# Vulnerability type mapping (24 types from Bean Vulnerable)
VULNERABILITY_TYPES = {
    'SQL_INJECTION': 0,
    'COMMAND_INJECTION': 1,
    'XSS': 2,
    'PATH_TRAVERSAL': 3,
    'XXE': 4,
    'SSRF': 5,
    'DESERIALIZATION': 6,
    'LDAP_INJECTION': 7,
    'LOG_INJECTION': 8,
    'XPATH_INJECTION': 9,
    'TRUST_BOUNDARY_VIOLATION': 10,
    'REFLECTION_INJECTION': 11,
    'RACE_CONDITION': 12,
    'WEAK_CRYPTO': 13,
    'HARDCODED_CREDENTIALS': 14,
    'INSECURE_RANDOM': 15,
    'NULL_DEREFERENCE': 16,
    'RESOURCE_LEAK': 17,
    'BUFFER_OVERFLOW': 18,
    'INTEGER_OVERFLOW': 19,
    'USE_AFTER_FREE': 20,
    'DOUBLE_FREE': 21,
    'MEMORY_LEAK': 22,
    'SAFE': 23  # No vulnerability
}


def _build_joern_env() -> Dict[str, str]:
    env = dict(os.environ)
    java_opts = env.get("JAVA_TOOL_OPTIONS", "")
    if "-Dfile.encoding=UTF-8" not in java_opts:
        env["JAVA_TOOL_OPTIONS"] = (java_opts + " " if java_opts else "") + "-Dfile.encoding=UTF-8"
    env.setdefault("LC_ALL", "en_US.UTF-8")
    env.setdefault("LANG", "en_US.UTF-8")
    # macOS: Homebrew often sets DYLD_LIBRARY_PATH which can break Joern/Java native
    # linking (e.g., `java.util.zip.Inflater.initIDs()` UnsatisfiedLinkError).
    # Joern should run with a clean dynamic library search path.
    env.pop("DYLD_LIBRARY_PATH", None)
    env.pop("DYLD_FALLBACK_LIBRARY_PATH", None)
    env.pop("DYLD_INSERT_LIBRARIES", None)
    return env


def extract_cpg_structure(java_file: Path, output_dir: Path, timeout: int = 480) -> Dict:
    """
    Extract CPG structure using Joern script
    
    Args:
        java_file: Path to Java source file
        output_dir: Output directory for CPG JSON
        timeout: Timeout in seconds (default: 480)
        
    Returns:
        CPG structure dictionary
    """
    script_path = Path(__file__).parent / "extract_cpg_for_gnn.sc"
    
    cmd = [
        "joern",
        "--script", str(script_path),
        "--param", f"cpgFile={java_file}",
        "--param", f"outputDir={output_dir}"
    ]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_build_joern_env(),
    )
    
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        combined = stderr or stdout
        if "UnsupportedClassVersionError" in combined or "class file version 55.0" in combined:
            LOG.error("Joern requires Java 11+. Set JAVA_HOME to a JDK 11+ before training.")
        if "MalformedInputException" in combined:
            LOG.error("Joern failed to read source; ensure UTF-8 locale or set JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8.")
        LOG.error(f"CPG extraction failed for {java_file}: {combined}")
        return None
    
    cpg_file = output_dir / "cpg_structure.json"
    if not cpg_file.exists():
        LOG.error(f"CPG file not found: {cpg_file}")
        return None
    
    with open(cpg_file, 'r') as f:
        cpg_structure = json.load(f)
    
    return cpg_structure


def infer_vulnerability_label(java_file: Path) -> Tuple[int, int]:
    """
    Infer vulnerability label from filename
    
    Expects filenames like: VUL001_SQLInjection_Basic.java, VUL019_TrustBoundaryViolation.java
    Or: SAFE_Example.java
    
    Returns:
        (binary_label, multiclass_label) where:
        - binary_label: 0=safe, 1=vulnerable
        - multiclass_label: vulnerability type ID from VULNERABILITY_TYPES
    """
    filename = java_file.stem
    
    # Check if it's a safe file
    if filename.startswith('SAFE') or 'Safe' in filename or 'good' in filename.lower():
        return (0, VULNERABILITY_TYPES['SAFE'])
    
    # Check for vulnerability type in filename
    filename_upper = filename.upper()
    
    for vuln_type, type_id in VULNERABILITY_TYPES.items():
        if vuln_type in filename_upper or vuln_type.replace('_', '') in filename_upper:
            return (1, type_id)
    
    # Default: assume vulnerable with unknown type
    LOG.warning(f"Could not infer vulnerability type from {filename}, defaulting to SQL_INJECTION")
    return (1, VULNERABILITY_TYPES['SQL_INJECTION'])


def cpg_to_pyg_data(cpg_structure: Dict, binary_label: int, multiclass_label: int) -> Data:
    """
    Convert CPG structure to PyTorch Geometric Data object
    
    Args:
        cpg_structure: CPG structure from Joern
        binary_label: Binary vulnerability label (0=safe, 1=vulnerable)
        multiclass_label: Multiclass vulnerability type label
        
    Returns:
        PyTorch Geometric Data object
    """
    nodes = cpg_structure['nodes']
    edges = cpg_structure['edges']
    
    # Node type and category encodings
    node_type_mapping = {
        'METHOD': 0, 'CALL': 1, 'IDENTIFIER': 2, 'LITERAL': 3,
        'LOCAL': 4, 'BLOCK': 5, 'CONTROL_STRUCTURE': 6, 'RETURN': 7,
        'METHOD_PARAMETER_IN': 8, 'FIELD_IDENTIFIER': 9, 'TYPE': 10
    }
    
    category_mapping = {
        'method': 0, 'call': 1, 'identifier': 2, 'literal': 3,
        'local': 4, 'block': 5, 'control': 6, 'return': 7,
        'parameter': 8, 'field': 9, 'type': 10, 'other': 11
    }
    
    # Create node features (128-dimensional)
    # IMPORTANT: Do NOT leak graph labels into node features.
    # Labels are provided via y_binary/y_multiclass only.
    node_features = []
    node_tokens = []
    for node in nodes:
        code = node.get("code") or node.get("name") or ""
        if not isinstance(code, str):
            code = str(code)
        node_tokens.append(code)
        features = [
            float(node_type_mapping.get(node.get("node_type"), 11)) / 12.0,
            float(category_mapping.get(node.get("category"), 11)) / 12.0,
            float(node.get("line", 0)) / 1000.0,
            float(node.get("order", 0)) / 100.0,
            float(bool(node.get("is_source", False))),
            float(bool(node.get("is_sink", False))),
            float(len(code)) / 200.0,
            float(bool(node.get("name"))),
            0.0,  # binary label placeholder (kept for schema parity with inference)
            0.0,  # multiclass label placeholder
        ]
        # Pad to 128 dimensions
        while len(features) < 128:
            features.append(0.0)
        node_features.append(features[:128])
    
    x = torch.tensor(node_features, dtype=torch.float32)
    
    # Create edge index
    edge_list = []
    edge_types = []
    
    for edge in edges:
        src = int(edge['source'])
        tgt = int(edge['target'])
        edge_type_id = int(edge['edge_type_id'])
        
        if src < len(nodes) and tgt < len(nodes) and src != tgt:
            edge_list.append([src, tgt])
            edge_types.append(edge_type_id)
    
    if not edge_list:
        # Create minimal connectivity
        for i in range(len(nodes) - 1):
            edge_list.append([i, i + 1])
            edge_types.append(2)  # DFG
    
    edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
    edge_type = torch.tensor(edge_types, dtype=torch.long)
    
    # Create labels
    y_binary = torch.tensor([binary_label], dtype=torch.long)
    y_multiclass = torch.tensor([multiclass_label], dtype=torch.long)
    
    # Create Data object
    data = Data(
        x=x,
        edge_index=edge_index,
        edge_type=edge_type,
        y_binary=y_binary,
        y_multiclass=y_multiclass
    )
    # Optional tokens for semantic embedding modules (e.g., CodeBERT)
    data.node_tokens = node_tokens
    
    return data


def _validate_split_ratios(train_split: float, val_split: float, test_split: float) -> None:
    total = float(train_split) + float(val_split) + float(test_split)
    if abs(total - 1.0) > 1e-6:
        raise ValueError(
            f"Split ratios must sum to 1.0; got train={train_split}, val={val_split}, test={test_split} (sum={total})"
        )


def _split_dataset(
    dataset: List[Data],
    *,
    train_split: float,
    val_split: float,
    test_split: float,
    seed: int,
    group_attr: Optional[str] = None,
) -> Tuple[List[Data], List[Data], List[Data], Dict[str, object]]:
    """
    Split a dataset into train/val/test.

    If group_attr is provided, **all samples sharing the same group id** (e.g. a Vul4J ID)
    will remain in the same split to prevent train/test leakage across paired versions.
    """
    _validate_split_ratios(train_split, val_split, test_split)

    if not dataset:
        return [], [], [], {"split_strategy": "empty"}

    rng = random.Random(seed)

    if not group_attr:
        rng.shuffle(dataset)
        n = len(dataset)
        train_end = int(n * train_split)
        val_end = train_end + int(n * val_split)
        return (
            dataset[:train_end],
            dataset[train_end:val_end],
            dataset[val_end:],
            {"split_strategy": "random_sample", "num_samples": n},
        )

    # Group-aware split
    groups: Dict[str, List[Data]] = {}
    for sample in dataset:
        gid = getattr(sample, group_attr, None)
        gid = str(gid) if gid is not None else "unknown"
        groups.setdefault(gid, []).append(sample)

    group_ids = list(groups.keys())
    rng.shuffle(group_ids)

    g = len(group_ids)
    train_end = int(g * train_split)
    val_end = train_end + int(g * val_split)

    train_groups = set(group_ids[:train_end])
    val_groups = set(group_ids[train_end:val_end])
    test_groups = set(group_ids[val_end:])

    train_data: List[Data] = []
    val_data: List[Data] = []
    test_data: List[Data] = []

    for gid in group_ids:
        if gid in train_groups:
            train_data.extend(groups[gid])
        elif gid in val_groups:
            val_data.extend(groups[gid])
        else:
            test_data.extend(groups[gid])

    meta = {
        "split_strategy": f"group_by_{group_attr}",
        "num_samples": len(dataset),
        "num_groups": g,
        "train_groups": len(train_groups),
        "val_groups": len(val_groups),
        "test_groups": len(test_groups),
    }
    return train_data, val_data, test_data, meta


def _save_splits(
    *,
    output_dir: Path,
    train_data: List[Data],
    val_data: List[Data],
    test_data: List[Data],
    metadata: Dict[str, object],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "train.pkl", "wb") as f:
        pickle.dump(train_data, f)
    with open(output_dir / "val.pkl", "wb") as f:
        pickle.dump(val_data, f)
    with open(output_dir / "test.pkl", "wb") as f:
        pickle.dump(test_data, f)

    with open(output_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    LOG.info(f"✅ Saved training data to {output_dir}")
    LOG.info(f"   - train.pkl: {len(train_data)} samples")
    LOG.info(f"   - val.pkl:   {len(val_data)} samples")
    LOG.info(f"   - test.pkl:  {len(test_data)} samples")
    LOG.info("   - metadata.json: Dataset statistics")


def prepare_dataset(
    input_dir: Path,
    output_dir: Path,
    train_split: float = 0.7,
    val_split: float = 0.15,
    test_split: float = 0.15,
    timeout: int = 480,
    limit: Optional[int] = None,
    seed: int = 42,
):
    """
    Prepare training dataset from Java files
    
    Args:
        input_dir: Directory containing Java files
        output_dir: Output directory for processed data
        train_split: Training set split ratio
        val_split: Validation set split ratio
        test_split: Test set split ratio
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all Java files
    java_files = sorted(input_dir.rglob("*.java"))
    LOG.info(f"Found {len(java_files)} Java files")

    if limit and limit > 0 and len(java_files) > limit:
        rng = random.Random(seed)
        rng.shuffle(java_files)
        java_files = java_files[:limit]
        LOG.info(f"Using limited sample: {len(java_files)} files (seed={seed})")
    
    if len(java_files) == 0:
        LOG.error("No Java files found!")
        return
    
    # Process each file
    dataset = []
    
    with tempfile.TemporaryDirectory() as tmpdir:
        for java_file in tqdm(java_files, desc="Processing files"):
            try:
                # Extract CPG
                cpg_structure = extract_cpg_structure(java_file, Path(tmpdir), timeout=timeout)
                
                if cpg_structure is None:
                    LOG.warning(f"Skipping {java_file} - CPG extraction failed")
                    continue
                
                # Infer label
                binary_label, multiclass_label = infer_vulnerability_label(java_file)
                
                # Convert to PyG Data
                data = cpg_to_pyg_data(cpg_structure, binary_label, multiclass_label)
                
                # Add metadata
                data.filename = str(java_file.name)
                data.num_nodes = len(cpg_structure['nodes'])
                data.num_edges = len(cpg_structure['edges'])
                
                dataset.append(data)
                
                LOG.info(f"✅ Processed {java_file.name}: {data.num_nodes} nodes, "
                        f"{data.num_edges} edges, "
                        f"label={binary_label}/{multiclass_label}")
                
            except Exception as e:
                LOG.error(f"Error processing {java_file}: {e}")
                continue
    
    LOG.info(f"✅ Successfully processed {len(dataset)} files")
    if not dataset:
        LOG.error("No CPGs extracted. Verify Java 11+ and UTF-8 locale for Joern.")
        return
    
    train_data, val_data, test_data, split_meta = _split_dataset(
        dataset,
        train_split=train_split,
        val_split=val_split,
        test_split=test_split,
        seed=seed,
        group_attr=None,
    )

    LOG.info(f"Split: Train={len(train_data)}, Val={len(val_data)}, Test={len(test_data)}")

    metadata: Dict[str, object] = {
        "dataset_type": "directory",
        "input_dir": str(input_dir),
        "num_files": len(dataset),
        "train_size": len(train_data),
        "val_size": len(val_data),
        "test_size": len(test_data),
        "vulnerability_types": VULNERABILITY_TYPES,
        "split_ratios": {"train": train_split, "val": val_split, "test": test_split},
        "split": split_meta,
        "seed": seed,
    }

    _save_splits(
        output_dir=output_dir,
        train_data=train_data,
        val_data=val_data,
        test_data=test_data,
        metadata=metadata,
    )


def _is_test_path(file_path: str) -> bool:
    p = (file_path or "").replace("\\", "/").lower()
    return (
        p.startswith("test/")
        or p.startswith("tests/")
        or "/test/" in p
        or "/tests/" in p
        or "/src/test/" in p
        or "/src/tests/" in p
    )


def _sanitize_sample_name(text: str) -> str:
    s = str(text)
    s = s.replace("\\", "/")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


def _run_git(
    args: List[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 600,
    check: bool = True,
) -> subprocess.CompletedProcess:
    cmd = ["git", *args]
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        msg = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {msg}")
    return result


def _ensure_repo_available(
    *,
    repo_slug: str,
    cache_dir: Path,
    commit: str,
    git_timeout: int,
) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    safe_name = repo_slug.replace("/", "__")
    repo_dir = cache_dir / safe_name
    repo_url = f"https://github.com/{repo_slug}.git"

    if not (repo_dir / ".git").exists():
        LOG.info(f"📥 Cloning {repo_slug} into cache ({repo_dir})")
        # Attempt partial clone; fallback if unsupported.
        res = _run_git(
            ["clone", "--no-checkout", "--filter=blob:none", repo_url, str(repo_dir)],
            timeout=git_timeout,
            check=False,
        )
        if res.returncode != 0:
            LOG.warning("Partial clone failed; falling back to full clone.")
            _run_git(["clone", "--no-checkout", repo_url, str(repo_dir)], timeout=git_timeout, check=True)

    # Fetch the commit (depth 2 usually brings its parent)
    fetched = _run_git(
        ["fetch", "--depth", "2", "origin", commit],
        cwd=repo_dir,
        timeout=git_timeout,
        check=False,
    )
    if fetched.returncode != 0:
        _run_git(["fetch", "origin"], cwd=repo_dir, timeout=git_timeout, check=True)

    return repo_dir


def _commit_parent(repo_dir: Path, commit: str, git_timeout: int) -> Optional[str]:
    res = _run_git(["rev-parse", f"{commit}^"], cwd=repo_dir, timeout=git_timeout, check=False)
    if res.returncode != 0:
        return None
    parent = (res.stdout or "").strip()
    return parent or None


def _changed_java_files(repo_dir: Path, parent: str, commit: str, git_timeout: int) -> List[str]:
    res = _run_git(["diff", "--name-only", parent, commit], cwd=repo_dir, timeout=git_timeout, check=True)
    paths: List[str] = []
    for line in (res.stdout or "").splitlines():
        p = line.strip()
        if not p or not p.endswith(".java"):
            continue
        if _is_test_path(p):
            continue
        paths.append(p)
    return paths


def _git_show_file(repo_dir: Path, commit: str, file_path: str, git_timeout: int) -> Optional[str]:
    res = _run_git(["show", f"{commit}:{file_path}"], cwd=repo_dir, timeout=git_timeout, check=False)
    if res.returncode != 0:
        return None
    return res.stdout


def prepare_vul4j_dataset(
    *,
    vul4j_csv: Path,
    output_dir: Path,
    cache_dir: Path,
    train_split: float = 0.7,
    val_split: float = 0.15,
    test_split: float = 0.15,
    timeout: int = 480,
    seed: int = 42,
    limit_vulns: Optional[int] = None,
    max_files_per_vuln: int = 3,
    allow_unmapped: bool = False,
    unmapped_fallback: str = "TRUST_BOUNDARY_VIOLATION",
    git_timeout: int = 600,
) -> None:
    """
    Prepare training data from Vul4J (real-world CVE vulnerabilities).

    Produces paired samples per modified Java file:
    - vulnerable snapshot (commit parent): y_binary=1, y_multiclass=mapped vulnerability type
    - fixed snapshot (human_patch commit): y_binary=0, y_multiclass=SAFE

    Splits by Vul4J ID to prevent leakage across paired snapshots.
    """
    try:
        from src.integrations.vul4j_parser import (  # type: ignore
            Vul4JDataset,
            map_vul4j_to_bean_vuln_type,
            parse_human_patch_commit_hash,
        )
    except Exception:  # pragma: no cover - supports PYTHONPATH=src style
        from integrations.vul4j_parser import (  # type: ignore
            Vul4JDataset,
            map_vul4j_to_bean_vuln_type,
            parse_human_patch_commit_hash,
        )

    if max_files_per_vuln <= 0:
        raise ValueError("--vul4j-max-files-per-vuln must be >= 1")
    if unmapped_fallback not in VULNERABILITY_TYPES:
        raise ValueError(
            f"--vul4j-unmapped-fallback must be one of {sorted(VULNERABILITY_TYPES.keys())}; got {unmapped_fallback}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    vul4j = Vul4JDataset(vul4j_csv)
    records = list(vul4j.iter_records())
    if not records:
        LOG.error("Vul4J CSV loaded, but contains no records.")
        return

    rng = random.Random(seed)
    rng.shuffle(records)
    if limit_vulns and limit_vulns > 0 and len(records) > limit_vulns:
        records = records[:limit_vulns]
        LOG.info(f"Using limited Vul4J sample: {len(records)} vulnerabilities (seed={seed})")

    attempted = 0
    skipped = 0
    dataset: List[Data] = []
    mapped_type_counts: Dict[str, int] = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        for rec in tqdm(records, desc="Processing Vul4J vulnerabilities"):
            attempted += 1

            mapped_type = map_vul4j_to_bean_vuln_type(
                cwe_id=rec.cwe_id,
                cwe_name=rec.cwe_name,
                repo_slug=rec.repo_slug,
                cve_id=rec.cve_id,
            )
            if mapped_type is None:
                if allow_unmapped:
                    mapped_type = unmapped_fallback
                else:
                    skipped += 1
                    continue

            multiclass_vuln = VULNERABILITY_TYPES[mapped_type]
            mapped_type_counts[mapped_type] = mapped_type_counts.get(mapped_type, 0) + 1

            commit = parse_human_patch_commit_hash(rec.human_patch)
            if not commit:
                skipped += 1
                continue

            try:
                repo_dir = _ensure_repo_available(
                    repo_slug=rec.repo_slug,
                    cache_dir=cache_dir,
                    commit=commit,
                    git_timeout=git_timeout,
                )
                parent = _commit_parent(repo_dir, commit, git_timeout)
                if not parent:
                    skipped += 1
                    continue

                changed_files = _changed_java_files(repo_dir, parent, commit, git_timeout)
                if not changed_files:
                    skipped += 1
                    continue

                for file_path in changed_files[:max_files_per_vuln]:
                    vuln_src = _git_show_file(repo_dir, parent, file_path, git_timeout)
                    fix_src = _git_show_file(repo_dir, commit, file_path, git_timeout)
                    if vuln_src is None or fix_src is None:
                        continue

                    variants = [
                        ("vulnerable", vuln_src, 1, multiclass_vuln),
                        ("human_patch", fix_src, 0, VULNERABILITY_TYPES["SAFE"]),
                    ]

                    for version, src, bin_lbl, multi_lbl in variants:
                        safe_file = _sanitize_sample_name(file_path)
                        temp_java = tmp_root / f"{rec.vul_id}__{version}__{safe_file}"
                        temp_java.write_text(src, encoding="utf-8", errors="replace")

                        cpg_structure = extract_cpg_structure(temp_java, tmp_root, timeout=timeout)
                        if cpg_structure is None:
                            continue

                        data = cpg_to_pyg_data(cpg_structure, bin_lbl, multi_lbl)
                        data.filename = str(temp_java.name)
                        data.num_nodes = len(cpg_structure.get("nodes", []))
                        data.num_edges = len(cpg_structure.get("edges", []))

                        # Group split key: keep paired snapshots together
                        data.group_id = rec.vul_id

                        # Vul4J metadata
                        data.vul4j_id = rec.vul_id
                        data.vul4j_version = version
                        data.repo_slug = rec.repo_slug
                        data.cve_id = rec.cve_id
                        data.cwe_id = rec.cwe_id
                        data.cwe_name = rec.cwe_name
                        data.human_patch_commit = commit
                        data.source_path = file_path
                        data.mapped_type = mapped_type

                        dataset.append(data)
            except Exception:
                skipped += 1
                continue

    LOG.info(
        "✅ Vul4J processed: %d attempted, %d skipped; produced %d graph samples",
        attempted,
        skipped,
        len(dataset),
    )
    if not dataset:
        LOG.error("No Vul4J graphs extracted. Check git network access and Joern availability.")
        return

    train_data, val_data, test_data, split_meta = _split_dataset(
        dataset,
        train_split=train_split,
        val_split=val_split,
        test_split=test_split,
        seed=seed,
        group_attr="group_id",
    )
    LOG.info(f"Split (grouped by Vul4J ID): Train={len(train_data)}, Val={len(val_data)}, Test={len(test_data)}")

    metadata: Dict[str, object] = {
        "dataset_type": "vul4j",
        "vul4j_csv": str(vul4j_csv),
        "vul4j_cache_dir": str(cache_dir),
        "vul4j_limit_vulns": int(limit_vulns or 0),
        "vul4j_max_files_per_vuln": int(max_files_per_vuln),
        "vul4j_allow_unmapped": bool(allow_unmapped),
        "vul4j_unmapped_fallback": unmapped_fallback,
        "records_attempted": attempted,
        "records_skipped": skipped,
        "mapped_type_counts": {k: mapped_type_counts[k] for k in sorted(mapped_type_counts.keys())},
        "num_samples": len(dataset),
        "train_size": len(train_data),
        "val_size": len(val_data),
        "test_size": len(test_data),
        "vulnerability_types": VULNERABILITY_TYPES,
        "split_ratios": {"train": train_split, "val": val_split, "test": test_split},
        "split": split_meta,
        "seed": seed,
    }

    _save_splits(
        output_dir=output_dir,
        train_data=train_data,
        val_data=val_data,
        test_data=test_data,
        metadata=metadata,
    )


def main():
    parser = argparse.ArgumentParser(description="Prepare training data for Spatial GNN")
    parser.add_argument(
        "--dataset",
        type=str,
        default="dir",
        choices=["dir", "vul4j"],
        help="Dataset type: dir (scan a folder of .java files) or vul4j (real CVE dataset).",
    )
    parser.add_argument("--input", type=str, required=False, help="Input directory with Java files (for --dataset dir)")
    parser.add_argument("--output", type=str, required=True, help="Output directory for processed data")
    parser.add_argument("--train-split", type=float, default=0.7, help="Training set split (default: 0.7)")
    parser.add_argument("--val-split", type=float, default=0.15, help="Validation set split (default: 0.15)")
    parser.add_argument("--test-split", type=float, default=0.15, help="Test set split (default: 0.15)")
    parser.add_argument("--timeout", type=int, default=480, help="Joern timeout in seconds (default: 480)")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of Java files (dir mode only; 0 = no limit)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling and splits")

    # Vul4J options (used when --dataset vul4j)
    default_vul4j_csv = Path(__file__).resolve().parent / "tests" / "vul4j" / "dataset" / "vul4j_dataset.csv"
    parser.add_argument("--vul4j-csv", type=str, default=str(default_vul4j_csv), help="Path to vul4j_dataset.csv")
    parser.add_argument(
        "--vul4j-cache",
        type=str,
        default=str(Path(__file__).resolve().parent / ".cache" / "vul4j_repos"),
        help="Git clone cache directory for Vul4J upstream repos",
    )
    parser.add_argument(
        "--vul4j-limit-vulns",
        type=int,
        default=0,
        help="Limit number of Vul4J vulnerabilities to process (0 = no limit)",
    )
    parser.add_argument(
        "--vul4j-max-files-per-vuln",
        type=int,
        default=3,
        help="Max modified Java files per Vul4J vulnerability (default: 3)",
    )
    parser.add_argument(
        "--vul4j-allow-unmapped",
        action="store_true",
        help="If set, map unmapped/unknown CWEs to a fallback type instead of skipping",
    )
    parser.add_argument(
        "--vul4j-unmapped-fallback",
        type=str,
        default="TRUST_BOUNDARY_VIOLATION",
        help="Fallback Bean vuln type for unmapped Vul4J rows (default: TRUST_BOUNDARY_VIOLATION)",
    )
    parser.add_argument(
        "--git-timeout",
        type=int,
        default=600,
        help="Git timeout (seconds) for Vul4J cloning/fetching (default: 600)",
    )
    
    args = parser.parse_args()

    if args.dataset == "dir":
        if not args.input:
            raise SystemExit("--input is required when --dataset dir")
        prepare_dataset(
            input_dir=Path(args.input),
            output_dir=Path(args.output),
            train_split=args.train_split,
            val_split=args.val_split,
            test_split=args.test_split,
            timeout=args.timeout,
            limit=args.limit if args.limit > 0 else None,
            seed=args.seed,
        )
        return

    if args.dataset == "vul4j":
        prepare_vul4j_dataset(
            vul4j_csv=Path(args.vul4j_csv),
            output_dir=Path(args.output),
            cache_dir=Path(args.vul4j_cache),
            train_split=args.train_split,
            val_split=args.val_split,
            test_split=args.test_split,
            timeout=args.timeout,
            seed=args.seed,
            limit_vulns=args.vul4j_limit_vulns if args.vul4j_limit_vulns > 0 else None,
            max_files_per_vuln=args.vul4j_max_files_per_vuln,
            allow_unmapped=bool(args.vul4j_allow_unmapped),
            unmapped_fallback=str(args.vul4j_unmapped_fallback),
            git_timeout=int(args.git_timeout),
        )
        return

    raise SystemExit(f"Unknown dataset type: {args.dataset}")


if __name__ == "__main__":
    main()

