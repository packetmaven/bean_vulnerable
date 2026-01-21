#!/usr/bin/env python3
"""
Prepare Training Data for Spatial GNN

This script:
1. Extracts CPG structures from Java files using Joern
2. Labels them as vulnerable/safe with vulnerability types
3. Creates PyTorch Geometric Data objects
4. Splits into train/val/test sets

Usage:
    python prepare_training_data.py --input tests/samples --output training_data --split 0.7/0.15/0.15
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import subprocess
import tempfile
import torch
from torch_geometric.data import Data, Dataset
import pickle
from tqdm import tqdm
import random

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
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    
    if result.returncode != 0:
        LOG.error(f"CPG extraction failed for {java_file}: {result.stderr}")
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
    node_features = []
    for node in nodes:
        features = [
            float(node_type_mapping.get(node['node_type'], 11)) / 12.0,
            float(category_mapping.get(node['category'], 11)) / 12.0,
            float(node['line']) / 1000.0,
            float(node['order']) / 100.0,
            float(node['is_source']),
            float(node['is_sink']),
            float(len(node['code'])) / 200.0,
            float(bool(node['name'])),
            float(binary_label),  # Graph-level label as node feature
            float(multiclass_label) / 24.0,  # Normalized
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
    
    return data


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
    
    # Split dataset
    random.seed(seed)
    random.shuffle(dataset)
    
    n = len(dataset)
    train_end = int(n * train_split)
    val_end = train_end + int(n * val_split)
    
    train_data = dataset[:train_end]
    val_data = dataset[train_end:val_end]
    test_data = dataset[val_end:]
    
    LOG.info(f"Split: Train={len(train_data)}, Val={len(val_data)}, Test={len(test_data)}")
    
    # Save datasets
    with open(output_dir / "train.pkl", 'wb') as f:
        pickle.dump(train_data, f)
    with open(output_dir / "val.pkl", 'wb') as f:
        pickle.dump(val_data, f)
    with open(output_dir / "test.pkl", 'wb') as f:
        pickle.dump(test_data, f)
    
    # Save metadata
    metadata = {
        'num_files': len(dataset),
        'train_size': len(train_data),
        'val_size': len(val_data),
        'test_size': len(test_data),
        'vulnerability_types': VULNERABILITY_TYPES,
        'split_ratios': {'train': train_split, 'val': val_split, 'test': test_split}
    }
    
    with open(output_dir / "metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    LOG.info(f"✅ Saved training data to {output_dir}")
    LOG.info(f"   - train.pkl: {len(train_data)} samples")
    LOG.info(f"   - val.pkl: {len(val_data)} samples")
    LOG.info(f"   - test.pkl: {len(test_data)} samples")
    LOG.info(f"   - metadata.json: Dataset statistics")


def main():
    parser = argparse.ArgumentParser(description="Prepare training data for Spatial GNN")
    parser.add_argument("--input", type=str, required=True, help="Input directory with Java files")
    parser.add_argument("--output", type=str, required=True, help="Output directory for processed data")
    parser.add_argument("--train-split", type=float, default=0.7, help="Training set split (default: 0.7)")
    parser.add_argument("--val-split", type=float, default=0.15, help="Validation set split (default: 0.15)")
    parser.add_argument("--test-split", type=float, default=0.15, help="Test set split (default: 0.15)")
    parser.add_argument("--timeout", type=int, default=480, help="Joern timeout in seconds (default: 480)")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of Java files (0 = no limit)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling and splits")
    
    args = parser.parse_args()
    
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


if __name__ == "__main__":
    main()

