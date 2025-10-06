#!/usr/bin/env python3
"""
Bean Vulnerable Framework - Dependency Verification
Ensures all required dependencies are properly installed before framework usage
"""

import sys
import os
import importlib
import subprocess
import logging

logger = logging.getLogger(__name__)

def verify_dependencies():
    """Verify all required dependencies are installed"""
    print("🔍 Bean Vulnerable Framework - Dependency Verification")
    print("=" * 60)
    
    # Strict requirements that must be present at import time
    required_deps = {
        'torch': {
            'install_cmd': 'pip install torch',
            'description': 'PyTorch for neural network operations'
        },
        'dgl': {
            'install_cmd': 'pip install dgl',
            'description': 'Deep Graph Library for graph neural networks'
        },
        'networkx': {
            'install_cmd': 'pip install networkx',
            'description': 'NetworkX for graph compatibility'
        },
        'numpy': {
            'install_cmd': 'pip install numpy',
            'description': 'NumPy for numerical operations'
        },
        'sklearn': {
            'install_cmd': 'pip install scikit-learn',
            'description': 'Scikit-learn for machine learning utilities'
        },
        'transformers': {
            'install_cmd': 'pip install transformers',
            'description': 'Transformers for CodeBERT integration'
        }
    }
    
    missing_deps = []
    for dep, info in required_deps.items():
        try:
            importlib.import_module(dep)
            print(f"✅ {dep:12} - {info['description']}")
        except ImportError:
            missing_deps.append((dep, info))
            print(f"❌ {dep:12} - MISSING: {info['description']}")
    
    # Check Joern installation
    joern_available = check_joern_installation()
    if not joern_available:
        print("❌ Joern        - MISSING: Code Property Graph generation")
        missing_deps.append(('joern', {
            'install_cmd': './scripts/install_joern.sh',
            'description': 'Joern for code property graph generation'
        }))
    else:
        print("✅ Joern        - Code Property Graph generation")
    
    print("=" * 60)
    
    if missing_deps:
        print("❌ DEPENDENCY CHECK FAILED")
        print("\nMissing required dependencies:")
        for dep, info in missing_deps:
            print(f"  - {dep}: {info['install_cmd']}")
        
        print("\n🔧 To install core dependencies:")
        print("pip install torch networkx numpy scikit-learn transformers")
        print("\nℹ️  Optional (recommended) GNN backend:")
        print("pip install dgl")
        print("./scripts/install_joern.sh")
        
        sys.exit(1)
    
    print("✅ ALL DEPENDENCIES VERIFIED")
    print("Bean Vulnerable Framework is ready to use!")
    return True

def check_joern_installation():
    """Check if Joern is properly installed"""
    # Check environment variable
    if 'JOERN_PATH' in os.environ:
        joern_path = os.environ['JOERN_PATH']
        if os.path.exists(joern_path):
            return True
    
    # Check common installation paths
    common_paths = [
        '/opt/joern/joern',
        '/usr/local/bin/joern',
        os.path.expanduser('~/joern/joern'),
        './joern/joern'
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return True
    
    # Check PATH
    try:
        subprocess.run(['joern', '--version'], 
                      capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False

def verify_dgl_functionality():
    """Verify DGL is working properly"""
    try:
        import dgl
        import torch
        
        # Test basic DGL functionality
        g = dgl.graph(([0, 1, 2], [1, 2, 0]))
        g.ndata['feat'] = torch.randn(3, 4)
        
        # Test basic operations
        assert g.num_nodes() == 3
        assert g.num_edges() == 3
        
        print("✅ DGL functionality verified")
        return True
    except Exception as e:
        print(f"❌ DGL functionality test failed: {e}")
        return False

def verify_torch_functionality():
    """Verify PyTorch is working properly"""
    try:
        import torch
        
        # Test basic tensor operations
        x = torch.randn(2, 3)
        y = torch.randn(3, 2)
        z = torch.matmul(x, y)
        
        assert z.shape == (2, 2)
        
        print("✅ PyTorch functionality verified")
        return True
    except Exception as e:
        print(f"❌ PyTorch functionality test failed: {e}")
        return False

def run_full_verification():
    """Run complete dependency and functionality verification"""
    print("🚀 Running full Bean Vulnerable Framework verification...")
    
    # Basic dependency check
    if not verify_dependencies():
        return False
    
    # Functionality tests
    torch_ok = verify_torch_functionality()
    dgl_ok = verify_dgl_functionality()
    
    if torch_ok and dgl_ok:
        print("\n🎉 Bean Vulnerable Framework is fully operational!")
        print("No fallbacks will be used - all dependencies are properly configured.")
        return True
    else:
        print("\n❌ Some functionality tests failed. Please check your installation.")
        return False

if __name__ == "__main__":
    success = run_full_verification()
    sys.exit(0 if success else 1) 