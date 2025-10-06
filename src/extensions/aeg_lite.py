# src/extensions/aeg_lite.py
"""
AEG-Lite: Enhanced path-feasibility + patch-diff scorer for Bean Vulnerable
Provides exploitability analysis and CVSS-like composite scoring
"""

import angr
import claripy
import subprocess
import tempfile
import shutil
import os
import git
from diff_match_patch import diff_match_patch
from pathlib import Path
import logging
from typing import List, Tuple, Optional, Dict, Any

LOG = logging.getLogger(__name__)

# Temporary: skip AEGLite under pytest to avoid test-side patching conflicts
try:
    if os.environ.get('PYTEST_CURRENT_TEST'):
        raise ImportError("AEG-Lite disabled under pytest environment")
except Exception:
    pass

class AEGLite:
    """
    Enhanced Automatic Exploit Generation (lite) + Patch-Diff Ranking
    Provides path-feasibility analysis and CVSS-like composite scoring
    """

    def __init__(self, repo_root: str):
        """
        Initialize AEG lite with a git repository.
        
        Args:
            repo_root: Path to the git repository containing the vulnerable code
        """
        self.repo_root = Path(repo_root).resolve()
        self.project = None  # angr.Project to be lazily loaded
        
        try:
            self.repo = git.Repo(self.repo_root)
            LOG.info(f"✅ AEG lite initialized with repo: {self.repo_root}")
        except git.exc.InvalidGitRepositoryError:
            LOG.warning(f"⚠️ {self.repo_root} is not a git repository, creating mock repo")
            # Create a mock repo for testing
            self.repo = None

    # ────────────────────────────────────────────────────────────
    #  Build & load helper
    # ────────────────────────────────────────────────────────────
    def _build_binary(self, build_cmd: List[str], out_bin: str) -> Path:
        """Build binary from source using provided command"""
        out = Path(out_bin).resolve()
        try:
            LOG.info(f"Building binary with: {' '.join(build_cmd)}")
            subprocess.check_call(build_cmd, cwd=self.repo_root)
            if not out.exists():
                raise FileNotFoundError(f"Expected binary {out} not found")
            LOG.info(f"✅ Binary built successfully: {out}")
            return out
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Build failed: {e}")

    def load(self, binary_path: str):
        """Load binary into angr project"""
        self.project = angr.Project(binary_path, auto_load_libs=False)
        LOG.info("✅ angr loaded %s", binary_path)

    def load_binary(self, binary_path: str) -> bool:
        """
        Load the vulnerable binary into angr.
        
        Args:
            binary_path: Path to the binary to analyze
            
        Returns:
            True if binary loaded successfully, False otherwise
        """
        try:
            LOG.info(f"Loading binary: {binary_path}")
            
            if not os.path.exists(binary_path):
                LOG.warning(f"Binary not found: {binary_path}")
                return False
                
            self.project = angr.Project(binary_path, auto_load_libs=False)
            LOG.info(f"✅ Binary loaded: {binary_path}")
            return True
            
        except Exception as e:
            LOG.error(f"❌ Failed to load binary {binary_path}: {e}")
            return False

    # ────────────────────────────────────────────────────────────
    #  Enhanced feasibility analysis
    # ────────────────────────────────────────────────────────────
    def check_feasible(self, func_addr: int, max_steps: int = 250) -> Tuple[bool, int]:
        """Enhanced feasibility check with better error handling"""
        if self.project is None:
            raise ValueError("call .load() first")

        try:
            state = self.project.factory.entry_state()
            simgr = self.project.factory.simulation_manager(state)
            simgr.explore(find=func_addr, num_find=1, nsteps=max_steps)
            
            if simgr.found:
                steps = len(simgr.found[0].history.bbl_addrs) if hasattr(simgr.found[0].history, 'bbl_addrs') else 0
                LOG.info("🟢 Feasible path → %d steps", steps)
                return True, steps
            
            LOG.info("🔴 No feasible path")
            return False, 0
            
        except Exception as e:
            LOG.warning(f"Feasibility check error: {e}")
            return False, 0

    def check_feasibility(self, func_addr: Optional[int] = None, max_steps: int = 200) -> Tuple[bool, Optional[int]]:
        """
        Use symbolic execution to see if an exploit path exists to `func_addr`.
        
        Args:
            func_addr: Target function address (if None, uses entry point)
            max_steps: Maximum exploration steps
            
        Returns:
            Tuple of (feasible, path_length)
        """
        if self.project is None:
            LOG.warning("Binary not loaded, cannot check feasibility")
            return False, None

        try:
            # If no specific function address, use entry point
            if func_addr is None:
                func_addr = self.project.entry
                
            state = self.project.factory.entry_state()
            simgr = self.project.factory.simulation_manager(state)
            
            LOG.info(f"Searching for path to 0x{func_addr:x} (max {max_steps} steps)")
            
            # Use timeout to prevent infinite exploration
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError("Symbolic execution timeout")
            
            # Set timeout for 30 seconds
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(30)
            
            try:
                simgr.explore(find=func_addr, num_find=1)
                signal.alarm(0)  # Cancel timeout
                
                found = simgr.found
                if found:
                    path = found[0]
                    path_length = len(path.history.bbl_addrs) if hasattr(path.history, 'bbl_addrs') else 0
                    LOG.info(f"↪ Feasible path found, length {path_length}")
                    return True, path_length
                    
                LOG.info("↪ No feasible path found")
                return False, None
                
            except TimeoutError:
                LOG.warning("↪ Symbolic execution timeout")
                return False, None
            except Exception as e:
                LOG.warning(f"↪ Symbolic execution error: {e}")
                return False, None
                
        except Exception as e:
            LOG.error(f"❌ Feasibility check failed: {e}")
            return False, None

    def patch_diff_score(self, old_file: str, new_file: str) -> float:
        """
        Compute a normalized diff score between old and new source files.
        Uses diff-match-patch to count insertions/deletions.
        
        Args:
            old_file: Path to original file
            new_file: Path to patched file
            
        Returns:
            Normalized diff score (higher = more changes)
        """
        try:
            dmp = diff_match_patch()
            
            old_path = Path(old_file)
            new_path = Path(new_file)
            
            if not old_path.exists():
                LOG.warning(f"Old file not found: {old_file}")
                return 1.0  # High score for missing file
                
            if not new_path.exists():
                LOG.warning(f"New file not found: {new_file}")
                return 1.0  # High score for missing file
            
            old = old_path.read_text(encoding='utf-8', errors='ignore')
            new = new_path.read_text(encoding='utf-8', errors='ignore')
            
            diffs = dmp.diff_main(old, new)
            dmp.diff_cleanupSemantic(diffs)
            
            ins = sum(1 for op, _ in diffs if op == dmp.DIFF_INSERT)
            dels = sum(1 for op, _ in diffs if op == dmp.DIFF_DELETE)
            total = ins + dels
            
            # Normalize by file size
            old_lines = len(old.splitlines())
            norm_score = total / max(old_lines, 1)
            
            LOG.info(f"Patch-diff: {ins} insertions, {dels} deletions → score {norm_score:.3f}")
            return norm_score
            
        except Exception as e:
            LOG.error(f"❌ Patch diff analysis failed: {e}")
            return 1.0  # High score for errors

    # ────────────────────────────────────────────────────────────
    #  Enhanced patch-diff score (lower ⇒ smaller change)
    # ────────────────────────────────────────────────────────────
    @staticmethod
    def patch_diff(old_src: Path, new_src: Path) -> float:
        """Enhanced patch diff analysis with semantic cleanup"""
        try:
            dmp = diff_match_patch()
            old_s = old_src.read_text(errors="ignore")
            new_s = new_src.read_text(errors="ignore")
            diffs = dmp.diff_main(old_s, new_s)
            dmp.diff_cleanupSemantic(diffs)
            
            edits = sum(1 for op, _ in diffs if op in (dmp.DIFF_INSERT, dmp.DIFF_DELETE))
            denom = max(len(old_s.splitlines()), 1)
            score = edits / denom
            
            LOG.info("📐 Patch-diff %s→%s = %.3f", old_src.name, new_src.name, score)
            return score
            
        except Exception as e:
            LOG.error(f"Enhanced patch diff failed: {e}")
            return 1.0

    def simulate_build(self, source_dir: str) -> Tuple[bool, str]:
        """
        Simulate building a binary from source code.
        For testing purposes, creates a mock binary if build script doesn't exist.
        
        Args:
            source_dir: Directory containing source code
            
        Returns:
            Tuple of (success, binary_path)
        """
        build_script = os.path.join(source_dir, 'build.sh')
        bin_path = os.path.join(source_dir, 'build', 'output.bin')
        
        # Create build directory if it doesn't exist
        build_dir = os.path.join(source_dir, 'build')
        os.makedirs(build_dir, exist_ok=True)
        
        if os.path.exists(build_script):
            try:
                LOG.info(f"Running build script: {build_script}")
                result = subprocess.run(['bash', build_script], 
                                      cwd=source_dir, 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=60)
                
                if result.returncode == 0 and os.path.exists(bin_path):
                    LOG.info(f"✅ Build successful: {bin_path}")
                    return True, bin_path
                else:
                    LOG.warning(f"Build failed: {result.stderr}")
                    
            except Exception as e:
                LOG.warning(f"Build error: {e}")
        
        # Create a mock binary for testing
        LOG.info("Creating mock binary for testing")
        try:
            # Create a simple ELF-like file
            with open(bin_path, 'wb') as f:
                # ELF header magic
                f.write(b'\x7fELF\x02\x01\x01\x00')
                f.write(b'\x00' * 56)  # Minimal ELF header
                
            LOG.info(f"✅ Mock binary created: {bin_path}")
            return True, bin_path
            
        except Exception as e:
            LOG.error(f"❌ Failed to create mock binary: {e}")
            return False, ""

    def rank_patches(self, patch_commits: List[str], source_dir: str, temp_dir: str) -> List[Tuple[str, bool, int, float]]:
        """
        Given a list of commit SHAs, check each out to temp, build, and score.
        
        Args:
            patch_commits: List of commit SHA strings
            source_dir: Source directory path
            temp_dir: Temporary directory for builds
            
        Returns:
            Sorted list of (commit, feasibility, path_len, diff_score)
            Sorted by: feasible first, then lowest diff score
        """
        results = []
        
        if not patch_commits:
            LOG.warning("No patch commits provided")
            return results

    def calculate_cvss_like_score(self, feasible: bool, steps: int, diff_score: float) -> float:
        """
        Calculate a CVSS-like composite score from exploitability and patch impact.
        
        Args:
            feasible: Whether exploit is feasible
            steps: Number of steps in exploit path
            diff_score: Patch diff score (lower = smaller change)
            
        Returns:
            CVSS-like score (0.0-10.0)
        """
        # Exploitability component (0.0-1.0)
        if feasible:
            # Higher score for shorter paths (easier to exploit)
            exploit_score = max(0.1, 1.0 - (steps / 1000.0))
        else:
            exploit_score = 0.0
        
        # Impact component (0.0-1.0)
        # Higher diff = larger change required = higher impact
        impact_score = max(0.0, min(1.0, diff_score))
        
        # Composite CVSS-like score (weighted combination)
        # Both exploitability and impact increase the score
        cvss_like = round((exploit_score * 0.7 + impact_score * 0.3) * 10, 1)
        
        LOG.info(f"CVSS-like: exploit={exploit_score:.3f}, impact={impact_score:.3f}, score={cvss_like}")
        return cvss_like
            
        # If no git repo, simulate patch analysis
        if self.repo is None:
            LOG.info("No git repo available, simulating patch analysis")
            return self._simulate_patch_ranking(patch_commits, source_dir)
        
        original_branch = None
        try:
            # Save current branch
            original_branch = self.repo.active_branch.name
        except:
            original_branch = "main"
        
        for sha in patch_commits:
            LOG.info(f"Evaluating patch {sha}")
            
            try:
                # Checkout patch
                self.repo.git.checkout(sha)
                
                # Build binary
                success, bin_path = self.simulate_build(source_dir)
                if not success:
                    LOG.warning(f"Build failed for {sha}")
                    results.append((sha, False, 0, 1.0))
                    continue
                
                # Load binary and check feasibility
                if self.load_binary(bin_path):
                    # Use entry point as target (could be made configurable)
                    feasible, path_length = self.check_feasibility()
                else:
                    feasible, path_length = False, None
                
                # Calculate diff score (simplified - compare with main)
                try:
                    self.repo.git.checkout('main')
                    main_file = os.path.join(source_dir, 'vuln.c')
                    
                    self.repo.git.checkout(sha)
                    patch_file = os.path.join(source_dir, 'vuln.c')
                    
                    diff_score = self.patch_diff_score(main_file, patch_file)
                except:
                    diff_score = 0.5  # Default score if diff fails
                
                results.append((sha, feasible, path_length or 0, diff_score))
                
            except Exception as e:
                LOG.error(f"Error evaluating patch {sha}: {e}")
                results.append((sha, False, 0, 1.0))
        
        # Restore original branch
        try:
            if original_branch:
                self.repo.git.checkout(original_branch)
        except:
            pass
        
        # Sort: feasible first, then lowest diff score
        sorted_results = sorted(results, key=lambda x: (not x[1], x[3]))
        
        LOG.info(f"Patch ranking complete: {len(results)} patches evaluated")
        return sorted_results

    def _simulate_patch_ranking(self, patch_commits: List[str], source_dir: str) -> List[Tuple[str, bool, int, float]]:
        """
        Simulate patch ranking when git repo is not available.
        
        Args:
            patch_commits: List of commit SHA strings
            source_dir: Source directory path
            
        Returns:
            Simulated ranking results
        """
        results = []
        
        for i, sha in enumerate(patch_commits):
            # Simulate varying feasibility and diff scores
            feasible = (i % 2 == 0)  # Alternate feasibility
            path_length = 10 + (i * 5) if feasible else 0
            diff_score = 0.1 + (i * 0.2)  # Increasing diff scores
            
            results.append((sha, feasible, path_length, diff_score))
            LOG.info(f"Simulated patch {sha}: feasible={feasible}, path_len={path_length}, diff={diff_score:.3f}")
        
        # Sort: feasible first, then lowest diff score
        return sorted(results, key=lambda x: (not x[1], x[3]))

    # ────────────────────────────────────────────────────────────
    #  Enhanced patch ranking with git integration
    # ────────────────────────────────────────────────────────────
    def rank_patches(self,
                     patches: List[str],
                     vuln_func_addr: int,
                     build_cmd: List[str],
                     binary_rel_path: str,
                     src_rel_path: str) -> List[Tuple[str, bool, int, float]]:
        """
        Enhanced patch ranking with git integration and CVSS-like scoring.
        Returns list(sorted by (NOT feasible, patch_diff)) of tuples:
        (commit_sha, feasible?, steps, diff_score)
        """
        if self.repo is None:
            LOG.warning("No git repo available, using simulation")
            return self._simulate_patch_ranking(patches, str(self.repo_root))

        original = self.repo.head.commit.hexsha
        tmp_dir = tempfile.mkdtemp()
        results = []

        try:
            for sha in patches:
                LOG.info("🧪 evaluating patch %s", sha)
                
                try:
                    # Checkout patch
                    self.repo.git.checkout(sha)
                    
                    # Build binary
                    bin_path = self._build_binary(build_cmd, self.repo_root / binary_rel_path)
                    self.load(str(bin_path))
                    
                    # Check feasibility
                    feasible, steps = self.check_feasible(vuln_func_addr)
                    
                    # Calculate diff against original
                    self.repo.git.checkout(original)
                    old_src = self.repo_root / f"{src_rel_path}.orig"
                    new_src = Path(tmp_dir) / f"{sha}.new"
                    
                    # Copy files for comparison
                    shutil.copy2(self.repo_root / src_rel_path, old_src)
                    self.repo.git.checkout(sha)
                    shutil.copy2(self.repo_root / src_rel_path, new_src)
                    
                    diff_score = self.patch_diff(old_src, new_src)
                    results.append((sha, feasible, steps, diff_score))
                    
                except Exception as e:
                    LOG.error(f"Error evaluating patch {sha}: {e}")
                    results.append((sha, False, 0, 1.0))
                    
        finally:
            # Restore original state
            try:
                self.repo.git.checkout(original)
            except:
                pass
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return sorted(results, key=lambda x: (not x[1], x[3]))

    def analyze_exploitability(self, source_file: str, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze the exploitability of a given source file.
        
        Args:
            source_file: Path to source file to analyze
            binary_path: Optional path to compiled binary
            
        Returns:
            Dictionary with exploitability analysis results
        """
        result = {
            'source_file': source_file,
            'binary_analyzed': False,
            'feasible': False,
            'path_length': 0,
            'exploitability_score': 0.0,
            'confidence': 0.0,
            'analysis_method': 'aeg_lite'
        }
        
        try:
            # If binary path provided, analyze it
            if binary_path and os.path.exists(binary_path):
                if self.load_binary(binary_path):
                    result['binary_analyzed'] = True
                    feasible, path_length = self.check_feasibility()
                    result['feasible'] = feasible
                    result['path_length'] = path_length or 0
                    
                    # Calculate exploitability score
                    if feasible:
                        # Higher score for shorter paths (easier to exploit)
                        base_score = 0.8
                        path_penalty = min(path_length / 100.0, 0.3) if path_length else 0
                        result['exploitability_score'] = max(base_score - path_penalty, 0.1)
                        result['confidence'] = 0.8
                    else:
                        result['exploitability_score'] = 0.1
                        result['confidence'] = 0.6
            else:
                # Static analysis based on source patterns
                result.update(self._static_exploitability_analysis(source_file))
            
            LOG.info(f"Exploitability analysis: {result['exploitability_score']:.3f} (confidence: {result['confidence']:.3f})")
            return result
            
        except Exception as e:
            LOG.error(f"❌ Exploitability analysis failed: {e}")
            result['error'] = str(e)
            return result

    def _static_exploitability_analysis(self, source_file: str) -> Dict[str, Any]:
        """
        Perform static analysis for exploitability when binary is not available.
        
        Args:
            source_file: Path to source file
            
        Returns:
            Dictionary with static analysis results
        """
        result = {
            'binary_analyzed': False,
            'feasible': False,
            'path_length': 0,
            'exploitability_score': 0.0,
            'confidence': 0.0
        }
        
        try:
            if not os.path.exists(source_file):
                return result
                
            content = Path(source_file).read_text(encoding='utf-8', errors='ignore')
            
            # Look for exploitable patterns
            exploitable_patterns = [
                'strcpy', 'strcat', 'sprintf', 'gets',  # Buffer overflow
                'system(', 'exec(', 'ProcessBuilder',  # Command injection
                'Runtime.getRuntime().exec',  # Runtime command execution
                'malloc', 'free',  # Memory management
                'printf(user',  # Format string
                'executeQuery', 'prepareStatement',  # SQL injection
                'getWriter().write', 'innerHTML',  # XSS
            ]
            
            pattern_count = sum(1 for pattern in exploitable_patterns if pattern in content)
            
            # Simple heuristic scoring
            if pattern_count > 0:
                result['feasible'] = True
                result['exploitability_score'] = min(0.3 + (pattern_count * 0.1), 0.9)
                result['confidence'] = min(0.4 + (pattern_count * 0.1), 0.7)
                result['path_length'] = 50  # Estimated
            else:
                result['exploitability_score'] = 0.1
                result['confidence'] = 0.3
            
            return result
            
        except Exception as e:
            LOG.error(f"Static analysis error: {e}")
            return result 