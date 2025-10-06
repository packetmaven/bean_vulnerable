"""
Bean Vulnerable GNN Framework - Real-time Analysis Module
Live vulnerability detection with file watching and streaming analysis
"""

import logging
import asyncio
import threading
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from queue import Queue, Empty
import hashlib

logger = logging.getLogger(__name__)

# File watching imports
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("Watchdog not available - install with: pip install watchdog")
    
    # Create dummy classes for when watchdog is not available
    class FileSystemEventHandler:
        def on_modified(self, event): pass
        def on_created(self, event): pass
    
    class Observer:
        def schedule(self, handler, path, recursive=True): pass
        def start(self): pass
        def stop(self): pass
        def join(self): pass

# WebSocket imports for real-time communication
try:
    import websockets
    import asyncio
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    logger.warning("WebSockets not available - install with: pip install websockets")


@dataclass
class RealTimeAnalysisResult:
    """Result from real-time analysis"""
    file_path: str
    timestamp: datetime
    vulnerability_detected: bool
    vulnerabilities_found: List[str]
    confidence: float
    analysis_time: float
    change_type: str  # 'created', 'modified', 'deleted'
    file_hash: str
    analysis_method: str
    error: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamingStats:
    """Statistics for streaming analysis"""
    total_files_processed: int = 0
    total_vulnerabilities_found: int = 0
    average_analysis_time: float = 0.0
    files_per_minute: float = 0.0
    start_time: datetime = field(default_factory=datetime.now)
    last_update: datetime = field(default_factory=datetime.now)


class VulnerabilityFileHandler(FileSystemEventHandler):
    """File system event handler for vulnerability detection"""
    
    def __init__(self, analysis_queue: Queue, file_extensions: Set[str] = None):
        """
        Initialize file handler
        
        Args:
            analysis_queue: Queue for analysis tasks
            file_extensions: Set of file extensions to monitor
        """
        super().__init__()
        self.analysis_queue = analysis_queue
        self.file_extensions = file_extensions or {'.java', '.py', '.js', '.ts', '.cpp', '.c', '.cs'}
        self.processed_files = {}  # Track file hashes to avoid duplicate processing
        
        logger.info(f"✅ File handler initialized for extensions: {self.file_extensions}")
    
    def should_process_file(self, file_path: str) -> bool:
        """Check if file should be processed"""
        
        path = Path(file_path)
        
        # Check extension
        if path.suffix.lower() not in self.file_extensions:
            return False
        
        # Skip hidden files and directories
        if any(part.startswith('.') for part in path.parts):
            return False
        
        # Skip common build/cache directories
        skip_dirs = {'node_modules', '__pycache__', '.git', 'build', 'target', 'dist', '.vscode'}
        if any(skip_dir in path.parts for skip_dir in skip_dirs):
            return False
        
        return True
    
    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Get hash of file content"""
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return hashlib.md5(content).hexdigest()
        except Exception as e:
            logger.warning(f"Failed to hash file {file_path}: {e}")
            return None
    
    def on_modified(self, event):
        """Handle file modification events"""
        
        if event.is_directory:
            return
        
        if self.should_process_file(event.src_path):
            # Check if file content actually changed
            file_hash = self.get_file_hash(event.src_path)
            if file_hash and file_hash != self.processed_files.get(event.src_path):
                self.processed_files[event.src_path] = file_hash
                
                analysis_task = {
                    'file_path': event.src_path,
                    'change_type': 'modified',
                    'timestamp': datetime.now(),
                    'file_hash': file_hash
                }
                
                self.analysis_queue.put(analysis_task)
                logger.debug(f"Queued modified file: {event.src_path}")
    
    def on_created(self, event):
        """Handle file creation events"""
        
        if event.is_directory:
            return
        
        if self.should_process_file(event.src_path):
            file_hash = self.get_file_hash(event.src_path)
            if file_hash:
                self.processed_files[event.src_path] = file_hash
                
                analysis_task = {
                    'file_path': event.src_path,
                    'change_type': 'created',
                    'timestamp': datetime.now(),
                    'file_hash': file_hash
                }
                
                self.analysis_queue.put(analysis_task)
                logger.debug(f"Queued new file: {event.src_path}")


class RealTimeAnalyzer:
    """Real-time vulnerability analyzer"""
    
    def __init__(self, framework, realtime_config: Optional[Dict[str, Any]] = None):
        """
        Initialize real-time analyzer
        
        Args:
            framework: Bean Vulnerable framework instance
            realtime_config: Configuration for real-time analysis
                - watch_directories: List of directories to watch
                - file_extensions: Set of file extensions to monitor
                - analysis_threads: Number of analysis threads
                - max_queue_size: Maximum queue size
                - websocket_port: Port for WebSocket server
                - buffer_time: Time to buffer changes before analysis
        """
        self.framework = framework
        self.config = realtime_config or {}
        
        self.watch_directories = self.config.get('watch_directories', ['.'])
        self.file_extensions = set(self.config.get('file_extensions', ['.java', '.py', '.js', '.ts']))
        self.analysis_threads = self.config.get('analysis_threads', 2)
        self.max_queue_size = self.config.get('max_queue_size', 100)
        self.websocket_port = self.config.get('websocket_port', 8765)
        self.buffer_time = self.config.get('buffer_time', 1.0)  # seconds
        
        # Analysis infrastructure
        self.analysis_queue = Queue(maxsize=self.max_queue_size)
        self.result_queue = Queue()
        self.observers = []
        self.analysis_threads_list = []
        self.websocket_clients = set()
        
        # State management
        self.is_running = False
        self.stats = StreamingStats()
        self.recent_results = []  # Keep recent results for dashboard
        self.max_recent_results = 100
        
        # Callbacks
        self.result_callbacks = []
        
        logger.info(f"✅ Real-time analyzer initialized for {len(self.watch_directories)} directories")
    
    def add_result_callback(self, callback: Callable[[RealTimeAnalysisResult], None]):
        """Add callback for analysis results"""
        self.result_callbacks.append(callback)
    
    def start_monitoring(self) -> bool:
        """Start real-time monitoring"""
        
        if not WATCHDOG_AVAILABLE:
            logger.error("Watchdog not available - cannot start file monitoring")
            return False
        
        if self.is_running:
            logger.warning("Real-time monitoring already running")
            return True
        
        try:
            # Start file system observers
            for watch_dir in self.watch_directories:
                if Path(watch_dir).exists():
                    observer = Observer()
                    handler = VulnerabilityFileHandler(self.analysis_queue, self.file_extensions)
                    observer.schedule(handler, watch_dir, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    logger.info(f"Started monitoring: {watch_dir}")
                else:
                    logger.warning(f"Watch directory does not exist: {watch_dir}")
            
            # Start analysis threads
            for i in range(self.analysis_threads):
                thread = threading.Thread(target=self._analysis_worker, name=f"AnalysisWorker-{i}")
                thread.daemon = True
                thread.start()
                self.analysis_threads_list.append(thread)
                logger.info(f"Started analysis worker thread {i}")
            
            # Start result processing thread
            result_thread = threading.Thread(target=self._result_processor, name="ResultProcessor")
            result_thread.daemon = True
            result_thread.start()
            
            # Start WebSocket server if enabled
            if WEBSOCKETS_AVAILABLE:
                websocket_thread = threading.Thread(target=self._start_websocket_server, name="WebSocketServer")
                websocket_thread.daemon = True
                websocket_thread.start()
                logger.info(f"WebSocket server starting on port {self.websocket_port}")
            
            self.is_running = True
            self.stats.start_time = datetime.now()
            
            logger.info("🚀 Real-time monitoring started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start real-time monitoring: {e}")
            self.stop_monitoring()
            return False
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        
        if not self.is_running:
            return
        
        logger.info("Stopping real-time monitoring...")
        
        self.is_running = False
        
        # Stop file system observers
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        self.observers.clear()
        
        # Signal analysis threads to stop
        for _ in self.analysis_threads_list:
            self.analysis_queue.put(None)  # Poison pill
        
        # Wait for threads to finish
        for thread in self.analysis_threads_list:
            thread.join(timeout=5.0)
        
        self.analysis_threads_list.clear()
        
        logger.info("✅ Real-time monitoring stopped")
    
    def _analysis_worker(self):
        """Worker thread for analyzing files"""
        
        while self.is_running:
            try:
                # Get task from queue with timeout
                task = self.analysis_queue.get(timeout=1.0)
                
                # Check for poison pill
                if task is None:
                    break
                
                # Analyze file
                result = self._analyze_file_task(task)
                
                # Put result in result queue
                self.result_queue.put(result)
                
                # Mark task as done
                self.analysis_queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Analysis worker error: {e}")
                continue
    
    def _analyze_file_task(self, task: Dict[str, Any]) -> RealTimeAnalysisResult:
        """Analyze a single file task"""
        
        start_time = time.time()
        file_path = task['file_path']
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            # Determine analysis method based on file extension
            path = Path(file_path)
            if path.suffix.lower() == '.java':
                # Use Bean Vulnerable framework
                analysis_result = self.framework.analyze_code(source_code, file_path)
                
                result = RealTimeAnalysisResult(
                    file_path=file_path,
                    timestamp=task['timestamp'],
                    vulnerability_detected=analysis_result.get('vulnerability_detected', False),
                    vulnerabilities_found=analysis_result.get('vulnerabilities_found', []),
                    confidence=analysis_result.get('confidence', 0.0),
                    analysis_time=time.time() - start_time,
                    change_type=task['change_type'],
                    file_hash=task['file_hash'],
                    analysis_method='bean_vulnerable',
                    additional_data=analysis_result
                )
            else:
                # Basic pattern-based analysis for other languages
                result = self._basic_pattern_analysis(
                    file_path, source_code, task, start_time
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to analyze {file_path}: {e}")
            
            return RealTimeAnalysisResult(
                file_path=file_path,
                timestamp=task['timestamp'],
                vulnerability_detected=False,
                vulnerabilities_found=[],
                confidence=0.0,
                analysis_time=time.time() - start_time,
                change_type=task['change_type'],
                file_hash=task['file_hash'],
                analysis_method='error',
                error=str(e)
            )
    
    def _basic_pattern_analysis(self, file_path: str, source_code: str, 
                              task: Dict[str, Any], start_time: float) -> RealTimeAnalysisResult:
        """Basic pattern-based analysis for non-Java files"""
        
        vulnerabilities = []
        confidence = 0.0
        
        # Basic security pattern detection
        patterns = {
            'sql_injection': [
                r'SELECT.*\+.*\+',
                r'INSERT.*\+.*\+',
                r'UPDATE.*\+.*\+',
                r'DELETE.*\+.*\+'
            ],
            'xss': [
                r'innerHTML\s*=',
                r'document\.write\(',
                r'eval\(',
                r'setTimeout\(',
                r'setInterval\('
            ],
            'hardcoded_credentials': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']'
            ],
            'command_injection': [
                r'exec\(',
                r'system\(',
                r'os\.system\(',
                r'subprocess\.',
                r'Runtime\.getRuntime\(\)\.exec'
            ]
        }
        
        import re
        
        for vuln_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, source_code, re.IGNORECASE):
                    vulnerabilities.append(vuln_type)
                    confidence += 0.3
                    break
        
        # Remove duplicates and cap confidence
        vulnerabilities = list(set(vulnerabilities))
        confidence = min(confidence, 1.0)
        
        return RealTimeAnalysisResult(
            file_path=file_path,
            timestamp=task['timestamp'],
            vulnerability_detected=len(vulnerabilities) > 0,
            vulnerabilities_found=vulnerabilities,
            confidence=confidence,
            analysis_time=time.time() - start_time,
            change_type=task['change_type'],
            file_hash=task['file_hash'],
            analysis_method='pattern_based'
        )
    
    def _result_processor(self):
        """Process analysis results"""
        
        while self.is_running:
            try:
                # Get result from queue with timeout
                result = self.result_queue.get(timeout=1.0)
                
                # Update statistics
                self._update_stats(result)
                
                # Store recent result
                self.recent_results.append(result)
                if len(self.recent_results) > self.max_recent_results:
                    self.recent_results.pop(0)
                
                # Call callbacks
                for callback in self.result_callbacks:
                    try:
                        callback(result)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")
                
                # Send to WebSocket clients
                if WEBSOCKETS_AVAILABLE and self.websocket_clients:
                    asyncio.run_coroutine_threadsafe(
                        self._broadcast_result(result),
                        asyncio.new_event_loop()
                    )
                
                # Log significant findings
                if result.vulnerability_detected:
                    logger.warning(
                        f"🚨 Vulnerability detected in {Path(result.file_path).name}: "
                        f"{result.vulnerabilities_found} (confidence: {result.confidence:.3f})"
                    )
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Result processor error: {e}")
                continue
    
    def _update_stats(self, result: RealTimeAnalysisResult):
        """Update streaming statistics"""
        
        self.stats.total_files_processed += 1
        
        if result.vulnerability_detected:
            self.stats.total_vulnerabilities_found += 1
        
        # Update average analysis time
        current_avg = self.stats.average_analysis_time
        new_count = self.stats.total_files_processed
        self.stats.average_analysis_time = (
            (current_avg * (new_count - 1) + result.analysis_time) / new_count
        )
        
        # Update files per minute
        now = datetime.now()
        time_diff = (now - self.stats.start_time).total_seconds() / 60.0
        if time_diff > 0:
            self.stats.files_per_minute = self.stats.total_files_processed / time_diff
        
        self.stats.last_update = now
    
    def _start_websocket_server(self):
        """Start WebSocket server for real-time communication"""
        
        async def handle_client(websocket, path):
            """Handle WebSocket client connection"""
            
            self.websocket_clients.add(websocket)
            logger.info(f"WebSocket client connected: {websocket.remote_address}")
            
            try:
                # Send current stats
                await websocket.send(json.dumps({
                    'type': 'stats',
                    'data': self._serialize_stats()
                }))
                
                # Send recent results
                for result in self.recent_results[-10:]:  # Last 10 results
                    await websocket.send(json.dumps({
                        'type': 'result',
                        'data': self._serialize_result(result)
                    }))
                
                # Keep connection alive
                await websocket.wait_closed()
                
            except Exception as e:
                logger.error(f"WebSocket client error: {e}")
            finally:
                self.websocket_clients.discard(websocket)
                logger.info("WebSocket client disconnected")
        
        # Start WebSocket server
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        start_server = websockets.serve(handle_client, "localhost", self.websocket_port)
        
        loop.run_until_complete(start_server)
        loop.run_forever()
    
    async def _broadcast_result(self, result: RealTimeAnalysisResult):
        """Broadcast result to all WebSocket clients"""
        
        if not self.websocket_clients:
            return
        
        message = json.dumps({
            'type': 'result',
            'data': self._serialize_result(result)
        })
        
        # Send to all connected clients
        disconnected_clients = set()
        for client in self.websocket_clients:
            try:
                await client.send(message)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket client: {e}")
                disconnected_clients.add(client)
        
        # Remove disconnected clients
        self.websocket_clients -= disconnected_clients
    
    def _serialize_result(self, result: RealTimeAnalysisResult) -> Dict[str, Any]:
        """Serialize result for JSON transmission"""
        
        return {
            'file_path': result.file_path,
            'timestamp': result.timestamp.isoformat(),
            'vulnerability_detected': result.vulnerability_detected,
            'vulnerabilities_found': result.vulnerabilities_found,
            'confidence': result.confidence,
            'analysis_time': result.analysis_time,
            'change_type': result.change_type,
            'file_hash': result.file_hash,
            'analysis_method': result.analysis_method,
            'error': result.error
        }
    
    def _serialize_stats(self) -> Dict[str, Any]:
        """Serialize stats for JSON transmission"""
        
        return {
            'total_files_processed': self.stats.total_files_processed,
            'total_vulnerabilities_found': self.stats.total_vulnerabilities_found,
            'average_analysis_time': self.stats.average_analysis_time,
            'files_per_minute': self.stats.files_per_minute,
            'start_time': self.stats.start_time.isoformat(),
            'last_update': self.stats.last_update.isoformat(),
            'uptime_minutes': (datetime.now() - self.stats.start_time).total_seconds() / 60.0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return self._serialize_stats()
    
    def get_recent_results(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent analysis results"""
        
        recent = self.recent_results[-limit:] if limit > 0 else self.recent_results
        return [self._serialize_result(result) for result in recent]
    
    def analyze_file_now(self, file_path: str) -> Optional[RealTimeAnalysisResult]:
        """Analyze a file immediately (synchronous)"""
        
        try:
            file_hash = hashlib.md5(Path(file_path).read_bytes()).hexdigest()
            
            task = {
                'file_path': file_path,
                'change_type': 'manual',
                'timestamp': datetime.now(),
                'file_hash': file_hash
            }
            
            return self._analyze_file_task(task)
            
        except Exception as e:
            logger.error(f"Failed to analyze file {file_path}: {e}")
            return None


class RealTimeAnalysisManager:
    """Manager for real-time analysis with multiple analyzers"""
    
    def __init__(self, framework):
        """Initialize real-time analysis manager"""
        
        self.framework = framework
        self.analyzers = {}
        self.global_stats = StreamingStats()
        
        logger.info("✅ Real-time Analysis Manager initialized")
    
    def create_analyzer(self, name: str, config: Dict[str, Any]) -> RealTimeAnalyzer:
        """Create a new real-time analyzer"""
        
        analyzer = RealTimeAnalyzer(self.framework, config)
        self.analyzers[name] = analyzer
        
        # Add callback to update global stats
        analyzer.add_result_callback(self._update_global_stats)
        
        logger.info(f"Created real-time analyzer: {name}")
        return analyzer
    
    def start_analyzer(self, name: str) -> bool:
        """Start a specific analyzer"""
        
        if name in self.analyzers:
            return self.analyzers[name].start_monitoring()
        else:
            logger.error(f"Analyzer '{name}' not found")
            return False
    
    def stop_analyzer(self, name: str):
        """Stop a specific analyzer"""
        
        if name in self.analyzers:
            self.analyzers[name].stop_monitoring()
        else:
            logger.error(f"Analyzer '{name}' not found")
    
    def start_all_analyzers(self) -> Dict[str, bool]:
        """Start all analyzers"""
        
        results = {}
        for name, analyzer in self.analyzers.items():
            results[name] = analyzer.start_monitoring()
        
        return results
    
    def stop_all_analyzers(self):
        """Stop all analyzers"""
        
        for analyzer in self.analyzers.values():
            analyzer.stop_monitoring()
    
    def _update_global_stats(self, result: RealTimeAnalysisResult):
        """Update global statistics from analyzer result"""
        
        self.global_stats.total_files_processed += 1
        
        if result.vulnerability_detected:
            self.global_stats.total_vulnerabilities_found += 1
        
        # Update average analysis time
        current_avg = self.global_stats.average_analysis_time
        new_count = self.global_stats.total_files_processed
        self.global_stats.average_analysis_time = (
            (current_avg * (new_count - 1) + result.analysis_time) / new_count
        )
        
        self.global_stats.last_update = datetime.now()
    
    def get_global_stats(self) -> Dict[str, Any]:
        """Get global statistics across all analyzers"""
        
        return {
            'total_files_processed': self.global_stats.total_files_processed,
            'total_vulnerabilities_found': self.global_stats.total_vulnerabilities_found,
            'average_analysis_time': self.global_stats.average_analysis_time,
            'active_analyzers': len([a for a in self.analyzers.values() if a.is_running]),
            'total_analyzers': len(self.analyzers),
            'last_update': self.global_stats.last_update.isoformat() if self.global_stats.last_update else None
        }
    
    def get_analyzer_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all analyzers"""
        
        return {
            name: analyzer.get_stats()
            for name, analyzer in self.analyzers.items()
        }


# Configuration templates
REALTIME_CONFIG_TEMPLATES = {
    'development': {
        'watch_directories': ['.'],
        'file_extensions': ['.java', '.py', '.js'],
        'analysis_threads': 1,
        'max_queue_size': 50,
        'websocket_port': 8765,
        'buffer_time': 0.5
    },
    'production': {
        'watch_directories': ['/app/src', '/app/lib'],
        'file_extensions': ['.java', '.py', '.js', '.ts', '.cpp', '.c'],
        'analysis_threads': 4,
        'max_queue_size': 200,
        'websocket_port': 8765,
        'buffer_time': 2.0
    },
    'high_throughput': {
        'watch_directories': ['/app'],
        'file_extensions': ['.java', '.py', '.js', '.ts'],
        'analysis_threads': 8,
        'max_queue_size': 500,
        'websocket_port': 8765,
        'buffer_time': 0.1
    }
} 