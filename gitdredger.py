#!/usr/bin/env python3

import requests
import gzip
import json
import re
import argparse
import sys
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
import concurrent.futures
from dataclasses import dataclass, asdict
from pathlib import Path
from abc import ABC, abstractmethod

# Constants
DEFAULT_CONFIG_FILE = "Config/Token_Regex.json"
DEFAULT_OUTPUT_FILE = "sensitive_tokens_results.json"
DEFAULT_WORKERS = 3
DEFAULT_CONTEXT_SIZE = 300
DEFAULT_TIMEOUT = 30
GITHUB_ARCHIVE_BASE_URL = "https://data.gharchive.org"
MAX_CONTENT_LENGTH = 1000


class GitDredgerError(Exception):
    """Base exception for GitDredger"""
    pass


class ConfigurationError(GitDredgerError):
    """Configuration related errors"""
    pass


class DownloadError(GitDredgerError):
    """Download related errors"""
    pass


@dataclass
class SearchResult:
    """Data class representing a search result"""
    event_type: str
    repository: str
    user: str
    timestamp: str
    location: str
    content: str
    url: str = ""
    pattern_matches: Optional[List[Dict[str, str]]] = None

    def __post_init__(self):
        if self.pattern_matches is None:
            self.pattern_matches = []


@dataclass
class ScanSummary:
    """Data class representing scan summary statistics"""
    scan_time: str
    start_time: str
    end_time: str
    total_results: int
    total_patterns_found: int
    unique_pattern_types: int
    scanned_patterns: List[str]
    pattern_statistics: Dict[str, int]


class Logger:
    """Centralized logging utility"""
    
    def __init__(self, name: str = "GitDredger", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def info(self, message: str, use_emoji: bool = True):
        """Log info message with optional emoji"""
        if use_emoji:
            self.logger.info(f"ℹ️  {message}")
        else:
            self.logger.info(message)
    
    def error(self, message: str, use_emoji: bool = True):
        """Log error message with optional emoji"""
        if use_emoji:
            self.logger.error(f"❌ {message}")
        else:
            self.logger.error(message)
    
    def warning(self, message: str, use_emoji: bool = True):
        """Log warning message with optional emoji"""
        if use_emoji:
            self.logger.warning(f"⚠️  {message}")
        else:
            self.logger.warning(message)
    
    def success(self, message: str):
        """Log success message"""
        self.logger.info(f"✅ {message}")
    
    def detection(self, message: str):
        """Log detection message"""
        self.logger.info(f"🚨 {message}")


class PatternLoader:
    """Handles loading and validation of token patterns"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def load_patterns(self, config_file: str = DEFAULT_CONFIG_FILE) -> Dict[str, str]:
        """Load sensitive token patterns from JSON file"""
        try:
            config_path = Path(config_file)
            if not config_path.exists():
                raise ConfigurationError(f"Configuration file {config_file} not found")
            
            with open(config_path, 'r', encoding='utf-8') as f:
                patterns = json.load(f)
            
            self._validate_patterns(patterns)
            self.logger.success(f"{len(patterns)} patterns loaded from {config_file}")
            return patterns
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in {config_file}: {e}")
            raise ConfigurationError(f"Configuration file parsing error: {e}")
        except Exception as e:
            self.logger.error(f"Failed to load patterns: {e}")
            return self._get_fallback_patterns()
    
    def _validate_patterns(self, patterns: Dict[str, str]) -> None:
        """Validate regex patterns"""
        invalid_patterns = []
        for name, pattern in patterns.items():
            try:
                re.compile(pattern)
            except re.error as e:
                invalid_patterns.append(f"{name}: {e}")
        
        if invalid_patterns:
            raise ConfigurationError(f"Invalid regex patterns: {', '.join(invalid_patterns)}")
    
    def _get_fallback_patterns(self) -> Dict[str, str]:
        """Return fallback patterns when config loading fails"""
        self.logger.warning("Using fallback patterns...")
        return {
            "github_token": r"gh[pouasr]_[A-Za-z0-9]{36}",
            "gitlab_personal_access_token": r"glpat-[A-Za-z0-9_-]{20}",
            "openai_api_key": r"sk-[A-Za-z0-9]{51}",
            "pypi_upload_token": r"pypi-[A-Za-z0-9+/=]+",
            "grafana_cloud_api_token": r"eyJ[a-zA-Z0-9._-]+"
        }


class ArchiveDownloader:
    """Handles downloading GitHub Archive data"""
    
    def __init__(self, logger: Logger, timeout: int = DEFAULT_TIMEOUT):
        self.logger = logger
        self.timeout = timeout
    
    def download_archive(self, hour_str: str) -> str:
        """Download archive file for the specified hour"""
        url = f"{GITHUB_ARCHIVE_BASE_URL}/{hour_str}.json.gz"
        
        try:
            self.logger.info(f"📥 Downloading: {hour_str}", use_emoji=False)
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                return gzip.decompress(response.content).decode('utf-8')
            elif response.status_code == 404:
                self.logger.warning(f"Data not found: {hour_str}")
                return ""
            else:
                raise DownloadError(f"HTTP {response.status_code} for {hour_str}")
                
        except requests.RequestException as e:
            self.logger.error(f"Download error {hour_str}: {e}")
            raise DownloadError(f"Failed to download {hour_str}: {e}")


class PatternDetector:
    """Handles pattern detection in text content"""
    
    def __init__(self, patterns: Dict[str, str], logger: Logger):
        self.patterns = patterns
        self.logger = logger
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Pre-compile regex patterns for better performance"""
        compiled = {}
        for name, pattern in self.patterns.items():
            try:
                compiled[name] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                self.logger.warning(f"Skipping invalid pattern {name}: {e}")
        return compiled
    
    def detect_patterns(self, text: str) -> List[Dict[str, str]]:
        """Detect sensitive patterns and return details"""
        matches = []
        for pattern_name, compiled_pattern in self.compiled_patterns.items():
            try:
                found_matches = compiled_pattern.findall(text)
                for match in found_matches:
                    matches.append({
                        "pattern_name": pattern_name,
                        "pattern_regex": self.patterns[pattern_name],
                        "matched_value": match,
                        "match_position": text.find(match)
                    })
            except Exception as e:
                self.logger.warning(f"Pattern detection error ({pattern_name}): {e}")
                continue
        return matches
    
    def extract_context(self, text: str, match_value: str, context_size: int = DEFAULT_CONTEXT_SIZE) -> str:
        """Extract context around the match"""
        pos = text.find(match_value)
        if pos != -1:
            start = max(0, pos - context_size)
            end = min(len(text), pos + len(match_value) + context_size)
            return text[start:end]
        return text[:MAX_CONTENT_LENGTH]


class EventProcessor:
    """Processes GitHub events and extracts searchable content"""
    
    def __init__(self, pattern_detector: PatternDetector, logger: Logger):
        self.pattern_detector = pattern_detector
        self.logger = logger
    
    def process_event(self, event: Dict[Any, Any]) -> List[SearchResult]:
        """Process a single GitHub event"""
        results = []
        
        try:
            event_info = self._extract_event_info(event)
            search_fields = self._extract_search_fields(event.get('payload', {}))
            
            for location, content in search_fields.items():
                if not content or not content.strip():
                    continue
                
                pattern_matches = self.pattern_detector.detect_patterns(content)
                if pattern_matches:
                    url = self._extract_url(event, event.get('payload', {}), location)
                    context_content = self._get_context_content(content, pattern_matches)
                    
                    self.logger.detection(
                        f"SENSITIVE TOKEN DETECTED: {len(pattern_matches)} patterns in {event_info['repository']}"
                    )
                    
                    for match in pattern_matches:
                        self.logger.info(
                            f"   - {match['pattern_name']}: {match['matched_value'][:20]}...",
                            use_emoji=False
                        )

                    results.append(SearchResult(
                        event_type=event_info['event_type'],
                        repository=event_info['repository'],
                        user=event_info['user'],
                        timestamp=event_info['timestamp'],
                        location=location,
                        content=context_content,
                        url=url,
                        pattern_matches=pattern_matches
                    ))
        
        except Exception as e:
            self.logger.warning(f"Error processing event: {e}")
        
        return results
    
    def _extract_event_info(self, event: Dict[Any, Any]) -> Dict[str, str]:
        """Extract basic event information"""
        return {
            'event_type': event.get('type', 'Unknown'),
            'repository': event.get('repo', {}).get('name', 'Unknown'),
            'user': event.get('actor', {}).get('login', 'Unknown'),
            'timestamp': event.get('created_at', '')
        }
    
    def _extract_search_fields(self, payload: Dict) -> Dict[str, str]:
        """Extract fields to search from event payload"""
        return {
            'commit_message': self._extract_commit_messages(payload),
            'pr_title': payload.get('pull_request', {}).get('title', ''),
            'pr_body': payload.get('pull_request', {}).get('body', ''),
            'issue_title': payload.get('issue', {}).get('title', ''),
            'issue_body': payload.get('issue', {}).get('body', ''),
            'comment_body': payload.get('comment', {}).get('body', ''),
            'release_body': payload.get('release', {}).get('body', ''),
            'gist_description': payload.get('gist', {}).get('description', ''),
            'gist_files': self._extract_gist_files(payload),
        }
    
    def _extract_commit_messages(self, payload: Dict) -> str:
        """Extract commit messages"""
        messages = []
        
        # From commits array
        commits = payload.get('commits', [])
        for commit in commits:
            if commit.get('message'):
                messages.append(commit['message'])
        
        # From head_commit
        head_commit = payload.get('head_commit', {})
        if head_commit.get('message'):
            messages.append(head_commit['message'])
        
        return ' '.join(messages)
    
    def _extract_gist_files(self, payload: Dict) -> str:
        """Extract gist file contents"""
        gist = payload.get('gist', {})
        files = gist.get('files', {})
        content = []
        
        for filename, file_data in files.items():
            if file_data.get('content'):
                content.append(f"=== {filename} ===\n{file_data['content']}")
        
        return '\n\n'.join(content)
    
    def _extract_url(self, event: Dict, payload: Dict, location: str) -> str:
        """Extract URL based on event type"""
        repo_name = event.get('repo', {}).get('name', '')
        
        url_mapping = {
            'commit_message': self._get_commit_url,
            'pr_title': lambda e, p: p.get('pull_request', {}).get('html_url', f"https://github.com/{repo_name}/pulls"),
            'pr_body': lambda e, p: p.get('pull_request', {}).get('html_url', f"https://github.com/{repo_name}/pulls"),
            'issue_title': lambda e, p: p.get('issue', {}).get('html_url', f"https://github.com/{repo_name}/issues"),
            'issue_body': lambda e, p: p.get('issue', {}).get('html_url', f"https://github.com/{repo_name}/issues"),
            'comment_body': lambda e, p: p.get('comment', {}).get('html_url', ''),
            'release_body': lambda e, p: p.get('release', {}).get('html_url', f"https://github.com/{repo_name}/releases"),
            'gist_description': lambda e, p: p.get('gist', {}).get('html_url', ''),
            'gist_files': lambda e, p: p.get('gist', {}).get('html_url', '')
        }
        
        url_func = url_mapping.get(location)
        if url_func:
            return url_func(event, payload)
        
        return f"https://github.com/{repo_name}"
    
    def _get_commit_url(self, event: Dict, payload: Dict) -> str:
        """Get commit URL"""
        repo_name = event.get('repo', {}).get('name', '')
        commit = payload.get('head_commit') or payload.get('commits', [{}])[0]
        
        if commit.get('url'):
            return commit['url']
        elif commit.get('sha'):
            return f"https://github.com/{repo_name}/commit/{commit['sha']}"
        
        return f"https://github.com/{repo_name}"
    
    def _get_context_content(self, content: str, pattern_matches: List[Dict[str, str]]) -> str:
        """Get context content for the first match"""
        if pattern_matches:
            first_match = pattern_matches[0]["matched_value"]
            return self.pattern_detector.extract_context(content, first_match, 400)
        return content


class ResultsManager:
    """Handles saving and formatting of scan results"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.output_dir = Path("Outputs")
    
    def save_results(self, results: List[SearchResult], output_file: str, 
                    start_time: datetime, end_time: datetime, 
                    scanned_patterns: List[str]) -> Tuple[str, str]:
        """Save results to detailed and tokens-only JSON files"""
        
        # Create Outputs directory if it doesn't exist
        self.output_dir.mkdir(exist_ok=True)
        
        start_str = start_time.strftime("%Y-%m-%d-%H")
        end_str = end_time.strftime("%Y-%m-%d-%H")
        
        base_name = Path(output_file).stem  # Get filename without extension
        detailed_filename = self.output_dir / f"{base_name}_{start_str}_to_{end_str}.json"
        tokens_filename = self.output_dir / f"{base_name}_tokens_only_{start_str}_to_{end_str}.json"
        
        # Generate statistics
        pattern_stats, detected_tokens = self._generate_statistics(results)
        
        # Save detailed report
        detailed_output = self._create_detailed_report(
            results, start_time, end_time, scanned_patterns, pattern_stats
        )
        self._save_json_file(detailed_output, detailed_filename)
        
        # Save tokens only
        tokens_output = {pattern: list(tokens) for pattern, tokens in detected_tokens.items()}
        self._save_json_file(tokens_output, tokens_filename)
        
        self.logger.success(f"Detailed report saved: {detailed_filename}")
        self.logger.success(f"Tokens only saved: {tokens_filename}")
        
        return str(detailed_filename), str(tokens_filename)
    
    def _generate_statistics(self, results: List[SearchResult]) -> Tuple[Dict[str, int], Dict[str, Set[str]]]:
        """Generate pattern statistics and collect unique tokens"""
        pattern_stats = {}
        detected_tokens = {}
        
        for result in results:
            if result.pattern_matches:
                for match in result.pattern_matches:
                    pattern_name = match['pattern_name']
                    token_value = match['matched_value']
                    
                    # Count for statistics
                    pattern_stats[pattern_name] = pattern_stats.get(pattern_name, 0) + 1
                    
                    # Collect unique tokens
                    if pattern_name not in detected_tokens:
                        detected_tokens[pattern_name] = set()
                    detected_tokens[pattern_name].add(token_value)
        
        return pattern_stats, detected_tokens
    
    def _create_detailed_report(self, results: List[SearchResult], start_time: datetime, 
                              end_time: datetime, scanned_patterns: List[str], 
                              pattern_stats: Dict[str, int]) -> Dict:
        """Create detailed report structure"""
        total_patterns = sum(pattern_stats.values())
        
        scan_summary = ScanSummary(
            scan_time=datetime.now().isoformat(),
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            total_results=len(results),
            total_patterns_found=total_patterns,
            unique_pattern_types=len(pattern_stats),
            scanned_patterns=scanned_patterns,
            pattern_statistics=pattern_stats
        )
        
        return {
            'scan_summary': asdict(scan_summary),
            'sensitive_token_detections': [self._result_to_dict(result) for result in results]
        }
    
    def _result_to_dict(self, result: SearchResult) -> Dict:
        """Convert SearchResult to dictionary"""
        return {
            'event_type': result.event_type,
            'repository': result.repository,
            'user': result.user,
            'timestamp': result.timestamp,
            'location': result.location,
            'content': result.content,
            'url': result.url,
            'detected_patterns': result.pattern_matches or []
        }
    
    def _save_json_file(self, data: Dict, filename: Path) -> None:
        """Save data to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise GitDredgerError(f"Failed to save {filename}: {e}")


class SummaryPrinter:
    """Handles printing of scan summaries"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def print_summary(self, results: List[SearchResult]) -> None:
        """Print comprehensive summary of search results"""
        if not results:
            self.logger.error("No sensitive tokens found!")
            return
        
        print(f"\n📊 SENSITIVE TOKEN SCAN SUMMARY")
        print("=" * 60)
        print(f"📈 Total detections: {len(results):,}")
        
        # Pattern statistics
        pattern_counts = {}
        total_matches = 0
        
        for result in results:
            if result.pattern_matches:
                for match in result.pattern_matches:
                    pattern_name = match['pattern_name']
                    pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
                    total_matches += 1
        
        print(f"📊 Total pattern matches: {total_matches:,}")
        print(f"🔍 Detected pattern types: {len(pattern_counts)}")
        
        self._print_pattern_statistics(pattern_counts)
        self._print_critical_findings(results)
        self._print_repository_statistics(results)
    
    def _print_pattern_statistics(self, pattern_counts: Dict[str, int]) -> None:
        """Print pattern statistics"""
        if pattern_counts:
            print(f"\n🚨 Detected Patterns:")
            for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"   {pattern}: {count:,} instances")
    
    def _print_critical_findings(self, results: List[SearchResult]) -> None:
        """Print top critical findings"""
        print(f"\n🔥 Top Critical Findings (First 5):")
        for i, result in enumerate(results[:5], 1):
            pattern_names = [m['pattern_name'] for m in result.pattern_matches] if result.pattern_matches else []
            print(f"   {i}. [{result.event_type}] {result.repository}")
            print(f"      👤 User: {result.user}")
            print(f"      📅 Time: {result.timestamp}")
            print(f"      📍 Location: {result.location}")
            print(f"      🚨 Patterns: {', '.join(pattern_names[:3])}")
            print(f"      🔗 URL: {result.url}")
            print()
    
    def _print_repository_statistics(self, results: List[SearchResult]) -> None:
        """Print repository statistics"""
        repositories = {}
        for result in results:
            repositories[result.repository] = repositories.get(result.repository, 0) + 1
        
        print(f"\n🏛️  Most Risky Repositories:")
        for repo, count in sorted(repositories.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"   {repo}: {count} detections")


class TimeRangeGenerator:
    """Generates time ranges for scanning"""
    
    @staticmethod
    def generate_hour_range(start_time: datetime, end_time: datetime) -> List[str]:
        """Generate hour range between start and end times"""
        hours = []
        current = start_time.replace(minute=0, second=0, microsecond=0)
        
        while current <= end_time:
            hours.append(current.strftime("%Y-%m-%d-%H"))
            current += timedelta(hours=1)
        
        return hours


class GitDredgerScanner:
    """Main scanner class that orchestrates the scanning process"""
    
    def __init__(self, output_file: str = DEFAULT_OUTPUT_FILE, 
                 config_file: str = DEFAULT_CONFIG_FILE):
        self.output_file = output_file
        self.config_file = config_file
        self.logger = Logger()
        
        # Initialize components
        self.pattern_loader = PatternLoader(self.logger)
        self.downloader = ArchiveDownloader(self.logger)
        self.results_manager = ResultsManager(self.logger)
        self.summary_printer = SummaryPrinter(self.logger)
        
        # Load patterns and initialize detector
        self.patterns = self.pattern_loader.load_patterns(config_file)
        if not self.patterns:
            raise ConfigurationError("No valid patterns loaded")
        
        self.pattern_detector = PatternDetector(self.patterns, self.logger)
        self.event_processor = EventProcessor(self.pattern_detector, self.logger)
    
    def scan_timerange(self, start_time: datetime, end_time: datetime, max_workers: int = DEFAULT_WORKERS) -> List[SearchResult]:
        """Perform parallel search in time range"""
        hours = TimeRangeGenerator.generate_hour_range(start_time, end_time)
        all_results = []
        
        self._print_scan_parameters(start_time, end_time, hours, max_workers)
        
        # Parallel search
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_hour = {
                executor.submit(self._scan_hour, hour): hour 
                for hour in hours
            }
            
            for future in concurrent.futures.as_completed(future_to_hour):
                hour = future_to_hour[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    self.logger.error(f"Error scanning {hour}: {e}")
        
        return all_results
    
    def _scan_hour(self, hour_str: str) -> List[SearchResult]:
        """Scan a single hour"""
        try:
            data = self.downloader.download_archive(hour_str)
            if not data:
                return []
            
            hour_results = []
            
            for line in data.strip().split('\n'):
                if not line:
                    continue
                    
                try:
                    event = json.loads(line)
                    event_results = self.event_processor.process_event(event)
                    hour_results.extend(event_results)
                    
                except json.JSONDecodeError:
                    continue
            
            self.logger.info(f"🔍 {hour_str}: {len(hour_results)} sensitive tokens found", use_emoji=False)
            return hour_results
            
        except Exception as e:
            self.logger.error(f"Failed to scan hour {hour_str}: {e}")
            return []
    
    def _print_scan_parameters(self, start_time: datetime, end_time: datetime, 
                             hours: List[str], max_workers: int) -> None:
        """Print scan parameters"""
        print(f"🎯 Sensitive Token Search Parameters:")
        print(f"   📅 Time range: {start_time} - {end_time}")
        print(f"   🔑 Number of patterns to search: {len(self.patterns)}")
        print(f"   ⏰ Number of hours to scan: {len(hours)}")
        print(f"   🔄 Number of parallel workers: {max_workers}")
        print("-" * 60)
    
    def save_results(self, results: List[SearchResult], start_time: datetime, end_time: datetime) -> Tuple[str, str]:
        """Save scan results"""
        return self.results_manager.save_results(
            results, self.output_file, start_time, end_time, list(self.patterns.keys())
        )
    
    def print_summary(self, results: List[SearchResult]) -> None:
        """Print scan summary"""
        self.summary_printer.print_summary(results)


class DateTimeParser:
    """Handles parsing of various datetime formats"""
    
    SUPPORTED_FORMATS = [
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d %H",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M",
        "%Y/%m/%d",
        "%d.%m.%Y %H:%M",
        "%d.%m.%Y"
    ]
    
    @classmethod
    def parse_datetime(cls, date_str: str) -> datetime:
        """Parse various date formats"""
        for fmt in cls.SUPPORTED_FORMATS:
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        
        raise ValueError(f"Unsupported date format: {date_str}")


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        description="GitDredger - GitHub Archive Sensitive Token Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Usage examples:
  python3 gitdredger.py -l 1
  python3 gitdredger.py -s "2024-01-01 12:00" -e "2024-01-01 15:00"
  python3 gitdredger.py -l 6 -o my_results.json

Search patterns are loaded from Config/Token_Regex.json
Project: https://github.com/your-username/GitDredger
        """
    )
    
    # Time parameters
    time_group = parser.add_mutually_exclusive_group(required=True)
    time_group.add_argument('-l', '--last-hours', type=int, 
                           help='Search within the last X hours')
    time_group.add_argument('-s', '--start-time', type=str,
                           help='Start time (YYYY-MM-DD HH:MM)')
    
    parser.add_argument('-e', '--end-time', type=str,
                       help='End time (YYYY-MM-DD HH:MM), used with -s')
    
    # Other parameters
    parser.add_argument('-o', '--output', type=str, default=DEFAULT_OUTPUT_FILE,
                       help=f'Output file name (default: {DEFAULT_OUTPUT_FILE})')
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS,
                       help=f'Number of parallel workers (default: {DEFAULT_WORKERS})')
    parser.add_argument('--no-save', action='store_true',
                       help='Do not save results to file')
    parser.add_argument('--config', type=str, default=DEFAULT_CONFIG_FILE,
                       help=f'Configuration file path (default: {DEFAULT_CONFIG_FILE})')
    
    return parser


def print_banner():
    """Print GitDredger ASCII art banner"""
    banner = r"""
   _____ _ _   _____               _                 
  / ____(_) | |  __ \             | |                
 | |  __ _| |_| |  | |_ __ ___  __| | __ _  ___ _ __ 
 | | |_ | | __| |  | | '__/ _ \/ _` |/ _` |/ _ \ '__|
 | |__| | | |_| |__| | | |  __/ (_| | (_| |  __/ |   
  \_____|_|\__|_____/|_|  \___|\__,_|\__, |\___|_|   
                                      __/ |          
                                     |___/           
    """
    print(banner)
    time.sleep(1)


def main():
    """Main entry point"""
    try:
        # Print banner and wait 1 second
        print_banner()
        
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Determine time range
        if args.last_hours:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=args.last_hours)
        else:
            start_time = DateTimeParser.parse_datetime(args.start_time)
            if args.end_time:
                end_time = DateTimeParser.parse_datetime(args.end_time)
            else:
                end_time = start_time + timedelta(hours=1)
        
        # Initialize scanner
        scanner = GitDredgerScanner(args.output, args.config)
        
        # Perform search
        results = scanner.scan_timerange(start_time, end_time, args.workers)
        
        # Show results
        scanner.print_summary(results)
        
        # Save results
        if not args.no_save:
            scanner.save_results(results, start_time, end_time)
    
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 
