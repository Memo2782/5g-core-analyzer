import asyncio
import json
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional

from core.log_processor import CoreLogProcessor
from core.database import AlertRecord, get_db


class Alert:
    """Represents a triggered alert rule."""
    def __init__(self, rule_id: str, rule_name: str, severity: str, 
                 message: str, count: int, window_seconds: int, 
                 node: str, interface: str, evidence: List[Dict], tenant_id: str = ""):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.message = message
        self.count = count
        self.window_seconds = window_seconds
        self.node = node
        self.interface = interface
        self.evidence = evidence
        self.tenant_id = tenant_id
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.id = f"alert-{int(time.time()*1000)}-{hash(self.timestamp) % 10000:04d}"

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "message": self.message,
            "count": self.count,
            "window_seconds": self.window_seconds,
            "node": self.node,
            "interface": self.interface,
            "timestamp": self.timestamp,
            "evidence": self.evidence[:5],  # limit evidence size
        }


class AlertWindow:
    """Sliding window for alert threshold detection."""
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.events: deque = deque()
    
    def add(self, event: Dict) -> Optional[Dict]:
        """Add event and return aggregated stats if threshold reached."""
        now = datetime.utcnow()
        self.events.append((now, event))
        
        # Prune old events
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
        
        return {
            "count": len(self.events),
            "window_seconds": self.window_seconds,
            "events": [e for _, e in self.events]
        }
    
    def reset(self):
        self.events.clear()


class LogAgent:
    """Real-time log monitoring agent for 5G Core nodes."""
    
    def __init__(self, config_path: str = "config/alert_rules.json"):
        self.processor = CoreLogProcessor()
        self.rules: List[Dict] = []
        self.alert_windows: Dict[str, AlertWindow] = {}
        self.alert_history: List[Alert] = []
        self.active_alerts: Dict[str, Alert] = {}
        self.subscribers: List[asyncio.Queue] = []
        self.running = False
        self._load_rules(config_path)
    
    def _load_rules(self, config_path: str):
        """Load alert rules from JSON config."""
        if not os.path.exists(config_path):
            print(f"[!] Alert rules not found: {config_path}")
            return
        
        with open(config_path, "r") as f:
            config = json.load(f)
        
        self.rules = config.get("rules", [])
        for rule in self.rules:
            rule_id = rule["id"]
            window_sec = rule["threshold"]["window_seconds"]
            self.alert_windows[rule_id] = AlertWindow(window_sec)
        
        print(f"[+] Loaded {len(self.rules)} alert rules")
    
    def subscribe(self) -> asyncio.Queue:
        """Add a subscriber for real-time alerts."""
        queue = asyncio.Queue()
        self.subscribers.append(queue)
        return queue
    
    def unsubscribe(self, queue: asyncio.Queue):
        """Remove a subscriber."""
        if queue in self.subscribers:
            self.subscribers.remove(queue)
    
    async def _broadcast(self, alert: Alert):
        """Send alert to all subscribers."""
        for queue in self.subscribers:
            try:
                queue.put_nowait(alert.to_dict())
            except asyncio.QueueFull:
                pass
    
    def _matches_condition(self, event: Dict, condition: Dict) -> bool:
        """Check if event matches alert rule condition."""
        field = condition.get("field", "")
        operator = condition.get("operator", "eq")
        
        if operator == "eq":
            result = str(event.get(field, "")) == str(condition.get("value", ""))
        elif operator == "in":
            result = str(event.get(field, "")) in [str(v) for v in condition.get("values", [])]
        elif operator == "regex":
            pattern = condition.get("pattern", "")
            result = bool(re.search(pattern, str(event.get(field, ""))))
        else:
            result = False
        return result
    
    def _evaluate_rules(self, event: Dict) -> List[Alert]:
        """Evaluate event against all alert rules."""
        triggered_alerts = []
        
        for rule in self.rules:
            if not self._matches_condition(event, rule["condition"]):
                continue
            
            rule_id = rule["id"]
            window = self.alert_windows[rule_id]
            stats = window.add(event)
            
            if stats and stats["count"] >= rule["threshold"]["count"]:
                # Check if we already have an active alert for this rule
                if rule_id not in self.active_alerts:
                    # Format message with template variables
                    msg = rule["message"].format(
                        count=stats["count"],
                        window=stats["window_seconds"],
                        rate=min(stats["count"] * 2, 100)
                    )
                    
                    alert = Alert(
                        rule_id=rule_id,
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        message=msg,
                        count=stats["count"],
                        window_seconds=stats["window_seconds"],
                        node=rule.get("node", "unknown"),
                        interface=rule.get("interface", "unknown"),
                        evidence=stats["events"]
                    )
                    
                    triggered_alerts.append(alert)
                    self.active_alerts[rule_id] = alert
                    self.alert_history.append(alert)
        
        return triggered_alerts
    
    async def process_event(self, event: Dict, tenant_id: str = ""):
        """Process a single log event through alert rules."""
        alerts = self._evaluate_rules(event)
        for alert in alerts:
            alert.tenant_id = tenant_id
            await self._broadcast(alert)
            await self._send_notifications(alert)
            self._persist_alert(alert)
    
    def _persist_alert(self, alert: Alert):
        """Persist alert to database if tenant_id is set."""
        if not alert.tenant_id:
            return
        try:
            db = next(get_db())
            record = AlertRecord(
                id=alert.id,
                tenant_id=alert.tenant_id,
                rule_id=alert.rule_id,
                rule_name=alert.rule_name,
                severity=alert.severity,
                message=alert.message,
                count=alert.count,
                window_seconds=alert.window_seconds,
                node=alert.node,
                interface=alert.interface,
                evidence=json.dumps(alert.evidence),
            )
            db.add(record)
            db.commit()
        except Exception as e:
            print(f"[!] Failed to persist alert: {e}")
    
    def get_alert_history(self, tenant_id: str = "", limit: int = 100) -> List[Dict]:
        """Get recent alert history, optionally filtered by tenant."""
        if tenant_id:
            try:
                db = next(get_db())
                records = (
                    db.query(AlertRecord)
                    .filter(AlertRecord.tenant_id == tenant_id)
                    .order_by(AlertRecord.created_at.desc())
                    .limit(limit)
                    .all()
                )
                return [
                    {
                        "id": r.id,
                        "rule_id": r.rule_id,
                        "rule_name": r.rule_name,
                        "severity": r.severity,
                        "message": r.message,
                        "count": r.count,
                        "window_seconds": r.window_seconds,
                        "node": r.node,
                        "interface": r.interface,
                        "timestamp": r.created_at.isoformat() + "Z",
                        "acknowledged": r.acknowledged,
                    }
                    for r in records
                ]
            except Exception as e:
                print(f"[!] Failed to load alert history: {e}")
        
        return [a.to_dict() for a in self.alert_history[-limit:]]
    
    def get_active_alerts(self, tenant_id: str = "") -> List[Dict]:
        """Get currently active alerts, optionally filtered by tenant."""
        if tenant_id:
            try:
                db = next(get_db())
                records = (
                    db.query(AlertRecord)
                    .filter(AlertRecord.tenant_id == tenant_id, AlertRecord.acknowledged == False)
                    .all()
                )
                return [
                    {
                        "id": r.id,
                        "rule_id": r.rule_id,
                        "rule_name": r.rule_name,
                        "severity": r.severity,
                        "message": r.message,
                        "count": r.count,
                        "node": r.node,
                        "interface": r.interface,
                        "timestamp": r.created_at.isoformat() + "Z",
                    }
                    for r in records
                ]
            except Exception as e:
                print(f"[!] Failed to load active alerts: {e}")
        
        return [a.to_dict() for a in self.active_alerts.values()]
    
    async def _send_notifications(self, alert: Alert):
        """Send notifications via configured channels."""
        # Placeholder for WhatsApp/Email/Slack integration
        # This will be implemented in notifier.py
        pass
    
    async def stream_from_file(self, filepath: str) -> AsyncGenerator[Dict, None]:
        """Stream log events from a file in real-time (tail -f pattern)."""
        path = Path(filepath)
        if not path.exists():
            print(f"[!] Log file not found: {filepath}")
            return
        
        # Initial read of existing content
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    log_entry = json.loads(line)
                    yield log_entry
                except json.JSONDecodeError:
                    continue
        
        # Tail new content
        with open(filepath, "r") as f:
            f.seek(0, 2)  # Seek to end
            while self.running:
                line = f.readline()
                if line:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        log_entry = json.loads(line)
                        yield log_entry
                    except json.JSONDecodeError:
                        continue
                else:
                    await asyncio.sleep(0.1)
    
    async def stream_from_directory(self, directory: str) -> AsyncGenerator[Dict, None]:
        """Stream logs from all files in a directory."""
        path = Path(directory)
        if not path.exists() or not path.is_dir():
            print(f"[!] Log directory not found: {directory}")
            return
        
        # Get all .log and .json files
        log_files = list(path.glob("*.log")) + list(path.glob("*.json"))
        if not log_files:
            print(f"[!] No log files found in {directory}")
            return
        
        # Create tasks for each file
        tasks = []
        for log_file in log_files:
            async def read_file(filepath):
                async for event in self.stream_from_file(filepath):
                    yield event
            
            tasks.append(read_file(log_file))
        
        # Merge streams using round-robin
        while self.running and tasks:
            for i, task in enumerate(tasks[:]):
                try:
                    event = await asyncio.wait_for(task.__anext__(), timeout=0.1)
                    yield event
                except StopAsyncIteration:
                    tasks.remove(task)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    print(f"[!] Error reading file: {e}")
                    tasks.remove(task)
    
    async def start_monitoring(self, source: str, tenant_id: str = ""):
        """Start monitoring logs from a file or directory."""
        self.running = True
        print(f"[+] Starting log monitoring: {source} (tenant={tenant_id or 'global'})")
        
        path = Path(source)
        if path.is_file():
            stream = self.stream_from_file(source)
        elif path.is_dir():
            stream = self.stream_from_directory(source)
        else:
            print(f"[!] Invalid source: {source}")
            return
        
        async for event in stream:
            if not self.running:
                break
            
            # Process event through alert rules with tenant context
            await self.process_event(event, tenant_id=tenant_id)
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        print("[+] Log monitoring stopped")
    
    def reset_alert(self, alert_id: str):
        """Reset an active alert to allow re-triggering."""
        for rule_id, alert in list(self.active_alerts.items()):
            if alert.id == alert_id:
                del self.active_alerts[rule_id]
                self.alert_windows[rule_id].reset()
                print(f"[+] Reset alert: {alert_id}")
