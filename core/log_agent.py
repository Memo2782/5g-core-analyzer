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

try:
    from scapy.all import AsyncSniffer, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class Alert:
    """Represents a triggered alert rule."""
    def __init__(self, rule_id: str, rule_name: str, severity: str, 
                 message: str, count: int, window_seconds: int, 
                 node: str, interface: str, evidence: List[Dict], tenant_id: str = "",
                 imsi: str = "", msisdn: str = ""):
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
        self.imsi = imsi
        self.msisdn = msisdn
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
            "imsi": self.imsi,
            "msisdn": self.msisdn,
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
        self.capture_sniffer = None
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
        """Add a subscriber for real-time alerts. Replays active alerts on connect."""
        queue = asyncio.Queue()
        self.subscribers.append(queue)
        for alert in self.active_alerts.values():
            queue.put_nowait(alert.to_dict())
        return queue
    
    def unsubscribe(self, queue: asyncio.Queue):
        """Remove a subscriber."""
        if queue in self.subscribers:
            self.subscribers.remove(queue)
    
    async def _broadcast(self, alert):
        """Send alert to all subscribers."""
        data = alert.to_dict() if hasattr(alert, 'to_dict') else alert
        for queue in self.subscribers:
            try:
                queue.put_nowait(data)
            except asyncio.QueueFull:
                pass

    async def broadcast_clear(self):
        """Broadcast a clear message to all subscribers."""
        await self._broadcast({"type": "clear"})
    
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
                        evidence=stats["events"],
                        imsi=event.get("imsi", ""),
                        msisdn=event.get("msisdn", "")
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
                imsi=alert.imsi,
                msisdn=alert.msisdn,
            )
            db.add(record)
            db.commit()
        except Exception as e:
            print(f"[!] Failed to persist alert: {e}")
    
    def get_alert_history(self, tenant_id: str = "", limit: int = 100, imsi: str = "", msisdn: str = "") -> List[Dict]:
        """Get recent alert history, optionally filtered by tenant and subscriber."""
        if tenant_id:
            try:
                db = next(get_db())
                query = db.query(AlertRecord).filter(AlertRecord.tenant_id == tenant_id)
                if imsi:
                    query = query.filter(AlertRecord.imsi == imsi)
                if msisdn:
                    query = query.filter(AlertRecord.msisdn == msisdn)
                records = query.order_by(AlertRecord.created_at.desc()).limit(limit).all()
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
                        "imsi": r.imsi,
                        "msisdn": r.msisdn,
                    }
                    for r in records
                ]
            except Exception as e:
                print(f"[!] Failed to load alert history: {e}")
        
        return [a.to_dict() for a in self.alert_history[-limit:]]
    
    def get_active_alerts(self, tenant_id: str = "", imsi: str = "", msisdn: str = "") -> List[Dict]:
        """Get currently active alerts, optionally filtered by tenant and subscriber."""
        alerts = []
        for alert in self.active_alerts.values():
            if tenant_id and alert.tenant_id and alert.tenant_id != tenant_id:
                continue
            if imsi and alert.imsi and alert.imsi != imsi:
                continue
            if msisdn and alert.msisdn and alert.msisdn != msisdn:
                continue
            alerts.append(alert.to_dict())
        return alerts
    
    async def _send_notifications(self, alert: Alert):
        """Send notifications via configured channels."""
        # Placeholder for WhatsApp/Email/Slack integration
        # This will be implemented in notifier.py
        pass
    
    async def stream_from_file(self, filepath: str) -> AsyncGenerator[Dict, None]:
        """Stream log events from a file in real-time (tail -f pattern).

        Reopens the file on each poll cycle to work around Docker for Mac
        file-system caching, which can serve a stale file descriptor that
        does not reflect appends made on the host.
        """
        path = Path(filepath)
        if not path.exists():
            print(f"[!] Log file not found: {filepath}")
            return

        last_pos = 0

        # Initial read of existing content
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    event = self._parse_log_line(line)
                    if event:
                        yield event
                last_pos = f.tell()
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")

        # Tail new content – reopen file each iteration so Docker for Mac
        # bind-mount caching doesn't serve a stale file descriptor.
        while self.running:
            try:
                file_size = os.path.getsize(filepath)
                if file_size < last_pos:
                    last_pos = 0

                new_lines: List[str] = []
                with open(filepath, "r") as f:
                    f.seek(last_pos)
                    new_lines = f.readlines()
                    last_pos = f.tell()

                if new_lines:
                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue
                        event = self._parse_log_line(line)
                        if event:
                            yield event
                else:
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                if not self.running:
                    raise
                continue
            except Exception as e:
                print(f"[!] Error tailing {filepath}: {e}")
                await asyncio.sleep(1.0)
    
    def _parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line into an event dict. Supports JSON and plain-text formats."""
        # Try JSON first
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            pass
        
        # Try plain-text HTTP/SIP log format
        event = self._parse_plain_text_log(line)
        return event
    
    def _parse_plain_text_log(self, line: str) -> Optional[Dict]:
        """Parse plain-text 5G/IMS log lines into structured events."""
        result = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_nf": "",
            "dest_nf": "",
            "interface": "",
            "http_status": "",
            "details": line[:200],
            "imsi": "",
            "msisdn": "",
            "call_id": "",
        }
        
        # Extract Open5GS-style timestamp: 08/20 19:56:04.335: [module] LEVEL: message
        o5gs_ts = re.match(r"(\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}):\s+\[([^\]]+)\]\s+(\w+):\s+(.*)", line)
        if o5gs_ts:
            result["timestamp"] = "2026-" + o5gs_ts.group(1).replace("/", "-").replace(" ", "T") + "Z"
            module = o5gs_ts.group(2).lower()
            level = o5gs_ts.group(3).upper()
            message = o5gs_ts.group(4)
            
            # Map Open5GS module names to NF names
            nf_map = {
                "sbi": "NRF",
                "amf": "AMF",
                "smf": "SMF",
                "upf": "UPF",
                "ausf": "AUSF",
                "udm": "UDM",
                "udr": "UDR",
                "pcf": "PCF",
                "bsf": "BSF",
                "nssf": "NSSF",
                "scp": "SCP",
                "gtp": "GTP",
                "pfcp": "PFCP",
                "sock": "SOCKET",
                "app": "APP",
                "core": "CORE",
            }
            result["source_nf"] = nf_map.get(module, module.upper())
            
            # Map error levels to HTTP status codes for alert rule compatibility
            if level == "FATAL":
                result["http_status"] = "500"
            elif level == "ERROR":
                result["http_status"] = "503"
            elif level == "WARNING":
                result["http_status"] = "504"
            elif level == "CRITICAL":
                result["http_status"] = "500"
            
            # Detect interface from message context
            if "N11" in message or "smf" in module:
                result["interface"] = result["interface"] or "N11"
            elif "N5" in message or "pcf" in module:
                result["interface"] = result["interface"] or "N5"
            elif "N12" in message or "ausf" in module:
                result["interface"] = result["interface"] or "N12"
            elif "N8" in message or "udm" in module:
                result["interface"] = result["interface"] or "N8"
            elif "N4" in message or "pfcp" in module:
                result["interface"] = result["interface"] or "N4"
            elif "GTP" in message or "gtp" in module:
                result["interface"] = result["interface"] or "N3"
            elif "NGAP" in message or "amf" in module:
                result["interface"] = result["interface"] or "N2"
            
            result["details"] = f"[{module}] {message[:150]}"
            return result
        
        # Extract ISO timestamp
        ts_match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s+", line)
        if ts_match:
            result["timestamp"] = ts_match.group(1)
        
        # Extract HTTP status code
        status_match = re.search(r'"\s+(\d{3})\s', line)
        if status_match:
            result["http_status"] = status_match.group(1)
        
        # Extract IMSI/MSISDN from URL params or P-Charging-Vector
        imsi_match = re.search(r"imsi=([0-9a-fA-F]+)", line)
        msisdn_match = re.search(r"msisdn=([0-9]+)", line)
        call_id_match = re.search(r"call-id=([^\s;]+)", line)
        
        if imsi_match:
            result["imsi"] = imsi_match.group(1)
        if msisdn_match:
            result["msisdn"] = msisdn_match.group(1)
        if call_id_match:
            result["call_id"] = call_id_match.group(1)
        
        # Extract interface from path
        iface_match = re.search(r"/n(\d+)[^/]*", line)
        if iface_match:
            result["interface"] = f"N{iface_match.group(1)}"
        
        # Detect SIP vs HTTP
        if "SIP/" in line or "INVITE" in line or "REGISTER" in line:
            result["interface"] = result["interface"] or "Gm/Mw"
        
        # Only return if we have at least a status or identity
        if result["http_status"] or result["imsi"] or result["msisdn"]:
            return result
        
        return None
    
    async def stream_from_directory(self, directory: str) -> AsyncGenerator[Dict, None]:
        """Stream logs from all files in a directory.

        Uses background producer tasks that push events into a shared
        asyncio.Queue.  This avoids the asyncio.wait_for cancellation
        problem: wait_for on an async-generator __anext__ injects
        CancelledError (a BaseException) which the generator does not
        catch, silently closing it and killing the monitoring loop.
        """
        path = Path(directory)
        if not path.exists() or not path.is_dir():
            print(f"[!] Log directory not found: {directory}")
            return

        log_files = list(path.glob("*.log")) + list(path.glob("*.json"))
        if not log_files:
            print(f"[!] No log files found in {directory}")
            return

        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        producers: List[asyncio.Task] = []

        async def _producer(filepath: str):
            try:
                async for event in self.stream_from_file(filepath):
                    if not self.running:
                        break
                    await queue.put(event)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                print(f"[!] Producer error for {filepath}: {e}")

        for log_file in log_files:
            producers.append(asyncio.create_task(_producer(str(log_file))))

        try:
            while self.running:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=2.0)
                    yield event
                except asyncio.TimeoutError:
                    continue
        finally:
            for p in producers:
                p.cancel()
            await asyncio.gather(*producers, return_exceptions=True)
    
    async def stream_from_live_capture(self, interface: str) -> AsyncGenerator[Dict, None]:
        """Stream parsed events from live packet capture on a network interface."""
        if not SCAPY_AVAILABLE:
            print("[!] scapy is not installed. Live capture unavailable.")
            return
        
        queue = asyncio.Queue(maxsize=1000)
        parser = PcapCoreParser()
        
        def packet_callback(pkt):
            try:
                payload_text = parser._extract_payload(pkt)
                if not payload_text:
                    return
                
                imsi, msisdn, call_id = parser._scan_identity(payload_text)
                
                event = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "source_nf": "LIVE_CAPTURE",
                    "dest_nf": "",
                    "interface": "CAPTURE",
                    "details": payload_text[:200],
                    "imsi": imsi or "",
                    "msisdn": msisdn or "",
                    "call_id": call_id or "",
                    "raw_payload": payload_text[:500],
                }
                
                if hasattr(pkt, 'haslayer') and pkt.haslayer('TCP'):
                    event["http_status"] = "200"
                    event["src_ip"] = pkt[0][1].src if hasattr(pkt[0][1], 'src') else ""
                    event["dst_ip"] = pkt[0][1].dst if hasattr(pkt[0][1], 'dst') else ""
                elif hasattr(pkt, 'haslayer') and pkt.haslayer('UDP'):
                    event["http_status"] = "200"
                    event["src_ip"] = pkt[0][1].src if hasattr(pkt[0][1], 'src') else ""
                    event["dst_ip"] = pkt[0][1].dst if hasattr(pkt[0][1], 'dst') else ""
                
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass
            except Exception as e:
                print(f"[!] Error parsing packet: {e}")
        
        sniffer = AsyncSniffer(iface=interface, prn=packet_callback, store=False)
        self.capture_sniffer = sniffer
        sniffer.start()
        print(f"[+] Started live capture on {interface}")
        
        try:
            while self.running:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield event
                except asyncio.TimeoutError:
                    continue
        finally:
            if sniffer.running:
                sniffer.stop()
            self.capture_sniffer = None
            print(f"[+] Stopped live capture on {interface}")
    
    async def ingest_events(self, events: List[Dict], tenant_id: str = ""):
        """Process a batch of ingested events through alert rules."""
        for event in events:
            await self.process_event(event, tenant_id=tenant_id)
    
    async def start_monitoring(self, source: str, tenant_id: str = ""):
        """Start monitoring logs from a file, directory, or live capture interface."""
        self.running = True
        self.active_alerts.clear()
        for window in self.alert_windows.values():
            window.reset()
        print(f"[+] Starting log monitoring: {source} (tenant={tenant_id or 'global'})")
        
        path = Path(source)
        if source.startswith("capture:"):
            interface = source[len("capture:"):]
            stream = self.stream_from_live_capture(interface)
        elif path.is_file():
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
    
    def get_capture_interfaces(self) -> List[str]:
        """Get list of available network interfaces for live capture."""
        if not SCAPY_AVAILABLE:
            return []
        try:
            return get_if_list()
        except Exception as e:
            print(f"[!] Failed to get interfaces: {e}")
            return []
    
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
    
    def clear_alerts(self, tenant_id: str = ""):
        """Clear all in-memory alert history and active alerts for a tenant."""
        self.alert_history.clear()
        self.active_alerts.clear()
        for window in self.alert_windows.values():
            window.reset()
        try:
            db = next(get_db())
            query = db.query(AlertRecord)
            if tenant_id:
                query = query.filter(AlertRecord.tenant_id == tenant_id)
            query.delete(synchronize_session=False)
            db.commit()
        except Exception as e:
            print(f"[!] Failed to clear alerts: {e}")
