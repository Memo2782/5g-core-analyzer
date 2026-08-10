import json
import os
import asyncio
import pytest
from core.log_agent import LogAgent, Alert


class TestLogAgentAlertRules:
    """Test alert rule evaluation and threshold detection."""

    def setup_method(self):
        """Create a fresh log agent for each test."""
        self.agent = LogAgent(config_path="config/alert_rules.json")
    
    def test_rules_loaded(self):
        """Verify alert rules are loaded from config."""
        assert len(self.agent.rules) > 0
        print(f"Loaded rules: {[r['name'] for r in self.agent.rules]}")
    
    def test_smf_timeout_triggers_alert(self):
        """SMF timeout burst should trigger critical alert."""
        smf_timeout_event = {
            "source_nf": "SMF",
            "dest_nf": "UPF",
            "interface": "N11",
            "http_status": "504",
            "timestamp": "2026-08-10T14:00:01Z"
        }
        
        alerts = []
        for _ in range(6):  # Threshold is 5
            result = self.agent._evaluate_rules(smf_timeout_event)
            alerts.extend(result)
        
        assert len(alerts) >= 1
        assert alerts[0].severity == "critical"
        assert "SMF" in alerts[0].message
        print(f"Triggered alert: {alerts[0].rule_name}")
    
    def test_ausf_auth_failure_triggers_alert(self):
        """AUSF auth failure should trigger critical alert."""
        auth_event = {
            "source_nf": "AUSF",
            "dest_nf": "AMF",
            "interface": "N12",
            "http_status": "401",
            "timestamp": "2026-08-10T14:00:01Z"
        }
        
        alerts = []
        for _ in range(4):  # Threshold is 3
            result = self.agent._evaluate_rules(auth_event)
            alerts.extend(result)
        
        assert len(alerts) >= 1
        assert alerts[0].severity == "critical"
        assert "AUSF" in alerts[0].message
    
    def test_non_matching_event_no_alert(self):
        """Events that don't match any rule should not trigger alerts."""
        normal_event = {
            "source_nf": "UE",
            "dest_nf": "GNB",
            "interface": "N2",
            "http_status": "200",
            "timestamp": "2026-08-10T14:00:01Z"
        }
        
        alerts = self.agent._evaluate_rules(normal_event)
        assert len(alerts) == 0
    
    def test_alert_history_tracks_alerts(self):
        """Alert history should persist triggered alerts."""
        event = {
            "source_nf": "SMF",
            "dest_nf": "UPF",
            "interface": "N11",
            "http_status": "504",
            "timestamp": "2026-08-10T14:00:01Z"
        }
        
        for _ in range(6):
            self.agent._evaluate_rules(event)
        
        history = self.agent.get_alert_history()
        assert len(history) >= 1
        assert history[0]["severity"] == "critical"
    
    def test_active_alerts_are_tracked(self):
        """Active alerts should be queryable."""
        event = {
            "source_nf": "UDM",
            "dest_nf": "AMF",
            "interface": "N8",
            "http_status": "404",
            "procedure": "Subscription Data Fetch",
            "timestamp": "2026-08-10T14:00:01Z"
        }
        
        for _ in range(4):
            self.agent._evaluate_rules(event)
        
        active = self.agent.get_active_alerts()
        assert len(active) >= 1
        udm_alerts = [a for a in active if a["node"] == "UDM"]
        assert len(udm_alerts) >= 1
    
    def test_reset_alert_allows_retrigger(self):
        """Resetting an alert should allow it to trigger again."""
        event = {
            "source_nf": "SMF",
            "dest_nf": "UPF",
            "interface": "N11",
            "http_status": "504",
            "timestamp": "2026-08-10T14:00:01Z"
        }
        
        # Trigger first alert
        for _ in range(6):
            self.agent._evaluate_rules(event)
        
        active_before = len(self.agent.get_active_alerts())
        assert active_before >= 1
        
        # Reset the alert
        active_alerts = self.agent.get_active_alerts()
        if active_alerts:
            alert_id = active_alerts[0]["id"]
            self.agent.reset_alert(alert_id)
        
        active_after = len(self.agent.get_active_alerts())
        assert active_after == 0
    
    def test_alert_has_unique_id(self):
        """Each alert should have a unique ID."""
        event = {
            "source_nf": "PCF",
            "dest_nf": "SMF",
            "interface": "N5",
            "http_status": "404",
            "timestamp": "2026-08-10T14:00:01Z"
        }
        
        for _ in range(3):
            self.agent._evaluate_rules(event)
        
        history = self.agent.get_alert_history()
        ids = [a["id"] for a in history]
        assert len(ids) == len(set(ids))  # All unique


class TestLogAgentStreaming:
    """Test log file streaming functionality."""

    def test_stream_from_file(self):
        """Test streaming events from a log file."""
        agent = LogAgent(config_path="config/alert_rules.json")
        
        # Create a temporary log file
        test_log = "/tmp/test_5g_log.json"
        test_events = [
            {"source_nf": "AMF", "dest_nf": "AUSF", "interface": "N12", "http_status": "401", "timestamp": "2026-08-10T14:00:01Z"},
            {"source_nf": "SMF", "dest_nf": "UPF", "interface": "N11", "http_status": "504", "timestamp": "2026-08-10T14:00:02Z"},
        ]
        
        with open(test_log, "w") as f:
            for event in test_events:
                f.write(json.dumps(event) + "\n")
        
        # Stream the file
        async def collect_events():
            events = []
            async for event in agent.stream_from_file(test_log):
                events.append(event)
            return events
        
        events = asyncio.run(collect_events())
        assert len(events) == 2
        assert events[0]["source_nf"] == "AMF"
        assert events[1]["source_nf"] == "SMF"
        
        # Cleanup
        os.remove(test_log)
