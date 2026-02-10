
import random
import time

class AIAnalyst:
    def __init__(self, api_key=None):
        self.api_key = api_key

    def analyze_process(self, process_data):
        """
        Simulates an LLM analysis of the process.
        In a real app, this would call OpenAI/Gemini API.
        """
        # Mock "Thinking"
        time.sleep(2)
        
        name = process_data.get('name', 'Unknown')
        cmd = process_data.get('cmdline', [])
        
        # Simple heuristics to generate "LLM-like" text
        risk_level = "LOW"
        narrative = f"I have analyzed the process **{name}** based on the provided telemetry.\n\n"
        
        if "nc" in name or "ncat" in name:
            risk_level = "CRITICAL"
            narrative += "- **Observation**: This appears to be `netcat`, a networking utility often used by attackers for reverse shells.\n"
            narrative += "- **Recommendation**: Unless you explicitly ran this, **KILL** it immediately.\n"
        elif "powershell" in name or "cmd" in name:
            risk_level = "MEDIUM"
            narrative += "- **Observation**: System shell detected. Check parent process.\n"
            narrative += "- **Context**: Legitimate system administration tool, but often abused for 'Fileless Malware'.\n"
        elif "python" in name:
            risk_level = "INFO"
            narrative += "- **Observation**: Python interpreter running script.\n"
            narrative += f"- **Command**: `{' '.join(cmd[:5])}...`\n"
        else:
            narrative += "- **Conclusion**: The process behavior seems consistent with standard application usage.\n"
            narrative += "- **Advice**: Continue monitoring active connections.\n"
            
        return {
            "risk": risk_level,
            "analysis": narrative,
            "confidence": f"{random.randint(85, 99)}%"
        }
