
import os
import json
from typing import Dict, Any

try:
    from openai import OpenAI  # SDK v1+
except Exception:
    OpenAI = None  # handled gracefully

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

def _client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return None, "⚠️ OpenAI not available. Install `openai` and set OPENAI_API_KEY."
    try:
        client = OpenAI(api_key=api_key)
        return client, None
    except Exception as e:
        return None, f"⚠️ OpenAI init error: {e}"

def explain_detection(score_json: Dict[str, Any], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> str:
    client, err = _client()
    if err: return err
    prompt = (
        "You are a senior cybersecurity mentor. Provide a concise, structured analysis of this "
        "ShadowLab Defender run. Explain likely causes of detection signals, risk drivers, and "
        "benign vs suspicious interpretations. Avoid making claims about real bypasses.\n\n"
        f"Score JSON:\n{json.dumps(score_json, indent=2)}\n\n"
        f"Defender Summary:\n{json.dumps(def_sum, indent=2)}\n\n"
        f"Sysmon Summary:\n{json.dumps(sys_sum, indent=2)}\n"
        "Return sections: Overview, Key Signals, Possible Benign Causes, Recommendations."
    )
    try:
        # Chat Completions API for compatibility
        resp = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "You are a helpful cybersecurity mentor."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"⚠️ OpenAI request failed: {e}"
