"""
Privacy-preserving AI Threat Advisory module.
Performs local pre-flight secret sanitization and dispatches sanitized diffs
to Gemini or OpenAI for structured incident triage and remediation advice.
"""
import re
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import requests
import config
from database.db_manager import get_db

logger = logging.getLogger(__name__)

@dataclass
class AIAdvisorResponse:
    executive_summary: str
    security_implications: List[str] = field(default_factory=list)
    confidence_level: str = "Medium"  # "Low", "Medium", "High"
    recommended_actions: List[str] = field(default_factory=list)
    is_offline_fallback: bool = False
    raw_response: str = ""
    error: Optional[str] = None

def sanitize_diff_content(diff_text: str, max_lines: int = config.MAX_DIFF_LINES_FOR_AI) -> str:
    """
    Sanitizes secrets, passwords, private keys, and high-entropy credentials
    from the diff using regex patterns, then truncates to max_lines.
    """
    if not diff_text:
        return ""

    sanitized = diff_text
    for pattern, replacement in config.REDACTION_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized)

    lines = sanitized.splitlines()
    if len(lines) > max_lines:
        truncated_count = len(lines) - max_lines
        sanitized = "\n".join(lines[:max_lines])
        sanitized += f"\n\n[... Diff truncated: {truncated_count} remaining lines suppressed for privacy and performance ...]"

    return sanitized

class AIThreatAdvisor:
    def __init__(self):
        self.db = get_db()

    def get_api_key(self, provider: str) -> Optional[str]:
        """Retrieves stored API key from database or environment variables."""
        if provider.lower() == "gemini":
            stored = self.db.get_setting("gemini_api_key")
            return stored or config.os.environ.get("GEMINI_API_KEY")
        elif provider.lower() == "openai":
            stored = self.db.get_setting("openai_api_key")
            return stored or config.os.environ.get("OPENAI_API_KEY")
        return None

    def get_preferred_provider(self) -> str:
        stored = self.db.get_setting("ai_provider")
        return stored or "gemini"

    def analyze_incident(self, file_path: str, diff_text: str,
                         heuristics_summary: List[Dict[str, Any]],
                         risk_level: str) -> AIAdvisorResponse:
        """
        Executes local redaction, constructs privacy-conscious prompt,
        and queries either Gemini or OpenAI. Falls back to offline heuristic report.
        """
        provider = self.get_preferred_provider().lower()
        api_key = self.get_api_key(provider)

        # 1. Local Pre-Filtering & Redaction
        sanitized_diff = sanitize_diff_content(diff_text)
        file_ext = config.Path(file_path).suffix or "unknown"
        filename = config.Path(file_path).name

        # If no API key configured, provide structured offline fallback
        if not api_key:
            return self._build_offline_fallback(
                filename=filename,
                risk_level=risk_level,
                heuristics=heuristics_summary,
                reason="No API Key configured. System operating in deterministic offline mode."
            )

        # 2. Build system instructions and user prompt
        system_instruction = (
            "You are a Cybersecurity Incident Response & Threat Triage Assistant for a File Integrity "
            "Monitoring (FIM) system. You will receive a sanitized diff of an unauthorized file modification, "
            "file metadata, and triggered heuristic rules. All credentials and secrets have been redacted locally.\n\n"
            "Respond ONLY with a valid JSON object strictly matching this schema:\n"
            "{\n"
            '  "executive_summary": "Concise summary of what was altered and why it matters",\n'
            '  "security_implications": ["List of potential attack vectors or vulnerabilities introduced"],\n'
            '  "confidence_level": "High" | "Medium" | "Low",\n'
            '  "recommended_actions": ["Immediate remediation and incident response steps"]\n'
            "}"
        )

        prompt_payload = (
            f"File: {filename} (Type: {file_ext})\n"
            f"Heuristic Risk Classification: {risk_level}\n"
            f"Triggered Heuristic Rules: {json.dumps(heuristics_summary, indent=2)}\n\n"
            f"Sanitized Diff Content:\n```diff\n{sanitized_diff}\n```\n\n"
            "Analyze the threat and provide your structured assessment in JSON format."
        )

        # 3. Dispatch to selected provider
        try:
            if provider == "gemini":
                return self._call_gemini(api_key, system_instruction, prompt_payload)
            elif provider == "openai":
                return self._call_openai(api_key, system_instruction, prompt_payload)
            else:
                return self._build_offline_fallback(filename, risk_level, heuristics_summary, f"Unknown provider: {provider}")
        except Exception as e:
            logger.error(f"AI Advisor API call failed: {e}")
            return self._build_offline_fallback(
                filename=filename,
                risk_level=risk_level,
                heuristics=heuristics_summary,
                reason=f"API connection error: {str(e)[:120]}"
            )

    def _call_gemini(self, api_key: str, system_instruction: str, prompt: str) -> AIAdvisorResponse:
        """Invokes Google Gemini using official google-genai SDK or direct REST fallback."""
        try:
            # Try using google-genai library if installed
            from google import genai
            from google.genai import types
            client = genai.Client(api_key=api_key)
            model_name = self.db.get_setting("gemini_model") or "gemini-2.5-flash"
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json"
                )
            )
            raw_text = response.text or "{}"
            return self._parse_json_response(raw_text)
        except Exception:
            # Fallback to direct REST endpoint
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": f"{system_instruction}\n\n{prompt}"}]}],
                "generationConfig": {"responseMimeType": "application/json"}
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            return self._parse_json_response(raw_text)

    def _call_openai(self, api_key: str, system_instruction: str, prompt: str) -> AIAdvisorResponse:
        """Invokes OpenAI REST endpoint."""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        model_name = self.db.get_setting("openai_model") or "gpt-4o-mini"
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        raw_text = data["choices"][0]["message"]["content"]
        return self._parse_json_response(raw_text)

    def _parse_json_response(self, raw_text: str) -> AIAdvisorResponse:
        """Extracts and parses JSON object from LLM response text."""
        cleaned = raw_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            parsed = json.loads(cleaned)
            return AIAdvisorResponse(
                executive_summary=parsed.get("executive_summary", "No summary provided."),
                security_implications=parsed.get("security_implications", []),
                confidence_level=parsed.get("confidence_level", "Medium"),
                recommended_actions=parsed.get("recommended_actions", []),
                is_offline_fallback=False,
                raw_response=raw_text
            )
        except Exception as e:
            logger.warning(f"Failed to parse LLM JSON: {e}. Raw: {raw_text[:200]}")
            return AIAdvisorResponse(
                executive_summary=cleaned[:300],
                security_implications=["Custom AI response generated (unstructured)."],
                confidence_level="Medium",
                recommended_actions=["Review the raw response details in the change viewer."],
                is_offline_fallback=False,
                raw_response=raw_text
            )

    def _build_offline_fallback(self, filename: str, risk_level: str,
                                heuristics: List[Dict[str, Any]], reason: str) -> AIAdvisorResponse:
        """Provides offline assessment based strictly on Step 4 heuristics."""
        implications = []
        actions = [
            f"Review the modified lines in {filename} against the trusted baseline snapshot.",
            "If changes were unauthorized, revert to the baseline immediately from the Monitored Files tab."
        ]

        if heuristics:
            for h in heuristics:
                rule_name = h.get("rule_name", "Security pattern")
                desc = h.get("description", "")
                implications.append(f"{rule_name}: {desc}")
                if "Privilege" in rule_name:
                    actions.append("Audit system user privileges and roll back elevated credentials.")
                if "Firewall" in rule_name:
                    actions.append("Verify host firewall rules and confirm antivirus daemon is running.")
                if "Secret" in rule_name:
                    actions.append("Rotate compromised API keys, passwords, or tokens immediately.")
        else:
            implications.append("No critical heuristics triggered. Modification appears to be standard configuration tuning.")

        return AIAdvisorResponse(
            executive_summary=(
                f"Offline Heuristic Assessment for '{filename}' ({risk_level} Risk). "
                f"Reason: {reason}"
            ),
            security_implications=implications,
            confidence_level="High" if risk_level == "HIGH" else "Medium",
            recommended_actions=actions,
            is_offline_fallback=True,
            raw_response=f"Offline Mode: {reason}"
        )

def get_ai_advisor() -> AIThreatAdvisor:
    return AIThreatAdvisor()
