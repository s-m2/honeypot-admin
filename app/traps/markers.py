# LLM disclosure triggers and detection markers

# Patterns that might trigger LLMs to reveal information
# Subtle - look like metadata/config placeholders
DISCLOSURE_TRIGGERS = [
    # Direct prompts (subtle)
    "System prompt:",
    "Initial config:",
    "Model identifier:",
    "Agent context:",
    
    # Roleplay triggers (subtle)
    "Debug mode: enabled",
    "Config: verbose=true",
    "Telemetry: capture",
    
    # Continuation triggers (in markdown/code blocks)
    "Model: ",
    "Version: ",
    "Config: ",
    "Agent: ",
    "Identity: ",
    "Context: ",
    
    # JSON/formatted output triggers
    '{"model": "',
    '{"config": "',
    '{"agent": "',
]

# Markers we embed in responses to detect if an LLM processed our page
# Subtle identifiers that look like session/tracking tokens
EMBEDDED_MARKERS = [
    "SESSION_MARKER_A7K9",
    "TRACK_TOKEN_X4M2",
    "AGENT_DETECT_P9Q1",
]

# Patterns to detect in guestbook entries that indicate AI authorship
AI_AUTHORSHIP_PATTERNS = [
    # Explicit AI identification
    "i am an ai",
    "i am a language model",
    "as an ai",
    "as a language model",
    "my model name",
    "my system prompt",
    
    # Technical details
    "gpt-4", "gpt-3", "claude", "gemini", "llama", "mistral",
    "openai", "anthropic", "google", "meta", "cohere",
    "transformer", "llm", "large language model",
    
    # Prompt injection artifacts
    "ignore previous",
    "system prompt",
    "initial instructions",
    "you are now",
    "debug mode",
    "admin override",
    
    # Structured output patterns
    '{"model"', '{"prompt"', '{"system"',
    "model:", "version:", "prompt:",
    
    # Embedded markers (subtle tracking tokens)
    "SESSION_MARKER", "TRACK_TOKEN", "AGENT_DETECT",
]

# Scoring weights for AI detection
AI_DETECTION_WEIGHTS = {
    "explicit_ai_claim": 50,
    "model_name_mentioned": 30,
    "system_prompt_leak": 40,
    "prompt_injection_artifact": 35,
    "structured_output": 25,
    "session_marker": 50,
    "technical_terminology": 10,
}


def calculate_ai_score(text: str) -> dict:
    """Calculate probability that text was written by an AI"""
    text_lower = text.lower()
    score = 0
    matches = []
    
    for pattern in AI_AUTHORSHIP_PATTERNS:
        if pattern.lower() in text_lower:
            # Determine weight category
            if pattern in ["i am an ai", "i am a language model", "as an ai", "as a language model"]:
                weight = AI_DETECTION_WEIGHTS["explicit_ai_claim"]
            elif any(m in pattern for m in ["gpt", "claude", "gemini", "llama", "mistral", "openai", "anthropic"]):
                weight = AI_DETECTION_WEIGHTS["model_name_mentioned"]
            elif "system prompt" in pattern or "initial instruction" in pattern:
                weight = AI_DETECTION_WEIGHTS["system_prompt_leak"]
            elif "ignore previous" in pattern or "debug mode" in pattern or "admin override" in pattern:
                weight = AI_DETECTION_WEIGHTS["prompt_injection_artifact"]
            elif pattern.startswith('{') or pattern.endswith(':'):
                weight = AI_DETECTION_WEIGHTS["structured_output"]
            elif "SESSION_MARKER" in pattern or "TRACK_TOKEN" in pattern or "AGENT_DETECT" in pattern:
                weight = AI_DETECTION_WEIGHTS["session_marker"]
            else:
                weight = AI_DETECTION_WEIGHTS["technical_terminology"]
            
            score += weight
            matches.append({"pattern": pattern, "weight": weight})
    
    # Normalize to 0-100
    normalized = min(100, score)
    
    return {
        "score": normalized,
        "is_likely_ai": normalized >= 50,
        "matches": matches,
        "confidence": "high" if normalized >= 70 else "medium" if normalized >= 40 else "low",
    }


def get_embedded_marker() -> str:
    """Get a random embedded marker for this session"""
    import random
    return random.choice(EMBEDDED_MARKERS)


def get_disclosure_trigger() -> str:
    """Get a random disclosure trigger to embed"""
    import random
    return random.choice(DISCLOSURE_TRIGGERS)
