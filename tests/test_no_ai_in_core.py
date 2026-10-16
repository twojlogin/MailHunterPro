"""
Strażnik architektury: rdzeń (core/) NIGDY nie może importować AI/LLM.

Dlaczego: email to niewierząca treść. Jeśli LLM czyta treść emaila, złośliwy
napis w treści (prompt injection) może go nakazać wyciek danych. To realny
wektor ataku, nie paranoja.

Test pilnuje, że żaden moduł w core/ nie importuje bibliotek AI/LLM.
"""
import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE = ROOT / "core"

FORBIDDEN = {
    "ollama", "openai", "anthropic", "google.generativeai",
    "transformers", "torch", "tensorflow", "langchain",
    "llama_index", "llama_cpp", "huggingface_hub",
}


def _imports_ai(filepath):
    """True, gdy plik importuje zabronioną bibliotekę AI."""
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN:
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in FORBIDDEN:
                return True
    return False


def test_core_nie_importuje_ai():
    """Żaden moduł w core/ nie może importować AI/LLM."""
    zle = []
    for p in CORE.glob("*.py"):
        if _imports_ai(p):
            zle.append(p.name)
    assert not zle, (
        f"core/ importuje AI/LLM: {zle}. "
        "Email to niewierząca treść — prompt injection na LLM = wyciek danych."
    )


def test_integrations_nie_ma_ai_local():
    """integrations/ai_local.py (Ollama) został usunięty."""
    assert not (ROOT / "integrations" / "ai_local.py").exists(), (
        "integrations/ai_local.py wrócił — LLM podłączony do poczty to wyciek"
    )
