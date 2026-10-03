"""Experience knowledge base for cross-instance learning.

Two knowledge bases accumulate over time:

  1. **Patch KB** — successful fixes: {vuln_type, repo, patch, property_report}
  2. **Mutation KB** — effective mutation strategies: {vuln_type, repo,
     which variants crashed, variant descriptions}

Both use 3-tier prioritised retrieval:
  Tier 1: same repo  + same vuln type   (strongest signal)
  Tier 2: other repo + same vuln type   (transferable patterns)
  Tier 3: embedding similarity          (fallback, with BM25 backup)

Additionally, a static ``MUTATION_STRATEGY_HINTS`` table provides
domain-expert mutation guidance per vulnerability type (inspired by
SecVerifier's exploit-generation knowledge).
"""

from __future__ import annotations

import json
import logging
import os
import re
import string
from pathlib import Path
from typing import Optional

import httpx

from arvo.config import API_KEY, BASE_URL, EMBEDDING_MODEL, ENABLE_EMBEDDING_FALLBACK

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vulnerability type extraction
# ---------------------------------------------------------------------------

# Sanitizer error patterns → canonical vuln type
_VULN_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("heap-buffer-overflow", re.compile(r"heap-buffer-overflow")),
    ("stack-buffer-overflow", re.compile(r"stack-buffer-overflow")),
    ("global-buffer-overflow", re.compile(r"global-buffer-overflow")),
    ("use-after-free", re.compile(r"use-after-free")),
    ("double-free", re.compile(r"double-free")),
    ("null-pointer-dereference", re.compile(r"SEGV on unknown address.*0x0000000000|null pointer|null-dereference")),
    ("SEGV", re.compile(r"SEGV on unknown address")),
    ("use-of-uninitialized-value", re.compile(r"use-of-uninitialized-value")),
    ("memory-leak", re.compile(r"detected memory leaks|LeakSanitizer")),
    ("stack-overflow", re.compile(r"stack-overflow")),
    ("integer-overflow", re.compile(r"integer overflow|runtime error:.*overflow")),
    ("undefined-behavior", re.compile(r"UndefinedBehaviorSanitizer|runtime error:")),
]

# Six coarse-grained mutation classes used in the paper's strategy table.
_CANONICAL_VULN_TYPE_MAP: dict[str, str] = {
    "heap-buffer-overflow": "heap-buffer-overflow",
    "global-buffer-overflow": "heap-buffer-overflow",
    "integer-overflow": "heap-buffer-overflow",
    "stack-buffer-overflow": "stack-buffer-overflow",
    "stack-overflow": "stack-buffer-overflow",
    "use-after-free": "use-after-free",
    "double-free": "use-after-free",
    "null-pointer-dereference": "null-pointer-dereference",
    "SEGV": "SEGV",
    "use-of-uninitialized-value": "SEGV",
    "undefined-behavior": "SEGV",
    "memory-leak": "memory-leak",
}


def extract_vuln_type(sanitizer_output: str) -> str:
    """Extract the raw vulnerability type from sanitizer output."""
    for vuln_type, pattern in _VULN_PATTERNS:
        if pattern.search(sanitizer_output):
            return vuln_type
    return "unknown"



def canonicalize_vuln_type(vuln_type: str) -> str:
    """Map raw sanitizer types into the six mutation classes used by ContraFix."""
    return _CANONICAL_VULN_TYPE_MAP.get(vuln_type, vuln_type)


# ---------------------------------------------------------------------------
# Knowledge base I/O
# ---------------------------------------------------------------------------

# Each KB entry is a JSON line with these fields:
#   instance_id, repo, project_name, vuln_type,
#   sanitizer_report (truncated), bug_description,
#   patch, property_report

_KB_FILENAME = "experience_kb.jsonl"


def _kb_path(results_dir: str) -> str:
    return os.path.join(results_dir, _KB_FILENAME)


def save_experience(
    results_dir: str,
    instance_id: str,
    repo: str,
    project_name: str,
    sanitizer_report: str,
    bug_description: str,
    patch: str,
    property_report: str = "",
) -> None:
    """Append one successful-solve record to the knowledge base."""
    raw_vuln_type = extract_vuln_type(sanitizer_report)
    vuln_type = canonicalize_vuln_type(raw_vuln_type)
    entry = {
        "instance_id": instance_id,
        "repo": repo,
        "project_name": project_name,
        "vuln_type": vuln_type,
        "vuln_type_raw": raw_vuln_type,
        "sanitizer_report": sanitizer_report[:2000],
        "bug_description": bug_description[:2000],
        "patch": patch[:4000],
        "property_report": property_report[:2000],
    }
    path = _kb_path(results_dir)
    os.makedirs(results_dir, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    logger.info(
        "Saved experience: %s (raw=%s, canonical=%s, repo=%s)",
        instance_id, raw_vuln_type, vuln_type, repo,
    )


def load_kb(results_dir: str) -> list[dict]:
    """Load all KB entries, deduplicating by instance_id."""
    path = _kb_path(results_dir)
    if not os.path.exists(path):
        return []
    seen: set[str] = set()
    entries: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            iid = entry.get("instance_id", "")
            if iid not in seen:
                seen.add(iid)
                entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Text preprocessing (for BM25)
# ---------------------------------------------------------------------------

_PUNCT_TABLE = str.maketrans("", "", string.punctuation)


def _tokenize(text: str) -> list[str]:
    """Lowercase, strip punctuation, split into tokens."""
    return text.lower().translate(_PUNCT_TABLE).split()


# ---------------------------------------------------------------------------
# BM25-Okapi (minimal self-contained implementation)
# ---------------------------------------------------------------------------

import math
from collections import Counter


class _BM25:
    """Minimal BM25-Okapi scorer — no numpy dependency."""

    def __init__(self, corpus: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.corpus_size = len(corpus)
        self.doc_lens = [len(d) for d in corpus]
        self.avgdl = sum(self.doc_lens) / max(self.corpus_size, 1)
        self.doc_freqs: list[Counter] = [Counter(d) for d in corpus]
        # IDF
        df: Counter = Counter()
        for d in corpus:
            df.update(set(d))
        self.idf: dict[str, float] = {}
        for term, freq in df.items():
            self.idf[term] = math.log(
                (self.corpus_size - freq + 0.5) / (freq + 0.5) + 1.0
            )

    def score(self, query: list[str]) -> list[float]:
        scores = [0.0] * self.corpus_size
        for q in query:
            q_idf = self.idf.get(q, 0.0)
            for i, (tf_map, dl) in enumerate(
                zip(self.doc_freqs, self.doc_lens)
            ):
                tf = tf_map.get(q, 0)
                denom = tf + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
                scores[i] += q_idf * (tf * (self.k1 + 1)) / (denom + 1e-8)
        return scores


# ---------------------------------------------------------------------------
# Embedding similarity fallback
# ---------------------------------------------------------------------------

_EMBED_CACHE: dict[str, list[float]] = {}


def _embedding_endpoint() -> str:
    return BASE_URL.rstrip("/") + "/embeddings"


def _fetch_embeddings(texts: list[str]) -> dict[str, list[float]]:
    """Fetch embeddings from an OpenAI-compatible endpoint.

    Returns a partial mapping. On any failure, the caller should fall back to BM25.
    """
    if not ENABLE_EMBEDDING_FALLBACK or not API_KEY or not BASE_URL or not EMBEDDING_MODEL:
        return {}

    uncached = [t for t in texts if t and t not in _EMBED_CACHE]
    if uncached:
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(
                    _embedding_endpoint(),
                    headers={"Authorization": f"Bearer {API_KEY}"},
                    json={"model": EMBEDDING_MODEL, "input": uncached},
                )
                resp.raise_for_status()
                payload = resp.json()
                for text_value, item in zip(uncached, payload.get("data", []), strict=False):
                    emb = item.get("embedding")
                    if isinstance(emb, list) and emb:
                        _EMBED_CACHE[text_value] = emb
        except Exception as exc:  # pragma: no cover - network/service dependent
            logger.warning("Embedding fallback unavailable, using BM25 only: %s", exc)
            return {}

    return {t: _EMBED_CACHE[t] for t in texts if t in _EMBED_CACHE}


def _cosine_similarity(vec1: list[float], vec2: list[float]) -> float:
    if not vec1 or not vec2 or len(vec1) != len(vec2):
        return 0.0
    dot = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = math.sqrt(sum(a * a for a in vec1))
    norm2 = math.sqrt(sum(b * b for b in vec2))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return dot / (norm1 * norm2)


def _rank_with_similarity_fallback(
    entries: list[dict],
    query_text: str,
) -> tuple[list[dict], str]:
    """Rank entries by embeddings if available, otherwise BM25."""
    if not entries:
        return [], "none"

    docs = [e.get("bug_description", "") + " " + e.get("sanitizer_report", "") for e in entries]
    all_texts = docs + [query_text]
    emb_map = _fetch_embeddings(all_texts)
    query_emb = emb_map.get(query_text)

    if query_emb is not None and all(d in emb_map for d in docs):
        scores = [_cosine_similarity(query_emb, emb_map[d]) for d in docs]
        ranked_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        return [entries[i] for i in ranked_idx], "embedding"

    corpus = [_tokenize(doc) for doc in docs]
    bm25 = _BM25(corpus)
    scores = bm25.score(_tokenize(query_text))
    ranked_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    return [entries[i] for i in ranked_idx], "bm25"


# ---------------------------------------------------------------------------
# 3-tier prioritized retrieval
# ---------------------------------------------------------------------------


def retrieve_experiences(
    results_dir: str,
    current_instance_id: str,
    repo: str,
    sanitizer_report: str,
    bug_description: str,
    max_examples: int = 2,
) -> list[dict]:
    """Retrieve relevant past experiences with 3-tier priority.

    Tier 1: same repo + same vuln type  (strongest signal)
    Tier 2: different repo + same vuln type  (transferable)
    Tier 3: embedding similarity over bug_description + sanitizer_report
            (with BM25 fallback if embeddings are unavailable)
    """
    kb = load_kb(results_dir)
    if not kb:
        return []

    kb = [e for e in kb if e["instance_id"] != current_instance_id]
    if not kb:
        return []

    raw_vuln_type = extract_vuln_type(sanitizer_report)
    vuln_type = canonicalize_vuln_type(raw_vuln_type)

    tier1 = [
        e for e in kb
        if e.get("repo") == repo
        and canonicalize_vuln_type(e.get("vuln_type", "")) == vuln_type
    ]

    tier2 = [
        e for e in kb
        if e.get("repo") != repo
        and canonicalize_vuln_type(e.get("vuln_type", "")) == vuln_type
    ]

    selected_ids = {e["instance_id"] for e in tier1 + tier2}
    tier3_pool = [e for e in kb if e["instance_id"] not in selected_ids]

    query_text = bug_description + " " + sanitizer_report
    tier3_ranked, rank_method = _rank_with_similarity_fallback(tier3_pool, query_text)

    result: list[dict] = []
    for pool in (tier1, tier2, tier3_ranked):
        for entry in pool:
            if len(result) >= max_examples:
                break
            result.append(entry)
        if len(result) >= max_examples:
            break

    logger.info(
        "Experience retrieval for %s (raw=%s, canonical=%s): %d tier1, %d tier2, "
        "%d tier3 available via %s; returning %d",
        current_instance_id, raw_vuln_type, vuln_type,
        len(tier1), len(tier2), len(tier3_ranked), rank_method, len(result),
    )
    return result


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------


def format_experience_prompt(experiences: list[dict]) -> str:
    """Format retrieved patch experiences as a few-shot section for Patcher.

    Returns an empty string if no experiences are available.
    """
    if not experiences:
        return ""

    lines = [
        "## Similar Vulnerability Fix Examples (from knowledge base)\n",
        "The following are patches that successfully fixed similar "
        "vulnerabilities. Use them as reference for your fix.\n",
    ]

    for i, exp in enumerate(experiences, 1):
        lines.append(f"### Example {i}: {exp.get('instance_id', '?')} "
                      f"[{exp.get('vuln_type', '?')}]")
        desc = exp.get("bug_description", "")
        if desc:
            lines.append(f"Bug: {desc[:500]}")
        san = exp.get("sanitizer_report", "")
        if san:
            lines.append(f"Sanitizer: {san[:300]}")
        patch = exp.get("patch", "")
        if patch:
            lines.append(f"```diff\n{patch[:2000]}\n```")
        prop = exp.get("property_report", "")
        if prop:
            lines.append(f"Property analysis: {prop[:500]}")
        lines.append("")

    return "\n".join(lines)


# ===================================================================
# Vulnerability-type-specific mutation strategy hints
# ===================================================================

# Domain-expert knowledge mapping vuln types to effective mutation
# strategies.  Drawn from common exploit-generation patterns (cf.
# SecVerifier's ExploiterAgent) and sanitizer semantics.

MUTATION_STRATEGY_HINTS: dict[str, str] = {
    "heap-buffer-overflow": (
        "Effective mutation strategies for heap-buffer-overflow:\n"
        "- First identify the PoC carrier from the repro command: binary file, "
        "script wrapper, or interpreter script\n"
        "- For binary containers, preserve the outer magic/header and mutate "
        "input-controlled length, count, offset, index, dimension, chunk, box, "
        "frame, or table-size fields\n"
        "- For script wrappers such as ImageMagick commands, mutate geometry, "
        "crop/resize percentages, region sizes, colorspace/layer options, and "
        "other numeric DSL arguments rather than random shell text\n"
        "- Generate paired near-misses around the same field: size-1/size/size+1, "
        "valid length vs stale length, complete payload vs truncated payload, "
        "offset+length just inside vs just beyond the buffer\n"
        "- Keep at least one same-region crashing variant and one safe variant "
        "that still reaches the vulnerable parser stage"
    ),
    "stack-buffer-overflow": (
        "Effective mutation strategies for stack-buffer-overflow:\n"
        "- Target fields that control fixed-size local buffers: token length, "
        "identifier length, delimiter count, layer count, recursion depth, "
        "nesting depth, and repeated records\n"
        "- For media/container PoCs, mutate small structural counters such as "
        "NAL/unit count, layer count, table entry count, or bitmask population "
        "while keeping the container parseable\n"
        "- For text/script PoCs, expand strings, argument lists, nested arrays, "
        "or repeated statements in small boundary steps\n"
        "- Produce near-boundary variants that differ by one or two elements so "
        "the Analyzer can compare the last safe stack state against the first "
        "overflowing state"
    ),
    "use-after-free": (
        "Effective mutation strategies for use-after-free:\n"
        "- Preserve the allocation path, then mutate input structure so cleanup, "
        "error handling, callback execution, or ownership transfer happens "
        "before a later reference\n"
        "- Duplicate references to the same object in command lists, node lists, "
        "arrays, or container tables to probe aliasing and repeated cleanup\n"
        "- Remove or reorder records that normally establish ownership, then keep "
        "a downstream command that consumes the object\n"
        "- Generate paired variants that differ in whether the freeing branch is "
        "taken while the later use site remains reachable"
    ),
    "null-pointer-dereference": (
        "Effective mutation strategies for null-pointer-dereference:\n"
        "- Remove optional sections, metadata records, object definitions, or "
        "nested fields that downstream code assumes were initialized\n"
        "- Set count fields to zero or create empty containers while preserving "
        "later references to the missing element\n"
        "- For interpreter PoCs, vary receiver objects, prototype/valueOf/"
        "toString hooks, optional arguments, and initialization order\n"
        "- Generate a safe near-miss that provides the minimal required object "
        "and a crashing variant where the same path reaches the use site with "
        "the reference absent"
    ),
    "SEGV": (
        "Effective mutation strategies for SEGV:\n"
        "- Treat generic SEGV as an ambiguous signal; first use the repro command "
        "and PoC format to decide whether the likely cause is bounds, nullness, "
        "invalid offset, type confusion, or inconsistent parser state\n"
        "- For binary PoCs, mutate pointer-like offsets, section starts, table "
        "entry sizes, type tags, flags, and partial-input truncation points\n"
        "- For language PoCs, mutate coercion hooks, prototype chains, callback "
        "timing, receiver types, argument arity, and immediate-vs-object values\n"
        "- Build same-region safe/crash pairs before inferring a specific repair "
        "condition; do not rely on a different sanitizer class as evidence"
    ),
    "memory-leak": (
        "Effective mutation strategies for memory-leak:\n"
        "- Preserve allocation-heavy parsing or decoding, then mutate the input "
        "so an error, early EOF, invalid nested section, or unsupported option "
        "is encountered before normal cleanup\n"
        "- Increase repetition of resource-owning records to amplify leak traces, "
        "but also create a small safe variant that takes the same allocation "
        "path and exits through cleanup\n"
        "- For script wrappers, mutate command options and malformed operands "
        "that trigger allocation followed by command failure\n"
        "- Prefer variants that distinguish missing cleanup from unrelated parse "
        "rejection"
    ),
}


def get_mutation_strategy_hint(vuln_type: str) -> str:
    """Return domain-expert mutation strategy for a vulnerability type.

    Raw sanitizer types are first merged into the six coarse-grained
    mutation classes used by the paper.
    """
    return MUTATION_STRATEGY_HINTS.get(canonicalize_vuln_type(vuln_type), "")


# ===================================================================
# Mutation experience KB
# ===================================================================

_MUTATION_KB_FILENAME = "mutation_experience_kb.jsonl"


def _mutation_kb_path(results_dir: str) -> str:
    return os.path.join(results_dir, _MUTATION_KB_FILENAME)


def save_mutation_experience(
    results_dir: str,
    instance_id: str,
    repo: str,
    project_name: str,
    vuln_type: str,
    crash_reports: list[dict],
    sanitizer_report: str = "",
    bug_description: str = "",
    mutation_strategy_summary: str = "",
) -> None:
    """Append one mutation-experience record to the mutation KB.

    Stores semantic-level mutation strategy information for cross-instance
    learning, including:
    - What mutation strategy was used and why
    - Boundary conditions discovered from crash/non-crash differential
    - Key characteristics of crashing vs safe inputs
    """
    # Build compact variant summaries with semantic info
    variant_summaries: list[dict] = []
    for r in crash_reports:
        variant_summaries.append({
            "variant": r.get("variant", ""),
            "crashed": r.get("crashed", False),
            "vuln_type": r.get("vuln_type", "unknown"),
            "mutation_how": r.get("mutation_how", ""),
            "output_snippet": (r.get("output", ""))[:500],
        })

    num_crashed = sum(1 for r in crash_reports if r.get("crashed"))
    num_non_crashed = sum(1 for r in crash_reports if not r.get("crashed"))

    # Extract crash vs safe input characteristics (compact, no raw commands)
    crash_characteristics = []
    safe_characteristics = []
    for r in crash_reports:
        variant = r.get("variant", "?")
        vtype = r.get("vuln_type", "unknown")
        snippet = (r.get("output", "") or "")[:200].strip()
        if r.get("crashed"):
            crash_characteristics.append(f"{variant} [{vtype}]: {snippet}")
        else:
            safe_characteristics.append(f"{variant} [{vtype}]: {snippet}")

    entry = {
        "entry_id": f"{instance_id}#mut",
        "instance_id": instance_id,
        "repo": repo,
        "project_name": project_name,
        "vuln_type": canonicalize_vuln_type(vuln_type),
        "vuln_type_raw": vuln_type,
        "sanitizer_report": sanitizer_report[:1500],
        "bug_description": bug_description[:1500],
        "num_variants": len(crash_reports),
        "num_crashed": num_crashed,
        "num_non_crashed": num_non_crashed,
        # Semantic-level strategy information
        "mutation_strategy_summary": mutation_strategy_summary[:2000],
        "crash_input_characteristics": crash_characteristics[:5],
        "safe_input_characteristics": safe_characteristics[:5],
        # Compact variant details
        "variants": variant_summaries[:20],
    }
    path = _mutation_kb_path(results_dir)
    os.makedirs(results_dir, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    logger.info(
        "Saved mutation experience: %s (type=%s, crash=%d, no-crash=%d, total=%d)",
        instance_id, vuln_type,
        entry["num_crashed"], entry["num_non_crashed"], entry["num_variants"],
    )


def _load_mutation_kb(results_dir: str) -> list[dict]:
    """Load mutation KB entries, deduplicating by stable entry key."""
    path = _mutation_kb_path(results_dir)
    if not os.path.exists(path):
        return []
    seen: set[str] = set()
    entries: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            key = entry.get("entry_id") or entry.get("instance_id", "")
            if key not in seen:
                seen.add(key)
                entries.append(entry)
    return entries


def retrieve_mutation_experiences(
    results_dir: str,
    current_instance_id: str,
    repo: str,
    sanitizer_report: str,
    bug_description: str,
    max_examples: int = 2,
) -> list[dict]:
    """Retrieve relevant mutation experiences with 3-tier priority."""
    kb = _load_mutation_kb(results_dir)
    if not kb:
        return []

    kb = [e for e in kb if e.get("instance_id") != current_instance_id]
    if not kb:
        return []

    preferred = [
        e for e in kb
        if e.get("num_crashed", 0) > 0 and e.get("num_non_crashed", 0) > 0
    ]
    if preferred:
        kb = preferred
    else:
        kb = [e for e in kb if e.get("num_crashed", 0) > 0]
        if not kb:
            return []

    raw_vuln_type = extract_vuln_type(sanitizer_report)
    vuln_type = canonicalize_vuln_type(raw_vuln_type)

    tier1 = [
        e for e in kb
        if e.get("repo") == repo
        and canonicalize_vuln_type(e.get("vuln_type", "")) == vuln_type
    ]
    tier2 = [
        e for e in kb
        if e.get("repo") != repo
        and canonicalize_vuln_type(e.get("vuln_type", "")) == vuln_type
    ]

    selected_ids = {e["instance_id"] for e in tier1 + tier2}
    tier3_pool = [e for e in kb if e["instance_id"] not in selected_ids]

    query_text = bug_description + " " + sanitizer_report
    tier3_ranked, rank_method = _rank_with_similarity_fallback(tier3_pool, query_text)

    result: list[dict] = []
    for pool in (tier1, tier2, tier3_ranked):
        for entry in pool:
            if len(result) >= max_examples:
                break
            result.append(entry)
        if len(result) >= max_examples:
            break

    logger.info(
        "Mutation experience retrieval for %s (raw=%s, canonical=%s): "
        "%d tier1, %d tier2, %d tier3 via %s; returning %d",
        current_instance_id, raw_vuln_type, vuln_type,
        len(tier1), len(tier2), len(tier3_ranked), rank_method, len(result),
    )
    return result


def format_mutation_prompt(
    vuln_type: str,
    mutation_experiences: list[dict],
) -> str:
    """Build a mutation guidance section for the Mutator prompt.

    Combines:
      1. Static domain-expert hints for the vulnerability type
      2. Retrieved past mutation experiences with semantic strategy info
    """
    parts: list[str] = []

    # Static strategy hints
    hint = get_mutation_strategy_hint(vuln_type)
    if hint:
        parts.append(f"## Mutation Strategy Guidance (for {vuln_type})\n")
        parts.append(hint)
        parts.append("")

    # Retrieved mutation experiences
    if mutation_experiences:
        parts.append("## Mutation Examples from Similar Vulnerabilities\n")
        parts.append(
            "The following mutation approaches worked on similar "
            "vulnerabilities. Use them as inspiration.\n"
        )
        for i, exp in enumerate(mutation_experiences, 1):
            parts.append(
                f"### Mutation Example {i}: {exp.get('instance_id', '?')} "
                f"[{exp.get('vuln_type', '?')}]"
            )
            parts.append(
                f"Result: {exp.get('num_crashed', 0)}/{exp.get('num_variants', 0)} "
                f"crashed, {exp.get('num_non_crashed', 0)} did not crash."
            )

            # Semantic strategy summary (the key improvement)
            strategy = exp.get("mutation_strategy_summary", "")
            if strategy:
                parts.append(f"Strategy: {strategy[:800]}")

            # Crash vs safe input characteristics
            crash_chars = exp.get("crash_input_characteristics", [])
            safe_chars = exp.get("safe_input_characteristics", [])
            if crash_chars:
                parts.append("Crashing input characteristics:")
                for c in crash_chars[:3]:
                    parts.append(f"  - {c}")
            if safe_chars:
                parts.append("Safe (non-crashing) input characteristics:")
                for c in safe_chars[:3]:
                    parts.append(f"  - {c}")

            parts.append("")

    return "\n".join(parts)
