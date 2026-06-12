"""
utils/embeddings.py — Local embedding model para clusterizar vulnerabilidades.

Reduce tokens enviados a la IA agrupando hallazgos similares (mismo CWE +
texto descriptivo cercano) y mandando solo 1 representante por cluster.

Backend preferido: sentence-transformers (all-MiniLM-L6-v2, 80MB, gratis local).
Fallback: TF-IDF + cosine via sklearn (más liviano).
Fallback final: hash-based bucketing por (cwe, módulo, primeras palabras).

Si nada está instalado, la función devuelve los vulns sin agrupar.
"""

from __future__ import annotations

import hashlib
import re
from typing import Callable, Optional


def _try_sentence_transformers() -> Optional[Callable]:
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
        import numpy as np  # type: ignore

        model = SentenceTransformer("all-MiniLM-L6-v2")

        def embed(texts: list[str]):
            return model.encode(texts, normalize_embeddings=True)

        return embed
    except ImportError:
        return None


def _try_tfidf() -> Optional[Callable]:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
        from sklearn.preprocessing import normalize  # type: ignore

        def embed(texts: list[str]):
            v = TfidfVectorizer(max_features=512, stop_words="english")
            m = v.fit_transform(texts)
            return normalize(m).toarray()

        return embed
    except ImportError:
        return None


def _hash_bucket(vuln) -> str:
    """Fallback final: agrupar por (cwe, módulo, primeras 5 palabras del título)."""
    title_words = " ".join(re.findall(r"\w+", vuln.title.lower())[:5])
    key = f"{vuln.cwe}|{vuln.module}|{title_words}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def cluster_vulns(vulns: list, threshold: float = 0.85) -> list[list]:
    """
    Agrupa vulns similares. Devuelve list de clusters; cada cluster es un
    list de Vuln. El representante del cluster es vulns[0] (mayor severidad).

    threshold: cosine similarity mínima para agrupar (sentence-transformers/tfidf).
    """
    if len(vulns) <= 1:
        return [[v] for v in vulns]

    # ── Texto representativo de cada vuln para embedding ────────────────────
    texts = [
        f"{v.title} {v.category} {v.description[:200]} cwe={v.cwe}"
        for v in vulns
    ]

    embed = _try_sentence_transformers() or _try_tfidf()

    if embed is None:
        # Hash bucket fallback
        buckets: dict[str, list] = {}
        for v in vulns:
            key = _hash_bucket(v)
            buckets.setdefault(key, []).append(v)
        return list(buckets.values())

    try:
        import numpy as np  # type: ignore
        embs = embed(texts)
        n = len(vulns)
        assigned = [-1] * n
        clusters: list[list] = []

        for i in range(n):
            if assigned[i] != -1:
                continue
            cluster = [vulns[i]]
            assigned[i] = len(clusters)
            for j in range(i + 1, n):
                if assigned[j] != -1:
                    continue
                sim = float(np.dot(embs[i], embs[j]))
                if sim >= threshold:
                    cluster.append(vulns[j])
                    assigned[j] = assigned[i]
            clusters.append(cluster)

        return clusters
    except Exception:
        return [[v] for v in vulns]


def dedupe_for_ai(vulns: list, threshold: float = 0.85) -> tuple[list, dict]:
    """
    Devuelve (representantes, mapping_cluster_id → [vulns originales]).
    El representante es el de mayor severidad/cvss del cluster.
    """
    clusters = cluster_vulns(vulns, threshold)
    reps = []
    mapping = {}
    _SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    for i, c in enumerate(clusters):
        c.sort(key=lambda v: (_SEV_ORDER.get(v.severity, 0), v.cvss), reverse=True)
        reps.append(c[0])
        mapping[i] = c
    return reps, mapping
