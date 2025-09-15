#!/usr/bin/env python3

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from collections import Counter, OrderedDict
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity as sk_cosine_similarity

try:
    import torch  
except Exception: 
    torch = None 

try:
    from sentence_transformers import SentenceTransformer, util
except Exception:  
    SentenceTransformer = None  
    util = None 

try:
    import Levenshtein as _lev
except Exception:  
    _lev = None 

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SimilarityResult:
    cosine: float
    jaccard: float
    levenshtein: float
    semantic: float
    structural: float
    weighted: float


class ContentSimilarity:
    DEFAULT_ST_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

    def __init__(self, model_name: str = DEFAULT_ST_MODEL, embedding_cache_size: int = 512):
        self.semantic_model = None
        self.device = "cpu"
        if SentenceTransformer is not None:
            try:
                if torch is not None and torch.cuda.is_available():
                    self.device = "cuda"
                self.semantic_model = SentenceTransformer(model_name, device=self.device)
                logger.info(f"Loaded semantic model: {model_name} on {self.device}")
            except Exception as e:  
                logger.error(f"Failed to load semantic model '{model_name}': {e}")
                self.semantic_model = None

        self.tfidf_vectorizer = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            max_features=5000,
        )
        self._embedding_cache: OrderedDict[str, np.ndarray] = OrderedDict()
        self._embedding_cache_size = max(64, int(embedding_cache_size))

    def preprocess_text(self, text: str) -> str:
        """Normalize text (lowercase, collapse whitespace, basic charset filtering)."""
        text = (text or "").lower()
        text = re.sub(r"\s+", " ", text).strip()
        text = re.sub(r"[^a-z0-9\s\.\,\!\?\;\:]", " ", text)
        return text

    def cosine_similarity(self, text1: str, text2: str) -> float:
        """Cosine similarity (TF-IDF)."""
        try:
            t1 = self.preprocess_text(text1)
            t2 = self.preprocess_text(text2)
            tfidf = self.tfidf_vectorizer.fit_transform([t1, t2])
            sim = float(sk_cosine_similarity(tfidf[0:1], tfidf[1:2])[0][0])
            return float(max(0.0, min(1.0, sim)))
        except Exception as e: 
            logger.error(f"Cosine similarity error: {e}")
            return 0.0

    def jaccard_similarity(self, text1: str, text2: str) -> float:
        """Jaccard similarity over token sets."""
        try:
            t1 = set(self.preprocess_text(text1).split())
            t2 = set(self.preprocess_text(text2).split())
            if not t1 and not t2:
                return 1.0
            union = len(t1 | t2)
            if union == 0:
                return 0.0
            return len(t1 & t2) / union
        except Exception as e:  
            logger.error(f"Jaccard similarity error: {e}")
            return 0.0

    def levenshtein_similarity(self, text1: str, text2: str) -> float:
        """Normalized Levenshtein similarity (1 - distance/max_len)."""
        try:
            a = self.preprocess_text(text1)
            b = self.preprocess_text(text2)
            if a == b:
                return 1.0
            max_len = max(len(a), len(b))
            if max_len == 0:
                return 1.0

            if _lev is not None:
                dist = _lev.distance(a, b)
            else:
                dist = self._levenshtein_dp(a, b)

            sim = 1.0 - (dist / max_len)
            return float(max(0.0, min(1.0, sim)))
        except Exception as e: 
            logger.error(f"Levenshtein similarity error: {e}")
            return 0.0

    def semantic_similarity(self, text1: str, text2: str) -> float:
        """Semantic cosine similarity via Sentence-Transformers (fallback: TF-IDF)."""
        try:
            if self.semantic_model is None or util is None:
                return self.cosine_similarity(text1, text2)

            t1 = self.preprocess_text(text1)
            t2 = self.preprocess_text(text2)

            emb1 = self._embed_cached(t1)
            emb2 = self._embed_cached(t2)
            denom = (np.linalg.norm(emb1) * np.linalg.norm(emb2)) or 1e-12
            sim = float(np.dot(emb1, emb2) / denom)
            return float(max(0.0, min(1.0, sim)))
        except Exception as e: 
            logger.error(f"Semantic similarity error: {e}")
            return self.cosine_similarity(text1, text2)

    def structural_similarity(self, text1: str, text2: str) -> float:
        """Similarity over structural features."""
        try:
            f1 = self._extract_structural_features(text1 or "")
            f2 = self._extract_structural_features(text2 or "")

            sims: List[float] = []
            for key, v1 in f1.items():
                if key not in f2:
                    continue
                v2 = f2[key]
                if isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
                    m = max(v1, v2)
                    sims.append(1.0 if m == 0 else 1.0 - (abs(v1 - v2) / m))
                elif isinstance(v1, str) and isinstance(v2, str):
                    sims.append(1.0 if v1 == v2 else 0.0)

            return float(sum(sims) / len(sims)) if sims else 0.0
        except Exception as e:  # pragma: no cover
            logger.error(f"Structural similarity error: {e}")
            return 0.0

    def calculate_weighted_similarity(
        self,
        text1: str,
        text2: str,
        weights: Optional[Dict[str, float]] = None,
    ) -> SimilarityResult:
        """
        Weighted aggregate of all metrics. Weights must sum roughly to 1.0.
        """
        if weights is None:
            weights = {
                "cosine": 0.30,
                "jaccard": 0.20,
                "levenshtein": 0.10,
                "semantic": 0.30,
                "structural": 0.10,
            }

        cos = self.cosine_similarity(text1, text2)
        jac = self.jaccard_similarity(text1, text2)
        lev = self.levenshtein_similarity(text1, text2)
        sem = self.semantic_similarity(text1, text2)
        struc = self.structural_similarity(text1, text2)

        w = weights
        weighted = (
            w.get("cosine", 0) * cos
            + w.get("jaccard", 0) * jac
            + w.get("levenshtein", 0) * lev
            + w.get("semantic", 0) * sem
            + w.get("structural", 0) * struc
        )

        return SimilarityResult(
            cosine=float(cos),
            jaccard=float(jac),
            levenshtein=float(lev),
            semantic=float(sem),
            structural=float(struc),
            weighted=float(max(0.0, min(1.0, weighted))),
        )

    def find_similar_documents(
        self, target_text: str, documents: List[str], threshold: float = 0.7
    ) -> List[Tuple[int, float]]:
        """
        Returns list of (index, similarity) for docs above threshold, sorted desc.
        """
        scored: List[Tuple[int, float]] = []
        for i, doc in enumerate(documents):
            sim = self.calculate_weighted_similarity(target_text, doc).weighted
            if sim >= threshold:
                scored.append((i, float(sim)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def create_similarity_matrix(self, documents: List[str]) -> np.ndarray:
        """
        NxN symmetric matrix of weighted similarities (1.0 on diagonal).
        """
        n = len(documents)
        M = np.zeros((n, n), dtype=float)
        for i in range(n):
            M[i, i] = 1.0
            for j in range(i + 1, n):
                sim = self.calculate_weighted_similarity(documents[i], documents[j]).weighted
                M[i, j] = M[j, i] = float(sim)
        return M

    def _extract_structural_features(self, text: str) -> Dict[str, float | str]:
        """Simple structural features."""
        words = text.split()
        sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]
        length = len(text)
        word_count = len(words)
        sentence_count = len(sentences)

        features: Dict[str, float | str] = {
            "length": float(length),
            "word_count": float(word_count),
            "sentence_count": float(sentence_count),
            "avg_word_length": (sum(len(w) for w in words) / word_count) if word_count else 0.0,
            "avg_sentence_length": (word_count / sentence_count) if sentence_count else 0.0,
            "digit_ratio": (sum(ch.isdigit() for ch in text) / length) if length else 0.0,
            "punctuation_ratio": (sum(ch in ".,!?;:" for ch in text) / length) if length else 0.0,
        }

        if words:
            features["most_common_word"] = Counter(words).most_common(1)[0][0]

        return features

    def _levenshtein_dp(self, a: str, b: str) -> int:
        """O(len(a)*len(b)) DP edit distance as a safe fallback."""
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)

        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            curr = [i]
            for j, cb in enumerate(b, start=1):
                cost = 0 if ca == cb else 1
                curr.append(
                    min(
                        curr[-1] + 1,        
                        prev[j] + 1,          
                        prev[j - 1] + cost,    
                    )
                )
            prev = curr
        return prev[-1]

    def _embed_cached(self, text: str) -> np.ndarray:
        if text in self._embedding_cache:
            vec = self._embedding_cache.pop(text)
            self._embedding_cache[text] = vec
            return vec

        vec = self._encode(text)
        self._embedding_cache[text] = vec
        if len(self._embedding_cache) > self._embedding_cache_size:
            self._embedding_cache.popitem(last=False) 
        return vec

    def _encode(self, text: str) -> np.ndarray:
        if self.semantic_model is None:
            tfidf = self.tfidf_vectorizer.fit_transform([text])
            arr = tfidf.toarray()[0]
            norm = np.linalg.norm(arr) or 1e-12
            return (arr / norm).astype(np.float32)
        try:
            emb = self.semantic_model.encode([text], convert_to_numpy=True, normalize_embeddings=True)
            return emb[0].astype(np.float32)
        except Exception as e:  
            logger.error(f"Embedding failed, falling back to TF-IDF: {e}")
            tfidf = self.tfidf_vectorizer.fit_transform([text])
            arr = tfidf.toarray()[0]
            norm = np.linalg.norm(arr) or 1e-12
            return (arr / norm).astype(np.float32)


# if __name__ == "__main__":
#     # Example usage
#     sim = ContentSimilarity()

#     text1 = "This is a sample text about machine learning and artificial intelligence."
#     text2 = "This text discusses artificial intelligence and machine learning concepts."
#     text3 = "The weather is nice today and I enjoy walking in the park."

#     res = sim.calculate_weighted_similarity(text1, text2)
#     print(f"Text 1: {text1}")
#     print(f"Text 2: {text2}")
#     print(f"Cosine: {res.cosine:.3f} | Jaccard: {res.jaccard:.3f} | Lev: {res.levenshtein:.3f} | "
#           f"Semantic: {res.semantic:.3f} | Structural: {res.structural:.3f} | Weighted: {res.weighted:.3f}")

#     res2 = sim.calculate_weighted_similarity(text1, text3)
#     print(f"\nSimilarity with unrelated text (weighted): {res2.weighted:.3f}")
