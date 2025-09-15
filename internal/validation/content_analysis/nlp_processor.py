#!/usr/bin/env python3
import re
import warnings
from typing import Dict, List, Tuple, Optional

import numpy as np
import torch
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib
import logging

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    pipeline,
)

warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NLPDeadPageDetector:
    ZERO_SHOT_MODEL = "typeform/distilbert-base-uncased-mnli"  
    HUGGINGFACE_CONF_FILES = {"config.json", "pytorch_model.bin", "tokenizer.json"}

    def __init__(self, model_path: Optional[str] = None, use_gpu: bool = False, zero_shot: bool = True):
        self.device = 0 if use_gpu and torch.cuda.is_available() else -1
        self.mode: str = "pattern"  
        self.hf_pipeline = None  
        self.sklearn_pipeline: Optional[Pipeline] = None

        self.dead_page_patterns = [
            r"404\b",
            r"page not found",
            r"\bnot found\b",
            r"\berror\b",
            r"does not exist",
            r"\binvalid\b",
            r"under construction",
            r"coming soon",
            r"domain parking",
            r"for sale",
            r"\bthis domain\b",
            r"default page",
            r"\bapache\b",
            r"\bnginx\b",
            r"\bindex of\b",
            r"placeholder",
            r"test page",
            r"welcome to",
        ]
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.dead_page_patterns]

        self.load_models(model_path=model_path, prefer_zero_shot=zero_shot)


    def load_models(self, model_path: Optional[str], prefer_zero_shot: bool = True):
        try:
            if model_path:
                if self._looks_like_hf_dir(model_path):
                    logger.info(f"Loading HuggingFace sequence classifier from: {model_path}")
                    tokenizer = AutoTokenizer.from_pretrained(model_path)
                    model = AutoModelForSequenceClassification.from_pretrained(model_path)
                    self.hf_pipeline = pipeline(
                        "text-classification",
                        model=model,
                        tokenizer=tokenizer,
                        device=self.device,
                        truncation=True,
                    )
                    self.mode = "sequence"
                    return

                if model_path.endswith((".joblib", ".pkl")):
                    logger.info(f"Loading sklearn pipeline from: {model_path}")
                    self.sklearn_pipeline = joblib.load(model_path)
                    self.mode = "sklearn"
                    return

                logger.info(f"Attempting to load HuggingFace model id: {model_path}")
                tokenizer = AutoTokenizer.from_pretrained(model_path)
                model = AutoModelForSequenceClassification.from_pretrained(model_path)
                self.hf_pipeline = pipeline(
                    "text-classification",
                    model=model,
                    tokenizer=tokenizer,
                    device=self.device,
                    truncation=True,
                )
                self.mode = "sequence"
                return

            if prefer_zero_shot:
                logger.info(f"Using zero-shot pipeline: {self.ZERO_SHOT_MODEL}")
                self.hf_pipeline = pipeline(
                    "zero-shot-classification",
                    model=self.ZERO_SHOT_MODEL,
                    device=self.device,
                )
                self.mode = "zero-shot"
                return

            self._setup_sklearn_fallback()
            logger.info("Initialized fallback TF-IDF + LogisticRegression model")
            self.mode = "sklearn"

        except Exception as e:
            logger.error(f"Failed to load preferred model, falling back. Error: {e}")
            try:
                self._setup_sklearn_fallback()
                self.mode = "sklearn"
            except Exception as e2:
                logger.error(f"Failed to initialize sklearn fallback: {e2}")
                self.mode = "pattern"

    def _looks_like_hf_dir(self, path: str) -> bool:
        import os
        try:
            if not os.path.isdir(path):
                return False
            files = set(os.listdir(path))
            return len(self.HUGGINGFACE_CONF_FILES & files) > 0
        except Exception:
            return False

    def _setup_sklearn_fallback(self):
        self.sklearn_pipeline = Pipeline(
            steps=[
                ("tfidf", TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2))),
                ("clf", LogisticRegression(max_iter=1000, random_state=42)),
            ]
        )

        texts = [
            "404 page not found",
            "this page does not exist",
            "error 404",
            "under construction",
            "coming soon",
            "domain parking",
            "welcome to our website",
            "home page",
            "about us",
            "contact information",
            "products and services",
            "blog posts",
            "news and updates",
        ]
        labels = [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0] 
        self.sklearn_pipeline.fit(texts, labels)

    def extract_features(self, text: str) -> Dict[str, float]:
        feats: Dict[str, float] = {}
        words = text.split()
        feats["length"] = len(text)
        feats["word_count"] = len(words)
        feats["avg_word_length"] = float(np.mean([len(w) for w in words])) if words else 0.0
        feats["pattern_matches"] = sum(1 for p in self.compiled_patterns if p.search(text))
        feats["has_html_tags"] = 1 if re.search(r"<[^>]+>", text) else 0
        feats["has_links"] = 1 if re.search(r"http[s]?://", text) else 0
        sentences = re.split(r"[.!?]+", text)
        feats["sentence_count"] = len([s for s in sentences if s.strip()])
        feats["avg_sentence_length"] = (
            float(np.mean([len(s.split()) for s in sentences if s.strip()])) if sentences else 0.0
        )
        return feats

    def pattern_based_detection(self, text: str) -> float:
        match_count = sum(1 for p in self.compiled_patterns if p.search(text))
        if match_count == 0:
            return 0.1
        if match_count == 1:
            return 0.5
        if match_count == 2:
            return 0.7
        return 0.9

    def adjust_probability(self, base_prob: float, features: Dict[str, float]) -> float:
        p = base_prob
        if features.get("length", 0) < 100:
            p = min(1.0, p + 0.2)
        if features.get("pattern_matches", 0) > 0:
            p = min(1.0, p + 0.1 * float(features["pattern_matches"]))
        if features.get("has_html_tags", 0) > 0:
            p = max(0.0, p - 0.1)
        return p

    def predict_dead_page(self, text: str, title: str = "") -> Tuple[float, Dict[str, float]]:
        """
        Returns (probability_dead, features_dict)
        """
        if not text or not text.strip():
            return 1.0, {} 

        combined = f"{title} {text}" if title else text

        try:
            if self.mode == "zero-shot" and self.hf_pipeline is not None:
                result = self.hf_pipeline(
                    combined,
                    candidate_labels=["dead page", "live page"],
                    hypothesis_template="This web page is {}.",
                    multi_label=False,
                )
                labels = [l.lower() for l in result["labels"]]
                scores = result["scores"]
                dead_prob = 0.0
                for lbl, score in zip(labels, scores):
                    if "dead page" in lbl:
                        dead_prob = float(score)
                        break
                features = self.extract_features(combined)
                return self.adjust_probability(dead_prob, features), features

            if self.mode == "sequence" and self.hf_pipeline is not None:
                out = self.hf_pipeline(combined, truncation=True, max_length=512)
                if isinstance(out, list) and len(out) > 0:
                    label = out[0].get("label", "")
                    score = float(out[0].get("score", 0.5))
                    if "dead" in label.lower():
                        dead_prob = score
                    else:
                        dead_prob = score if label in {"LABEL_1", "1", "POSITIVE"} else (1.0 - score)
                else:
                    dead_prob = self.pattern_based_detection(combined)
                features = self.extract_features(combined)
                return self.adjust_probability(dead_prob, features), features

            if self.mode == "sklearn" and self.sklearn_pipeline is not None:
                proba = self.sklearn_pipeline.predict_proba([combined])[0]
                dead_prob = float(proba[1])
                features = self.extract_features(combined)
                return self.adjust_probability(dead_prob, features), features

            dead_prob = self.pattern_based_detection(combined)
            return dead_prob, self.extract_features(combined)

        except Exception as e:
            logger.error(f"Error in dead page prediction: {e}")
            dead_prob = self.pattern_based_detection(combined)
            return dead_prob, {}

    def batch_predict(self, texts: List[str], titles: Optional[List[str]] = None) -> List[Tuple[float, Dict[str, float]]]:
        """
        Batched prediction for efficiency (especially for transformers).
        """
        if not texts:
            return []
        if titles is None:
            titles = [""] * len(texts)
        combined = [(f"{t} {x}".strip() if t else x) for x, t in zip(texts, titles)]

        results: List[Tuple[float, Dict[str, float]]] = []

        try:
            if self.mode == "zero-shot" and self.hf_pipeline is not None:
                zs_out = self.hf_pipeline(
                    combined,
                    candidate_labels=["dead page", "live page"],
                    hypothesis_template="This web page is {}.",
                    multi_label=False,
                )
                # normalize to list
                if isinstance(zs_out, dict):
                    zs_out = [zs_out]
                for text_item, out in zip(combined, zs_out):
                    labels = [l.lower() for l in out["labels"]]
                    scores = out["scores"]
                    dead_prob = 0.0
                    for lbl, score in zip(labels, scores):
                        if "dead page" in lbl:
                            dead_prob = float(score)
                            break
                    feats = self.extract_features(text_item)
                    results.append((self.adjust_probability(dead_prob, feats), feats))
                return results

            if self.mode == "sequence" and self.hf_pipeline is not None:
                out = self.hf_pipeline(combined, truncation=True)
                if isinstance(out, dict):
                    out = [out]
                for text_item, o in zip(combined, out):
                    label = o.get("label", "")
                    score = float(o.get("score", 0.5))
                    if "dead" in label.lower():
                        dead_prob = score
                    else:
                        dead_prob = score if label in {"LABEL_1", "1", "POSITIVE"} else (1.0 - score)
                    feats = self.extract_features(text_item)
                    results.append((self.adjust_probability(dead_prob, feats), feats))
                return results

            if self.mode == "sklearn" and self.sklearn_pipeline is not None:
                probas = self.sklearn_pipeline.predict_proba(combined)
                for text_item, p in zip(combined, probas):
                    dead_prob = float(p[1])
                    feats = self.extract_features(text_item)
                    results.append((self.adjust_probability(dead_prob, feats), feats))
                return results

            for text_item in combined:
                dead_prob = self.pattern_based_detection(text_item)
                feats = self.extract_features(text_item)
                results.append((dead_prob, feats))
            return results

        except Exception as e:
            logger.error(f"Error in batch prediction: {e}")
            # fall back individually
            for x, t in zip(texts, titles):
                results.append(self.predict_dead_page(x, t))
            return results

    def save_model(self, path: str):
        """
        Save current backend to disk.
        - sequence (HF): save_pretrained to directory `path`
        - sklearn: joblib.dump to file `path` (use .joblib)
        """
        try:
            if self.mode == "sequence" and self.hf_pipeline is not None:
                # Extract underlying model/tokenizer from pipeline
                model = self.hf_pipeline.model
                tokenizer = self.hf_pipeline.tokenizer
                model.save_pretrained(path)
                tokenizer.save_pretrained(path)
                logger.info(f"Saved HuggingFace model to {path}")
            elif self.mode == "sklearn" and self.sklearn_pipeline is not None:
                joblib.dump(self.sklearn_pipeline, path)
                logger.info(f"Saved sklearn pipeline to {path}")
            else:
                logger.warning("Current mode does not support saving or nothing to save.")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def load_model(self, path: str):
        """
        Load a model from disk. Determines type automatically.
        """
        self.load_models(model_path=path, prefer_zero_shot=False)

# # -----------------------------------------------------------------------------
# # CLI demo
# # -----------------------------------------------------------------------------
# if __name__ == "__main__":
#     detector = NLPDeadPageDetector()

#     test_cases = [
#         ("404 Page Not Found", "The page you are looking for does not exist."),
#         ("Welcome to our website", "We offer the best services in the industry."),
#         ("", ""),  # Empty content
#         ("Under Construction", "This page is currently under construction. Please check back later."),
#     ]

#     for title, content in test_cases:
#         prob, features = detector.predict_dead_page(content, title)
#         print(f"Title: {title}")
#         print(f"Content: {content[:80]}{'...' if len(content) > 80 else ''}")
#         print(f"Dead page probability: {prob:.2f}")
#         print(f"Features: {features}")
#         print("-" * 60)
