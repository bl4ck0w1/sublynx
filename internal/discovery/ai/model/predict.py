#!/usr/bin/env python3
"""
prediction interface for subdomain prediction model.

- Works with Keras (.keras/.h5) or ONNX (.onnx)
- Uses the same config keys as dataset/train (training.seq_length, training.max_words_per_subdomain)
- Robust preprocessing, dtype handling, and top-k + temperature sampling
"""

from __future__ import annotations

import argparse
import json
import os
import re
from typing import Any, Dict, List, Tuple

import numpy as np
import tensorflow as tf 
from tensorflow.keras.models import load_model
from dataset import SubdomainDataset

DEFAULT_CONFIG: Dict[str, Any] = {
    "paths": {
        "vocab_dir": "data/vocab",
    },
    "training": {
        "seq_length": 50,
        "max_words_per_subdomain": 10,
    },
    "prediction": {
        "top_k": 5,
        "temperature": 1.0, 
    }
}


class SubdomainPredictor:
    def __init__(self, model_path: str, config_path: str = "configs/ai_config.json"):
        self.config = self._load_config(config_path)
        self.model_path = model_path
        self.model = None             
        self.session = None         
        self.char_vocab: Dict[str, int] = {}
        self.word_vocab: Dict[str, int] = {}
        self.dataset = SubdomainDataset(config_path)

        self._load_vocabularies()
        mp = model_path.lower()
        if mp.endswith(".keras") or mp.endswith(".h5"):
            self._load_keras_model(model_path)
        elif mp.endswith(".onnx"):
            self._load_onnx_model(model_path)
        else:
            raise ValueError("Unsupported model format. Use .keras, .h5, or .onnx")

    def _load_config(self, path: str) -> Dict[str, Any]:
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))  
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                user = json.load(f)
            for k, v in user.items():
                if isinstance(v, dict) and k in cfg and isinstance(cfg[k], dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        return cfg

    def _load_vocabularies(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        vdir = self.config["paths"]["vocab_dir"]
        with open(os.path.join(vdir, "char_vocab.json"), "r", encoding="utf-8") as f:
            self.char_vocab = json.load(f)
        with open(os.path.join(vdir, "word_vocab.json"), "r", encoding="utf-8") as f:
            self.word_vocab = json.load(f)
        return self.char_vocab, self.word_vocab

    def _load_keras_model(self, model_path: str) -> None:
        self.model = tf.keras.models.load_model(model_path)

    def _load_onnx_model(self, model_path: str) -> None:
        try:
            import onnxruntime as ort
        except Exception as e:
            raise RuntimeError("onnxruntime is not installed but an .onnx model was provided.") from e
        providers = ["CPUExecutionProvider"]
        try:
            self.session = ort.InferenceSession(model_path, providers=providers)
        except Exception:
            self.session = ort.InferenceSession(model_path)

    def _preprocess_input(self, subdomain: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Turn a (partial) subdomain string into model inputs."""
        feat = self.dataset.extract_features([subdomain])[0]

        seq_len = int(self.config["training"]["seq_length"])
        max_words = int(self.config["training"]["max_words_per_subdomain"])

        char_ids = [self.char_vocab.get(c, self.char_vocab.get("<UNK>", 0)) for c in feat["subdomain"]]
        pad_id = self.char_vocab.get("<PAD>", 0)
        if len(char_ids) < seq_len:
            char_ids = [pad_id] * (seq_len - len(char_ids)) + char_ids
        else:
            char_ids = char_ids[:seq_len]

        words = feat["word_features"]["words"]
        unk_w = self.word_vocab.get("<UNK>", 0)
        pad_w = self.word_vocab.get("<PAD>", 0)
        word_ids = [self.word_vocab.get(w, unk_w) for w in words][:max_words]
        if len(word_ids) < max_words:
            word_ids += [pad_w] * (max_words - len(word_ids))

        s = feat["stat_features"]
        stat = np.asarray([
            s["length"], s["digit_count"], s["letter_count"],
            s["hyphen_count"], s["underscore_count"], s["dot_count"],
            s["entropy"],
        ], dtype=np.float32)

        return (np.asarray([char_ids], dtype=np.int32),
                np.asarray([word_ids], dtype=np.int32),
                np.asarray([stat], dtype=np.float32))

    def predict_next_char(self, subdomain: str) -> List[Tuple[str, float]]:
        """Return [(char, prob), ...] sorted by prob desc (top_k from config)."""
        X_char, X_word, X_stat = self._preprocess_input(subdomain)

        if self.model is not None:
            probs = self.model.predict([X_char, X_word, X_stat], verbose=0)[0]
        elif self.session is not None:
            inputs = {
                "char_input": X_char.astype(np.int32),
                "word_input": X_word.astype(np.int32),
                "stat_input": X_stat.astype(np.float32),
            }
            probs = self.session.run(None, inputs)[0][0]
        else:
            raise RuntimeError("No model/session loaded.")

        temperature = float(self.config["prediction"].get("temperature", 1.0))
        if temperature and temperature != 1.0:
            logits = np.log(np.maximum(probs, 1e-12)) / max(temperature, 1e-4)
            probs = np.exp(logits)
            probs /= probs.sum()

        top_k = int(self.config["prediction"].get("top_k", 5))
        idxs = np.argsort(probs)[-top_k:][::-1]

        idx_to_char = {idx: ch for ch, idx in self.char_vocab.items()}
        result: List[Tuple[str, float]] = []
        for i in idxs:
            result.append((idx_to_char.get(int(i), "<UNK>"), float(probs[int(i)])))
        return result

    def generate_subdomains(self, base_domain: str, seed: str = "", num_predictions: int = 10, max_length: int = 30
                            ) -> List[str]:
        """Autoregressively sample label strings and append .<base_domain>.

        Notes:
          - We suppress sampling of <PAD> and <START>.
          - If <END> is sampled, we stop the current sequence.
        """
        generated: List[str] = []
        forbidden = {"<PAD>", "<START>"}
        end_tok = "<END>"

        for _ in range(max(1, num_predictions)):
            current = seed
            for _ in range(max(1, max_length)):
                preds = self.predict_next_char(current)
                chars, probs = zip(*preds)
                chars = list(chars)
                probs = np.asarray(probs, dtype=np.float64)

                for i, ch in enumerate(chars):
                    if ch in forbidden:
                        probs[i] = 0.0

                if probs.sum() <= 0:
                    break
                probs = probs / probs.sum()

                next_ch = np.random.choice(chars, p=probs)
                if next_ch == end_tok or len(current) >= max_length:
                    break
                current += next_ch

            if self._is_valid_label(current):
                fqdn = f"{current}.{base_domain}".lower().strip(".")
                if fqdn not in generated:
                    generated.append(fqdn)

        return generated

    def _is_valid_label(self, label: str) -> bool:
        """DNS label validity checks (single label, not full FQDN)."""
        if not (1 <= len(label) <= 63):
            return False
        if not re.match(r"^[a-z0-9](?:[a-z0-9\-_.]*[a-z0-9])?$", label, re.IGNORECASE):
            return False
        if ".." in label or "--" in label:
            return False
        if label.startswith("-") or label.endswith("-") or label.startswith(".") or label.endswith("."):
            return False
        return True

    def predict_domain_variations(self, domain: str, num_variations: int = 20) -> List[str]:
        """Return likely FQDN variations for a domain."""
        dom = domain.strip().lower()
        if dom.startswith("http://") or dom.startswith("https://"):
            dom = re.sub(r"^https?://", "", dom)
        dom = dom.strip("/").strip(".")

        parts = dom.split(".")
        if len(parts) < 2:
            return []

        base = ".".join(parts[-2:])         
        subparts = parts[:-2]                 

        variations: List[str] = []

        common = ["www", "api", "app", "web", "admin", "test", "dev", "stage", "prod"]
        for p in common:
            variations.append(f"{p}.{base}")

        seed = ".".join(subparts) if subparts else ""
        if seed:
            variations.extend(self.generate_subdomains(base, seed, max(1, num_variations // 2)))

        variations.extend(self.generate_subdomains(base, "", max(1, num_variations // 2)))

        uniq = []
        seen = set()
        for v in variations:
            v = v.lower()
            if v not in seen:
                seen.add(v)
                uniq.append(v)
            if len(uniq) >= num_variations:
                break
        return uniq

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Predict subdomain variations")
    parser.add_argument("domain", type=str, help="Domain to predict variations for (e.g., example.com)")
    parser.add_argument("--model", type=str, default="data/trained_models/subdomain_predictor.onnx",
                        help="Path to trained model (.keras/.h5/.onnx)")
    parser.add_argument("--config", type=str, default="configs/ai_config.json",
                        help="Path to configuration file")
    parser.add_argument("--num", type=int, default=20, help="Number of variations to generate")
    args = parser.parse_args()

    predictor = SubdomainPredictor(args.model, args.config)
    vars_ = predictor.predict_domain_variations(args.domain, args.num)

    print(f"Predicted variations for {args.domain}:")
    for i, v in enumerate(vars_, 1):
        print(f"{i}. {v}")
