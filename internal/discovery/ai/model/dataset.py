#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import glob
import os
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Any

import numpy as np
from collections import Counter
from math import log2

from sklearn.model_selection import train_test_split
import tldextract

try:
    import fasttext  
    import fasttext.util  
except Exception: 
    fasttext = None  
    fasttext_util = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_CONFIG: Dict[str, Any] = {
    "data_sources": {
        "common_crawl": False,          
        "ct_logs": False,               
        "public_datasets": False,       
        "internal_discovery": True    
    },
    "tldextract": {
        "cache_file": "data/tldextract_cache.json",
        "include_psl_private_domains": True
    },
    "preprocessing": {
        "strip_common_prefixes": False, 
        "min_length": 3,
        "max_length": 253               
    },
    "vocab": {
        "max_chars": 100,
        "max_words": 10000
    },
    "training": {
        "seq_length": 50,
        "max_words_per_subdomain": 10,
        "val_split": 0.15,
        "test_split": 0.15,
        "random_state": 42
    },
    "embeddings": {
        "use_fasttext": False,
        "lang": "en",
        "model": "cc.en.300.bin",
        "dir": "data/embeddings"
    },
    "paths": {
        "discovery_glob": "data/discovery/*.json",
        "training_out_dir": "data/training",
        "vocab_out_dir": "data/vocab",
        "config_path": "configs/ai_config.json"
    }
}


@dataclass
class SubdomainDataset:
    config_path: str = "configs/ai_config.json"
    config: Dict[str, Any] = field(default_factory=dict)
    char_vocab: Dict[str, int] | None = None
    word_vocab: Dict[str, int] | None = None
    fasttext_model: Any | None = None
    _tldx: Any | None = None 

    def __post_init__(self) -> None:
        self.config = self.load_config(self.config_path)
        self._tldx = self._build_tldextract(self.config.get("tldextract", {}))

    def load_config(self, path: str) -> Dict[str, Any]:
        """Load configuration JSON; fallback to DEFAULT_CONFIG if missing/invalid."""
        cfg = DEFAULT_CONFIG.copy()
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    for k, v in loaded.items():
                        if isinstance(v, dict) and k in cfg and isinstance(cfg[k], dict):
                            cfg[k].update(v)
                        else:
                            cfg[k] = v
            else:
                logger.warning("Config %s not found; using defaults.", path)
        except Exception as e: 
            logger.error("Failed to load config %s: %s; using defaults.", path, e)
        return cfg

    def _build_tldextract(self, tld_cfg: Dict[str, Any]):
        cache_file = tld_cfg.get("cache_file", DEFAULT_CONFIG["tldextract"]["cache_file"])
        include_private = tld_cfg.get(
            "include_psl_private_domains",
            DEFAULT_CONFIG["tldextract"]["include_psl_private_domains"],
        )
        
        return tldextract.TLDExtract(cache_file=cache_file, include_psl_private_domains=include_private)


    def load_data_sources(self) -> List[str]:
        """Load data from multiple sources into a flat list of subdomain strings."""
        cfg_sources = self.config["data_sources"]
        datasets: List[str] = []

        if cfg_sources.get("common_crawl", False):
            datasets.extend(self.load_common_crawl_data())

        if cfg_sources.get("ct_logs", False):
            datasets.extend(self.load_ct_logs_data())

        if cfg_sources.get("public_datasets", False):
            datasets.extend(self.load_public_datasets())

        if cfg_sources.get("internal_discovery", True):
            datasets.extend(self.load_internal_discovery_data())

        return datasets

    def load_common_crawl_data(self) -> List[str]:
        """Placeholder: implement your WARC/CC index parsing here."""
        logger.info("Loading Common Crawl data (placeholder)...")
        return []

    def load_ct_logs_data(self) -> List[str]:
        """Placeholder: feed from your Go CT pipeline artifacts if desired."""
        logger.info("Loading CT logs data (placeholder)...")
        return []

    def load_public_datasets(self) -> List[str]:
        """Placeholder: DNSDB / VirusTotal / SecurityTrails / program exports."""
        logger.info("Loading public datasets (placeholder)...")
        return []

    def load_internal_discovery_data(self) -> List[str]:
        """Load subdomains from internal discovery results JSON files."""
        logger.info("Loading internal discovery data...")
        out: List[str] = []
        pattern = self.config["paths"]["discovery_glob"]
        for file_path in glob.glob(pattern):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                subs = data.get("subdomains", [])
                for s in subs:
                    if isinstance(s, str):
                        out.append(s)
                    elif isinstance(s, dict) and "name" in s:
                        out.append(str(s["name"]))
            except Exception as e:
                logger.error("Error loading %s: %s", file_path, e)
        logger.info("Loaded %d subdomains from internal discovery.", len(out))
        return out

    def preprocess_subdomains(self, subdomains: List[str]) -> List[str]:
        """Clean and normalize subdomains for training."""
        logger.info("Preprocessing subdomains...")
        cfg = self.config["preprocessing"]
        strip_common = cfg.get("strip_common_prefixes", False)
        min_len = int(cfg.get("min_length", 3))
        max_len = int(cfg.get("max_length", 253))

        processed: List[str] = []
        for s in subdomains:
            s = s.strip()
            if not s:
                continue

            s = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
            s = re.sub(r"/.*$", "", s)

            s = s.lower().rstrip(".")

            if strip_common:
                s = re.sub(r"^(www|api)\.", "", s)

            if "." not in s:
                continue

            if not (min_len <= len(s) <= max_len):
                continue

            processed.append(s)

        processed = sorted(set(processed))
        logger.info("Preprocessed to %d unique subdomains.", len(processed))
        return processed


    def extract_features(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Extract multi-granularity features per subdomain string."""
        logger.info("Extracting features...")
        feats: List[Dict[str, Any]] = []
        for sd in subdomains:
            feats.append({
                "subdomain": sd,
                "char_features": self.extract_char_features(sd),
                "word_features": self.extract_word_features(sd),
                "stat_features": self.extract_statistical_features(sd),
                "domain_features": self.extract_domain_features(sd),
            })
        return feats

    def extract_char_features(self, subdomain: str) -> Dict[str, Any]:
        n = 3
        ngrams = [subdomain[i:i+n] for i in range(len(subdomain) - n + 1)] if len(subdomain) >= n else []
        return {
            "char_ngrams": ngrams,
            "char_freq": dict(Counter(subdomain)),
            "char_positions": {ch: [i for i, c in enumerate(subdomain) if c == ch] for ch in set(subdomain)},
        }

    def extract_word_features(self, subdomain: str) -> Dict[str, Any]:
        words = [w for w in re.split(r"[.\-_]", subdomain) if w]
        return {
            "words": words,
            "word_count": len(words),
            "word_lengths": [len(w) for w in words],
        }

    def extract_statistical_features(self, subdomain: str) -> Dict[str, Any]:
        length = len(subdomain)
        digits = sum(ch.isdigit() for ch in subdomain)
        letters = sum(ch.isalpha() for ch in subdomain)
        hyphens = subdomain.count("-")
        underscores = subdomain.count("_")
        dots = subdomain.count(".")
        probs = [subdomain.count(c) / length for c in set(subdomain)]
        entropy = -sum(p * log2(p) for p in probs if p > 0)
        return {
            "length": length,
            "digit_count": digits,
            "letter_count": letters,
            "hyphen_count": hyphens,
            "underscore_count": underscores,
            "dot_count": dots,
            "entropy": float(entropy),
        }

    def extract_domain_features(self, subdomain: str) -> Dict[str, Any]:
        ext = self._tldx(subdomain)
        labels = subdomain.split(".")
        return {
            "domain": ext.domain,
            "suffix": ext.suffix,
            "subdomain_part": ext.subdomain,
            "is_www": labels[0] == "www" if labels else False,
            "is_api": "api" in labels,
            "is_admin": "admin" in labels,
            "is_test": any(w in labels for w in ["test", "dev", "stage", "qa"]),
        }


    def build_char_vocabulary(self, subdomains: List[str], max_chars: int | None = None) -> Dict[str, int]:
        logger.info("Building character vocabulary...")
        if max_chars is None:
            max_chars = int(self.config["vocab"]["max_chars"])

        counter = Counter("".join(subdomains))
        most_common = [ch for ch, _ in counter.most_common(max_chars)]
        vocab = {ch: idx for idx, ch in enumerate(most_common)}

        special = {
            "<PAD>": len(vocab),
            "<UNK>": len(vocab) + 1,
            "<START>": len(vocab) + 2,
            "<END>": len(vocab) + 3,
        }
        vocab.update(special)
        self.char_vocab = vocab
        logger.info("Char vocab size: %d", len(vocab))
        return vocab

    def build_word_vocabulary(self, subdomains: List[str], max_words: int | None = None) -> Dict[str, int]:
        logger.info("Building word vocabulary...")
        if max_words is None:
            max_words = int(self.config["vocab"]["max_words"])
        words: List[str] = []
        for sd in subdomains:
            words.extend([w for w in re.split(r"[.\-_]", sd) if w])
        counter = Counter(words)
        most_common = [w for w, _ in counter.most_common(max_words)]
        vocab = {w: idx for idx, w in enumerate(most_common)}
        specials = {"<PAD>": len(vocab), "<UNK>": len(vocab) + 1}
        vocab.update(specials)
        self.word_vocab = vocab
        logger.info("Word vocab size: %d", len(vocab))
        return vocab

    def load_fasttext_embeddings(self) -> Any | None:
        """Optionally load FastText vectors if enabled and available."""
        emb_cfg = self.config["embeddings"]
        if not emb_cfg.get("use_fasttext", False):
            logger.info("FastText disabled by config; skipping.")
            return None
        if fasttext is None: 
            logger.warning("fasttext package not available; skipping embeddings.")
            return None

        os.makedirs(emb_cfg["dir"], exist_ok=True)
        model_path = os.path.join(emb_cfg["dir"], emb_cfg.get("model", "cc.en.300.bin"))
        lang = emb_cfg.get("lang", "en")
        try: 
            if not os.path.exists(model_path):
                logger.info("Downloading FastText model (%s) to %s ...", lang, model_path)
                fasttext.util.download_model(lang, if_exists="ignore")
                dl = f"cc.{lang}.300.bin"
                if os.path.exists(dl) and model_path != dl:
                    os.replace(dl, model_path)
            self.fasttext_model = fasttext.load_model(model_path)
            logger.info("FastText model loaded from %s", model_path)
        except Exception as e: 
            logger.error("Failed to load FastText: %s", e)
            self.fasttext_model = None
        return self.fasttext_model

    def create_training_data(self, features: List[Dict[str, Any]], seq_length: int | None = None
                             ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Create simple multi-input training arrays.

        X_char: [N, seq_length] integer char IDs (left-padded)
        X_word: [N, max_words_per_subdomain] integer word IDs
        X_stat: [N, 7] numeric features
        y:      [N] next-subdomain first-char ID (naive target)
        """
        if seq_length is None:
            seq_length = int(self.config["training"]["seq_length"])
        max_words_per_sd = int(self.config["training"]["max_words_per_subdomain"])

        assert self.char_vocab is not None and self.word_vocab is not None, "Call vocab builders first."

        X_char: List[List[int]] = []
        X_word: List[List[int]] = []
        X_stat: List[List[float]] = []
        y: List[int] = []

        for i, f in enumerate(features):
            sd = f["subdomain"]

            char_ids = [self.char_vocab.get(c, self.char_vocab["<UNK>"]) for c in sd]
            if len(char_ids) < seq_length:
                char_ids = [self.char_vocab["<PAD>"]] * (seq_length - len(char_ids)) + char_ids
            else:
                char_ids = char_ids[:seq_length]
            X_char.append(char_ids)

            words = f["word_features"]["words"]
            word_ids = [self.word_vocab.get(w, self.word_vocab["<UNK>"]) for w in words][:max_words_per_sd]
            if len(word_ids) < max_words_per_sd:
                word_ids += [self.word_vocab["<PAD>"]] * (max_words_per_sd - len(word_ids))
            X_word.append(word_ids)

            s = f["stat_features"]
            X_stat.append([
                s["length"], s["digit_count"], s["letter_count"],
                s["hyphen_count"], s["underscore_count"], s["dot_count"],
                s["entropy"],
            ])

            if i + 1 < len(features) and features[i + 1]["subdomain"]:
                next_first = features[i + 1]["subdomain"][0]
                y.append(self.char_vocab.get(next_first, self.char_vocab["<UNK>"]))
            else:
                y.append(self.char_vocab["<UNK>"])

        return np.asarray(X_char, dtype=np.int32), np.asarray(X_word, dtype=np.int32), \
            np.asarray(X_stat, dtype=np.float32), np.asarray(y, dtype=np.int32)

    def prepare_datasets(self):
        """End-to-end: load → preprocess → features → vocabs → arrays → split → save."""
        logger.info("Preparing datasets...")

        raw = self.load_data_sources()
        processed = self.preprocess_subdomains(raw)
        feats = self.extract_features(processed)

        self.build_char_vocabulary(processed)
        self.build_word_vocabulary(processed)

        self.load_fasttext_embeddings()

        X_char, X_word, X_stat, y = self.create_training_data(feats)

        val_split = float(self.config["training"]["val_split"])
        test_split = float(self.config["training"]["test_split"])
        random_state = int(self.config["training"]["random_state"])
        Xc_train, Xc_temp, Xw_train, Xw_temp, Xs_train, Xs_temp, y_train, y_temp = train_test_split(
            X_char, X_word, X_stat, y, test_size=val_split + test_split, random_state=random_state, shuffle=True
        )
        if (val_split + test_split) > 0:
            rel_test = test_split / (val_split + test_split)
        else:
            rel_test = 0.5
        Xc_val, Xc_test, Xw_val, Xw_test, Xs_val, Xs_test, y_val, y_test = train_test_split(
            Xc_temp, Xw_temp, Xs_temp, y_temp, test_size=rel_test, random_state=random_state, shuffle=True
        )

        self._save_datasets(
            Xc_train, Xc_val, Xc_test,
            Xw_train, Xw_val, Xw_test,
            Xs_train, Xs_val, Xs_test,
            y_train, y_val, y_test,
        )
        self._save_vocabularies()

        return (Xc_train, Xw_train, Xs_train, y_train,
                Xc_val, Xw_val, Xs_val, y_val,
                Xc_test, Xw_test, Xs_test, y_test)

    def _save_datasets(
        self,
        X_char_train: np.ndarray, X_char_val: np.ndarray, X_char_test: np.ndarray,
        X_word_train: np.ndarray, X_word_val: np.ndarray, X_word_test: np.ndarray,
        X_stat_train: np.ndarray, X_stat_val: np.ndarray, X_stat_test: np.ndarray,
        y_train: np.ndarray, y_val: np.ndarray, y_test: np.ndarray,
    ) -> None:
        """Save datasets to .npy files (fixed broken indexing from original)."""
        out_dir = self.config["paths"]["training_out_dir"]
        os.makedirs(out_dir, exist_ok=True)
        datasets = {
            "X_char_train": X_char_train, "X_char_val": X_char_val, "X_char_test": X_char_test,
            "X_word_train": X_word_train, "X_word_val": X_word_val, "X_word_test": X_word_test,
            "X_stat_train": X_stat_train, "X_stat_val": X_stat_val, "X_stat_test": X_stat_test,
            "y_train": y_train, "y_val": y_val, "y_test": y_test,
        }
        for name, arr in datasets.items():
            np.save(os.path.join(out_dir, f"{name}.npy"), arr)
        logger.info("Saved datasets to %s", out_dir)

    def _save_vocabularies(self) -> None:
        out_dir = self.config["paths"]["vocab_out_dir"]
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "char_vocab.json"), "w", encoding="utf-8") as f:
            json.dump(self.char_vocab or {}, f, ensure_ascii=False)
        with open(os.path.join(out_dir, "word_vocab.json"), "w", encoding="utf-8") as f:
            json.dump(self.word_vocab or {}, f, ensure_ascii=False)
        logger.info("Saved vocabularies to %s", out_dir)


if __name__ == "__main__":
    ds = SubdomainDataset()
    ds.prepare_datasets()
