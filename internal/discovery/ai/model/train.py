#!/usr/bin/env python3
"""
Advanced model training for subdomain prediction.

- Robust config with sensible defaults (works even if ai_config.json is missing/partial)
- Matches dataset.py shapes:
    X_char: [N, seq_length]  int32
    X_word: [N, max_words_per_subdomain] int32
    X_stat: [N, 7]  float32
    y:      [N]  int32  (class = first-char id)
- Safe GPU init, deterministic seeds (optional), clear logging
- Optional ONNX export via tf2onnx
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from typing import Any, Dict, Tuple
import numpy as np
import tensorflow as tf
from tensorflow.keras.layers import (
    Input, Embedding, LSTM, Dense, Dropout,
    Bidirectional, Conv1D, GlobalMaxPooling1D, BatchNormalization, Concatenate
)
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import (
    ModelCheckpoint, EarlyStopping, ReduceLROnPlateau, TensorBoard
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "paths": {
        "config_path": "configs/ai_config.json",
        "training_dir": "data/training",
        "vocab_dir": "data/vocab",
        "models_dir": "data/trained_models",
        "ckpt_dir": "data/trained_models/checkpoints",
        "logs_dir": "logs",
    },
    "training": {
        "seq_length": 50,        
        "max_words_per_subdomain": 10,
        "batch_size": 256,
        "epochs": 30,
        "learning_rate": 1e-3,
        "gradient_clip": 1.0,
        "early_stopping_patience": 8,
        "seed": None            
    },
    "model": {
        "char_embedding_dim": 64,
        "word_embedding_dim": 64,
        "dropout_rate": 0.25,
        "recurrent_dropout_rate": 0.0  
    },
    "export": {
        "onnx": True,
        "onnx_path": "data/trained_models/subdomain_predictor.onnx",
        "keras_path": "data/trained_models/subdomain_predictor.keras",
        "h5_path": "data/trained_models/subdomain_predictor.h5"
    }
}

def _load_config(path: str) -> Dict[str, Any]:
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


def _maybe_set_seed(seed: Any) -> None:
    if seed is None:
        return
    try:
        s = int(seed)
    except Exception:
        return
    tf.keras.utils.set_random_seed(s) 
    tf.config.experimental.enable_op_determinism(True)


def _init_gpu_memory_growth() -> None:
    try:
        gpus = tf.config.list_physical_devices("GPU")
        for g in gpus:
            tf.config.experimental.set_memory_growth(g, True)
    except Exception:
        pass

class SubdomainPredictor:
    def __init__(self, config_path: str = "configs/ai_config.json"):
        self.config = _load_config(config_path)
        self.model: Model | None = None
        self.char_vocab: Dict[str, int] | None = None
        self.word_vocab: Dict[str, int] | None = None

        _init_gpu_memory_growth()
        _maybe_set_seed(self.config["training"].get("seed"))

        os.makedirs(self.config["paths"]["training_dir"], exist_ok=True)
        os.makedirs(self.config["paths"]["vocab_dir"], exist_ok=True)
        os.makedirs(self.config["paths"]["models_dir"], exist_ok=True)
        os.makedirs(self.config["paths"]["ckpt_dir"], exist_ok=True)
        os.makedirs(self.config["paths"]["logs_dir"], exist_ok=True)


    def load_vocabularies(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        vdir = self.config["paths"]["vocab_dir"]
        with open(os.path.join(vdir, "char_vocab.json"), "r", encoding="utf-8") as f:
            self.char_vocab = json.load(f)
        with open(os.path.join(vdir, "word_vocab.json"), "r", encoding="utf-8") as f:
            self.word_vocab = json.load(f)
        return self.char_vocab, self.word_vocab

    def load_datasets(self):
        tdir = self.config["paths"]["training_dir"]
        def load(name: str):
            path = os.path.join(tdir, f"{name}.npy")
            if not os.path.exists(path):
                raise FileNotFoundError(f"Missing dataset file: {path}")
            return np.load(path)

        X_char_train = load("X_char_train").astype(np.int32)
        X_word_train = load("X_word_train").astype(np.int32)
        X_stat_train = load("X_stat_train").astype(np.float32)
        y_train = load("y_train").astype(np.int32)

        X_char_val = load("X_char_val").astype(np.int32)
        X_word_val = load("X_word_val").astype(np.int32)
        X_stat_val = load("X_stat_val").astype(np.float32)
        y_val = load("y_val").astype(np.int32)

        X_char_test = load("X_char_test").astype(np.int32)
        X_word_test = load("X_word_test").astype(np.int32)
        X_stat_test = load("X_stat_test").astype(np.float32)
        y_test = load("y_test").astype(np.int32)

        assert X_char_train.ndim == 2
        assert X_word_train.ndim == 2
        assert X_stat_train.shape[1] == 7

        return (X_char_train, X_word_train, X_stat_train, y_train,
                X_char_val, X_word_val, X_stat_val, y_val,
                X_char_test, X_word_test, X_stat_test, y_test)

     def build_model(self) -> Model:
        assert self.char_vocab is not None and self.word_vocab is not None, "Load vocabularies first."

        seq_len = int(self.config["training"]["seq_length"])
        max_words = int(self.config["training"]["max_words_per_subdomain"])
        char_emb = int(self.config["model"]["char_embedding_dim"])
        word_emb = int(self.config["model"]["word_embedding_dim"])
        dr = float(self.config["model"]["dropout_rate"])
        rdr = float(self.config["model"]["recurrent_dropout_rate"])

        num_chars = int(len(self.char_vocab))
        num_words = int(len(self.word_vocab))
        char_input = Input(shape=(seq_len,), dtype="int32", name="char_input")
        x_char = Embedding(num_chars, char_emb, mask_zero=True, name="char_embedding")(char_input)
        x_char = Conv1D(128, 3, padding="same", activation="relu", name="char_conv1")(x_char)
        x_char = BatchNormalization()(x_char)
        x_char = Conv1D(64, 5, padding="same", activation="relu", name="char_conv2")(x_char)
        x_char = BatchNormalization()(x_char)
        x_char = GlobalMaxPooling1D()(x_char)
        x_char = Dropout(dr)(x_char)
        word_input = Input(shape=(max_words,), dtype="int32", name="word_input")
        x_word = Embedding(num_words, word_emb, mask_zero=True, name="word_embedding")(word_input)
        x_word = Bidirectional(LSTM(64, return_sequences=False, dropout=dr, recurrent_dropout=rdr, name="word_lstm"))(x_word)
        x_word = Dropout(dr)(x_word)
        stat_input = Input(shape=(7,), dtype="float32", name="stat_input")
        x_stat = Dense(32, activation="relu", name="stat_dense")(stat_input)
        x_stat = Dropout(dr)(x_stat)
        x = Concatenate(name="fuse")([x_char, x_word, x_stat])
        x = Dense(256, activation="relu", name="dense1")(x)
        x = BatchNormalization()(x)
        x = Dropout(dr)(x)
        x = Dense(128, activation="relu", name="dense2")(x)
        x = BatchNormalization()(x)
        x = Dropout(dr)(x)

        out = Dense(num_chars, activation="softmax", name="output")(x)

        model = Model(inputs=[char_input, word_input, stat_input], outputs=out, name="subdomain_predictor")

        opt = Adam(learning_rate=float(self.config["training"]["learning_rate"]),
                   clipnorm=float(self.config["training"]["gradient_clip"]))

        model.compile(optimizer=opt, loss="sparse_categorical_crossentropy", metrics=["accuracy"])
        self.model = model
        return model

    def train_model(self):
        self.load_vocabularies()
        (Xc_tr, Xw_tr, Xs_tr, y_tr,
         Xc_va, Xw_va, Xs_va, y_va,
         Xc_te, Xw_te, Xs_te, y_te) = self.load_datasets()
        self.build_model()
        self.model.summary()
        ckpt_dir = self.config["paths"]["ckpt_dir"]
        os.makedirs(ckpt_dir, exist_ok=True)
        tb_log_dir = os.path.join(self.config["paths"]["logs_dir"], datetime.now().strftime("%Y%m%d-%H%M%S"))

        callbacks = [
            ModelCheckpoint(
                filepath=os.path.join(ckpt_dir, "model_{epoch:02d}_{val_accuracy:.4f}.keras"),
                save_best_only=True, monitor="val_accuracy", mode="max", verbose=1
            ),
            EarlyStopping(
                monitor="val_loss",
                patience=int(self.config["training"]["early_stopping_patience"]),
                restore_best_weights=True,
                verbose=1
            ),
            ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=5, min_lr=1e-7, verbose=1),
            TensorBoard(log_dir=tb_log_dir, histogram_freq=1),
        ]

        history = self.model.fit(
            x=[Xc_tr, Xw_tr, Xs_tr],
            y=y_tr,
            validation_data=([Xc_va, Xw_va, Xs_va], y_va),
            batch_size=int(self.config["training"]["batch_size"]),
            epochs=int(self.config["training"]["epochs"]),
            verbose=1,
            callbacks=callbacks,
            shuffle=True,
        )

        test_loss, test_acc = self.model.evaluate([Xc_te, Xw_te, Xs_te], y_te, verbose=0)
        print(f"Test Loss: {test_loss:.4f}")
        print(f"Test Accuracy: {test_acc:.4f}")

        self.save_model()
        return history

    def save_model(self) -> None:
        exp = self.config["export"]
        os.makedirs(os.path.dirname(exp["keras_path"]), exist_ok=True)

        self.model.save(exp["keras_path"])
        try:
            self.model.save(exp["h5_path"], include_optimizer=False)
        except Exception:
            pass

        if exp.get("onnx", True):
            self.convert_to_onnx(exp["onnx_path"])

    def convert_to_onnx(self, output_path: str) -> None:
        try:
            import tf2onnx 
            seq_len = int(self.config["training"]["seq_length"])
            max_words = int(self.config["training"]["max_words_per_subdomain"])

            spec = (
                tf.TensorSpec((None, seq_len), tf.int32, name="char_input"),
                tf.TensorSpec((None, max_words), tf.int32, name="word_input"),
                tf.TensorSpec((None, 7), tf.float32, name="stat_input"),
            )

            tf2onnx.convert.from_keras(self.model, input_signature=spec, output_path=output_path)
            print(f"ONNX model saved to {output_path}")
        except Exception as e:
            print(f"ONNX conversion skipped or failed: {e}")

    def load_trained_model(self, model_path: str) -> Model:
        self.model = tf.keras.models.load_model(model_path)
        return self.model

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train subdomain prediction model")
    parser.add_argument("--config", type=str, default="configs/ai_config.json", help="Path to configuration file")
    args = parser.parse_args()

    trainer = SubdomainPredictor(args.config)
    trainer.train_model()
