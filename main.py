#!/usr/bin/env python3
"""
Ransomware detection tool using entropy, whitespace, printable detection, distinctiveness, and fingerprint sampling.

Monitors existing and new files, detecting possible encryption by:
- Absolute entropy threshold crossing.
- Relative entropy increase (delta) from baseline.
- Significant drop in whitespace ratio *and* low printable ratio (indicates non-text content).
- Significant high distinctiveness in printable content (e.g., Base64-like random printable).
- Significant full-file rewrite (fingerprint sample changes).
- Resets baseline on entropy decrease (possible decryption) or minor content changes.

Approach:
- On startup: scan directory recursively, compute baseline for each file:
    * metrics: (entropy, ws_ratio, printable_ratio, distinct_count)
    * fingerprint: samples of bytes at start, middle, end (SAMPLE_SIZE each)
- Monitor directory using watchdog:
    - On new file: compute baseline only.
    - On modification: recompute metrics and fingerprint:
        1. If entropy < prev_entropy: reset baseline (no alert).
        2. Compute fingerprint segment changes; if changes < FP_CHANGE_THRESHOLD: minor change, update baseline quietly.
        3. Compute dynamic thresholds based on file size (capped at CHUNK_SIZE):
              scale = min(size, CHUNK_SIZE) / CHUNK_SIZE
              dyn_abs = ABSOLUTE_THRESHOLD * scale
              dyn_delta = DELTA_THRESHOLD * scale
        4. Detection conditions:
              cond_entropy = entropy >= dyn_abs and (entropy - prev_entropy) >= dyn_delta
              cond_ws = ws_ratio <= WHITESPACE_THRESHOLD and printable_ratio <= PRINTABLE_THRESHOLD
              cond_distinct = printable_ratio >= PRINTABLE_THRESHOLD and distinct_count >= DISTINCT_COUNT_THRESHOLD
           If cond_entropy and (cond_ws or cond_distinct): alert and update baseline.
        5. Else: update baseline quietly.
- Skip internal key file (key.key).

References:
- Shannon entropy: https://en.wikipedia.org/wiki/Entropy_(information_theory)

Resource analysis:
- Time complexity: O(n) per event for metrics + O(k) for fingerprint sampling.
- Memory usage: O(CHUNK_SIZE)+O(SAMPLE_SIZE*3).
- I/O: event-driven, plus initial scan.
"""
import os
import math
import time
import argparse
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration constants
MIN_FILE_SIZE = 16              # Bytes; ignore very small files
CHUNK_SIZE = 64 * 1024          # Bytes for chunked read
DELTA_THRESHOLD = 1.0           # Bits; minimal entropy increase
ABSOLUTE_THRESHOLD = 6.0        # Bits; absolute entropy threshold
WHITESPACE_THRESHOLD = 0.05     # Fraction; max whitespace ratio for text content
PRINTABLE_THRESHOLD = 0.8       # Fraction; min printable chars to treat as text
DISTINCT_COUNT_THRESHOLD = 50   # Minimum distinct byte values to indicate high randomness in printable
SAMPLE_SIZE = 64                # Bytes per fingerprint segment
FP_CHANGE_THRESHOLD = 2         # Number of segments changed for major rewrite
KEY_FILE_NAME = "key.key"      # Skip this file

class EncryptionDetectorHandler(FileSystemEventHandler):
    def __init__(self, min_size, delta_thresh, abs_thresh, ws_thresh, printable_thresh, distinct_thresh, key_file_name):
        super().__init__()
        self.min_size = min_size
        self.delta_thresh = delta_thresh
        self.abs_thresh = abs_thresh
        self.ws_thresh = ws_thresh
        self.printable_thresh = printable_thresh
        self.distinct_thresh = distinct_thresh
        self.key_file_name = key_file_name
        # baseline: path -> (entropy, ws_ratio, printable_ratio, distinct_count, fingerprint)
        self.baseline = {}

    def _calculate_metrics(self, file_path):
        freq = [0] * 256
        total = 0
        ws_count = 0
        printable_count = 0
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    for b in chunk:
                        freq[b] += 1
                        if b in (0x20, 0x09, 0x0A, 0x0D):
                            ws_count += 1
                        if 0x20 <= b <= 0x7E:
                            printable_count += 1
        except (FileNotFoundError, PermissionError):
            return None, None, None, None
        if total == 0:
            return 0.0, 1.0, 1.0, 0
        entropy = -sum((count / total) * math.log2(count / total) for count in freq if count)
        ws_ratio = ws_count / total
        printable_ratio = printable_count / total
        distinct_count = sum(1 for count in freq if count > 0)
        return entropy, ws_ratio, printable_ratio, distinct_count

    def _sample_fingerprint(self, file_path):
        try:
            size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                segments = []
                f.seek(0)
                segments.append(f.read(SAMPLE_SIZE))
                mid = max((size - SAMPLE_SIZE) // 2, 0)
                f.seek(mid)
                segments.append(f.read(SAMPLE_SIZE))
                end = max(size - SAMPLE_SIZE, 0)
                f.seek(end)
                segments.append(f.read(SAMPLE_SIZE))
                return segments
        except (OSError, PermissionError):
            return None

    def _init_baseline(self, root_path):
        for dirpath, _, filenames in os.walk(root_path):
            for fname in filenames:
                if fname == self.key_file_name:
                    continue
                path = os.path.join(dirpath, fname)
                metrics = self._calculate_metrics(path)
                if metrics[0] is None:
                    continue
                entropy, ws, pr, dc = metrics
                fp = self._sample_fingerprint(path)
                self.baseline[path] = (entropy, ws, pr, dc, fp)
                logging.debug(f"Init {path}: ent={entropy:.2f}, ws={ws:.2f}, pr={pr:.2f}, dc={dc}")

    def _process(self, file_path):
        if os.path.basename(file_path) == self.key_file_name:
            return
        try:
            size = os.path.getsize(file_path)
        except OSError:
            return
        if size < self.min_size:
            return
        metrics = self._calculate_metrics(file_path)
        if metrics[0] is None:
            return
        entropy, ws, pr, dc = metrics
        fp_new = self._sample_fingerprint(file_path)
        prev = self.baseline.get(file_path)
        if prev is None:
            # new file: set baseline only
            self.baseline[file_path] = (entropy, ws, pr, dc, fp_new)
            logging.info(f"Baseline set new '{file_path}' ent={entropy:.2f}, ws={ws:.2f}, pr={pr:.2f}, dc={dc}")
            return
        prev_e, prev_ws, prev_pr, prev_dc, fp_old = prev
        # reset on entropy decrease
        if entropy < prev_e:
            logging.info(f"Entropy decreased for '{file_path}' {prev_e:.2f}->{entropy:.2f}, baseline reset")
            self.baseline[file_path] = (entropy, ws, pr, dc, fp_new)
            return
        # fingerprint change check
        changes = sum(1 for a, b in zip(fp_old, fp_new) if a != b)
        if changes < FP_CHANGE_THRESHOLD:
            self.baseline[file_path] = (entropy, ws, pr, dc, fp_new)
            return
        # compute dynamic thresholds (capped at CHUNK_SIZE)
        scale = min(size, CHUNK_SIZE) / CHUNK_SIZE
        dyn_abs = self.abs_thresh * scale
        dyn_delta = self.delta_thresh * scale
        # detection conditions
        cond_entropy = entropy >= dyn_abs and (entropy - prev_e) >= dyn_delta
        cond_ws = ws <= self.ws_thresh and pr <= self.printable_thresh
        cond_distinct = pr >= self.printable_thresh and dc >= self.distinct_thresh
        if cond_entropy and (cond_ws or cond_distinct):
            logging.warning(
                f"Possible encryption: '{file_path}' ent {prev_e:.2f}->{entropy:.2f} "
                f"(thr={dyn_abs:.2f}, Δ={dyn_delta:.2f}), ws={ws:.2f}, pr={pr:.2f}, dc={dc}, changes={changes}"
            )
        self.baseline[file_path] = (entropy, ws, pr, dc, fp_new)

    def on_created(self, event):
        if not event.is_directory:
            self._process(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process(event.src_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Detect file encryption via entropy/printable/fingerprint.")
    parser.add_argument('path', help="Directory to monitor")
    parser.add_argument('--min-size', type=int, default=MIN_FILE_SIZE)
    parser.add_argument('--delta', type=float, default=DELTA_THRESHOLD)
    parser.add_argument('--threshold', type=float, default=ABSOLUTE_THRESHOLD)
    parser.add_argument('--ws-thresh', type=float, default=WHITESPACE_THRESHOLD)
    parser.add_argument('--printable-thresh', type=float, default=PRINTABLE_THRESHOLD)
    parser.add_argument('--distinct-thresh', type=int, default=DISTINCT_COUNT_THRESHOLD)
    parser.add_argument('--log-file', type=str, default=None)
    args = parser.parse_args()
    log_fmt = '%(asctime)s - %(levelname)s - %(message)s'
    if args.log_file:
        logging.basicConfig(level=logging.INFO, filename=args.log_file, format=log_fmt)
    else:
        logging.basicConfig(level=logging.INFO, format=log_fmt)
    handler = EncryptionDetectorHandler(
        args.min_size, args.delta, args.threshold,
        args.ws_thresh, args.printable_thresh, args.distinct_thresh, KEY_FILE_NAME
    )
    handler._init_baseline(args.path)
    observer = Observer()
    observer.schedule(handler, args.path, recursive=True)
    observer.start()
    logging.info(f"Started monitoring: {args.path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
