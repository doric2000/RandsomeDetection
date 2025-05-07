#!/usr/bin/env python3
r"""
Self-contained test harness for the ransomware detection tool (ransomware_detector.py).

Verifies that the detection tool meets assignment requirements without external dependencies:
1. No alerts on legitimate ASCII text modifications (append, delete, empty).
2. Alerts when files are XOR-encrypted inline.
3. Alerts when files are Fernet-encrypted inline.
4. Operates on the target folder: C:\Users\doric\Desktop\Dor\Studies\Ariel\Second Year\Semester B\Cyber\Lab\folder4hash

Usage:
    python test_ransomware_detector.py

Prerequisites:
- `ransomware_detector.py` in same directory (accepts args: <path> --log-file <log>)
- Python 3.8+, `watchdog` and `cryptography` installed
"""
import sys
import time
import subprocess
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet

# Paths and settings
BASE_DIR = Path(__file__).parent
DETECTOR = BASE_DIR / 'randsomware_detector.py'
TEST_DIR = Path(r"C:\Users\doric\Desktop\Dor\Studies\Ariel\Second Year\Semester B\Cyber\Lab\folder4hash")
LOG_FILE = TEST_DIR / 'ransomware_detector.log'
NUM_FILES = 3
SLEEP = 1.5

# Simple XOR key
XOR_KEY = b'mysecretkey'

def xor_data(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))

def setup_test_folder():
    # Prepare directory: recreate sample .txt files and clear log
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    # Remove only .txt and .bak files
    for ext in ('*.txt', '*.bak'):
        for file in TEST_DIR.glob(ext):
            try:
                file.unlink()
            except Exception:
                pass
    # Clear log file if exists
    if LOG_FILE.exists():
        try:
            LOG_FILE.write_text('')
        except Exception:
            pass
    # Create fresh sample .txt files
    for i in range(1, NUM_FILES + 1):
        p = TEST_DIR / f'file{i}.txt'
        p.write_text(f"Sample file {i}\nLine2 of file {i}\n")

def start_detector():
    # Use Python executable to start detector
    cmd = [sys.executable, str(DETECTOR), str(TEST_DIR), '--log-file', str(LOG_FILE)]
    return subprocess.Popen(cmd)

def stop_detector(proc):
    proc.terminate()
    proc.wait(timeout=5)

def read_log():
    if not LOG_FILE.exists():
        return ''
    return LOG_FILE.read_text()

# Tests

def test_no_alert_on_legit_changes():
    f = TEST_DIR / 'file1.txt'
    # Append safe ASCII
    with f.open('a', encoding='utf-8') as fp:
        fp.write('Appended safe ASCII.\n')
    time.sleep(SLEEP)
    assert 'WARNING' not in read_log(), 'False-positive alert on append'

    # Empty the file
    f.write_text('')
    time.sleep(SLEEP)
    assert 'WARNING' not in read_log(), 'False-positive alert on empty file'


def test_alert_on_xor_encrypt():
    # Apply XOR encryption inline
    for path in TEST_DIR.glob('*.txt'):
        data = path.read_bytes()
        path.write_bytes(xor_data(data))
    time.sleep(SLEEP)
    log = read_log()
    assert 'Possible encryption' in log, 'No alert on XOR encryption'


def test_alert_on_fernet_encrypt():
    # Restart plaintext files without deleting log
    setup_test_folder()
    time.sleep(0.5)
    key = Fernet.generate_key()
    fernet = Fernet(key)
    for path in TEST_DIR.glob('*.txt'):
        data = path.read_bytes()
        path.write_bytes(fernet.encrypt(data))
    time.sleep(SLEEP)
    log = read_log()
    assert 'Possible encryption' in log, 'No alert on Fernet encryption'

# Runner

def main():
    print('Setting up test folder...')
    setup_test_folder()
    print('Starting detector...')
    proc = start_detector()
    try:
        time.sleep(SLEEP)
        print('Testing legitimate changes...')
        test_no_alert_on_legit_changes()
        print('PASS: No false positives on legit changes')

        print('Testing XOR encryption alert...')
        test_alert_on_xor_encrypt()
        print('PASS: Alert on XOR encryption')

        print('Testing Fernet encryption alert...')
        test_alert_on_fernet_encrypt()
        print('PASS: Alert on Fernet encryption')

        print('All tests passed!')
    finally:
        print('Stopping detector...')
        stop_detector(proc)

if __name__ == '__main__':
    main()
