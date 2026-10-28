# Filyzer
offline forensic file triage. it scans files and folders, flags the ones that look disguised, packed or known-bad, and tells you why with a score from 0 to 100.

#FEATURES
-reads the real type from the file's first bytes (magic bytes) and flags mismatches
-measures how random the contents are (0 to 8) to spot encrypted or packed data
-checks MD5 and SHA-256 against your own list of known-bad hashes
-shows LOW, MEDIUM or HIGH, with the exact reasons listed for each file
-responsive GUI with tkinter

#RUN
git clone https://github.com/diyamnr0210/Filyzer.git
cd Filyzer
pip install -r requirements.txt
python main.py
