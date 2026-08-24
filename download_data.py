#!/usr/bin/env python
"""
Download full CIC-IDS2017 dataset for Hugging Face Spaces.
Run this once during Space build or at runtime.
"""
import os
import requests
from pathlib import Path

# CIC-IDS2017 files (hosted on various mirrors)
# Using a reliable mirror - update URLs as needed
FILES = {
    "Monday-WorkingHours.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "Tuesday-WorkingHours.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    # ... add actual download URLs when available
}

def download_file(url: str, dest: Path):
    """Download file with progress."""
    print(f"Downloading {dest.name}...")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    total = int(response.headers.get('content-length', 0))
    
    with open(dest, 'wb') as f:
        downloaded = 0
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
            downloaded += len(chunk)
            if total > 0:
                pct = downloaded / total * 100
                print(f"\r  {pct:.1f}%", end='')
    print(f"\n  Saved: {dest}")

def main():
    raw_dir = Path("data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    
    # Check what's already there
    existing = list(raw_dir.glob("*.csv"))
    print(f"Found {len(existing)} existing CSV files:")
    for f in existing:
        print(f"  {f.name} ({f.stat().st_size / 1e6:.1f} MB)")
    
    # For demo, we already have demo_sample.csv
    demo = raw_dir / "demo_sample.csv"
    if demo.exists():
        print(f"\n✅ Demo sample ready: {demo.stat().st_size / 1e6:.1f} MB")
    
    print("\n📥 To add full dataset:")
    print("1. Download from: https://www.unb.ca/cic/datasets/ids-2017.html")
    print("2. Place CSV files in data/raw/")
    print("3. Re-run pipeline: python -m src.data.clean_data && python -m src.data.create_windows && python -m src.models.train")

if __name__ == "__main__":
    main()