# Aarambh
A Lost Data Retrieval Tool
A Python-based tool to recover deleted files from drives on Windows. It supports both quick and deep scans to locate and restore files like JPG, PNG, PDF, DOCX, and more.

## Features
- Quick Scan: Scans recently deleted files.
- Deep Scan: Performs a thorough scan to recover files beyond the Recycle Bin.
- Supports multiple file types (JPG, PNG, PDF, DOCX, etc.).
- GUI built with PyQt6 for easy interaction.
- Preview files before recovery.

## Requirements
- Windows OS (due to `pywin32` dependency)
- Python 3.8 or higher

## Installation
1. Clone the repository: git clone https://github.com/Prix-0803/Aarambh.git cd your-repo

2. Create a virtual environment (optional but recommended): python -m venv venv source venv/bin/activate 
On Windows: venv\Scripts\activate

3. Install dependencies: pip install -r requirements.txt

4. Run the script: python aarambh.py


## Usage
1. Select a drive to scan.
2. Choose a recovery path (preferably on a different drive).
3. Select Quick Scan or Deep Scan.
4. Preview and restore files as needed.

## Notes
- This tool requires administrative privileges to access raw disk data.
- Ensure the recovery path is on a different drive to avoid overwriting data.

## License
MIT License