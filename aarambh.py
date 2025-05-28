import os
import sys
import ctypes
import logging
import datetime
import time
import traceback
from charset_normalizer import detect
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
        QComboBox, QLineEdit, QPushButton, QRadioButton, QProgressBar,
        QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox, QFrame, QScrollArea, QLabel
    )
    from PyQt6.QtGui import QIcon, QPixmap
    from PyQt6.QtCore import Qt, QCoreApplication, QThread, pyqtSignal
    import win32api
    import win32file
    import struct
    import zipfile
    from io import BytesIO
except ImportError as e:
    print(f"Failed to import required modules: {e}")
    sys.exit(1)

# Logging Configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("file_recovery_debug.log")]
)
logging.info("Logging initialized")

class SystemUtils:
    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception as e:
            logging.error(f"Admin check failed: {e}")
            return False

    @staticmethod
    def run_as_admin():
        try:
            if sys.platform == "win32" and not SystemUtils.is_admin():
                logging.info("Requesting admin privileges...")
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit(0)
        except Exception as e:
            logging.error(f"Admin elevation failed: {e}")
            sys.exit(1)

    @staticmethod
    def get_drives():
        try:
            drives = win32api.GetLogicalDriveStrings()
            drive_list = drives.split('\0')[:-1]
            logging.debug(f"Drives detected: {drive_list}")
            return drive_list
        except Exception as e:
            logging.error(f"Get drives failed: {e}")
            return []

class FileSignatures:
    SIGNATURES = {
        'jpg': {'start': [bytes.fromhex('FFD8FFE0'), bytes.fromhex('FFD8FFE1')], 'end': bytes.fromhex('FFD9'), 'max_size': 10 * 1024 * 1024, 'avg_size': 2 * 1024 * 1024},
        'png': {'start': [bytes.fromhex('89504E47')], 'end': bytes.fromhex('49454E44AE426082'), 'max_size': 10 * 1024 * 1024, 'avg_size': 1 * 1024 * 1024},
        'pdf': {'start': [bytes.fromhex('25504446')], 'end': bytes.fromhex('2525454F46'), 'max_size': 20 * 1024 * 1024, 'avg_size': 5 * 1024 * 1024},
        'docx': {'start': [bytes.fromhex('504B0304')], 'end': None, 'max_size': 20 * 1024 * 1024, 'avg_size': 5 * 1024 * 1024},
        'txt': {'start': [bytes.fromhex('EFBBBF'), bytes.fromhex('FFFE'), bytes.fromhex('FEFF')], 'end': None, 'max_size': 5 * 1024 * 1024, 'avg_size': 100 * 1024},
        'gif': {'start': [bytes.fromhex('474946383761'), bytes.fromhex('474946383961')], 'end': bytes.fromhex('003B'), 'max_size': 10 * 1024 * 1024, 'avg_size': 500 * 1024},
        'mp4': {'start': [bytes.fromhex('0000001866747970')], 'end': None, 'max_size': 50 * 1024 * 1024, 'avg_size': 10 * 1024 * 1024},
        'zip': {'start': [bytes.fromhex('504B0304')], 'end': None, 'max_size': 20 * 1024 * 1024, 'avg_size': 5 * 1024 * 1024},
        'xlsx': {'start': [bytes.fromhex('504B0304')], 'end': None, 'max_size': 20 * 1024 * 1024, 'avg_size': 5 * 1024 * 1024},
        'wav': {'start': [bytes.fromhex('52494646')], 'end': None, 'max_size': 20 * 1024 * 1024, 'avg_size': 5 * 1024 * 1024},
        'avi': {'start': [bytes.fromhex('52494646')], 'end': None, 'max_size': 50 * 1024 * 1024, 'avg_size': 10 * 1024 * 1024},
    }

class ScanThread(QThread):
    file_found = pyqtSignal(dict)
    progress_updated = pyqtSignal(int)

    def __init__(self, drive, scan_type):
        super().__init__()
        self.drive = drive
        self.scan_type = scan_type
        self.handle = None
        self.sector_size = 512
        self.cluster_size = self.get_cluster_size()
        self.buffer_size = self.cluster_size * 8
        self.should_stop = False
        self.paused = False
        self.fs_type = None
        self.mft_offset = None

    def get_cluster_size(self):
        try:
            sectors_per_cluster, bytes_per_sector, _, _ = win32file.GetDiskFreeSpace(self.drive)
            return sectors_per_cluster * bytes_per_sector
        except Exception as e:
            logging.error(f"Failed to get cluster size: {e}")
            return 4096

    def run(self):
        if not self.open_drive():
            return
        try:
            drive_size = win32file.GetDiskFreeSpaceEx(self.drive)[0]
            bytes_read = 0
            self.fs_type = self.detect_file_system()
            logging.info(f"Scanning {self.drive} ({drive_size:,} bytes) with {self.scan_type} scan, FS: {self.fs_type}")

            if self.scan_type == "Quick":
                self.quick_scan(bytes_read, drive_size)
            else:
                self.deep_scan(bytes_read, drive_size)

            self.close()
            logging.info("Scan completed")
        except Exception as e:
            logging.error(f"Scan failed: {traceback.format_exc()}")
            self.close()

    def open_drive(self):
        try:
            self.handle = win32file.CreateFile(
                f"\\\\.\\{self.drive[:2]}",
                win32file.GENERIC_READ,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            logging.info(f"Drive opened: {self.drive}")
            return True
        except Exception as e:
            logging.error(f"Failed to open drive {self.drive}: {traceback.format_exc()}")
            return False

    def detect_file_system(self):
        try:
            win32file.SetFilePointer(self.handle, 0, 0)
            _, boot_sector = win32file.ReadFile(self.handle, 512, None)
            if boot_sector[3:8] == b'NTFS ':
                return 'NTFS'
            elif boot_sector[82:90] == b'FAT32   ':
                return 'FAT32'
            return 'Unknown'
        except Exception as e:
            logging.error(f"File system detection failed: {traceback.format_exc()}")
            return 'Unknown'

    def quick_scan(self, start_offset, drive_size):
        offset = start_offset
        while offset < drive_size and not self.should_stop:
            if self.paused:
                while self.paused and not self.should_stop:
                    time.sleep(0.1)
                if self.should_stop:
                    break
            if self.fs_type == 'NTFS' and self.check_cluster_allocation(offset // self.cluster_size):
                offset += self.cluster_size
                continue
            self.carve_chunk(offset, drive_size)
            offset += self.buffer_size
            self.progress_updated.emit(int((offset / drive_size) * 100))

    def deep_scan(self, start_offset, drive_size):
        if self.fs_type == 'NTFS':
            self.mft_offset = self.find_mft_offset()
            if self.mft_offset:
                self.parse_mft(self.mft_offset, drive_size)
            else:
                logging.warning("MFT not found, falling back to signature scan")
                self.quick_scan(start_offset, drive_size)
        elif self.fs_type == 'FAT32':
            self.parse_fat32(start_offset, drive_size)
        else:
            self.quick_scan(start_offset, drive_size)

    def find_mft_offset(self):
        try:
            win32file.SetFilePointer(self.handle, 0, 0)
            _, boot_sector = win32file.ReadFile(self.handle, 512, None)
            mft_cluster = struct.unpack('<Q', boot_sector[48:56])[0]
            return mft_cluster * self.cluster_size
        except Exception as e:
            logging.error(f"Failed to find MFT: {traceback.format_exc()}")
            return None

    def parse_mft(self, mft_offset, drive_size):
        offset = mft_offset
        while offset < drive_size and not self.should_stop:
            if self.paused:
                while self.paused and not self.should_stop:
                    time.sleep(0.1)
                if self.should_stop:
                    break
            try:
                win32file.SetFilePointer(self.handle, offset, 0)
                _, mft_record = win32file.ReadFile(self.handle, 1024, None)
                if mft_record[:4] != b'FILE':
                    offset += 1024
                    continue
                in_use = struct.unpack('<H', mft_record[22:24])[0]
                if in_use == 0:  # Deleted file
                    file_info = self.extract_mft_file_info(mft_record, offset)
                    if file_info:
                        self.file_found.emit(file_info)
                offset += 1024
                self.progress_updated.emit(int((offset / drive_size) * 100))
            except Exception as e:
                logging.error(f"MFT parsing failed at {offset}: {traceback.format_exc()}")
                break

    def extract_mft_file_info(self, mft_record, offset):
        try:
            # Extract filename from $FILE_NAME attribute
            filename_offset = mft_record.find(b'\x30\x00')
            if filename_offset == -1:
                logging.warning(f"No $FILE_NAME attribute at offset {offset}")
                name = f"file_{offset}"
                extension = ""
            else:
                name_length = mft_record[filename_offset + 64]
                name = mft_record[filename_offset + 66:filename_offset + 66 + name_length * 2].decode('utf-16le', errors='ignore')
                # Extract extension from the name
                extension = name.split('.')[-1].lower() if '.' in name else ""

            # Extract data from $DATA attribute
            data_offset = mft_record.find(b'\x80\x00')
            if data_offset == -1:
                logging.warning(f"No $DATA attribute at offset {offset}")
                return None
            non_resident = mft_record[data_offset + 8] == 1
            if non_resident:
                run_offset = struct.unpack('<H', mft_record[data_offset + 32:data_offset + 34])[0]
                run_data = mft_record[data_offset + run_offset:]
                file_data, file_size, state = self.read_data_runs(run_data, offset)
            else:
                file_size = struct.unpack('<I', mft_record[data_offset + 48:data_offset + 52])[0]  # Real size for resident
                file_data = mft_record[data_offset + 56:data_offset + 56 + file_size]
                state = "Good"

            # Guess file type from header
            file_type = self.guess_file_type(file_data[:16]) or extension or 'unknown'
            if file_type != 'unknown':
                file_data, state = self.reconstruct_file(file_type, file_data)
                state = "Good" if self.validate_file(file_type, file_data) else state

            # Get timestamp
            last_modified = self.get_mft_timestamp(mft_record)

            # Use original name with extension, or fallback
            if extension and file_type != 'unknown':
                name = f"{name.split('.')[0]}.{file_type}"
            elif file_type != 'unknown':
                name = f"{name}.{file_type}"
            else:
                name = f"{name}.dat"

            return {
                'offset': offset,
                'type': file_type,
                'data': file_data,
                'size': file_size,
                'name': name,
                'status': "Recoverable",
                'state': state,
                'last_modified': last_modified.strftime("%Y-%m-%d %H:%M:%S"),
                'path': f"{self.drive}{offset}"
            }
        except Exception as e:
            logging.error(f"Failed to extract MFT info at {offset}: {traceback.format_exc()}")
            return None

    def read_data_runs(self, run_data, base_offset):
        file_data = bytearray()
        total_size = 0
        pos = 0
        state = "Good"
        fragments = []
        while pos < len(run_data) and run_data[pos] != 0 and not self.should_stop:
            header = run_data[pos]
            length_size = header & 0x0F
            offset_size = (header >> 4) & 0x0F
            pos += 1

            length = int.from_bytes(run_data[pos:pos + length_size], 'little')
            pos += length_size
            offset = int.from_bytes(run_data[pos:pos + offset_size], 'little', signed=True)
            pos += offset_size

            cluster_offset = (base_offset // self.cluster_size + offset) * self.cluster_size
            fragment_size = length * self.cluster_size
            if self.check_cluster_allocation(cluster_offset // self.cluster_size):
                state = "Partially Overwritten"
                fragments.append((file_data, total_size))
                file_data = bytearray()
                total_size = 0
                continue
            try:
                win32file.SetFilePointer(self.handle, cluster_offset, 0)
                _, data = win32file.ReadFile(self.handle, fragment_size, None)
                file_data.extend(data)
                total_size += len(data)
            except Exception as e:
                logging.error(f"Data run read failed at {cluster_offset}: {e}")
                state = "Corrupted"
                break
        if fragments:
            file_type = self.guess_file_type(file_data[:16]) or 'unknown'
            file_data, state = self.reconstruct_fragments(file_type, fragments + [(file_data, total_size)])
            total_size = len(file_data)
        return file_data, total_size, state

    def get_mft_timestamp(self, mft_record):
        try:
            # Look for $STANDARD_INFORMATION attribute (type 0x10)
            std_info_offset = mft_record.find(b'\x10\x00')
            if std_info_offset == -1:
                logging.warning("No $STANDARD_INFORMATION attribute found")
                return datetime.datetime.now()
            # Last modified time is at offset 8 in the attribute (FILETIME format)
            timestamp = struct.unpack('<Q', mft_record[std_info_offset + 24:std_info_offset + 32])[0]
            if timestamp == 0:
                return datetime.datetime.now()
            # Convert FILETIME (100-nanosecond intervals since 1601-01-01) to datetime
            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp / 10)
        except Exception as e:
            logging.error(f"Failed to extract MFT timestamp: {traceback.format_exc()}")
            return datetime.datetime.now()

    def parse_fat32(self, start_offset, drive_size):
        try:
            win32file.SetFilePointer(self.handle, 0, 0)
            _, boot_sector = win32file.ReadFile(self.handle, 512, None)
            sectors_per_cluster = boot_sector[13]
            reserved_sectors = struct.unpack('<H', boot_sector[14:16])[0]
            fat_copies = boot_sector[16]
            sectors_per_fat = struct.unpack('<I', boot_sector[36:40])[0]
            root_cluster = struct.unpack('<I', boot_sector[44:48])[0]

            fat_offset = reserved_sectors * self.sector_size
            dir_offset = (reserved_sectors + fat_copies * sectors_per_fat) * self.sector_size

            offset = dir_offset
            while offset < drive_size and not self.should_stop:
                if self.paused:
                    while self.paused and not self.should_stop:
                        time.sleep(0.1)
                    if self.should_stop:
                        break
                win32file.SetFilePointer(self.handle, offset, 0)
                _, dir_data = win32file.ReadFile(self.handle, 32, None)
                if dir_data[0] == 0xE5:  # Deleted entry
                    # Extract name and extension
                    name = dir_data[0:8].decode('ascii', errors='ignore').strip()
                    ext = dir_data[8:11].decode('ascii', errors='ignore').strip()
                    full_name = f"{name}.{ext}" if ext else name
                    cluster = struct.unpack('<H', dir_data[26:28])[0] + (struct.unpack('<H', dir_data[20:22])[0] << 16)
                    size = struct.unpack('<I', dir_data[28:32])[0]
                    # Extract last modified time
                    time = struct.unpack('<H', dir_data[14:16])[0]
                    date = struct.unpack('<H', dir_data[16:18])[0]
                    last_modified = self.fat32_to_datetime(date, time)
                    file_data, actual_size, state = self.read_fat32_file(cluster, size, reserved_sectors, fat_copies, sectors_per_fat, sectors_per_cluster)
                    if file_data:
                        file_type = self.guess_file_type(file_data[:16]) or ext.lower() or 'unknown'
                        file_data, state = self.reconstruct_file(file_type, file_data)
                        if file_type != 'unknown':
                            full_name = f"{name}.{file_type}"
                        self.file_found.emit({
                            'offset': offset,
                            'type': file_type,
                            'data': file_data,
                            'size': actual_size,
                            'name': full_name,
                            'status': "Recoverable",
                            'state': state,
                            'last_modified': last_modified.strftime("%Y-%m-%d %H:%M:%S"),
                            'path': f"{self.drive}{offset}"
                        })
                offset += 32
        except Exception as e:
            logging.error(f"FAT32 parsing failed: {traceback.format_exc()}")

    def fat32_to_datetime(self, date, time):
        try:
            # FAT32 date: (year-1980) << 9 | month << 5 | day
            # FAT32 time: hour << 11 | minute << 5 | second/2
            year = 1980 + (date >> 9)
            month = (date >> 5) & 0xF
            day = date & 0x1F
            hour = (time >> 11) & 0x1F
            minute = (time >> 5) & 0x3F
            second = (time & 0x1F) * 2
            return datetime.datetime(year, month, day, hour, minute, second)
        except Exception as e:
            logging.error(f"Failed to convert FAT32 timestamp: {e}")
            return datetime.datetime.now()

    def read_fat32_file(self, start_cluster, size, reserved_sectors, fat_copies, sectors_per_fat, sectors_per_cluster):
        file_data = bytearray()
        bytes_read = 0
        cluster = start_cluster
        state = "Good"
        fragments = []
        try:
            while bytes_read < size and cluster != 0x0FFFFFFF and not self.should_stop:
                offset = (reserved_sectors + fat_copies * sectors_per_fat + (cluster - 2) * sectors_per_cluster) * self.sector_size
                win32file.SetFilePointer(self.handle, offset, 0)
                _, data = win32file.ReadFile(self.handle, min(self.cluster_size, size - bytes_read), None)
                if self.check_cluster_allocation((offset // self.cluster_size)):
                    state = "Partially Overwritten"
                    fragments.append((file_data, bytes_read))
                    file_data = bytearray()
                    bytes_read = 0
                else:
                    file_data.extend(data)
                    bytes_read += len(data)
                fat_offset = reserved_sectors * self.sector_size + cluster * 4
                win32file.SetFilePointer(self.handle, fat_offset, 0)
                _, next_cluster = win32file.ReadFile(self.handle, 4, None)
                cluster = struct.unpack('I', next_cluster)[0]
            if fragments:
                file_type = self.guess_file_type(file_data[:16]) or 'unknown'
                file_data, state = self.reconstruct_fragments(file_type, fragments + [(file_data, bytes_read)])
                bytes_read = len(file_data)
            return file_data[:size], bytes_read, state
        except Exception as e:
            logging.error(f"FAT32 file read failed: {traceback.format_exc()}")
            return file_data, bytes_read, "Corrupted"

    def carve_chunk(self, offset, drive_size):
        try:
            win32file.SetFilePointer(self.handle, offset, 0)
            _, data = win32file.ReadFile(self.handle, self.buffer_size, None)
            if not data or data == b'\x00' * len(data):
                return
            for file_type, sig in FileSignatures.SIGNATURES.items():
                if self.should_stop:
                    return
                for start_sig in sig['start']:
                    pos = 0
                    while (pos := data.find(start_sig, pos)) != -1 and not self.should_stop:
                        file_offset = offset + pos
                        file_data = self.carve_file(file_offset, file_type, drive_size)
                        if file_data:
                            file_data, state = self.reconstruct_file(file_type, file_data)
                            if self.validate_file(file_type, file_data) or state != "Corrupted":
                                file_info = {
                                    'offset': file_offset,
                                    'type': file_type,
                                    'data': file_data,
                                    'size': len(file_data),
                                    'name': f"file_{file_offset}.{file_type}",
                                    'status': "Recoverable",
                                    'state': state,
                                    'last_modified': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    'path': f"{self.drive}{file_offset}"
                                }
                                self.file_found.emit(file_info)
                                logging.debug(f"Carved {file_type} at offset {file_offset}, state: {state}")
                        pos += 1
        except Exception as e:
            logging.error(f"Chunk carving failed at {offset}: {traceback.format_exc()}")

    def carve_file(self, offset, file_type, drive_size):
        try:
            win32file.SetFilePointer(self.handle, offset, 0)
            max_size = FileSignatures.SIGNATURES[file_type]['max_size']
            avg_size = FileSignatures.SIGNATURES[file_type]['avg_size']
            buffer = bytearray()
            bytes_read = 0
            end_sig = FileSignatures.SIGNATURES[file_type]['end']
            while bytes_read < max_size and (offset + bytes_read) < drive_size and not self.should_stop:
                _, data = win32file.ReadFile(self.handle, self.cluster_size, None)
                if not data:
                    break
                buffer.extend(data)
                bytes_read += len(data)
                if end_sig and end_sig in buffer:
                    return buffer[:buffer.index(end_sig) + len(end_sig)]
                if bytes_read >= avg_size and not end_sig:
                    return buffer[:bytes_read]
            return buffer[:bytes_read] if bytes_read else None
        except Exception as e:
            logging.error(f"File carving failed at {offset}: {traceback.format_exc()}")
            return None

    def reconstruct_file(self, file_type, data):
        state = "Good" if self.validate_file(file_type, data) else "Corrupted"
        try:
            if file_type == 'jpg' and not data.endswith(FileSignatures.SIGNATURES['jpg']['end']):
                data += FileSignatures.SIGNATURES['jpg']['end']
                state = "Reconstructed"
            elif file_type == 'png' and not data.endswith(FileSignatures.SIGNATURES['png']['end']):
                data += FileSignatures.SIGNATURES['png']['end']
                state = "Reconstructed"
            elif file_type == 'pdf' and b'%%EOF' not in data[-1024:]:
                data += b'\n%%EOF'
                state = "Reconstructed"
            elif file_type in ['docx', 'zip', 'xlsx'] and not zipfile.is_zipfile(BytesIO(data)):
                for i in range(len(data) - 1, -1, -1):
                    if data[i:i+4] == b'PK\x05\x06':
                        data = data[:i + 22]
                        state = "Reconstructed"
                        break
            elif file_type == 'txt':
                encoding = detect(data[:1024])['encoding'] or 'utf-8'
                decoded = data.decode(encoding, errors='ignore')
                cleaned = ''.join(c for c in decoded if c.isprintable() or c in '\n\r\t')
                data = cleaned.encode(encoding, errors='ignore')
                state = "Reconstructed" if len(cleaned) > 0 else "Corrupted"
            return data, state
        except Exception as e:
            logging.error(f"Reconstruction failed for {file_type}: {traceback.format_exc()}")
            return data, "Corrupted"

    def reconstruct_fragments(self, file_type, fragments):
        try:
            combined_data = bytearray()
            for fragment_data, _ in fragments:
                combined_data.extend(fragment_data)
            if not combined_data:
                return bytearray(), "Corrupted"
            repaired_data, state = self.reconstruct_file(file_type, combined_data)
            return repaired_data, f"Fragmented ({state})"
        except Exception as e:
            logging.error(f"Fragment reconstruction failed for {file_type}: {traceback.format_exc()}")
            return combined_data, "Corrupted"

    def validate_file(self, file_type, data):
        try:
            if file_type == 'jpg':
                return data.startswith(b'\xFF\xD8') and data.endswith(b'\xFF\xD9')
            elif file_type == 'png':
                return data.startswith(b'\x89\x50\x4E\x47') and data.endswith(b'\x49\x45\x4E\x44\xAE\x42\x60\x82')
            elif file_type == 'pdf':
                return data.startswith(b'%PDF') and b'%%EOF' in data[-1024:]
            elif file_type in ['docx', 'zip', 'xlsx']:
                return zipfile.is_zipfile(BytesIO(data))
            elif file_type == 'gif':
                return (data.startswith(b'GIF89a') or data.startswith(b'GIF87a')) and data.endswith(b'\x00\x3B')
            elif file_type == 'txt':
                encoding = detect(data[:1024])['encoding'] or 'utf-8'
                return bool(data.decode(encoding, errors='ignore').strip())
            return len(data) > 0
        except Exception:
            return False

    def guess_file_type(self, header):
        for file_type, sig in FileSignatures.SIGNATURES.items():
            for start_sig in sig['start']:
                if header.startswith(start_sig):
                    return file_type
        return None

    def check_cluster_allocation(self, cluster):
        if self.fs_type != 'NTFS' or not self.mft_offset:
            return False
        try:
            bitmap_offset = self.mft_offset + 6 * 1024
            win32file.SetFilePointer(self.handle, bitmap_offset, 0)
            _, bitmap_record = win32file.ReadFile(self.handle, 1024, None)
            data_offset = bitmap_record.find(b'\x80\x00')
            if data_offset == -1:
                return False
            run_offset = struct.unpack('<H', bitmap_record[data_offset + 32:data_offset + 34])[0]
            run_data = bitmap_record[data_offset + run_offset:]
            bitmap_data, _, _ = self.read_data_runs(run_data, bitmap_offset // self.cluster_size)
            bit_offset = cluster // 8
            if bit_offset >= len(bitmap_data):
                return False
            bit_mask = 1 << (cluster % 8)
            return (bitmap_data[bit_offset] & bit_mask) != 0
        except Exception as e:
            logging.error(f"Cluster allocation check failed: {traceback.format_exc()}")
            return False

    def stop(self):
        self.should_stop = True
        logging.debug("Stop signal sent")

    def pause(self):
        self.paused = True
        logging.debug("Pause signal sent")

    def resume(self):
        self.paused = False
        logging.debug("Resume signal sent")

    def close(self):
        if self.handle:
            win32file.CloseHandle(self.handle)
            self.handle = None
            logging.debug("Drive handle closed")

class FileRecoveryToolGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phoenix: Lost Data Retrieval Tool")
        self.setWindowIcon(QIcon("icon.png"))
        self.setMinimumSize(800, 600)
        self.setGeometry(100, 100, 900, 600)
        self.found_files = {}
        self.selected_files = set()
        self.scan_thread = None
        self.setup_gui()
        self.apply_theme()
        logging.info("GUI initialized")

    def apply_theme(self):
        self.setStyleSheet("""
            QWidget { background-color: #1A1F2B; color: #E0E6F0; font-family: 'Segoe UI', sans-serif; font-size: 13px; }
            QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00C4B4, stop:1 #00A3E0); border: 1px solid #3A4559; padding: 8px; border-radius: 10px; color: #FFFFFF; font-weight: 600; font-size: 14px; }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00A3E0, stop:1 #00C4B4); }
            QPushButton:disabled { background: #4A5366; color: #A0A0A0; border: 1px solid #3A4559; }
            QComboBox, QLineEdit { background-color: #252C3D; border: 1px solid #3A4559; padding: 5px; border-radius: 8px; color: #E0E6F0; }
            QTreeWidget { background-color: #252C3D; border: 1px solid #3A4559; border-radius: 12px; alternate-background-color: #2E3548; padding: 5px; }
            QFrame { background-color: #252C3D; border: 1px solid #3A4559; border-radius: 12px; }
            QProgressBar { border: 1px solid #3A4559; background-color: #1A1F2B; text-align: center; color: #E0E6F0; border-radius: 8px; }
            QProgressBar::chunk { background-color: #00C4B4; border-radius: 8px; }
        """)
        logging.debug("Theme applied")

    def setup_gui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)

        input_frame = QFrame()
        input_layout = QFormLayout(input_frame)
        self.driver_combo = QComboBox()
        self.driver_combo.addItems(SystemUtils.get_drives() or ["No drives detected"])
        input_layout.addRow("Select Drive:", self.driver_combo)
        recovery_layout = QHBoxLayout()
        self.recovery_path = QLineEdit()
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_recovery)
        recovery_layout.addWidget(self.recovery_path)
        recovery_layout.addWidget(browse_btn)
        input_layout.addRow("Recovery Path:", recovery_layout)
        scroll_layout.addWidget(input_frame)

        filter_frame = QFrame()
        filter_layout = QHBoxLayout(filter_frame)
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All files"] + [ft.upper() for ft in FileSignatures.SIGNATURES.keys()])
        self.filter_combo.currentTextChanged.connect(self.update_file_list)
        filter_layout.addWidget(self.filter_combo)
        self.scan_type = QRadioButton("Quick Scan")
        self.scan_type.setChecked(True)
        filter_layout.addWidget(self.scan_type)
        filter_layout.addWidget(QRadioButton("Deep Scan"))
        scroll_layout.addWidget(filter_frame)

        control_frame = QFrame()
        control_layout = QVBoxLayout(control_frame)
        self.progress = QProgressBar()
        control_layout.addWidget(self.progress)
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.pause_btn)
        btn_layout.addWidget(self.stop_btn)
        control_layout.addLayout(btn_layout)
        scroll_layout.addWidget(control_frame)

        preview_frame = QFrame()
        preview_layout = QVBoxLayout(preview_frame)
        self.file_list = QTreeWidget()
        self.file_list.setHeaderLabels(['Select', 'Name', 'Type', 'Size', 'Modified', 'Status', 'State', 'Path'])
        for i, w in enumerate([50, 150, 80, 80, 120, 100, 80, 150]):
            self.file_list.setColumnWidth(i, w)
        self.file_list.setSortingEnabled(True)
        self.file_list.header().setSortIndicator(1, Qt.SortOrder.AscendingOrder)
        self.file_list.itemClicked.connect(self.toggle_selection)
        self.file_list.itemDoubleClicked.connect(self.preview_file)
        preview_layout.addWidget(self.file_list)
        scroll_layout.addWidget(preview_frame)

        restore_layout = QHBoxLayout()
        restore_btn = QPushButton("Restore Selected")
        restore_btn.clicked.connect(self.restore_files)
        recover_all_btn = QPushButton("Restore All")
        recover_all_btn.clicked.connect(self.recover_all_files)
        restore_layout.addWidget(restore_btn)
        restore_layout.addWidget(recover_all_btn)
        scroll_layout.addLayout(restore_layout)

    def browse_recovery(self):
        path = QFileDialog.getExistingDirectory(self, "Select Recovery Path")
        if path:
            self.recovery_path.setText(path)

    def toggle_selection(self, item, column):
        if column == 0:
            file_id = item.text(1)
            if file_id in self.selected_files:
                self.selected_files.remove(file_id)
                item.setText(0, '☐')
            else:
                self.selected_files.add(file_id)
                item.setText(0, '☑')

    def preview_file(self, item, column):
        file_id = item.text(1)
        file_info = self.found_files.get(file_id)
        if not file_info or not file_info['data']:
            QMessageBox.warning(self, "Preview", "No data available for preview")
            return
        try:
            if file_info['type'] in ['jpg', 'png', 'gif']:
                pixmap = QPixmap()
                if pixmap.loadFromData(file_info['data']):
                    scaled_pixmap = pixmap.scaled(400, 400, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                    label = QLabel()
                    label.setPixmap(scaled_pixmap)
                    msg_box = QMessageBox(self)
                    msg_box.setWindowTitle("Preview")
                    msg_box.setText(f"Preview of {file_info['name']}")
                    msg_box.layout().addWidget(label, 1, 1)
                    msg_box.exec()
                else:
                    QMessageBox.warning(self, "Preview", f"Cannot preview {file_info['type']} file: Corrupted or invalid data")
            elif file_info['type'] == 'txt':
                encoding = detect(file_info['data'][:1024])['encoding'] or 'utf-8'
                text = file_info['data'].decode(encoding, errors='ignore')[:500]
                if text.strip():
                    QMessageBox.information(self, "Preview", f"Text Preview ({encoding}):\n\n{text}")
                else:
                    QMessageBox.warning(self, "Preview", "Text file is empty or unreadable")
            elif file_info['type'] == 'pdf':
                QMessageBox.information(self, "Preview", "PDF preview not supported yet\nFirst 500 bytes:\n" + file_info['data'][:500].decode('ascii', errors='ignore'))
            else:
                QMessageBox.information(self, "Preview", f"No preview available for {file_info['type']}\nFirst 500 bytes:\n" + file_info['data'][:500].decode('ascii', errors='ignore'))
        except Exception as e:
            logging.error(f"Preview failed for {file_id}: {traceback.format_exc()}")
            QMessageBox.warning(self, "Preview", f"Failed to preview file: {str(e)}")

    def start_scan(self):
        drive = self.driver_combo.currentText()
        recovery_path = self.recovery_path.text()
        if not drive or "No drives" in drive:
            QMessageBox.critical(self, "Error", "Please select a drive")
            return
        if not recovery_path:
            QMessageBox.critical(self, "Error", "Please select a recovery path")
            return
        if drive[:2] in recovery_path[:2]:
            QMessageBox.warning(self, "Warning", "Recovery path should be on a different drive to avoid overwriting data")

        self.found_files.clear()
        self.selected_files.clear()
        self.file_list.clear()
        self.progress.setValue(0)
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.pause_btn.setText("Pause")

        scan_type = "Quick" if self.scan_type.isChecked() else "Deep"
        self.scan_thread = ScanThread(drive, scan_type)
        self.scan_thread.file_found.connect(self.add_file_to_list)
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.finished.connect(self.finish_scan)
        self.scan_thread.start()

    def toggle_pause(self):
        if self.scan_thread and self.scan_thread.isRunning():
            if self.scan_thread.paused:
                self.scan_thread.resume()
                self.pause_btn.setText("Pause")
            else:
                self.scan_thread.pause()
                self.pause_btn.setText("Resume")
            logging.info(f"Scan {'paused' if self.scan_thread.paused else 'resumed'}")

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait()

    def finish_scan(self):
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.scan_thread = None
        self.update_file_list()
        logging.info(f"Scan finished, found {len(self.found_files)} files")

    def update_progress(self, value):
        self.progress.setValue(value)

    def add_file_to_list(self, file_info):
        file_id = file_info['name']
        self.found_files[file_id] = file_info
        self.update_file_list()

    def update_file_list(self):
        self.file_list.clear()
        filter_type = self.filter_combo.currentText().lower()
        for file_id, info in self.found_files.items():
            if filter_type == "all files" or info['type'] == filter_type:
                item = QTreeWidgetItem([
                    '☐', info['name'], info['type'].upper(), f"{info['size']} bytes",
                    info['last_modified'], info['status'], info['state'], info['path']
                ])
                self.file_list.addTopLevelItem(item)

    def restore_files(self):
        if not self.selected_files:
            QMessageBox.warning(self, "Warning", "No files selected")
            return
        recovery_path = self.recovery_path.text()
        os.makedirs(recovery_path, exist_ok=True)
        restored = 0
        for file_id in self.selected_files:
            info = self.found_files.get(file_id)
            if info:
                try:
                    filename = f"{info['name']}"
                    with open(os.path.join(recovery_path, filename), 'wb') as f:
                        f.write(info['data'])
                    restored += 1
                    logging.info(f"Restored: {filename}")
                except Exception as e:
                    logging.error(f"Restore failed for {file_id}: {traceback.format_exc()}")
        QMessageBox.information(self, "Complete", f"Restored {restored} files")

    def recover_all_files(self):
        self.selected_files = set(self.found_files.keys())
        self.restore_files()

def main():
    try:
        logging.info("Application starting")
        SystemUtils.run_as_admin()
        app = QApplication(sys.argv)
        window = FileRecoveryToolGUI()
        window.show()
        logging.info("Entering event loop")
        sys.exit(app.exec())
    except Exception as e:
        error_msg = f"Application failed to start: {str(e)}\n{traceback.format_exc()}"
        logging.error(error_msg)
        QMessageBox.critical(None, "Fatal Error", error_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()