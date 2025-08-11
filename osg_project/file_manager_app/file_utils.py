import os
import shutil
import time
import re
from datetime import datetime

# Define the root directory for your application's files
BASE_DIR = 'my_application_files'
ARCHIVE_DIR = os.path.join(BASE_DIR, 'archive')
WORKING_DIR = os.path.join(BASE_DIR, 'working')

def setup_directories():
    """Ensures the base and archive directories exist."""
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    os.makedirs(WORKING_DIR, exist_ok=True)

def delete_file_soft(file_path):
    """
    Simulates a soft deletion by moving a file to the archive directory.
    The file is renamed to prevent conflicts and includes a timestamp.
    """
    # file_path should be the absolute path or relative to BASE_DIR
    if not os.path.isabs(file_path):
        file_path = os.path.join(BASE_DIR, file_path)
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return False

    # Generate a new name for the archived file with a timestamp and ARCHIVED suffix
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name, file_extension = os.path.splitext(os.path.basename(file_path))
    new_file_name = f"{file_name}_{timestamp}_ARCHIVED{file_extension}"
    archive_path = os.path.join(ARCHIVE_DIR, new_file_name)

    try:
        shutil.move(file_path, archive_path)
        print(f"File '{file_path}' soft-deleted to '{archive_path}'.")
        return True
    except Exception as e:
        print(f"Error moving file: {e}")
        return False

def restore_file(archived_file_name):
    import os, shutil
    archive_path = os.path.join(ARCHIVE_DIR, archived_file_name)
    if not os.path.exists(archive_path):
        print(f"Error: Archived file '{archived_file_name}' not found.")
        return False

    # Restore to a 'restored' directory for safety
    restored_dir = os.path.join(BASE_DIR, 'restored')
    os.makedirs(restored_dir, exist_ok=True)
    restored_path = os.path.join(restored_dir, archived_file_name)
    try:
        shutil.move(archive_path, restored_path)
        print(f"File '{archived_file_name}' restored to '{restored_path}'.")
        return True
    except Exception as e:
        print(f"Error restoring file: {e}")
        return False

def get_archived_files():
    """
    Retrieves a list of all files in the archive directory.

    Returns:
        A list of dictionaries, where each dictionary contains the 
        'original_name', 'archived_name', and 'archived_date' of a file.
    """
    if not os.path.exists(ARCHIVE_DIR):
        print(f"Error: Archive directory not found at {ARCHIVE_DIR}")
        return []

    archived_files = []
    # Regular expression to parse the archived file name
    # e.g., 'invoice.pdf_2025-08-11_10-28-00_ARCHIVED.pdf'
    pattern = re.compile(r"^(.*)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})_ARCHIVED(\..+)$")

    for filename in os.listdir(ARCHIVE_DIR):
        match = pattern.match(filename)
        if match:
            original_name = match.group(1) + match.group(3)
            date_str = match.group(2)
            try:
                archived_date = datetime.strptime(date_str, "%Y-%m-%d_%H-%M-%S")
                archived_files.append({
                    "original_name": original_name,
                    "archived_name": filename,
                    "archived_date": archived_date.strftime("%Y-%m-%d %H:%M:%S")
                })
            except ValueError:
                archived_files.append({
                    "original_name": filename,
                    "archived_name": filename,
                    "archived_date": "Unknown"
                })
        else:
            # If the file doesn't match the pattern, show as unknown
            archived_files.append({
                "original_name": filename,
                "archived_name": filename,
                "archived_date": "Unknown"
            })

    return archived_files
