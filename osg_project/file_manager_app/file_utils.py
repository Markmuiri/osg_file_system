import os
import shutil
import time
import os
import re
from datetime import datetime

# Define the root directory for your application's files
BASE_DIR = 'my_application_files'

# Define the archive directory where 'deleted' files will be moved
ARCHIVE_DIR = os.path.join(BASE_DIR, '.archive')

def setup_directories():
    """Ensures the base and archive directories exist."""
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)
    if not os.path.exists(ARCHIVE_DIR):
        os.makedirs(ARCHIVE_DIR)

def delete_file_soft(file_path):
    """
    Simulates a soft deletion by moving a file to the archive directory.
    The file is renamed to prevent conflicts.
    """
    file_path = os.path.join(BASE_DIR, file_path)
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return False
    
    # Generate a new name for the archived file with a timestamp
    timestamp = int(time.time())
    file_name, file_extension = os.path.splitext(os.path.basename(file_path))
    new_file_name = f"{file_name}_{timestamp}{file_extension}"
    
    archive_path = os.path.join(ARCHIVE_DIR, new_file_name)
    
    try:
        shutil.move(file_path, archive_path)
        print(f"File '{file_path}' soft-deleted to '{archive_path}'.")
        return True
    except Exception as e:
        print(f"Error moving file: {e}")
        return False

def restore_file(archived_file_name):
    """
    Restores a file from the archive directory to its original location.
    Note: This example assumes you know the original name, but a more robust
    system would store original paths in a database.
    """
    archive_path = os.path.join(ARCHIVE_DIR, archived_file_name)
    if not os.path.exists(archive_path):
        print(f"Error: Archived file '{archived_file_name}' not found.")
        return False
        
    # Get the original file name by stripping the timestamp
    original_file_name = '_'.join(archived_file_name.split('_')[:-1]) + os.path.splitext(archived_file_name)[1]
    original_path = os.path.join(BASE_DIR, original_file_name)

    try:
        shutil.move(archive_path, original_path)
        print(f"File '{archived_file_name}' restored to '{original_path}'.")
        return True
    except Exception as e:
        print(f"Error restoring file: {e}")
        return False

# --- Example Usage ---
if __name__ == "__main__":
    setup_directories()
    
    # Create a dummy file to 'delete'
    with open(os.path.join(BASE_DIR, 'report.txt'), 'w') as f:
        f.write("This is a sample report.")

    print("Created 'report.txt'")
    
    # Soft-delete the file
    delete_file_soft('report.txt')
    
    # List files in the base directory (should be empty now)
    print("\nFiles in base directory:", os.listdir(BASE_DIR))
    
    # List files in the archive directory (should contain the 'deleted' file)
    print("Files in archive directory:", os.listdir(ARCHIVE_DIR))
    
    # Now, let's restore the file (you would need the full archived filename)
    archived_file = os.listdir(ARCHIVE_DIR)[0]
    print(f"\nRestoring file '{archived_file}'...")
    restore_file(archived_file)

    print("\nFiles in base directory:", os.listdir(BASE_DIR))
    print("Files in archive directory:", os.listdir(ARCHIVE_DIR))
# Assuming the ARCHIVE_DIR is defined as before
ARCHIVE_DIR = "my_application_files/archive"
WORKING_DIR = "my_application_files/working"

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
    # e.g., 'invoice.pdf_2025-08-11_10-28-00_ARCHIVED'
    pattern = re.compile(r"^(.*)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})_ARCHIVED$")

    for filename in os.listdir(ARCHIVE_DIR):
        match = pattern.match(filename)
        if match:
            original_name = match.group(1)
            date_str = match.group(2)
            try:
                # Convert the date string back to a datetime object for better formatting
                archived_date = datetime.strptime(date_str, "%Y-%m-%d_%H-%M-%S")
                archived_files.append({
                    "original_name": original_name,
                    "archived_name": filename,
                    "archived_date": archived_date.strftime("%Y-%m-%d %H:%M:%S")
                })
            except ValueError:
                # Handle cases where the file name doesn't match the expected date format
                archived_files.append({
                    "original_name": filename,
                    "archived_name": filename,
                    "archived_date": "Unknown"
                })

    return archived_files

# --- Example Usage ---
# You would call this function from a view in your application
print("List of Archived Files:")
for file_info in get_archived_files():
    print(f"Original Name: {file_info['original_name']}, Archived on: {file_info['archived_date']}")

