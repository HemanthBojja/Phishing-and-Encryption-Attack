#!/usr/bin/env python3
import os
import time
import sqlite3
import getpass
from collections import deque

# Set up the SQLite database
def setup_database():
    conn = sqlite3.connect("permission_changes.db")
    cursor = conn.cursor()
    # Table for permission changes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permission_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            old_permissions TEXT,
            new_permissions TEXT,
            timestamp TEXT NOT NULL,
            user TEXT NOT NULL
        )
    """)
    # Table for file modifications
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS modification_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            user TEXT NOT NULL
        )
    """)
    # Table for file deletions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS deletion_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            user TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn, cursor

# Convert permission mode (e.g., 0o644) to a readable string (e.g., "rw-r--r--")
def mode_to_string(mode):
    perms = ""
    for i in range(2, -1, -1):  # Owner, group, others
        value = (mode >> (i * 3)) & 0o7
        perms += "r" if value & 4 else "-"
        perms += "w" if value & 2 else "-"
        perms += "x" if value & 1 else "-"
    return perms

# Log to a text file
def log_to_file(log_entry, log_type="permission"):
    with open(f"{log_type}_changes.log", "a") as log_file:
        log_file.write(log_entry + "\n")

# Detect policy violations
def detect_violations(recent_changes, recent_modifications, recent_deletions, current_user):
    violations = []

    # Rule 1: Only root is allowed to change permissions
    authorized_user = "root"
    for change in recent_changes:
        user = change["user"]
        file_path = change["file_path"]
        old_perms = change["old_permissions"]
        new_perms = change["new_permissions"]
        timestamp = change["timestamp"]
        if user != authorized_user:
            violations.append(f"Non-root user {user} changed permissions of {file_path} from {old_perms} to {new_perms} at {timestamp}")

    # Rule 2: Rapid Permission Changes (retained from previous version)
    if len(recent_changes) > 5:
        timestamps = [time.mktime(time.strptime(change["timestamp"], "%Y-%m-%d %H:%M:%S")) for change in recent_changes]
        if timestamps[-1] - timestamps[0] <= 10:  # Within 10 seconds
            violations.append(f"Rapid permission changes detected: {len(recent_changes)} changes in {timestamps[-1] - timestamps[0]} seconds")

    # Rule 3: File Modifications by Unauthorized Users (retained, but using sec-lab as authorized)
    authorized_user_for_modifications = "sec-lab"
    for mod in recent_modifications:
        user = mod["user"]
        file_path = mod["file_path"]
        timestamp = mod["timestamp"]
        if user != authorized_user_for_modifications:
            violations.append(f"Unauthorized user {user} modified {file_path} at {timestamp}")

    # Rule 4: Deletion of Metadata Files by Unauthorized Users (retained)
    for deletion in recent_deletions:
        user = deletion["user"]
        file_path = deletion["file_path"]
        timestamp = deletion["timestamp"]
        if user != authorized_user_for_modifications and file_path.endswith("permissions.txt"):
            violations.append(f"Unauthorized user {user} deleted metadata file {file_path} at {timestamp}")

    return violations

# Scan the directory and check for permission changes, modifications, and deletions
def check_permissions(directory, permissions_cache, mtime_cache, file_list_cache, cursor, conn):
    current_permissions = {}
    current_mtimes = {}
    current_files = set()
    current_user = getpass.getuser()
    recent_changes = deque(maxlen=10)  # Store recent permission changes for analysis
    recent_modifications = deque(maxlen=10)  # Store recent modifications
    recent_deletions = deque(maxlen=10)  # Store recent deletions

    # Walk through the directory and collect current state
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            # Skip the database and log files
            if file_path.endswith("permission_changes.db") or file_path.endswith("changes.log"):
                continue
            current_files.add(file_path)
            try:
                stat_info = os.stat(file_path)
                mode = stat_info.st_mode & 0o777  # Get permission bits
                mtime = stat_info.st_mtime  # Get modification time
                current_permissions[file_path] = mode_to_string(mode)
                current_mtimes[file_path] = mtime
            except Exception as e:
                print(f"Error accessing {file_path}: {e}")

    # Check for permission changes
    for file_path, new_perms in current_permissions.items():
        old_perms = permissions_cache.get(file_path, "unknown")
        if old_perms != new_perms and old_perms != "unknown":  # Ignore initial scan
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO permission_logs (file_path, old_permissions, new_permissions, timestamp, user) VALUES (?, ?, ?, ?, ?)",
                (file_path, old_perms, new_perms, timestamp, current_user)
            )
            conn.commit()
            log_entry = f"{timestamp} | User: {current_user} | {file_path} | {old_perms} -> {new_perms}"
            print(f"Permission change detected: {log_entry}")
            log_to_file(log_entry, "permission")
            recent_changes.append({
                "file_path": file_path,
                "old_permissions": old_perms,
                "new_permissions": new_perms,
                "timestamp": timestamp,
                "user": current_user
            })

    # Check for file modifications
    for file_path, new_mtime in current_mtimes.items():
        old_mtime = mtime_cache.get(file_path, 0)
        if old_mtime != new_mtime and old_mtime != 0:  # Ignore initial scan
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO modification_logs (file_path, timestamp, user) VALUES (?, ?, ?)",
                (file_path, timestamp, current_user)
            )
            conn.commit()
            log_entry = f"{timestamp} | User: {current_user} | {file_path} | Modified"
            print(f"File modification detected: {log_entry}")
            log_to_file(log_entry, "modification")
            recent_modifications.append({
                "file_path": file_path,
                "timestamp": timestamp,
                "user": current_user
            })

    # Check for file deletions
    deleted_files = file_list_cache - current_files
    for file_path in deleted_files:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO deletion_logs (file_path, timestamp, user) VALUES (?, ?, ?)",
            (file_path, timestamp, current_user)
        )
        conn.commit()
        log_entry = f"{timestamp} | User: {current_user} | {file_path} | Deleted"
        print(f"File deletion detected: {log_entry}")
        log_to_file(log_entry, "deletion")
        recent_deletions.append({
            "file_path": file_path,
            "timestamp": timestamp,
            "user": current_user
        })

    # Detect violations
    violations = detect_violations(recent_changes, recent_modifications, recent_deletions, current_user)
    for violation in violations:
        print(f"ALERT: Policy violation detected - {violation}")
        # Mitigation measure (e.g., log to a separate file, alert admin, terminate process)
        log_to_file(f"ALERT: {violation}", "violation")

    # Update caches
    return current_permissions, current_mtimes, current_files

# Main function to monitor the directory using polling
def monitor_directory(directory, interval=5):
    conn, cursor = setup_database()
    permissions_cache = {}
    mtime_cache = {}
    file_list_cache = set()

    print(f"Monitoring directory: {directory} (polling every {interval} seconds)")
    try:
        while True:
            permissions_cache, mtime_cache, file_list_cache = check_permissions(
                directory, permissions_cache, mtime_cache, file_list_cache, cursor, conn
            )
            time.sleep(interval)  # Wait for the specified interval before the next scan
    except KeyboardInterrupt:
        print("Monitoring stopped.")
    finally:
        conn.close()

if __name__ == "__main__":
    directory_to_monitor = input("Enter the directory to monitor: ")
    if not os.path.isdir(directory_to_monitor):
        print("Invalid directory.")
    else:
        monitor_directory(directory_to_monitor)
