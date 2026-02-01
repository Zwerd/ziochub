#!/usr/bin/env python3
"""
TTL Cleaner Script for ThreatGate IOC Submission Portal
Removes expired IOCs from text files based on EXP: date tags.
Run this script via cron to clean expired entries nightly.
"""

import os
import re
from datetime import datetime
import portalocker

# Directory path
DATA_MAIN = os.path.join(os.path.dirname(__file__), 'data', 'Main')

# Pattern to extract expiration date from line
EXP_PATTERN = re.compile(r'EXP:(\d{4}-\d{2}-\d{2}|NEVER)')


def parse_expiration_date(exp_str):
    """Parse expiration date string to datetime object or None for NEVER."""
    if exp_str == 'NEVER':
        return None
    try:
        return datetime.strptime(exp_str, '%Y-%m-%d')
    except ValueError:
        return None


def clean_file(filepath):
    """Remove expired lines from a single file."""
    if not os.path.exists(filepath):
        return 0
    
    deleted_count = 0
    today = datetime.now()
    valid_lines = []
    
    try:
        # Read all lines
        with open(filepath, 'r', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            lines = f.readlines()
            portalocker.unlock(f)
        
        # Process each line
        for line in lines:
            line = line.rstrip('\n\r')
            if not line.strip():
                valid_lines.append(line + '\n')
                continue
            
            # Extract expiration date
            match = EXP_PATTERN.search(line)
            if match:
                exp_str = match.group(1)
                exp_date = parse_expiration_date(exp_str)
                
                # Keep if NEVER or expiration date is in the future
                if exp_date is None:  # NEVER
                    valid_lines.append(line + '\n')
                elif exp_date >= today:
                    valid_lines.append(line + '\n')
                else:
                    # Expired - skip this line
                    deleted_count += 1
            else:
                # No EXP tag found - keep the line (might be legacy format)
                valid_lines.append(line + '\n')
        
        # Write back only valid lines
        if deleted_count > 0:
            with open(filepath, 'w', encoding='utf-8') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                f.writelines(valid_lines)
                portalocker.unlock(f)
        
        return deleted_count
        
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return 0


def main():
    """Main cleaning function."""
    if not os.path.exists(DATA_MAIN):
        print(f"Error: Data directory not found: {DATA_MAIN}")
        return
    
    # List of IOC files to clean
    ioc_files = ['ip.txt', 'domain.txt', 'hash.txt', 'email.txt', 'url.txt']
    
    total_deleted = 0
    file_stats = {}
    
    print(f"Starting TTL cleanup at {datetime.now().isoformat()}")
    print(f"Processing files in: {DATA_MAIN}")
    print("-" * 60)
    
    for filename in ioc_files:
        filepath = os.path.join(DATA_MAIN, filename)
        deleted = clean_file(filepath)
        file_stats[filename] = deleted
        total_deleted += deleted
        
        if deleted > 0:
            print(f"{filename}: Removed {deleted} expired entry/entries")
        else:
            print(f"{filename}: No expired entries found")
    
    print("-" * 60)
    print(f"Cleanup complete. Total entries removed: {total_deleted}")
    print(f"Finished at {datetime.now().isoformat()}")


if __name__ == '__main__':
    main()
