#!/usr/bin/env python3
"""
File deduplication tool for APFS filesystems.

This module provides functionality to find and deduplicate duplicate files
on APFS filesystems using copy-on-write (COW) capabilities. It identifies
duplicates through multi-stage hashing (file size, first 1KB hash, full file hash)
and uses the cp command to create hard links or clones.
"""

import hashlib
import os
import subprocess
import glob
from subprocess import CalledProcessError
from os.path import isfile, islink, splitext, basename
import argparse
import shutil
import filecmp
import tempfile
import getpass
import re


class RecursiveDepthAction(argparse.Action):
    """Custom action to handle -r flag with optional depth value.
    
    Allows -r testdir (defaults to depth 1) or -r 2 testdir (depth 2).
    """
    def __init__(self, option_strings, dest, nargs=None, const=None, default=None,
                 type=None, choices=None, required=False, help=None, metavar=None):
        if nargs == '?':
            super().__init__(option_strings, dest, nargs=nargs, const=const,
                           default=default, type=int, required=required, help=help)
        else:
            super().__init__(option_strings, dest, nargs=nargs, const=const,
                           default=default, type=type, required=required, help=help)
    
    def __call__(self, parser, namespace, values, option_string=None):
        # If values is None or can't be converted to int, use default depth of 1
        if values is None:
            setattr(namespace, self.dest, 1)
        else:
            try:
                depth = int(values)
                setattr(namespace, self.dest, depth)
            except (ValueError, TypeError):
                # If value can't be parsed as int, treat -r as having no value
                # This means we need to treat 'values' as a path, not a depth
                # We'll set depth to 1 (default) and put 'values' back in the paths
                setattr(namespace, self.dest, 1)
                # We can't easily add it back to paths here, so we'll need to handle this differently
                # Actually, argparse won't let us do this easily. Let's use a different approach.
                setattr(namespace, self.dest, 1)
                # Store the value that was mis-parsed so we can add it back later
                if not hasattr(namespace, '_misparsed_path'):
                    namespace._misparsed_path = values
                else:
                    # If there's already a misparsed path, add to paths
                    if not hasattr(namespace, 'paths'):
                        namespace.paths = []
                    namespace.paths.insert(0, namespace._misparsed_path)
                    namespace._misparsed_path = values


def chunk_reader(fobj, chunk_size=65536):
    """Generator that reads a file in chunks of bytes"""
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            return
        yield chunk


def get_hash(filename, first_chunk_only=False, hash_func=hashlib.sha1):
    hashobj = hash_func()
    try:
        file_object = open(filename, "rb")
    except PermissionError:
        return

    if first_chunk_only:
        hashobj.update(file_object.read(1024))
    else:
        for chunk in chunk_reader(file_object):
            hashobj.update(chunk)
    hashed = hashobj.hexdigest()

    file_object.close()
    return hashed


def collect_files_from_paths(paths, recursive=False, recursive_depth=None):
    """
    Collect files from paths based on recursion mode.

    Args:
        paths: List of input paths (can be glob patterns or directory paths)
        recursive: If True, unlimited recursion (like -R flag)
        recursive_depth: If set, limit recursion to this depth (like -r flag)
                         If recursive is False and recursive_depth is None, use glob behavior

    Yields:
        Absolute file paths matching the criteria
    """
    for input_path in paths:
        if recursive:
            # Unlimited recursion using os.walk()
            if os.path.isdir(input_path):
                root_dir = os.path.abspath(input_path)
                for dirpath, dirnames, filenames in os.walk(root_dir):
                    # Explicitly exclude '..' entries
                    dirnames[:] = [d for d in dirnames if d != ".."]
                    for filename in filenames:
                        file_path = os.path.join(dirpath, filename)
                        full_path = os.path.abspath(file_path)
                        if isfile(full_path) and not islink(full_path):
                            yield full_path
            else:
                # If not a directory, treat as glob pattern and recurse
                for file_path in glob.iglob(input_path, recursive=True):
                    full_path = os.path.abspath(file_path)
                    if isfile(full_path) and not islink(full_path):
                        yield full_path
        elif recursive_depth is not None:
            # Limited depth recursion
            if os.path.isdir(input_path):
                root_dir = os.path.abspath(input_path)
                # Depth 0 = root directory only
                # Depth 1 = root + immediate subdirs (not subdirs of subdirs)
                # Depth N = N levels deep
                current_depth = 0
                dirs_to_process = [(root_dir, current_depth)]

                while dirs_to_process:
                    current_dir, depth = dirs_to_process.pop(0)

                    if depth > recursive_depth:
                        continue

                    try:
                        entries = os.listdir(current_dir)
                    except (OSError, PermissionError):
                        continue

                    for entry in entries:
                        if entry == "..":
                            continue  # Explicitly exclude '..'

                        entry_path = os.path.join(current_dir, entry)
                        full_path = os.path.abspath(entry_path)

                        if isfile(full_path) and not islink(full_path):
                            yield full_path
                        elif os.path.isdir(full_path) and depth < recursive_depth:
                            # Add subdirectory for processing at next depth level
                            dirs_to_process.append((full_path, depth + 1))
            else:
                # If not a directory, treat as glob pattern
                for file_path in glob.iglob(input_path, recursive=True):
                    full_path = os.path.abspath(file_path)
                    if isfile(full_path) and not islink(full_path):
                        yield full_path
        else:
            # Default: use glob.iglob() behavior (backward compatible)
            for file_path in glob.iglob(input_path, recursive=True):
                full_path = os.path.abspath(file_path)
                if isfile(full_path) and not islink(full_path):
                    yield full_path


# ============================================================================
# WEE-33: DMG Detection and Metadata Extraction
# ============================================================================

def is_dmg_file(filepath):
    """Check if a file is a DMG image.
    
    Component: WEE-33 - DMG Detection and Metadata Extraction
    """
    return splitext(filepath)[1].lower() == '.dmg' and isfile(filepath)


def get_dmg_info(dmg_path, verbose=0):
    """Get DMG image information including compression format and encryption.
    
    Component: WEE-33 - DMG Detection and Metadata Extraction
    
    Returns:
        dict with keys: format, encryption, encryption_key_length, or None if error
    """
    try:
        result = subprocess.run(
            ['hdiutil', 'imageinfo', dmg_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        output = result.stdout
        
        info = {}
        
        # Parse format (compression type)
        format_match = re.search(r'Format:\s+(\S+)', output)
        if format_match:
            info['format'] = format_match.group(1)
        else:
            # Try alternative pattern
            format_match = re.search(r'image\s+format:\s+(\S+)', output, re.IGNORECASE)
            if format_match:
                info['format'] = format_match.group(1)
        
        # Parse encryption
        encryption_match = re.search(r'Encryption:\s+(\S+)', output)
        if encryption_match:
            info['encryption'] = encryption_match.group(1)
            
            # Check for AES-128 or AES-256
            aes_match = re.search(r'AES-(\d+)', output)
            if aes_match:
                info['encryption_key_length'] = int(aes_match.group(1))
        
        if verbose > 1:
            print("DMG info for %s: %s" % (dmg_path, info))
        
        return info
    except (CalledProcessError, FileNotFoundError) as e:
        if verbose > 0:
            print("Could not get DMG info for %s: %s" % (dmg_path, e))
        return None


# ============================================================================
# WEE-34: DMG Mounting and Unmounting Functionality
# ============================================================================

def mount_dmg(dmg_path, mount_point=None, password=None, readonly=False, verbose=0):
    """Mount a DMG image to a temporary or specified mount point.
    
    Component: WEE-34 - DMG Mounting and Unmounting Functionality
    
    Returns:
        dict with keys: mount_point, device, or None if failed
    """
    try:
        # Create temporary mount point if not specified
        if mount_point is None:
            mount_point = tempfile.mkdtemp(prefix='apfs-dedup-dmg-')
        
        attach_args = ['hdiutil', 'attach', dmg_path, '-mountpoint', mount_point]
        
        if readonly:
            attach_args.append('-readonly')
        else:
            attach_args.append('-readwrite')
        
        # For encrypted DMGs, pass password if provided
        env = os.environ.copy()
        if password:
            attach_args.append('-stdinpass')
            process = subprocess.Popen(
                attach_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            stdout, stderr = process.communicate(input=password + '\n')
            if process.returncode != 0:
                raise CalledProcessError(process.returncode, attach_args, stdout, stderr)
            output = stdout
        else:
            result = subprocess.run(
                attach_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            output = result.stdout
        
        # Parse device path from output
        # Format: /dev/diskXsY    /path/to/mountpoint
        device = None
        for line in output.split('\n'):
            if mount_point in line or '/dev/disk' in line:
                parts = line.split()
                for part in parts:
                    if part.startswith('/dev/disk'):
                        device = part
                        break
                if device:
                    break
        
        if verbose > 0:
            print("Mounted %s to %s (device: %s)" % (dmg_path, mount_point, device))
        
        return {
            'mount_point': mount_point,
            'device': device
        }
    except CalledProcessError as e:
        if verbose > 0:
            print("Failed to mount %s: %s" % (dmg_path, e.stderr if e.stderr else e))
        return None
    except Exception as e:
        if verbose > 0:
            print("Error mounting %s: %s" % (dmg_path, e))
        return None


def unmount_dmg(mount_point, force=False, verbose=0):
    """Unmount a DMG image.
    
    Component: WEE-34 - DMG Mounting and Unmounting Functionality
    """
    try:
        detach_args = ['hdiutil', 'detach', mount_point]
        if force:
            detach_args.append('-force')
        
        subprocess.run(
            detach_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        
        # Clean up temporary mount point directory if it exists
        if os.path.exists(mount_point) and mount_point.startswith(tempfile.gettempdir()):
            try:
                os.rmdir(mount_point)
            except OSError:
                pass  # Directory may not be empty or already removed
        
        if verbose > 0:
            print("Unmounted %s" % mount_point)
        return True
    except CalledProcessError as e:
        if verbose > 0:
            print("Failed to unmount %s: %s" % (mount_point, e.stderr if e.stderr else e))
        return False


# ============================================================================
# WEE-36: DMG Recreation with Compression and Encryption Preservation
# ============================================================================

def get_hdiutil_format_for_compression(compression_format):
    """Convert compression format string to hdiutil format code.
    
    Component: WEE-36 - DMG Recreation with Compression and Encryption Preservation
    
    Formats:
    - UDCO: LZMA compression (older)
    - ULMO: LZMA compression (newer, preferred)
    - UDZO: zlib compression
    - UDRW: uncompressed read-write
    - UDRO: uncompressed read-only
    """
    format_map = {
        'UDCO': 'UDCO',  # LZMA
        'ULMO': 'ULMO',  # LZMA (preferred)
        'UDZO': 'UDZO',  # zlib
        'UDRW': 'UDRW',  # uncompressed read-write
        'UDRO': 'UDRO',  # uncompressed read-only
        'UDIF': 'UDZO',  # Default to zlib for generic UDIF
    }
    
    # Check if format contains LZMA
    if 'LZMA' in compression_format.upper() or 'UDCO' in compression_format or 'ULMO' in compression_format:
        return 'ULMO'  # Use ULMO for LZMA
    
    return format_map.get(compression_format.upper(), 'UDZO')  # Default to zlib


def create_dmg_from_folder(source_folder, output_dmg, compression_format='ULMO', encryption=None, encryption_key_length=None, password=None, verbose=0):
    """Create a DMG from a folder, preserving compression and encryption settings.
    
    Component: WEE-36 - DMG Recreation with Compression and Encryption Preservation
    
    Args:
        source_folder: Path to folder containing files to image
        output_dmg: Path for output DMG file
        compression_format: hdiutil format code (ULMO for LZMA, UDZO for zlib, etc.)
        encryption: Encryption type (e.g., 'AES')
        encryption_key_length: Key length in bits (128 or 256)
        password: Password for encryption (if needed)
        verbose: Verbosity level
    """
    try:
        create_args = [
            'hdiutil', 'create',
            '-srcfolder', source_folder,
            '-format', compression_format,
            '-volname', basename(splitext(output_dmg)[0])
        ]
        
        # Add encryption if specified
        if encryption and encryption_key_length:
            encryption_type = 'AES-%d' % encryption_key_length
            create_args.extend(['-encryption', encryption_type])
            
            if password:
                create_args.append('-stdinpass')
                process = subprocess.Popen(
                    create_args + ['-o', output_dmg],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(input=password + '\n')
                if process.returncode != 0:
                    raise CalledProcessError(process.returncode, create_args, stdout, stderr)
            else:
                # Will prompt interactively for password
                create_args.extend(['-o', output_dmg])
                subprocess.run(create_args, check=True)
        else:
            create_args.extend(['-o', output_dmg])
            subprocess.run(create_args, check=True)
        
        if verbose > 0:
            print("Created DMG: %s (format: %s, encryption: %s)" % (
                output_dmg,
                compression_format,
                ('AES-%d' % encryption_key_length) if encryption and encryption_key_length else 'none'
            ))
        return True
    except CalledProcessError as e:
        if verbose > 0:
            print("Failed to create DMG %s: %s" % (output_dmg, e.stderr if e.stderr else e))
        return False
    except Exception as e:
        if verbose > 0:
            print("Error creating DMG %s: %s" % (output_dmg, e))
        return False


# ============================================================================
# WEE-38: DMG Feature Integration and Testing (Backup/Replacement logic)
# ============================================================================

def replace_dmg_with_deduplicated(original_dmg, new_dmg, force=False, verbose=0):
    """Replace original DMG with deduplicated version, creating backup.
    
    Component: WEE-38 - DMG Feature Integration and Testing
    
    Args:
        original_dmg: Path to original DMG file
        new_dmg: Path to new deduplicated DMG file
        force: If True, replace immediately; if False, keep both files
        verbose: Verbosity level
    
    Returns:
        dict with paths or None if failed
    """
    if not os.path.exists(new_dmg):
        if verbose > 0:
            print("New DMG does not exist: %s" % new_dmg)
        return None
    
    if force:
        # Backup original
        backup_path = original_dmg + '.backup'
        if os.path.exists(backup_path):
            os.remove(backup_path)
        shutil.move(original_dmg, backup_path)
        
        # Replace with new DMG
        shutil.move(new_dmg, original_dmg)
        
        if verbose > 0:
            print("Replaced original DMG with deduplicated version")
            print("Original backed up to: %s" % backup_path)
        
        return {
            'original_dmg': original_dmg,
            'new_dmg': original_dmg,
            'backup_dmg': backup_path
        }
    else:
        if verbose > 0:
            print("New DMG created at: %s" % new_dmg)
            print("Original DMG preserved at: %s" % original_dmg)
        
        return {
            'original_dmg': original_dmg,
            'new_dmg': new_dmg,
            'backup_dmg': None
        }


# ============================================================================
# WEE-35: Deduplication Workflow for Mounted DMG Volumes
# ============================================================================

def deduplicate_dmg_basic(
    dmg_path,
    dry_run=False,
    force=False,
    verbose=0,
    compare=False,
    password=None,
    password_prompt=True,
):
    """Deduplicate files inside a mounted DMG volume (basic workflow).
    
    Component: WEE-35 - Deduplication Workflow for Mounted DMG Volumes
    
    This function handles mounting, deduplication, and unmounting only.
    DMG recreation and replacement logic is handled separately (WEE-36, WEE-38).
    
    Workflow:
    1. Get DMG info (compression, encryption) - uses WEE-33
    2. Mount DMG to temp location - uses WEE-34
    3. Run deduplication on mounted volume
    4. Clean up and unmount - uses WEE-34
    
    Returns:
        dict with success status, mount_point, and stats, or None if failed
        If successful, mount_point remains mounted for caller to handle DMG recreation
    """
    dmg_path = os.path.abspath(dmg_path)
    
    if not is_dmg_file(dmg_path):
        if verbose > 0:
            print("%s is not a DMG file, skipping" % dmg_path)
        return None
    
    if verbose > 0:
        print("Processing DMG: %s" % dmg_path)
    
    # Step 1: Get DMG information
    dmg_info = get_dmg_info(dmg_path, verbose=verbose)
    
    if dmg_info is None:
        if verbose > 0:
            print("Could not read DMG info for %s, skipping" % dmg_path)
        return None
    
    # Step 2: Handle encryption - get password if needed
    encryption = dmg_info.get('encryption')
    encryption_key_length = dmg_info.get('encryption_key_length')
    needs_password = encryption and encryption_key_length and not password
    
    if needs_password and password_prompt and not dry_run:
        print("DMG %s is encrypted (AES-%d). Password required." % (dmg_path, encryption_key_length))
        password = getpass.getpass("Enter DMG password: ")
    
    # Step 3: Mount DMG
    mount_result = mount_dmg(
        dmg_path,
        password=password,
        readonly=dry_run,  # Read-only for dry-run, read-write otherwise
        verbose=verbose
    )
    
    if mount_result is None:
        if verbose > 0:
            print("Failed to mount DMG: %s" % dmg_path)
        return None
    
    mount_point = mount_result['mount_point']
    device = mount_result.get('device')
    
    try:
        # Step 4: Run deduplication on mounted volume
        if verbose > 0:
            print("Deduplicating files inside mounted DMG at %s..." % mount_point)
        
        # Collect statistics before deduplication
        pre_stat = shutil.disk_usage(mount_point)
        
        # Run deduplication recursively on the mounted volume
        # Don't scan DMG files inside the mounted DMG (avoid recursion)
        check_for_duplicates(
            paths=[mount_point],
            dry_run=dry_run,
            force=force,
            verbose=verbose,
            compare=compare,
            recursive=True,  # Always recurse for DMG contents
            recursive_depth=None,
            scan_dmg=False,  # Don't process DMGs inside DMGs
            dmg_password=password,  # Pass same password if needed
            dmg_password_prompt=False,  # Don't prompt again
        )
        
        # Collect statistics after deduplication
        post_stat = shutil.disk_usage(mount_point)
        
        result = {
            'success': True,
            'dry_run': dry_run,
            'dmg_path': dmg_path,
            'mount_point': mount_point,
            'dmg_info': dmg_info,
            'encryption': encryption,
            'encryption_key_length': encryption_key_length,
            'password': password,
            'space_freed': pre_stat.used - post_stat.used,
            'pre_stat': pre_stat,
            'post_stat': post_stat,
        }
        
        if dry_run:
            if verbose > 0:
                print("Dry run completed for DMG: %s" % dmg_path)
                print("Mount point remains mounted: %s" % mount_point)
            # For dry-run, return without unmounting so caller can inspect
            # Caller must call unmount_dmg() manually
            return result
        
        # For non-dry-run, mount point remains mounted for DMG recreation
        # Caller is responsible for unmounting after DMG recreation
        # This allows stepwise implementation: WEE-35 stops here, WEE-36/WEE-38 handle recreation
        return result
    
    except Exception as e:
        # On error, ensure cleanup
        if 'mount_point' in locals():
            unmount_dmg(mount_point, force=True, verbose=verbose)
        if verbose > 0:
            print("Error during DMG deduplication: %s" % e)
        return None


# ============================================================================
# WEE-38: DMG Feature Integration and Testing (Complete workflow)
# ============================================================================

def deduplicate_dmg(
    dmg_path,
    dry_run=False,
    force=False,
    verbose=0,
    compare=False,
    password=None,
    password_prompt=True,
):
    """Complete DMG deduplication workflow including recreation and replacement.
    
    Component: WEE-38 - DMG Feature Integration and Testing
    
    This is the full workflow that combines:
    - WEE-35: Basic deduplication workflow
    - WEE-36: DMG recreation
    - WEE-38: Backup/replacement logic
    
    Workflow:
    1. Run basic deduplication (WEE-35)
    2. Create new DMG with deduplicated contents (WEE-36)
    3. Replace original DMG with backup (WEE-38)
    4. Clean up
    
    Returns:
        dict with success status and stats, or None if failed
    """
    # Step 1: Run basic deduplication workflow (WEE-35)
    result = deduplicate_dmg_basic(
        dmg_path,
        dry_run=dry_run,
        force=force,
        verbose=verbose,
        compare=compare,
        password=password,
        password_prompt=password_prompt,
    )
    
    if not result or not result.get('success'):
        return None
    
    mount_point = result['mount_point']
    dmg_info = result['dmg_info']
    encryption = result['encryption']
    encryption_key_length = result['encryption_key_length']
    password = result['password']
    
    # For dry-run, unmount and return
    if dry_run:
        unmount_dmg(mount_point, force=True, verbose=verbose)
        return result
    
    try:
        # Step 2: Create new DMG with deduplicated contents (WEE-36)
        compression_format = get_hdiutil_format_for_compression(dmg_info.get('format', 'ULMO'))
        
        # Create temporary output DMG path
        dmg_dir = os.path.dirname(dmg_path)
        dmg_basename = os.path.basename(dmg_path)
        dmg_name, dmg_ext = splitext(dmg_basename)
        temp_dmg_path = os.path.join(dmg_dir, dmg_name + '.deduped' + dmg_ext)
        
        if verbose > 0:
            print("Creating new DMG with deduplicated contents...")
            print("  Format: %s" % compression_format)
            if encryption and encryption_key_length:
                print("  Encryption: AES-%d" % encryption_key_length)
        
        # Create new DMG (WEE-36)
        success = create_dmg_from_folder(
            source_folder=mount_point,
            output_dmg=temp_dmg_path,
            compression_format=compression_format,
            encryption=encryption,
            encryption_key_length=encryption_key_length,
            password=password,
            verbose=verbose
        )
        
        if not success:
            if verbose > 0:
                print("Failed to create new DMG for %s" % dmg_path)
            return None
        
        # Step 3: Replace original DMG with backup (WEE-38)
        replace_result = replace_dmg_with_deduplicated(
            dmg_path,
            temp_dmg_path,
            force=force,
            verbose=verbose
        )
        
        result.update(replace_result)
        return result
    
    finally:
        # Step 4: Always unmount and clean up
        unmount_dmg(mount_point, force=True, verbose=verbose)


def check_for_duplicates(
    paths,
    dry_run,
    force,
    verbose,
    compare,
    recursive=False,
    recursive_depth=None,
    hash_func=hashlib.sha1,
    scan_dmg=False,
    dmg_password=None,
    dmg_password_prompt=True,
):
    hashes_by_size = {}
    hashes_on_1k = {}
    hashes_full = {}
    pre_stat = shutil.disk_usage("/")

    if dry_run:
        print("Dry run! no change will be applied")

    print("Disk Used: %d bytes  Free: %d bytes" % (pre_stat.used, pre_stat.free))

    visited_dirs = set()

    # ============================================================================
    # WEE-37: Command-Line Flags and Password Handling (Basic Integration)
    # WEE-38: DMG Feature Integration and Testing (Full Integration)
    # ============================================================================
    
    # First, check for DMG files if scan_dmg is enabled (WEE-37/WEE-38)
    if scan_dmg:
        dmg_files = set()
        
        for input_path in paths:
            # Check if the input path itself is a DMG file
            abs_input = os.path.abspath(input_path)
            if is_dmg_file(abs_input):
                dmg_files.add(abs_input)
            elif os.path.isdir(input_path) or os.path.isfile(input_path):
                # Collect all files from the path to check for DMGs
                for file_path in collect_files_from_paths(
                    [input_path], recursive, recursive_depth
                ):
                    full_path = os.path.abspath(file_path)
                    if is_dmg_file(full_path):
                        dmg_files.add(full_path)
        
        # Process DMG files first
        if dmg_files:
            print("Found %d DMG file(s) to process..." % len(dmg_files))
            for dmg_file in sorted(dmg_files):
                try:
                    result = deduplicate_dmg(
                        dmg_file,
                        dry_run=dry_run,
                        force=force,
                        verbose=verbose,
                        compare=compare,
                        password=dmg_password,
                        password_prompt=dmg_password_prompt,
                    )
                    if result and verbose > 0:
                        if result.get('space_freed'):
                            print("Space freed in DMG: %d bytes" % result['space_freed'])
                except Exception as e:
                    if verbose > 0:
                        print("Error processing DMG %s: %s" % (dmg_file, e))
        
        # Skip regular file deduplication if all paths were DMG files
        # Otherwise continue to process non-DMG files
        dmg_paths_set = set(os.path.abspath(p) for p in paths if is_dmg_file(os.path.abspath(p)))
        if dmg_paths_set == set(os.path.abspath(p) for p in paths):
            return  # All paths were DMG files, we're done
    
    # Process regular files (non-DMG files)
    for input_path in paths:
        print("Scanning %s ..." % (input_path))
        for file_path in collect_files_from_paths(
            [input_path], recursive, recursive_depth
        ):
            full_path = os.path.abspath(file_path)
            
            # Skip DMG files if scan_dmg is enabled (already processed above)
            if scan_dmg and is_dmg_file(full_path):
                continue

            try:
                file_size = os.path.getsize(full_path)
            except (OSError,):
                # not accessible (permissions, etc)
                continue

            if file_size < 1024:
                continue

            dirname = os.path.dirname(full_path)
            if dirname not in visited_dirs:
                if verbose > 1:
                    print("Scanning %s/ ..." % (dirname))
                visited_dirs.add(dirname)

            duplicate = hashes_by_size.get(file_size)

            if duplicate:
                hashes_by_size[file_size].append(full_path)
            else:
                hashes_by_size[file_size] = []  # create the list for this file size
                hashes_by_size[file_size].append(full_path)

    # For all files with the same file size, get their hash on the 1st 1024 bytes
    print("Hashing headers...")
    visited_dirs = set()
    for __, files in hashes_by_size.items():
        if len(files) < 2:
            continue  # this file size is unique, no need to spend cpu cycles on it

        for filename in files:
            dirname = os.path.dirname(filename)
            if dirname not in visited_dirs:
                if verbose > 1:
                    print("Header hashing %s/ ..." % (dirname))
                visited_dirs.add(dirname)

            small_hash = get_hash(filename, first_chunk_only=True, hash_func=hash_func)

            duplicate = hashes_on_1k.get(small_hash)
            if duplicate:
                hashes_on_1k[small_hash].append(filename)
            else:
                hashes_on_1k[small_hash] = []  # create the list for this 1k hash
                hashes_on_1k[small_hash].append(filename)

    # For all files with the hash on the 1st 1024 bytes, get their hash on the full file - collisions will be duplicates
    print("Hashing...")
    visited_dirs = set()
    for __, files in hashes_on_1k.items():
        if len(files) < 2:
            continue  # this hash of fist 1k file bytes is unique, no need to spend cpu cycles on it

        for filename in files:
            dirname = os.path.dirname(filename)
            if dirname not in visited_dirs:
                if verbose > 1:
                    print("Hashing %s/ ..." % (dirname))
                visited_dirs.add(dirname)

            full_hash = get_hash(filename, first_chunk_only=False, hash_func=hash_func)

            duplicate = hashes_full.get(full_hash)
            if duplicate:
                duplicate = hashes_full[full_hash].append(filename)
            else:
                hashes_full[full_hash] = []  # create the list for this 1k hash
                hashes_full[full_hash].append(filename)

    total_bytes = 0
    unique_bytes = 0
    total_hashes = 0
    errors = 0

    # Issue dedupes
    print("Deduping...")

    for full_hash, files in hashes_full.items():
        if len(files) < 2:
            continue  # this hash of fist 1k file bytes is unique, no need to spend cpu cycles on it

        duplicate = files[0]
        file_size = os.path.getsize(duplicate)
        total_bytes += file_size * len(files)
        unique_bytes += file_size
        total_hashes += 1
        if verbose > 0:
            print("Hash:%s Size:%d" % (full_hash, file_size))
        for filename in files:
            if filename == duplicate:
                if verbose > 0:
                    print("\t> %s" % (filename))
                continue

            if verbose > 0:
                print("\t%s" % (filename))

            if not dry_run:
                if compare and not filecmp.cmp(duplicate, filename, shallow=False):
                    continue

                try:
                    cp_args = ["cp", "-cv"]
                    if force:
                        cp_args.append("-f")
                    cp_args.append(duplicate)
                    cp_args.append(filename)
                    copyCommand = subprocess.run(
                        cp_args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        check=True,
                    )
                    if verbose > 1:
                        print(copyCommand)
                except CalledProcessError:
                    errors += 1
                    if verbose > 0:
                        print("Could not dedupe file: %s. Skipping ..." % filename)

    print("Deduped %d clusters" % total_hashes)
    print("Skipped due to errors %d files" % errors)
    print("Total potential deduped: %d bytes" % (total_bytes - unique_bytes))
    post_stat = shutil.disk_usage("/")
    print("Disk Used: %d bytes  Free: %d bytes" % (post_stat.used, post_stat.free))
    print("Freed %d bytes" % (post_stat.free - pre_stat.free))


parser = argparse.ArgumentParser(
    description="Deduplicate files in apfs",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""Examples:
  # Default: glob pattern (backward compatible)
  %(prog)s "*.bin"
  %(prog)s 'Applications/Unity*/**'
  
  # Unlimited recursion (-R flag)
  %(prog)s -R /some/directory
  
  # Single-level recursion (-r flag, defaults to depth 1)
  %(prog)s -r /some/directory
  
  # Limited depth recursion (-r N flag)
  %(prog)s -r 2 /some/directory
  %(prog)s -r 3 /some/directory
  
  # With other flags
  %(prog)s --dry-run -R /some/directory
  %(prog)s -v -r 2 /some/directory""",
)

parser.add_argument(
    "paths", metavar="path", nargs="+", help="Paths to scan, glob accepted"
)

parser.add_argument(
    "--dry-run",
    dest="dry_run",
    action="store_const",
    const=True,
    default=False,
    help="Do not actually perform deduplication",
)

parser.add_argument(
    "--force",
    "-f",
    dest="force",
    action="store_const",
    const=True,
    default=False,
    help="Copy with -f",
)

parser.add_argument(
    "--verbose", "-v", dest="verbose", action="count", default=0, help="Verbosity level"
)

parser.add_argument(
    "--compare",
    "-c",
    dest="compare",
    action="store_const",
    const=True,
    default=False,
    help="Only copy if file contents perfectly matches",
)

parser.add_argument(
    "-R",
    "--recursive",
    dest="recursive",
    action="store_const",
    const=True,
    default=False,
    help="Recurse into all subdirectories (unlimited depth)",
)

parser.add_argument(
    "-r",
    "--recursive-depth",
    dest="recursive_depth",
    type=int,
    nargs="?",
    const=1,
    default=None,
    help=(
        "Recurse into subdirectories with limited depth. If no number specified, "
        "defaults to 1 level (rootdir + immediate subdirs only). If number "
        "specified, recurses that many levels deep."
    ),
)

# ============================================================================
# WEE-37: Command-Line Flags and Password Handling
# ============================================================================

parser.add_argument(
    "--scan-dmg",
    dest="scan_dmg",
    action="store_const",
    const=True,
    default=False,
    help="Scan and deduplicate files inside DMG disk images (.dmg files). "
         "DMG files will be mounted, deduplicated, and recreated with preserved "
         "compression (LZMA) and encryption (AES-128/256) settings.",
)

parser.add_argument(
    "--dmg-password",
    dest="dmg_password",
    type=str,
    default=None,
    help="Password for encrypted DMG files. If not provided and DMG is encrypted, "
         "will prompt interactively. For multiple DMGs, use the same password for all.",
)

parser.add_argument(
    "--dmg-password-prompt",
    dest="dmg_password_prompt",
    action="store_const",
    const=True,
    default=True,
    help="Prompt for DMG password interactively if encrypted (default: True). "
         "Set to False to skip encrypted DMGs silently.",
)

# Preprocess arguments to handle -r followed by a path (not a number)
# When -r testdir is used, argparse tries to parse 'testdir' as an int and fails.
# We preprocess to detect this case: if -r is followed by a non-numeric value,
# we don't pass that value as the depth argument.
import sys
original_argv = sys.argv[:]
argv_list = sys.argv[1:]
processed_argv = []

i = 0
insert_separator = False
while i < len(argv_list):
    arg = argv_list[i]
    if arg in ['-r', '--recursive-depth']:
        processed_argv.append(arg)
        # Check if next arg exists and if it's a number
        if i + 1 < len(argv_list):
            next_arg = argv_list[i + 1]
            try:
                # Try to parse as int - if it works, it's a depth value
                int(next_arg)
                processed_argv.append(next_arg)
                i += 1  # Skip the number
            except ValueError:
                # Not a number, so -r uses default depth (1) via const
                # Insert '--' before next arg to prevent argparse from consuming it as depth value
                insert_separator = True
        i += 1
        continue
    else:
        # If we need to insert a separator before this arg, do it now
        if insert_separator:
            processed_argv.append('--')
            insert_separator = False
        processed_argv.append(arg)
        i += 1

# Replace sys.argv temporarily for parsing
sys.argv = [sys.argv[0]] + processed_argv

try:
    args = parser.parse_args()
finally:
    # Restore original sys.argv
    sys.argv = original_argv

# If -r was used but no depth was provided, default to 1
# This handles the case where -r was followed by a path (not a number)
if '-r' in argv_list or '--recursive-depth' in argv_list:
    if args.recursive_depth is None:
        args.recursive_depth = 1

# Validate that -R and -r are not both specified
if args.recursive and args.recursive_depth is not None:
    parser.error("Cannot specify both -R and -r flags")

check_for_duplicates(
    args.paths,
    args.dry_run,
    args.force,
    args.verbose,
    args.compare,
    args.recursive,
    args.recursive_depth,
    scan_dmg=args.scan_dmg,
    dmg_password=args.dmg_password,
    dmg_password_prompt=args.dmg_password_prompt,
)
