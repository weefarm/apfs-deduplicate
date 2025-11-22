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
from os.path import isfile, islink
import argparse
import shutil
import filecmp


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


def check_for_duplicates(
    paths,
    dry_run,
    force,
    verbose,
    compare,
    recursive=False,
    recursive_depth=None,
    hash_func=hashlib.sha1,
):
    hashes_by_size = {}
    hashes_on_1k = {}
    hashes_full = {}
    pre_stat = shutil.disk_usage("/")

    if dry_run:
        print("Dry run! no change will be applied")

    print("Disk Used: %d bytes  Free: %d bytes" % (pre_stat.used, pre_stat.free))

    visited_dirs = set()

    for input_path in paths:
        print("Scanning %s ..." % (input_path))
        for file_path in collect_files_from_paths(
            [input_path], recursive, recursive_depth
        ):
            full_path = os.path.abspath(file_path)

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
)
