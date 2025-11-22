# APFS Deduplicate

Deduplicate files on your APFS file system using copy-on-write (COW) capabilities.

## What is this repository for?

* APFS allows cloning files instead of copying them
* This script detects duplicates and replaces them with clones
* More information (clones): https://developer.apple.com/documentation/foundation/file_system/about_apple_file_system

## Features

* **Multi-stage hashing**: Fast duplicate detection using file size, first 1KB hash, then full file hash
* **Recursive search**: Support for unlimited recursion (`-R`) or limited depth recursion (`-r [depth]`)
* **DMG support**: Deduplicate files inside DMG disk images with preserved compression and encryption
* **Backward compatible**: Default glob pattern behavior maintained

## How do I use it?

### Requirements

* Python 3
* macOS with APFS filesystem
* `hdiutil` command (for DMG support)

### Installation

Clone this repository:
```bash
git clone ssh://git@codefloe.com/weefarm/apfs-deduplicate.git
cd apfs-deduplicate
chmod +x deduplicate.py
```

Or from GitHub (mirror):
```bash
git clone git@github.com:weefarm/apfs-deduplicate.git
cd apfs-deduplicate
chmod +x deduplicate.py
```

### Basic Usage

```bash
# Show help
./deduplicate.py -h

# Default: glob pattern (backward compatible)
./deduplicate.py "*.bin"

# Unlimited recursion
./deduplicate.py -R /some/directory

# Single-level recursion (defaults to depth 1)
./deduplicate.py -r /some/directory

# Limited depth recursion
./deduplicate.py -r 2 /some/directory

# Dry run (no changes)
./deduplicate.py --dry-run -R /some/directory

# Verbose output
./deduplicate.py -v -r 2 /some/directory
```

### DMG Image Support

Deduplicate files inside DMG disk images:

```bash
# Scan and deduplicate files inside DMG images
./deduplicate.py --scan-dmg /path/to/dmgs/*.dmg

# With password for encrypted DMGs
./deduplicate.py --scan-dmg --dmg-password "mypassword" /path/to/dmgs/*.dmg

# Dry run for DMG processing
./deduplicate.py --dry-run --scan-dmg /path/to/dmgs/*.dmg
```

The DMG feature:
* Preserves original compression format (LZMA/ULMO, UDZO, etc.)
* Preserves encryption settings (AES-128, AES-256)
* Creates backup files before replacing originals
* Supports both encrypted and unencrypted DMGs

### How It Works

To save time, this script uses a multi-stage approach:
1. First, it compiles a list of probable duplicates by computing a hash of the first 1024 bytes
2. Of the probable matches, a hash of the full file contents is computed
3. Duplicates are replaced with clones via `cp -c` (APFS copy-on-write)

### Important Notes

* This script is considered experimental
* Although it has been tested on various data sets (git repositories, RDBMS storage, DMG images, etc.), it should not be run on sensitive data without backups
* Always test with `--dry-run` first
* DMG processing requires sufficient disk space for temporary mount points

## License

This fork is licensed under the MIT License. See LICENSE file for details.

## Credits

This tool was originally created by dchevell and later forked by capyvara. This repository is a hard fork (no longer tracking upstream) with significant enhancements.

* Original repository: https://bitbucket.org/dchevell/apfs-deduplicate/
* Previously forked from: https://github.com/capyvara/apfs-deduplicate
* Primary repository: ssh://git@codefloe.com/weefarm/apfs-deduplicate.git
* GitHub mirror: https://github.com/weefarm/apfs-deduplicate

Note: The original work was distributed without an explicit license. This fork includes modifications and enhancements including recursive search flags and DMG image support. This repository is maintained independently and no longer tracks the upstream capyvara repository.
