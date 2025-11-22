#!/bin/bash
function finish {
    rm -rf *.bin testdir
}

trap finish EXIT

echo ""
echo "================================================================================"
echo "Test 1: Default glob behavior (backward compatibility)"
echo "================================================================================"
echo "Command: ./deduplicate.py --dry-run \"*.bin\""
echo ""
mkfile -nv 1g file0.bin
cp -v file0.bin file1.bin
cp -v file0.bin file2.bin
cp -v file0.bin file3.bin
cp -v file0.bin file4.bin
cp -v file0.bin file5.bin
rm -f file0.bin
echo "Files created:"
du -shc *.bin
echo ""
echo "Running deduplicate..."
./deduplicate.py --dry-run "*.bin"
echo ""

# Clean up for next test
rm -f *.bin

echo ""
echo "================================================================================"
echo "Test 2: Unlimited recursion (-R flag)"
echo "================================================================================"
echo "Command: ./deduplicate.py --dry-run -R testdir"
echo ""
mkdir -p testdir/level1/level2/level3
mkfile -nv 1g testdir/file0.bin
cp -v testdir/file0.bin testdir/file1.bin
cp -v testdir/file0.bin testdir/level1/file2.bin
cp -v testdir/file0.bin testdir/level1/level2/file3.bin
cp -v testdir/file0.bin testdir/level1/level2/level3/file4.bin
rm -f testdir/file0.bin
echo "Directory structure created:"
du -shc testdir
echo ""
echo "Running deduplicate..."
./deduplicate.py --dry-run -R testdir
echo ""

# Clean up for next test
rm -rf testdir

echo ""
echo "================================================================================"
echo "Test 3: Single-level recursion (-r flag, default depth 1)"
echo "================================================================================"
echo "Command: ./deduplicate.py --dry-run -r testdir"
echo "Expected: Should process testdir/ and testdir/level1/ but NOT testdir/level1/level2/"
echo ""
mkdir -p testdir/level1/level2
mkfile -nv 1g testdir/file0.bin
cp -v testdir/file0.bin testdir/file1.bin
cp -v testdir/file0.bin testdir/level1/file2.bin
cp -v testdir/file0.bin testdir/level1/level2/file3.bin
rm -f testdir/file0.bin
echo "Directory structure created:"
du -shc testdir
echo ""
echo "Running deduplicate..."
./deduplicate.py --dry-run -r testdir
echo ""

# Clean up for next test
rm -rf testdir

echo ""
echo "================================================================================"
echo "Test 4: Limited depth recursion (-r 2 flag)"
echo "================================================================================"
echo "Command: ./deduplicate.py --dry-run -r 2 testdir"
echo "Expected: Should process testdir/, testdir/level1/, and testdir/level1/level2/ but NOT testdir/level1/level2/level3/"
echo ""
mkdir -p testdir/level1/level2/level3
mkfile -nv 1g testdir/file0.bin
cp -v testdir/file0.bin testdir/file1.bin
cp -v testdir/file0.bin testdir/level1/file2.bin
cp -v testdir/file0.bin testdir/level1/level2/file3.bin
cp -v testdir/file0.bin testdir/level1/level2/level3/file4.bin
rm -f testdir/file0.bin
echo "Directory structure created:"
du -shc testdir
echo ""
echo "Running deduplicate..."
./deduplicate.py --dry-run -r 2 testdir
echo ""

# Clean up
rm -rf testdir

echo ""
echo "================================================================================"
echo "All tests completed!"
echo "================================================================================"

