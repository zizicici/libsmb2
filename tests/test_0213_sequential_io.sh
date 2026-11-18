#!/bin/sh
. ./functions.sh

echo -n "Testing failed seeks preserve the file position ... "
./prog_sequential_io "${TESTURL}/sequential-io-$$" || failure
success
