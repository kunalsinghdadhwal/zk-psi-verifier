#!/bin/bash

set -e

echo "Running comprehensive test suite..."
echo ""

echo "1. Unit tests"
cargo test --lib

echo ""
echo "2. Integration tests"
cargo test --test integration

echo ""
echo "3. Serialization tests"
cargo test --test serialization

echo ""
echo "4. Documentation tests"
cargo test --doc

echo ""
echo "5. Example compilation"
cargo build --examples

echo ""
echo "All tests passed!"
