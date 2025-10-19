#!/bin/bash

set -e

echo "=== ZK-PSI Verifier Demo Script ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build the project
echo -e "${BLUE}Step 1: Building the project...${NC}"
cargo build --release
echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Generate keys
echo -e "${BLUE}Step 2: Generating cryptographic keys...${NC}"
cargo run --release --bin setup -- --k 12 --output-dir ./demo_keys
echo -e "${GREEN}✓ Keys generated${NC}"
echo ""

# Generate a proof
echo -e "${BLUE}Step 3: Generating a ZK proof...${NC}"
echo "  Set A: 1,2,3,4,5"
echo "  Set B: 3,4,5,6,7"
echo "  Expected intersection: {3,4,5} = 3 elements"
cargo run --release --bin cli -- prove \
    --set-a "1,2,3,4,5" \
    --set-b "3,4,5,6,7" \
    --output ./demo_proof.bin \
    --pk ./demo_keys/proving_key.bin \
    --params ./demo_keys/params.bin \
    --public-inputs-file ./demo_public_inputs.bin
echo -e "${GREEN}✓ Proof generated${NC}"
echo ""

# Verify the proof
echo -e "${BLUE}Step 4: Verifying the ZK proof...${NC}"
cargo run --release --bin cli -- verify \
    --proof ./demo_proof.bin \
    --public-inputs ./demo_public_inputs.bin \
    --vk ./demo_keys/verifying_key.bin \
    --params ./demo_keys/params.bin
echo -e "${GREEN}✓ Proof verified${NC}"
echo ""

# Cleanup
echo -e "${BLUE}Cleaning up demo files...${NC}"
rm -rf ./demo_keys ./demo_proof.bin ./demo_public_inputs.bin
echo -e "${GREEN}✓ Cleanup complete${NC}"
echo ""

echo "=== Demo Complete ==="
echo "The zero-knowledge proof successfully demonstrated that two sets"
echo "have an intersection of size 3 without revealing the sets themselves!"
