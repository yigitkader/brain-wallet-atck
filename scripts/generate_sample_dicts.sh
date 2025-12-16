#!/bin/bash

echo "Generating sample dictionaries..."

# Common phrases
cat > dictionaries/common-phrases.txt << 'EOF'
hello world
to be or not to be
the quick brown fox
all your base are belong to us
may the force be with you
winter is coming
i'll be back
EOF

# Crypto terms
cat > dictionaries/crypto-terms.txt << 'EOF'
bitcoin
satoshi
ethereum
blockchain
crypto
wallet
hodl
moon
lambo
diamond hands
to the moon
EOF

# Known weak seeds (examples - DO NOT USE THESE)
cat > dictionaries/known-weak-seeds.txt << 'EOF'
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
EOF

# Top names
cat > dictionaries/top-names.txt << 'EOF'
john
jane
alice
bob
charlie
david
emma
satoshi
nakamoto
vitalik
buterin
bitcoin
crypto
EOF

echo "✅ Sample dictionaries generated!"