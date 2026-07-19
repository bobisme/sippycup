#!/usr/bin/env python3
"""Return a deterministic fixture secret for a named reference."""

import sys

print(f"provider-value-for-{sys.argv[1]}")
