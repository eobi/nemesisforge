"""python -m forge_mcp [--target-root DIR] [--ring2]"""
from __future__ import annotations

import argparse
import sys

from .server import Server


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="forge_mcp", description=__doc__)
    p.add_argument("--target-root", default=None,
                   help="the only directory tools may read or write")
    p.add_argument("--ring2", action="store_true",
                   help="allow nf_lab, which COMPILES AND EXECUTES the harness it is given")
    p.add_argument("--max-ring", type=int, default=1)
    a = p.parse_args(argv)
    try:
        return Server(target_root=a.target_root, ring2=a.ring2, max_ring=a.max_ring).serve()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
