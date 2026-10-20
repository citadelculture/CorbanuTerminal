"""Fixed child-only core-dump limit; exec exact argv without a shell."""
import os
from pathlib import Path
import resource
import sys


def main():
    argv = sys.argv[1:]
    if not argv or not Path(argv[0]).is_absolute() or any(not value for value in argv):
        raise SystemExit("Expected explicit absolute executable argv")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # All other resource limits and the complete caller-supplied environment survive.
    os.execve(argv[0], argv, os.environ)


if __name__ == "__main__":
    main()
