from .cli import main

if __name__ == "__main__":
    import os
    import sys

    code = int(main() or 0)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
