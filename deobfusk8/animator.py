import sys
import time
import random

SCRAMBLE_CHARS = "!@#$%^&*()_+~{}[]|:;/?,.<>1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def print_scrambled(
    prefix: str, secret: str, steps: int = 15, delay: float = 0.01
) -> None:
    if not sys.stdout.isatty():
        print(f"{prefix}{secret}")
        return

    length = len(secret)
    sys.stdout.write(prefix)
    sys.stdout.flush()

    for _ in range(steps):
        scrambled = "".join(random.choice(SCRAMBLE_CHARS) for _ in range(length))
        sys.stdout.write(scrambled)
        sys.stdout.flush()
        time.sleep(delay)
        sys.stdout.write("\b" * length)

    sys.stdout.write(secret + "\n")
    sys.stdout.flush()
