import itertools
import string
import time

from generatePassword import CHARACTER_SETS

ALL_CHARACTERS = (
    string.ascii_lowercase
    + string.ascii_uppercase
    + string.digits
    + string.punctuation
)
DEFAULT_ATTEMPTS_PER_SECOND = 250000
SIMULATION_LIMIT = 500000
ESTIMATE_LENGTH_LIMIT = 8


def infer_character_pool(password):
    pool = []

    if any(char.islower() for char in password):
        pool.append(CHARACTER_SETS["lowercase"])
    if any(char.isupper() for char in password):
        pool.append(CHARACTER_SETS["uppercase"])
    if any(char.isdigit() for char in password):
        pool.append(CHARACTER_SETS["digits"])
    if any(char in CHARACTER_SETS["symbols"] for char in password):
        pool.append(CHARACTER_SETS["symbols"])

    return "".join(pool) or ALL_CHARACTERS


def format_time(total_seconds):
    if total_seconds < 1:
        return "less than 1 second"

    total_seconds = int(total_seconds)
    units = [
        ("year", 31536000),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]

    parts = []
    for label, size in units:
        if total_seconds >= size:
            value, total_seconds = divmod(total_seconds, size)
            suffix = "" if value == 1 else "s"
            parts.append(f"{value} {label}{suffix}")
        if len(parts) == 2:
            break

    return ", ".join(parts) if parts else "less than 1 second"


def estimate_crack_time(password_length, charset_size, attempts_per_second=None):
    """Estimate brute-force crack time using O(n^k) search space growth."""
    attempts_per_second = attempts_per_second or DEFAULT_ATTEMPTS_PER_SECOND
    total_combinations = charset_size ** password_length
    total_seconds = total_combinations / attempts_per_second

    return {
        "total_combinations": total_combinations,
        "attempts_per_second": attempts_per_second,
        "estimated_seconds": total_seconds,
        "formatted_time": format_time(total_seconds),
        "complexity": f"O({charset_size}^{password_length})",
    }


def benchmark_attempt_rate(sample_charset=string.ascii_lowercase, sample_length=4):
    search_space = len(sample_charset) ** sample_length
    attempts = min(search_space, 50000)
    start = time.perf_counter()

    for attempt_number, _ in enumerate(
        itertools.islice(itertools.product(sample_charset, repeat=sample_length), attempts),
        start=1,
    ):
        if attempt_number == attempts:
            break

    elapsed = max(time.perf_counter() - start, 1e-9)
    return max(DEFAULT_ATTEMPTS_PER_SECOND, int(attempts / elapsed))


def simulate_bruteforce(password, max_combinations=SIMULATION_LIMIT):
    pool = infer_character_pool(password)
    estimate = estimate_crack_time(
        password_length=len(password),
        charset_size=len(pool),
        attempts_per_second=benchmark_attempt_rate(),
    )

    result = {
        "password_length": len(password),
        "charset_size": len(pool),
        "character_pool": pool,
        "attempts": 0,
        "elapsed_seconds": 0.0,
        "estimated": estimate,
        "mode": "estimate_only",
        "message": "",
        "found_password": "",
    }

    if not password:
        result["message"] = "Enter a password before running the brute-force simulation."
        return result

    if len(password) > ESTIMATE_LENGTH_LIMIT:
        result["message"] = (
            "Password is longer than the safe simulation limit, so only an estimate is shown."
        )
        return result

    if estimate["total_combinations"] > max_combinations:
        result["message"] = (
            "Search space is too large for an exact simulation in the UI, so only an estimate is shown."
        )
        return result

    start = time.perf_counter()
    for attempt_number, guess_tuple in enumerate(
        itertools.product(pool, repeat=len(password)),
        start=1,
    ):
        guess = "".join(guess_tuple)
        if guess == password:
            elapsed = time.perf_counter() - start
            result.update(
                {
                    "attempts": attempt_number,
                    "elapsed_seconds": elapsed,
                    "mode": "simulated",
                    "message": "Exact brute-force simulation completed.",
                    "found_password": guess,
                }
            )
            return result

    result["message"] = "Password was not found in the inferred search pool."
    return result


def crackPassword(target_password, password_length):
    if len(target_password) != password_length:
        raise ValueError("Password length does not match the supplied target password.")

    result = simulate_bruteforce(target_password)

    if result["mode"] == "simulated":
        print(f"Password Found: {result['found_password']}")
        print(f"Attempts Made: {result['attempts']}")
        print(f"Elapsed Time: {result['elapsed_seconds']:.4f} seconds")
    else:
        print(result["message"])
        print(f"Estimated Crack Time: {result['estimated']['formatted_time']}")

    return result


def timeEstimation(password_length):
    estimate = estimate_crack_time(password_length, len(ALL_CHARACTERS), benchmark_attempt_rate())
    print(f"Estimated Crack Time: {estimate['formatted_time']}")
    print(f"Complexity: {estimate['complexity']}")
    return estimate
