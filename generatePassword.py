import math
import secrets
import string


CHARACTER_SETS = {
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": string.punctuation,
}

def selected_character_sets(
    use_lowercase=True,
    use_uppercase=True,
    use_digits=True,
    use_symbols=True,
):
    sets = []

    if use_lowercase:
        sets.append(("lowercase", CHARACTER_SETS["lowercase"]))
    if use_uppercase:
        sets.append(("uppercase", CHARACTER_SETS["uppercase"]))
    if use_digits:
        sets.append(("digits", CHARACTER_SETS["digits"]))
    if use_symbols:
        sets.append(("symbols", CHARACTER_SETS["symbols"]))

    return sets

def build_character_pool(
    use_lowercase=True,
    use_uppercase=True,
    use_digits=True,
    use_symbols=True,
):
    sets = selected_character_sets(
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
    )
    return "".join(chars for _, chars in sets)


def generate_password(
    length=12,
    use_lowercase=True,
    use_uppercase=True,
    use_digits=True,
    use_symbols=True,
):
    active_sets = selected_character_sets(
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
    )

    if not active_sets:
        raise ValueError("Select at least one character set.")
    if length < len(active_sets):
        raise ValueError(
            "Password length must be at least the number of selected character sets."
        )

    password_chars = [secrets.choice(chars) for _, chars in active_sets]
    pool = "".join(chars for _, chars in active_sets)

    while len(password_chars) < length:
        password_chars.append(secrets.choice(pool))

    for index in range(len(password_chars) - 1, 0, -1):
        swap_index = secrets.randbelow(index + 1)
        password_chars[index], password_chars[swap_index] = (
            password_chars[swap_index],
            password_chars[index],
        )

    return "".join(password_chars)


def calculate_password_strength(password):
    """Calculate entropy-driven strength metrics and recommendations."""
    if not password:
        return {
            "entropy_bits": 0.0,
            "score": 0,
            "strength": "Weak",
            "pool_size": 0,
            "contains": [],
            "recommendations": [
                "Enter a password to analyze its strength.",
            ],
        }

    contains = []
    pool_size = 0

    if any(char.islower() for char in password):
        contains.append("lowercase")
        pool_size += len(CHARACTER_SETS["lowercase"])
    if any(char.isupper() for char in password):
        contains.append("uppercase")
        pool_size += len(CHARACTER_SETS["uppercase"])
    if any(char.isdigit() for char in password):
        contains.append("digits")
        pool_size += len(CHARACTER_SETS["digits"])
    if any(char in CHARACTER_SETS["symbols"] for char in password):
        contains.append("symbols")
        pool_size += len(CHARACTER_SETS["symbols"])

    entropy_bits = len(password) * math.log2(pool_size) if pool_size else 0.0
    score = min(100, round(entropy_bits * 1.4))

    if entropy_bits < 40:
        strength = "Weak"
    elif entropy_bits < 65:
        strength = "Medium"
    else:
        strength = "Strong"

    recommendations = []
    if len(password) < 12:
        recommendations.append("Use at least 12 characters for better resilience.")
    if "lowercase" not in contains or "uppercase" not in contains:
        recommendations.append("Mix lowercase and uppercase letters.")
    if "digits" not in contains:
        recommendations.append("Add digits to expand the search space.")
    if "symbols" not in contains:
        recommendations.append("Include symbols to increase entropy.")
    if not recommendations:
        recommendations.append("This password already uses strong length and variety.")

    return {
        "entropy_bits": round(entropy_bits, 2),
        "score": score,
        "strength": strength,
        "pool_size": pool_size,
        "contains": contains,
        "recommendations": recommendations,
    }

def main():
    password = generate_password(length=12)
    strength_info = calculate_password_strength(password)

    print(f"Generated Password: {password}")
    print(f"Strength: {strength_info['strength']}")
    print(f"Entropy: {strength_info['entropy_bits']} bits")
