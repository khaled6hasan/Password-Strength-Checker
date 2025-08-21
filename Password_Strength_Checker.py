import re
import math
import secrets
import string


class PasswordChecker:
    def __init__(self, min_length=8, min_upper=1, min_lower=1, min_digits=1, min_special=1):
        self.min_length = min_length
        self.min_upper = min_upper
        self.min_lower = min_lower
        self.min_digits = min_digits
        self.min_special = min_special

    def calculate_entropy(self, password):
        """Calculates the entropy of the password (in bits)"""
        if not password:
            return 0

        char_set = 0
        if any(c in string.ascii_lowercase for c in password):
            char_set += 26
        if any(c in string.ascii_uppercase for c in password):
            char_set += 26
        if any(c in string.digits for c in password):
            char_set += 10
        if any(c in string.punctuation for c in password):
            char_set += 32

        if char_set == 0:
            return 0

        entropy = len(password) * math.log2(char_set)
        return entropy

    def estimate_crack_time(self, entropy):
        """Entropy-based crack time estimation"""
        if entropy <= 0:
            return "Instant"

        # Estimate: 10,000,000,000 hashes/second
        hashes_per_second = 10e9
        possible_combinations = 2 ** entropy
        seconds = possible_combinations / hashes_per_second

        # Conversion to time units
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.2f} Seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.2f} Minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.2f} Hours"
        elif seconds < 31536000:
            return f"{seconds / 86400:.2f} Days"
        else:
            years = seconds / 31536000
            if years > 1e9:
                return f"{years / 1e9:.2f} Billion Years"
            elif years > 1e6:
                return f"{years / 1e6:.2f} Million Years"
            else:
                return f"{years:.2f} Years"

    def generate_strong_password(self, length=12):
        """Create strong passwords"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def check_password_strength(self, password):
        """Password strength test"""
        if not password:
            return 0, "Invalid", ["Password empty"], 0, "Instant"

        score = 0
        feedback = []

        # Length test
        length = len(password)
        if length >= self.min_length:
            length_score = min(30, (length / self.min_length) * 20)
            score += length_score
        else:
            feedback.append(f"The password is too short (at least {self.min_length} Characters required)")

        # Capitalization test
        upper_count = len(re.findall(r'[A-Z]', password))
        if upper_count >= self.min_upper:
            score += 15
        else:
            feedback.append(f"At least {self.min_upper}uppercase letters")

        # Lowercase test
        lower_count = len(re.findall(r'[a-z]', password))
        if lower_count >= self.min_lower:
            score += 15
        else:
            feedback.append(f"Add at least {self.min_lower}lowercase letters")

        # Number test
        digit_count = len(re.findall(r'\d', password))
        if digit_count >= self.min_digits:
            score += 15
        else:
            feedback.append(f"Add at least {self.min_digits}digits")

        # Special character test
        special_count = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', password))
        if special_count >= self.min_special:
            score += 15
        else:
            feedback.append(f"Add at least {self.min_special}special characters")

        # Diversity Bonus
        unique_chars = len(set(password))
        if length > 0:
            diversity_bonus = min(10, (unique_chars / length) * 10)
            score += diversity_bonus

        # General pattern test
        common_patterns = [
            '123456', 'password', 'qwerty', 'admin', 'welcome',
            'asdfgh', 'zxcvbn', '987654', 'abcdef'
        ]

        for pattern in common_patterns:
            if pattern in password.lower():
                score = max(0, score - 10)
                feedback.append("Avoid common patterns")
                break

        # Entropy calculation
        entropy = self.calculate_entropy(password)
        crack_time = self.estimate_crack_time(entropy)

        # Rating
        if score >= 80:
            rating = "Very strong"
        elif score >= 60:
            rating = "Strong"
        elif score >= 40:
            rating = "Medium"
        elif score >= 20:
            rating = "Weak"
        else:
            rating = "Very weak"

        return min(100, max(0, round(score))), rating, feedback, entropy, crack_time


def main():
    print("🔐 Password strength checker 🔐")
    print("=" * 40)

    checker = PasswordChecker()

    password = input("👉 Enter your password: ")

    score, rating, feedback, entropy, crack_time = checker.check_password_strength(password)

    print(f"\nPassword strength: {score}%")
    print(f"Rating: {rating}")
    print(f"Entropy: {entropy:.2f} Bit")
    print(f"Estimated crack time: {crack_time}")

    if feedback:
        print("\nRecommendations:")
        for item in feedback:
            print(f"- {item}")

        print("\nStrong password recommendations:")
        for i in range(3):
            strong_pass = checker.generate_strong_password(12)
            print(f"{i + 1}. {strong_pass}")
    else:
        print("\nYour password is great!")


if __name__ == "__main__":
    main()