import random
import string

def calculate_password_strength(password):
    """Calculate password strength based on character diversity and length."""
    score = 0
    feedback = []
    
    length = len(password)
    if length >= 8:
        score += 20
    elif length >= 6:
        score += 10

    if any(c.islower() for c in password):
        score += 20
        feedback.append("lowercase")
    
    if any(c.isupper() for c in password):
        score += 20
        feedback.append("uppercase")
    
    if any(c.isdigit() for c in password):
        score += 20
        feedback.append("digits")
    
    if any(c in string.punctuation for c in password):
        score += 20
        feedback.append("special characters")
    
    if score >= 80:
        strength = "Strong"
    elif score >= 60:
        strength = "Moderate"
    elif score >= 40:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    return {
        'score': score,
        'strength': strength,
        'contains': feedback,
        'length': length
    }

def main():
    lowercase = string.ascii_lowercase  
    uppercase = string.ascii_uppercase 
    digits = string.digits             
    special = string.punctuation        
    
    all_characters = lowercase + uppercase + digits + special
    
    password = ''.join(random.choice(all_characters) for _ in range(8))
    
    print(f"Generated Password: {password}")
    
    strength_info = calculate_password_strength(password)
    print(f"  Strength: {strength_info['strength']}")

if __name__ == "__main__":
    main()
