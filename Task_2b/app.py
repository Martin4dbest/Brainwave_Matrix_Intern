from flask import Flask, jsonify, request, render_template
import re
import string
import math

app = Flask(__name__)

# Load common passwords from a file or define them in a constant
COMMON_PASSWORDS = {'password', '123456', '123456789', 'qwerty', 'abc123', 'password1', 'letmein'}

# Function to check common password patterns
def is_common_password(password):
    return password.lower() in COMMON_PASSWORDS

# Function to calculate entropy of the password (how unpredictable it is)
def calculate_entropy(password):
    pool_size = 0
    if any(char.islower() for char in password):
        pool_size += 26  # Lowercase letters
    if any(char.isupper() for char in password):
        pool_size += 26  # Uppercase letters
    if any(char.isdigit() for char in password):
        pool_size += 10  # Digits
    if any(char in string.punctuation for char in password):
        pool_size += len(string.punctuation)  # Special characters
    return len(password) * math.log2(pool_size) if pool_size > 0 else 0

# Password strength checker function
def password_strength_checker(password):
    score = 0
    feedback = []

    # Length requirement
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
    elif len(password) >= 12:
        score += 2
    else:
        score += 1

    # Check for complexity (uppercase, lowercase, digits, special chars)
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Add at least one digit.")
    
    if re.search(r'[\W_]', password):
        score += 1
    else:
        feedback.append("Add at least one special character (e.g., @, #, $, etc.).")
    
    # Check for consecutive characters (e.g., "aaa", "111")
    if re.search(r'(.)\1{2,}', password):
        feedback.append("Avoid consecutive repeating characters.")
        score -= 1
    
    # Check if password contains common patterns
    if is_common_password(password):
        feedback.append("Password is too common. Choose a more unique password.")
        score -= 1
    
    # Check if password contains dictionary words (simplified version)
    if re.search(r'password|qwerty|abc123|letmein', password, re.IGNORECASE):
        feedback.append("Avoid using common words or phrases.")
        score -= 1

    # Calculate entropy
    entropy = calculate_entropy(password)
    if entropy < 30:
        feedback.append("Password has low entropy, making it easy to guess.")
    elif entropy >= 50:
        score += 2

    # Provide feedback based on the score
    if score <= 2:
        strength = "Weak"
    elif 3 <= score <= 4:
        strength = "Moderate"
    elif 5 <= score <= 6:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return {
        "strength": strength,
        "score": score,
        "entropy": entropy,
        "feedback": feedback,
        "length": len(password),
        "common_patterns": is_common_password(password)
    }

@app.route('/')
def home():
    return render_template('index.html')  # Serve index.html

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({"error": "Password cannot be empty"}), 400
    
    result = password_strength_checker(password)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
