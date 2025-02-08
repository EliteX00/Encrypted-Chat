import requests

BASE_URL = "http://127.0.0.1:5000"  # Change this if your API is running on a different port

# Test user details
test_user = {
    "email": "example@gmail.com", #put your email
    "password": "test123" #set your password
}

def register_user():
    url = f"{BASE_URL}/register"
    response = requests.post(url, json=test_user)
    print("Register Response:", response.json())

def verify_email():
    verification_code = input("Enter the email verification code: ")  # Get it from your email
    url = f"{BASE_URL}/verify-email"
    response = requests.post(url, json={"email": test_user["email"], "code": verification_code})
    print("Email Verification Response:", response.json())

def login_user():
    url = f"{BASE_URL}/login"
    response = requests.post(url, json=test_user)
    print("Login Response:", response.json())
    if response.status_code == 200:
        return response.json().get("token")
    return None

def access_protected_route(token):
    url = f"{BASE_URL}/protected"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    print("Protected Route Response:", response.json())

def logout_user(token):
    url = f"{BASE_URL}/logout"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(url, headers=headers)
    print("Logout Response:", response.json())

if __name__ == "__main__":
    register_user()
    verify_email()  # Manually enter the email verification code received in your email
    token = login_user()
    if token:
        access_protected_route(token)
        logout_user(token)
