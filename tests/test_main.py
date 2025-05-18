import pytest
from src.main import b64e, b64d, password_strength



def test_b64e_and_b64d():
    original = b"hello world"
    encoded = b64e(original)
    assert isinstance(encoded, str)
    decoded = b64d(encoded)
    assert decoded == original

@pytest.mark.parametrize("password,expected", [
    ("short", 1),
    ("longerpassword", 2),
    ("LongerPassword1!", 4),
    ("Password123!", 4),
    ("password", 1),
    ("PASSWORD123!", 4),
    ("", 0),
])
def test_password_strength(password, expected):
    assert password_strength(password) == expected

# def test_login_user_success(requests_mock, monkeypatch):
#     url = "http://testserver/login/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.post(url, json={"access_token": "abc", "refresh_token": "def"}, status_code=200)
#     response, error = ApiClient.login_user("user@example.com", "password")
#     assert error is None
#     assert response["access_token"] == "abc"

# def test_login_user_failure(requests_mock, monkeypatch):
#     url = "http://testserver/login/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.post(url, json={"detail": "Invalid credentials"}, status_code=401)
#     response, error = ApiClient.login_user("user@example.com", "wrongpassword")
#     assert response is None
#     assert "401" in error or "Invalid credentials" in error

# def test_signup_user_success(requests_mock, monkeypatch):
#     url = "http://testserver/users/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.post(url, json={"message": "User created"}, status_code=201)
#     response, error = ApiClient.signup_user("user@example.com", "Password123!", "UTC", ["tag"])
#     assert error is None
#     assert response["message"] == "User created"

# def test_signup_user_failure(requests_mock, monkeypatch):
#     url = "http://testserver/users/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.post(url, json={"detail": [{"msg": "Email already exists"}]}, status_code=422)
#     response, error = ApiClient.signup_user("user@example.com", "Password123!", "UTC", ["tag"])
#     assert response is None
#     assert "Email already exists" in str(error) or "422" in str(error)

# def test_delete_user_success(requests_mock, monkeypatch):
#     url = "http://testserver/users/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.delete(url, json={"message": "User deleted"}, status_code=200)
#     response, error = ApiClient.delete_user("user@example.com", "Password123!")
#     assert error is None
#     assert response["message"] == "User deleted"

# def test_delete_user_failure(requests_mock, monkeypatch):
#     url = "http://testserver/users/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.delete(url, json={"detail": "User not found"}, status_code=404)
#     response, error = ApiClient.delete_user("user@example.com", "Password123!")
#     assert response is None
#     assert "User not found" in str(error) or "404" in str(error)

# def test_add_record_success(requests_mock, monkeypatch):
#     url = "http://testserver/records/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.post(url, json={"message": "Record added"}, status_code=201)
#     response, error = ApiClient.add_record("token", 7.0, ["tag"], "note", "2024-01-01T00:00:00Z")
#     assert error is None
#     assert response["message"] == "Record added"

# def test_add_record_failure(requests_mock, monkeypatch):
#     url = "http://testserver/records/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.post(url, json={"detail": "Unauthorized"}, status_code=401)
#     response, error = ApiClient.add_record("token", 7.0, ["tag"], "note", "2024-01-01T00:00:00Z")
#     assert response is None
#     assert "Unauthorized" in str(error) or "401" in str(error)

# def test_get_records_success(requests_mock, monkeypatch):
#     url = "http://testserver/records/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.get(url, json={"records": []}, status_code=200)
#     response, error = ApiClient.get_records("token")
#     assert error is None
#     assert "records" in response

# def test_get_records_failure(requests_mock, monkeypatch):
#     url = "http://testserver/records/"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.get(url, json={"detail": "Unauthorized"}, status_code=401)
#     response, error = ApiClient.get_records("token")
#     assert response is None
#     assert "Unauthorized" in str(error) or "401" in str(error)

# def test_refresh_access_token_success(requests_mock, monkeypatch):
#     url = "http://testserver/refresh_token"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.post(url, json={"access_token": "newtoken"}, status_code=200)
#     response, error = ApiClient.refresh_access_token("refresh")
#     assert error is None
#     assert response["access_token"] == "newtoken"

# def test_refresh_access_token_failure(requests_mock, monkeypatch):
#     url = "http://testserver/refresh_token"
#     monkeypatch.setattr("src.main.BACKEND_URL", "http://testserver")
#     requests_mock.post(url, json={"detail": "Invalid token"}, status_code=401)
#     response, error = ApiClient.refresh_access_token("refresh")
#     assert response is None
#     assert "Invalid token" in str(error) or "401" in str(error)