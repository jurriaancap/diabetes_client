import requests
import base64
from datetime import datetime, timezone
import pytz
import pandas as pd
import plotly.express as px
from datetime import datetime
import pytz
import streamlit as st
import re

# Helper functions for base64 encoding/decoding
def b64e(x): return base64.b64encode(x).decode()
def b64d(x): return base64.b64decode(x)

# Backend API base URL
BASE_URL = "http://127.0.0.1:8000"  # Update this to the actual backend URL if deployed



## helper

def password_strength(password):
    score = 0
    if len(password) >= 12:
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[^\w\s]", password):
        score += 1
    return min(score, 4)


# --- API Client Functions ---

def login_user(email, password):
    """
    Logs in the user and retrieves the access token, refresh token, master key, SID, and timezone.
    """
    url = f"{BASE_URL}/login/"
    payload = {"email": email, "password": password}
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.RequestException as e:
        return None, str(e)


def get_records(access_token):
    """
    Retrieves all glucose records for the logged-in user.
    """
    url = f"{BASE_URL}/records/"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.RequestException as e:
        return None, str(e)


def add_record(access_token, glucose, tags, notes, record_datetime_utc):
    """
    Adds a new glucose record for the logged-in user.
    """
    url = f"{BASE_URL}/records/"
    headers = {"Authorization": f"Bearer {access_token}"}
    record_datetime_utc_str =  record_datetime_utc
    # Debugging: Log the payload
    print("Preparing payload for /records/:")

    payload = {
        "glucose": glucose,
        "tags": tags,
        "notes": notes,
        "record_datetime_utc": record_datetime_utc_str
    }
    print(payload)
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.RequestException as e:
        return None, str(e)

def refresh_access_token(refresh_token):
    """
    Refreshes the access token using the refresh token.
    """
    url = f"{BASE_URL}/refresh_token"
    payload = {"refresh_token": refresh_token}
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.RequestException as e:
        return None, str(e)


# --- UI Helper Functions ---

# --- Example Usage ---
# --- UI ---
st.set_page_config(page_title="Diabetes Tracker", layout="wide")
st.title("🩸 Diabetes Tracker")

# Sidebar for navigation
page = st.sidebar.radio("Navigation", ["Login", "Signup", "Add Record"])


# Helper function to fetch and display records
def process_records(data, user_timezone, title="Records"):
    records = data.get("records", [])
    total_records = data.get("totalrecords", len(records))
    failed_records = data.get("failed_records", 0)

    if records:
        # Filter out decryption errors
        filtered = [
            r for r in records 
            if "[ERROR:" not in str(r["glucose"])
        ]

        if not filtered:
            st.info("No valid records to display.")
            return

        df = pd.DataFrame(filtered)

        # Convert datetime to timezone-aware timestamp
        df['timestamp'] = pd.to_datetime(df['datetime']).dt.tz_convert(pytz.timezone(user_timezone))

        # Ensure optional columns exist
        df['tags'] = df.get('tags', "")
        df['notes'] = df.get('notes', "")
        df['short_notes'] = df['notes'].apply(lambda x: x[:32] if isinstance(x, str) else '')

        # Convert glucose to float
        df['glucose'] = df['glucose'].astype(float)

        # Plot glucose levels over time
        st.subheader("📈 Blood Sugar Over Time")
        fig = px.line(df, x="timestamp", y="glucose", markers=True,
                      labels={"timestamp": "Time", "glucose": "Glucose (mmol/L)"},
                      hover_data={"tags": True, "short_notes": True},
                      line_shape="linear")
        fig.add_hline(y=5, line_dash="dash", line_color="orange", annotation_text="Low")
        fig.add_hline(y=12, line_dash="dash", line_color="red", annotation_text="High")
        st.plotly_chart(fig)

        # Display data
        st.subheader(title)
        st.dataframe(df.drop(columns=["datetime", "short_notes"]).sort_values(by="timestamp", ascending=False))
        if failed_records >= 1:
            if total_records == failed_records:
                st.error(f"All records failed to decode")
            else:
                st.warning(f"Total records: {total_records}, Failed decryptions: {failed_records}")
        else:
            st.success(f"Total records: {total_records}")
    else:
        st.info("No data found for this user, please add some records  b")

def handle_signup_page():
    """Handle the Signup page logic."""
    st.header("Create a New Account")

    if st.session_state.get("logged_in"):
        st.session_state.logged_in = False  # Clear the login state
        st.session_state.email = None  # Clear the email
        st.toast("Logged out", icon="✅")
        st.rerun() # Rerun to reflect logout
    else:
        
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_password")

        confirm_password = st.text_input(
            "Confirm Password", type="password", key="signup_confirm_password"
        )

        if password:
            score = password_strength(password)
            labels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
            emojis = ["🔴", "🟠", "🟡", "🔵", "🟢"]
            st.write(f"Password strength: {emojis[score]} {labels[score]}")
            ##st.progress(score / 4)
        if len(password) >= 1 and len(confirm_password) >= 1:
            if password != confirm_password:
                st.warning(f"password should match !", icon="🚫")

        user_tags = st.multiselect(
            "Select  tags",  # Add a label for the multiselect
            options=[
                "sober",
                "after breakfast",
                "after lunch",
                "after dinner",
            ],  # The available options
            default=[
                "sober",
                "after breakfast",
                "after lunch",
                "after dinner",
            ],  # The pre-selected values
        )

        user_timezone = st.selectbox(
            "Select youre Timezone", pytz.all_timezones, index=pytz.all_timezones.index("UTC")
        )

        if st.button("Signup"):
            if not email or not password or not confirm_password:
                st.error("All fields are required.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            else:
                # Prepare the payload for the backend
                payload = {
                    "email": email,
                    "password": password,
                    "user_timezone": user_timezone,
                    "user_tags": user_tags
                }

                # Call the backend signup endpoint
                url = f"{BASE_URL}/users/"
                try:
                    response = requests.post(url, json=payload)
                    response.raise_for_status()
                    st.success("Account created successfully! Please log in.")
                    st.session_state.show_login = True  # Redirect to login page
                    st.rerun()
                except requests.exceptions.RequestException as e:
                    if response.status_code == 400:
                        st.error("This email is already in use.")
                    else:
                        st.error(f"Signup failed: {str(e)}")

def handle_add_record_page():
    """Handle the Add Record page logic."""
    st.header("Add a New Glucose Record")

    # Get the user's timezone
    user_timezone = pytz.timezone(st.session_state.user_timezone)
    now_local = datetime.now(user_timezone)
    if st.session_state.get("logged_in"):
        access_token = st.session_state.get("access_token")
        refresh_token = st.session_state.get("refresh_token")

        # Check if the access token is present
        if not access_token:
            st.toast("No access token found. Please log in again.", icon="❌")
            st.session_state.logged_in = False
            st.session_state.access_token = None
            st.session_state.refresh_token = None
            st.rerun()
        else:
            headers = {"Authorization": f"Bearer {access_token}"}
    # Use local timezone for both date and time inputs
    date = st.date_input("Date", value=now_local.date(), max_value=now_local)
    default_time = now_local.replace(
        minute=(now_local.minute // 15) * 15, second=0, microsecond=0
    ).time()
    time = st.time_input("Time", value=default_time, step=900)

    # Combine date and time in local timezone and convert to UTC
    local_dt = user_timezone.localize(datetime.combine(date, time))
    record_datetime_utc = local_dt.astimezone(pytz.utc).isoformat()

    # Input fields
    glucose = st.slider(
        "Glucose Level", min_value=0.0, max_value=25.0, value=7.0, step=0.1
    )
    tags = st.multiselect("Tags (select one or more)", st.session_state.user_tags)
    notes = st.text_area("Notes (optional)")

    if st.button("Add Record"):
        # Validate inputs
        if not glucose:
            st.error("Glucose level is required.")
        else:
            # Call the add_record function
            response, error = add_record(access_token, glucose, tags, notes, record_datetime_utc)
            if error:
                st.error(f"Failed to add record: {error}")
            else:
                st.success("Record added successfully!")

# Handle navigation

# --- LOGIN ---
if page == "Login":
    # Check if already logged in
    if not st.session_state.get("logged_in"):
        st.sidebar.subheader("🔐 Login")
        email = st.sidebar.text_input("Email", key="login_email")
        password = st.sidebar.text_input("Password", type="password", key="login_pwd")

        if st.sidebar.button("Login"):
            response, error = login_user(
                email, password
            )  # Ensure the function returns response, error
            if error:
                st.toast(f"{error}", icon="❌")
            else:
                # Store session details
                st.session_state.logged_in = True
                st.session_state.email = email
                st.session_state.user_timezone = response.get("user_timezone", "UTC")
                st.session_state.user_tags = response.get("user_tags", [])
                st.session_state.access_token = response[
                    "access_token"
                ]  # Store the access token
                st.session_state.refresh_token = response["refresh_token"]
                st.toast(f"Logged in as: {email}", icon="✅")
                st.rerun()
    else:
        # Already logged in, display the user's email
        st.sidebar.subheader("Welcome back!")
        st.sidebar.write(f"Logged in as: {st.session_state.email}")
        # Optionally add a logout button
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False  # Clear the login state
            st.session_state.email = None  # Clear the email
            st.toast("Logged out", icon="✅")
            st.rerun() # Rerun to reflect logout

elif page == "Signup":
    handle_signup_page()

elif page == "Add Record":
    if st.session_state.get("logged_in"):
        handle_add_record_page()
    else:
        st.warning("Please log in to add a record.")

# --- TOKEN MANAGEMENT ---
if st.session_state.get("logged_in"):
    access_token = st.session_state.get("access_token")
    refresh_token = st.session_state.get("refresh_token")

    # Check if the access token is present
    if not access_token:
        st.toast("No access token found. Please log in again.", icon="❌")
        st.session_state.logged_in = False
        st.session_state.access_token = None
        st.session_state.refresh_token = None
        st.rerun()
    else:
        headers = {"Authorization": f"Bearer {access_token}"}

        # Example API request using the stored token
        response = requests.get(f"{BASE_URL}/records/", headers=headers)

        if response.status_code == 401:  # Token has expired
            st.write("Access token expired, refreshing token...")
            new_access_token, error = refresh_access_token(refresh_token)

            if new_access_token:
                st.session_state.access_token = new_access_token[
                    "access_token"
                ]  # Update the session with new token
                st.write("Token refreshed successfully.")

                # Retry the request with the new token
                headers["Authorization"] = f"Bearer {new_access_token['access_token']}"
                response = requests.get(f"{BASE_URL}/records/", headers=headers)

            else:
                st.toast(
                    f"Failed to refresh token: {error}. Please log in again.", icon="❌"
                )
                st.session_state.logged_in = False  # Log out the user
                st.session_state.access_token = None
                st.session_state.refresh_token = None
                st.rerun()
                
        if response.status_code == 200:
            data = response.json()
            user_timezone = st.session_state.get("user_timezone", "UTC")
            process_records(data, user_timezone)
        else:
            st.toast("Failed to retrieve records", icon="❌")
