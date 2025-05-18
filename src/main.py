import requests
import base64
import re
from datetime import datetime
import pytz
import pandas as pd
import plotly.express as px
import streamlit as st

# Configuration


BACKEND_URL = st.secrets["BACKEND_URL"]


# ---- Helper Functions ----
def b64e(x):
    return base64.b64encode(x).decode()


def b64d(x):
    return base64.b64decode(x)


def password_strength(password):
    """Evaluate password strength on a scale of 0-4"""
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


# ---- API Client Functions ----
class ApiClient:
    """Client for interacting with the backend API"""

    @staticmethod
    def login_user(email, password):
        """Log in user and retrieve authentication tokens"""


        url = f"{BACKEND_URL}/login/"
        payload = {"email": email, "password": password}
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as e:
            return None, str(e)

    @staticmethod
    def delete_user(email, password):
        """delete user using the password and login name s"""
        url = f"{BACKEND_URL}/users/"
        payload = {"email": email, "password": password}
        try:
            response = requests.delete(url, json=payload)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as e:
            return None, str(e)


    @staticmethod
    def get_records(access_token):
        """Retrieve all glucose records for the logged-in user"""
        url = f"{BACKEND_URL}/records/"
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as e:
            return None, str(e)

    @staticmethod
    def add_record(access_token, glucose, tags, notes, record_datetime_utc):
        """Add a new glucose record for the logged-in user"""
        url = f"{BACKEND_URL}/records/"
        headers = {"Authorization": f"Bearer {access_token}"}

        payload = {
            "glucose": glucose,
            "tags": tags,
            "notes": notes,
            "record_datetime_utc": record_datetime_utc,
        }

        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as e:
            return None, str(e)

    @staticmethod
    def delete_record(access_token, record_datetime_utc):
        """delete a glucose record for the logged-in user"""
        url = f"{BACKEND_URL}/records/{record_datetime_utc}"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as e:
            return None, str(e)

    @staticmethod
    def refresh_access_token(refresh_token):
        """Refresh the access token using the refresh token"""
        url = f"{BACKEND_URL}/refresh_token"
        payload = {"refresh_token": refresh_token}
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as e:
            return None, str(e)

    @staticmethod
    def signup_user(email, password, user_timezone, user_tags):
        """Register a new user"""
        url = f"{BACKEND_URL}/users/"
        payload = {
            "email": email,
            "password": password,
            "user_timezone": user_timezone,
            "user_tags": user_tags,
        }

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            # Extract error details from the response if available
            if e.response is not None:
                try:
                    error_detail = e.response.json().get("detail", "An error occurred.")
                    return None, error_detail
                except ValueError:
                    # If the response is not JSON, return the raw text
                    return None, e.response.text
            return None, str(e)
        except requests.exceptions.RequestException as e:
            return None, str(e)


# ---- UI Components ----
class DiabetesTrackerUI:
    """Main UI class for the Diabetes Tracker application"""

    def __init__(self):
        st.set_page_config(page_title="Diabetes Tracker", layout="wide")
        st.title("🩸 Diabetes Tracker")

        # Initialize session state variables if they don't exist
        if "logged_in" not in st.session_state:
            st.session_state.logged_in = False
        if "email" not in st.session_state:
            st.session_state.email = None
        if "user_timezone" not in st.session_state:
            st.session_state.user_timezone = "UTC"
        if "user_tags" not in st.session_state:
            st.session_state.user_tags = []
        if "access_token" not in st.session_state:
            st.session_state.access_token = None
        if "refresh_token" not in st.session_state:
            st.session_state.refresh_token = None

    def run(self):
        """Main entry point for the application"""


        if "page" not in st.session_state:
            st.session_state.page = "Login"

        nav = st.sidebar.container()

        def nav_button(label, page_name):
            cols = nav.columns(1)
            if cols[0].button(label, use_container_width=True):
                st.session_state.page = page_name

        if st.session_state.get("logged_in", False):
            nav_button("Show Records", "Show Records")
            nav_button("Add Record", "Add Record")
            nav_button("Delete User", "Delete User")
            cols = nav.columns(1)
            if cols[0].button("Logout", use_container_width=True):
                st.session_state.logged_in = False
                st.session_state.page = "Login"
        else:
            nav_button("Login", "Login")
            nav_button("Signup", "Signup")

        # Render selected page
        if st.session_state.page == "Login":
            self.render_login_page()
        elif st.session_state.page == "Signup":
            self.render_signup_page()
        elif st.session_state.page == "Add Record":
            self.render_add_record_page()
        elif st.session_state.page == "Show Records":
            st.header("Your Glucose Records")
            if not st.session_state.get("logged_in", False):
                st.warning("Please log in to view your records.")
            else:
                data = self.fetch_records()
                if data:
                    self.process_records(data)
        elif st.session_state.page == "Delete User":
            self.render_delete_user_page()
        # Token management
        if st.session_state.get("logged_in", False):
            self.manage_token_and_fetch_data()

    def render_login_page(self):
        """Render the login page"""
        if not st.session_state.logged_in:
            st.subheader("🔐 Login")
            email = st.text_input("Email", key="login_email")
            password = st.text_input(
                "Password", type="password", key="login_pwd"
            )

            # --- Backend health check ---
            
            docs_url = f"{BACKEND_URL}/docs"
            try:
                resp = requests.get(docs_url, timeout=2)
                if resp.status_code == 200 and "Swagger UI" in resp.text:
                    st.success(f"Backend is online", icon="🟢")
                else:
                    st.error(f"Backend  is NOT YET  online, this can take up to 60 seconds", icon="🔴")
            except Exception:
                st.error(f"Backend is NOT YET  online, this can take up to 60 seconds", icon="🔴")
                

            if st.button("Login", key="login"):
                response, error = ApiClient.login_user(email, password)

                if error:
                    # Use the error message directly if response is None
                    error_message = response.get("detail") if response else error
                    st.toast(f"Unable to login the user {email}", icon="❌")
                else:
                    # Store session details
                    st.session_state.logged_in = True
                    st.session_state.email = email
                    st.session_state.user_timezone = response.get(
                        "user_timezone", "UTC"
                    )
                    st.session_state.user_tags = response.get("user_tags", [])
                    st.session_state.access_token = response["access_token"]
                    st.session_state.refresh_token = response["refresh_token"]
                    st.toast(f"Logged in as: {email}", icon="✅")
                    st.rerun()
        else:
            # Already logged in, display user info
            st.subheader("Welcome back!")
            st.write(f"Logged in as: {st.session_state.email}")
            if st.button("Logout",key="logout"):
                self.logout_user()

    def render_delete_user_page(self):
        """Render the delete user page """
        if st.session_state.logged_in:
            st.subheader("🗑️ Delete user")
            email = st.text_input("Email", key="login_email")
            password = st.text_input("Password", type="password", key="login_pwd")
            confirm_delete = st.checkbox("I confirm that I want to delete my account, i understand that all my personal records and user information will be lost forever !")
            delete_button_disabled = not confirm_delete


            if st.button("delete user", key="delete_user",disabled=delete_button_disabled):
                if not email or not password:
                    st.error("Email and password are required.")
                else:
                    response, error = ApiClient.delete_user(email, password)
                    if error:
                        st.error(f"{error}", icon="❌")
                    else:
                        #clear session state 
                        st.session_state.logged_in = False
                        st.session_state.email = None
                        st.session_state.access_token = None
                        st.session_state.refresh_token = None
                        st.success(f"{response.get("message")}", icon="✅")

    def render_signup_page(self):
        """Render the signup page"""
        st.header("Create a New Account")
        st.subheader("this a Alpha POC , only selected emails can sign up !!!")

        if st.session_state.logged_in:
            self.logout_user()
        else:
            email = st.text_input("Email", key="signup_email")
            password = st.text_input("Password", type="password", key="signup_password")
            confirm_password = st.text_input(
                "Confirm Password", type="password", key="signup_confirm_password"
            )

            # Password strength indicator
            if password:
                score = password_strength(password)
                labels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
                emojis = ["🔴", "🟠", "🟡", "🔵", "🟢"]
                st.write(f"Password strength: {emojis[score]} {labels[score]}")

            # Password match validation
            if len(password) >= 1 and len(confirm_password) >= 1:
                if password != confirm_password:
                    st.warning("Passwords do not match!", icon="🚫")

            # Tag selection
            default_tags = ["sober", "after breakfast", "after lunch", "after dinner"]
            user_tags = st.multiselect(
                "Select tags", options=default_tags, default=default_tags
            )

            # Timezone selection
            user_timezone = st.selectbox(
                "Select your Timezone",
                pytz.all_timezones,
                index=pytz.all_timezones.index("UTC"),
            )

            if st.button("Signup", key="signup"):
                if not email or not password or not confirm_password:
                    st.error("All fields are required.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    response, error = ApiClient.signup_user(
                        email, password, user_timezone, user_tags
                    )
                    if error:
                        # Display the error message from the API
                        st.error(f"Signup failed: {error}")
                    else:
                        # Only navigate to the login page if signup is successful
                        st.success("Account created successfully! Redirecting to login...")
                        st.session_state.page = "Login"
                        st.rerun()

    def render_add_record_page(self):
        """Render the add record page"""
        st.header("Add a New Glucose Record")

        if not st.session_state.logged_in:
            st.warning("Please log in to add a record.")
            return

        # Get the user's timezone
        user_timezone = pytz.timezone(st.session_state.user_timezone)
        now_local = datetime.now(user_timezone)

        # Date and time inputs
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

        if st.button("Add Record", key="add_record"):
            if not glucose:
                st.error("Glucose level is required.")
            else:
                access_token = st.session_state.access_token
                response, error = ApiClient.add_record(
                    access_token, glucose, tags, notes, record_datetime_utc
                )
                if error:
                    st.error(f"Failed to add record: {error}")
                else:
                    st.success("Record added successfully!")
                    # Refresh the data display
                    st.rerun()

    def process_records(self, data):
        """Process and display glucose records"""
        records = data.get("records", [])
        total_records = data.get("totalrecords", len(records))
        failed_records = data.get("failed_records", 0)
        user_timezone = st.session_state.user_timezone

        if not records:
            st.info("No data found for this user, please add some records")
            return

        # Filter out decryption errors
        filtered = [r for r in records if "[ERROR:" not in str(r["glucose"])]

        if not filtered:
            st.info("No valid records to display.")
            return
        st.sidebar.subheader("Graphic settings")
        line_options = {
            "Straight": "linear", 
            "Smooth": "spline",
            "steo vertical": "hv",
            "step vertical-horizontal": "vh",
            "Rounded": "spline",  # Met later aangepaste smoothing
        }
        
        selected_line_type = st.selectbox(
            "Select the line type",
            options=list(line_options.keys()),
            index=0
        )
        
        # Haal de plotly line_shape op
        line_shape = line_options[selected_line_type]
        # Extra smoothing opties voor splines
        smoothing = 0.0
        if selected_line_type == "Smooth":
            smoothing = 0.8
            st.info("Vloeiende lijnen tonen de trend maar kunnen details afvlakken.")
        elif selected_line_type == "Rounded":
            smoothing = 0.3

        show_zones = st.checkbox("Show upper , best and lower limits", value=True)
    

        df = pd.DataFrame(filtered)

        # Convert datetime to timezone-aware timestamp
        df["timestamp"] = pd.to_datetime(df["datetime"]).dt.tz_convert(
            pytz.timezone(user_timezone)
        )

        # Ensure optional columns exist
        df["tags"] = df.get("tags", "")
        df["notes"] = df.get("notes", "")
        df["short_notes"] = df["notes"].apply(
            lambda x: x[:32] if isinstance(x, str) else ""
        )

        # Convert glucose to float
        df["glucose"] = df["glucose"].astype(float)

        # Plot glucose levels over time
        st.subheader("📈 Blood Sugar Over Time")
        fig = px.line(
            df,
            x="timestamp",
            y="glucose",
            markers=True,
            labels={"timestamp": "Time", "glucose": "Glucose (mmol/L)"},
            hover_data={"tags": True, "short_notes": True},
            line_shape=line_shape,
        )
        if selected_line_type in ["Smooth", "Rounded"]:
            fig.update_traces(line=dict(shape=line_shape, smoothing=smoothing))
    
        # fig.add_hline(y=5, line_dash="dash", line_color="orange", annotation_text="Low")
        # fig.add_hline(y=12, line_dash="dash", line_color="red", annotation_text="High")

        if show_zones:
            fig.add_hrect(y0=0, y1=2, fillcolor="orange", opacity=0.1, line_width=0)
            fig.add_hrect(y0=5, y1=7, fillcolor="green", opacity=0.1, line_width=0)
            fig.add_hrect(y0=12, y1=12, fillcolor="red", opacity=0.1, line_widht=0)

        st.plotly_chart(fig)

    # Display data with selection column
        st.subheader("Records")
        
        # Add selection column to dataframe for deletion
        if "selected_records" not in st.session_state:
            st.session_state.selected_records = []
        
        # Create a copy for display with a select column
        display_df = df.copy().sort_values(by="timestamp", ascending=False)
        
        # Create multiselect for choosing records to delete
        selected_indices = st.multiselect(
            "Select records to delete:",
            options=list(range(len(display_df))),
            format_func=lambda i: f"Record {i+1}: {display_df.iloc[i]['timestamp'].strftime('%Y-%m-%d %H:%M')} - {display_df.iloc[i]['glucose']} mmol/L"
        )

        # Display data
        st.subheader("Records2")
        st.dataframe(
            df.drop(columns=["datetime", "short_notes"]).sort_values(
                by="timestamp", ascending=False
            )
        )

        # Delete button
        if selected_indices and st.button(
            "Delete Selected Records", type="primary", key="delete_records"
        ):
            access_token = st.session_state.access_token
            success_count = 0
            error_messages = []

            with st.spinner("Deleting selected records..."):
                for idx in selected_indices:
                    # Get the UTC datetime string of the record to delete
                    record_datetime_utc = display_df.iloc[idx]["datetime"]

                    # Call the delete API
                    result, error = ApiClient.delete_record(
                        access_token, record_datetime_utc
                    )

                    if error:
                        error_messages.append(f"Failed to delete record {idx + 1}: {error}")
                    else:
                        success_count += 1

            if success_count > 0:
                st.success(f"Successfully deleted {success_count} record(s)")
                st.rerun()  # Refresh to show updated data

            if error_messages:
                for msg in error_messages:
                    st.error(msg)

        # Show record status
        if failed_records >= 1:
            if total_records == failed_records:
                st.error("All records failed to decode")
            else:
                st.warning(
                    f"Total records: {total_records}, Failed decryptions: {failed_records}"
                )
        else:
            st.success(f"Total records: {total_records}")

    def manage_token_and_fetch_data(self):
        """Manage authentication tokens without fetching data"""
        access_token = st.session_state.access_token
        refresh_token = st.session_state.refresh_token

        # Check if the access token is present
        if not access_token:
            st.toast("No access token found. Please log in again.", icon="❌")
            self.logout_user()
            return

        # Simple check if token is valid
        if not access_token:
            st.toast("Invalid access token. Please log in again.", icon="❌")
            self.logout_user()


    def fetch_records(self):
        """Fetch records from the API and handle token refresh if needed"""
        access_token = st.session_state.access_token
        refresh_token = st.session_state.refresh_token

        if not access_token:
            st.warning("No access token found. Please log in again.")
            return None

        # Attempt to fetch records with the current token
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(f"{BACKEND_URL}/records/", headers=headers)

        # Handle token expiration
        if response.status_code == 401:
            st.info("Access token expired, refreshing token...")
            new_tokens, error = ApiClient.refresh_access_token(refresh_token)

            if new_tokens:
                st.session_state.access_token = new_tokens["access_token"]
                st.success("Token refreshed successfully.")

                # Retry the request with the new token
                headers["Authorization"] = f"Bearer {new_tokens['access_token']}"
                response = requests.get(f"{BACKEND_URL}/records/", headers=headers)
            else:
                st.error(f"Failed to refresh token: {error}. Please log in again.")
                self.logout_user()
                return None

        # Process successful response
        if response.status_code == 200:
            return response.json()
        else:
            st.error("Failed to retrieve records.")
            return None

    def logout_user(self):
        """Log out the current user"""
        st.session_state.logged_in = False
        st.session_state.email = None
        st.session_state.access_token = None
        st.session_state.refresh_token = None
        st.toast("Logged out", icon="✅")
        st.rerun()


# ---- Main Application Entry Point ----
if __name__ == "__main__":
    app = DiabetesTrackerUI()
    app.run()
