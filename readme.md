# Diabetes Tracker Frontend

This is a POC front end gui to my backend. i am not a proffessional programmer and this is my first python project. please be gentle ;)

The **Diabetes Tracker Frontend** is a Streamlit-based application that provides an intuitive user interface for managing user accounts, tracking glucose records, and visualizing data. It interacts with the backend API to perform operations such as user authentication, adding records, and retrieving glucose data.

---

## Features

### User Management
- **Login**: Authenticate users and retrieve access and refresh tokens.
- **Signup**: Create new user accounts with timezone and tag preferences.
- **Logout**: Securely log out users and clear session data.

### Glucose Record Management
- **Add Records**: Add new glucose records with tags, notes, and timestamps.
- **View Records**: Retrieve and display glucose records in a tabular format.
- **Visualize Data**: Plot glucose levels over time using interactive charts.

### Token Management
- Automatically refresh expired access tokens using refresh tokens.
- Handle token expiration gracefully with user notifications.

### Data Visualization
- Interactive line charts for glucose levels over time.
- Highlight glucose levels that are too high or too low.

---

## Requirements

### Environment Variables
The following environment variables must be set for the application to function correctly:

| **Variable**   | **Description**                                      |
|----------------|------------------------------------------------------|
| `BASE_URL`     | The backend API's base URL (e.g., `http://127.0.0.1:8000`). |

### Python Dependencies
The frontend requires the following Python packages, which are listed in the `requirements.txt` file:

```plaintext
streamlit==1.25.0
requests==2.31.0
pytz==2025.2
pandas==2.1.0
plotly==5.17.0