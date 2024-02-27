# UBA-UseCase
Scenario: You're a security analyst at a company concerned about potential unauthorized access to user accounts. You want to develop a Python script to analyze user login data and flag anomalies that might indicate compromised accounts.

Data:

user_data: A list of dictionaries, where each dictionary represents a user login attempt and includes the following keys:
username: The username of the user who attempted to log in.
login_time: The timestamp of the login attempt.
ip_address: The IP address from which the login attempt originated.
location: (Optional) The geographic location associated with the IP address (if available).
Example Data:

Python
user_data = [
    {"username": "user1", "login_time": "2023-11-19 10:00:00", "ip_address": "192.168.1.1", "location": "New York"},
    {"username": "user2", "login_time": "2023-11-19 12:00:00", "ip_address": "10.0.0.1", "location": "California"},
    {"username": "user1", "login_time": "2023-11-19 13:00:00", "ip_address": "172.16.0.1", "location": "London"},  # Potential anomaly
    {"username": "user3", "login_time": "2023-11-19 15:00:00", "ip_address": "10.0.0.1", "location": "California"},
]

Anomaly Detection Logic:

This use case refines the anomaly detection logic based on expert suggestions and incorporates additional considerations:

Python
import datetime
import pytz  # For handling time zones (optional)

def is_anomalous_login(login, user_data):
    """
    Identifies potential anomalies based on login data.

    Args:
        login (dict): A dictionary representing a user login attempt.
        user_data (list): A list of dictionaries representing all user login attempts.

    Returns:
        bool: True if the login is considered anomalous, False otherwise.
    """

    # Check for unusual login location compared to previous logins for the same user:
    previous_logins = [l for l in user_data if l["username"] == login["username"] and l != login]
    if previous_logins and login["location"] not in [l["location"] for l in previous_logins]:
        return True

    # Check for login from a blacklisted IP address (replace with actual mechanism):
    if login["ip_address"] in ["1.2.3.4"]:  # Replace with actual blacklist
        return True

    # Check for unusually frequent login attempts within a short time window:
    time_threshold = datetime.timedelta(minutes=10)  # Customize time threshold
    recent_logins = [l for l in user_data if l["username"] == login["username"] and
                      (login["login_time"] - l["login_time"]) < time_threshold]
    if len(recent_logins) > 3:  # Customize threshold for frequent attempts
        return True

    # Consider time zone differences (optional):
    if "location" in login:
        try:
            user_timezone = pytz.timezone(login["location"])  # Assuming location maps to a time zone
            login_time_local = user_timezone.localize(datetime.datetime.fromisoformat(login["login_time"]))

            # Check for logins outside usual hours based on historical data and/or user preferences
            # (replace with more sophisticated logic based on available information)
            if login_time_local.hour not in [9, 10, 11, 12, 13, 14, 15, 16, 17]:
                return True
        except pytz.exceptions.UnknownTimeZoneError:
            pass  # Handle potential errors gracefully

    return False

Analysis and Reporting:

Python
potential_compromises = [login for login in user_data if is_anomalous_login(login, user_data)]

if potential
Use code with caution.


