import os
import time
import smtplib
import logging
import pyautogui
import cv2
import pytesseract
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Set Tesseract OCR Path (modify if needed)
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Configuration
CONFIG = {
    "monitored_folder": r"C:\Users\kavya\OneDrive\Pictures\Screenshots",
    "authorized_users": {"Arumugam": "appa@1980"},
    "email_notifications": {
        "enabled": True,
        "smtp_server": "smtp.gmail.com",
        "port": 587,
        "email": "kavyaarupre807@gmail.com",
        "password": "waxw repo xrmq lxxc",
        "recipient": "kavyaarupre807@gmail.com",
    },
    "log_file": "access_logs.txt",
    "screenshot_folder": "./screenshots",
    "notification_interval": 30,
}

# Create necessary folders if not exist
os.makedirs(CONFIG["monitored_folder"], exist_ok=True)
os.makedirs(CONFIG["screenshot_folder"], exist_ok=True)

# Set up logging
logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)
# User Authentication System
def authenticate_user():
    """Authenticate the user once before starting monitoring."""
    print("User Authentication")
    username = input("Enter username: ").strip()

    if username not in CONFIG["authorized_users"]:
        print("Authentication failed! Username not recognized.")
        return False

    try:
        password = input("Enter password: ")  # Not secure, but works in PyCharm

    except Exception:
        print("Warning: Secure password entry not supported. Using visible input.")
        password = input("Enter password: ")  # Visible input (not secure)

    if CONFIG["authorized_users"].get(username) == password:
        print("Authentication successful. Monitoring will start now.")
        return True

    print("Authentication failed! Incorrect password.")
    return False

last_notification_time = 0

def extract_text_from_screenshot(image_path):
    """Extract visible text from a screenshot using OCR."""
    try:
        img = cv2.imread(image_path)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        text = pytesseract.image_to_string(gray)
        return text.strip()
    except Exception as e:
        print(f"Failed to process screenshot: {e}")
        return "[Error extracting text]"

def send_email_notification(event, screenshot_path):
    """Send an email with extracted AI-based analysis."""
    global last_notification_time
    current_time = time.time()

    if current_time - last_notification_time < CONFIG["notification_interval"]:
        return

    if CONFIG["email_notifications"]["enabled"]:
        try:
            extracted_text = extract_text_from_screenshot(screenshot_path)
            msg = MIMEMultipart()
            msg["From"] = CONFIG["email_notifications"]["email"]
            msg["To"] = CONFIG["email_notifications"]["recipient"]
            msg["Subject"] = "Intrusion Detected"

            body = f"""
            Unauthorized access detected!
            Event Type: {event.event_type}
            File/Folder: {event.src_path}
            Timestamp: {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}

            Extracted Screenshot Text:
            {extracted_text}
            """
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(CONFIG["email_notifications"]["smtp_server"],
                              CONFIG["email_notifications"]["port"]) as server:
                server.starttls()
                server.login(CONFIG["email_notifications"]["email"], CONFIG["email_notifications"]["password"])
                server.sendmail(CONFIG["email_notifications"]["email"], CONFIG["email_notifications"]["recipient"], msg.as_string())
            print("Email notification sent.")
        except Exception as e:
            print(f"Failed to send email notification: {e}")

    last_notification_time = current_time

def capture_screenshot():
    """Take a screenshot, save it, and return the file path."""
    try:
        screenshot_path = os.path.join(CONFIG["screenshot_folder"], f"screenshot_{int(time.time())}.png")
        pyautogui.screenshot(screenshot_path)
        print(f"Screenshot saved to {screenshot_path}")
        return screenshot_path
    except Exception as e:
        print(f"Failed to take screenshot: {e}")
        return None

class FolderMonitor(FileSystemEventHandler):
    """Monitor the folder for changes."""

    def on_modified(self, event):
        self.log_and_alert(event)

    def on_created(self, event):
        self.log_and_alert(event)

    def on_deleted(self, event):
        self.log_and_alert(event)

    def log_and_alert(self, event):
        """Log and alert if unauthorized access is detected."""
        logging.info(f"{event.event_type} - {event.src_path}")
        print(f"{event.event_type} - {event.src_path}")

        print("Unauthorized access detected!")
        screenshot_path = capture_screenshot()
        if screenshot_path:
            send_email_notification(event, screenshot_path)

def start_monitoring():
    """Start monitoring the folder."""
    folder_to_monitor = CONFIG["monitored_folder"]
    event_handler = FolderMonitor()
    observer = Observer()
    observer.schedule(event_handler, folder_to_monitor, recursive=True)
    observer.start()
    print(f"Monitoring folder: {folder_to_monitor}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped.")
    observer.join()

if __name__ == "__main__":
    print("Starting Intrusion Detection System...")

    # Authenticate user ONCE before starting monitoring
    if authenticate_user():
        start_monitoring()
    else:
        print("Exiting due to failed authentication.")



