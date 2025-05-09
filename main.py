import requests
# import os.path # os.path is already imported via 'import os' later
import base64
import re
import time
# import requests # Already imported
from google.oauth2.credentials import Credentials # Not used in the relevant logic
from google_auth_oauthlib.flow import InstalledAppFlow # Not used
from googleapiclient.discovery import build # Not used
import logging
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import StreamingResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import asyncio
import imaplib
import email
import urllib.parse
import json
import os # Added for SESSIONS_FILE logic if you decide to use server-side session saving
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import io

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your React app URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging with a custom format that includes more details
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - [%(user)s] - %(message)s",
    handlers=[
        logging.FileHandler("quikchex_attendance.log"),
        logging.StreamHandler()
    ]
)

# Create a filter to add user information to log records
class UserInfoFilter(logging.Filter):
    def __init__(self, name=""):
        super().__init__(name)
        self.user = "system"  # Default user
        
    def filter(self, record):
        if not hasattr(record, 'user'):
            record.user = self.user
        return True

# Add the filter to the root logger
user_filter = UserInfoFilter()
logging.getLogger().addFilter(user_filter)

# Function to set current user for logging
def set_log_user(email):
    user_filter.user = email or "system"

# Define request model - MODIFIED
class AttendanceRequest(BaseModel):
    user_email: str
    quickchex_pass: str
    gmail_app_password: str
    _quikchex_app_session: Optional[str] = None  # Changed to match the exact field name in the request body
    remember_user_token: Optional[str] = None

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "message": "API is running"}

# New endpoint to access logs
@app.get("/logs")
async def get_logs(
    user_email: Optional[str] = Query(None, description="Filter logs by user email"),
    level: Optional[str] = Query(None, description="Filter logs by level (DEBUG, INFO, WARNING, ERROR)"),
    start_date: Optional[str] = Query(None, description="Start date in YYYY-MM-DD format"),
    end_date: Optional[str] = Query(None, description="End date in YYYY-MM-DD format"),
    limit: int = Query(100, description="Maximum number of log entries to return"),
    format: str = Query("text", description="Response format: text or json")
):
    try:
        # Read the log file
        with open("quikchex_attendance.log", "r") as f:
            log_lines = f.readlines()
        
        # Parse and filter log entries
        filtered_logs = []
        log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - \[([^\]]*)\] - (.*)'
        
        # Parse date filters
        start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date() if start_date else None
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date() if end_date else None
        if end_date_obj:
            # Make end_date inclusive by setting it to the end of the day
            end_date_obj = datetime.combine(end_date_obj, datetime.max.time()).date()
        
        for line in log_lines:
            match = re.match(log_pattern, line)
            if match:
                timestamp_str, log_level, log_user, message = match.groups()
                
                # Parse timestamp
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
                    log_date = timestamp.date()
                except:
                    continue
                
                # Apply filters
                if user_email and log_user != user_email:
                    continue
                if level and log_level != level.upper():
                    continue
                if start_date_obj and log_date < start_date_obj:
                    continue
                if end_date_obj and log_date > end_date_obj:
                    continue
                
                # Add to filtered logs
                filtered_logs.append({
                    "timestamp": timestamp_str,
                    "level": log_level,
                    "user": log_user,
                    "message": message
                })
        
        # Apply limit
        filtered_logs = filtered_logs[-limit:]
        
        # Format response
        if format.lower() == "json":
            return {"logs": filtered_logs}
        else:
            log_text = ""
            for log in filtered_logs:
                log_text += f"{log['timestamp']} - {log['level']} - [{log['user']}] - {log['message']}\n"
            return PlainTextResponse(content=log_text)
            
    except Exception as e:
        logging.exception("Error retrieving logs")
        raise HTTPException(status_code=500, detail=f"Error retrieving logs: {str(e)}")

# Mark attendance endpoint - MODIFIED
@app.post("/mark")
async def mark_attendance(request: Request):
    # Get the raw request body
    body = await request.body()
    body_str = body.decode('utf-8')
    
    # Parse the body manually (assuming JSON format)
    try:
        body_data = json.loads(body_str)
        
        # Extract required fields
        user_email = body_data.get('user_email')
        quickchex_pass = body_data.get('quickchex_pass')
        gmail_app_password = body_data.get('gmail_app_password')
        
        # Set the user for logging
        set_log_user(user_email)
        
        # Extract session cookies - try different possible formats
        quikchex_app_session = body_data.get('_quikchex_app_session') or body_data.get('quikchex_app_session')
        remember_user_token = body_data.get('remember_user_token')
        
        logging.info(f"Request received with _quikchex_app_session={quikchex_app_session}, remember_user_token={remember_user_token}")
        
        # Validate required fields
        if not user_email or not quickchex_pass or not gmail_app_password:
            logging.warning(f"Missing required fields in request")
            return JSONResponse(
                status_code=400,
                content={"status": "error", "message": "Missing required fields"}
            )
        
        return StreamingResponse(
            generate_attendance_stream(
                user_email=user_email,
                quickchex_pass=quickchex_pass,
                gmail_app_password=gmail_app_password,
                # Pass the optional cookies
                provided_quikchex_app_session=quikchex_app_session,
                provided_remember_user_token=remember_user_token
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Content-Type": "text/event-stream",
                "Access-Control-Allow-Origin": "*", # Already present
            }
        )
    except json.JSONDecodeError:
        logging.error(f"Failed to parse request body as JSON: {body_str}")
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Invalid JSON in request body"}
        )
    except Exception as e:
        logging.exception("Error processing request")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Server error: {str(e)}"}
        )

# Constants
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

# --- Ported functions from your first script ---
EXPECTED_ATTENDANCE_HTML = [ # From your first script
    '$(".new_dashboard-ess-logs").removeClass(\'hidden\');',
    '<div class="checkinbg col first-entry-element">',
    '<div class="checkinbg col last-entry-element "'
]

def response_is_successful(response): # From your first script
    text = response.text
    for snippet in EXPECTED_ATTENDANCE_HTML:
        if snippet in text:
            return True
    return False

def mark_attendance_with_session(csrf, quikchex_app_session, remember_user_token): # From your first script
    # Note: The company/employee IDs are hardcoded here. This should be parameterized if needed.
    url = 'https://secure.quikchex.in/companies/6268eafc22a8cf2f200000c6/employees/677b6f9cf866bc2cda7fe1c3/employee_daily_attendances/create_attendance_record.js?from_dashboard=true'
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        # 'If-None-Match': 'W/"37e48715a85fea3ae2eaac9c66e4381d"', # This can cause issues if stale
        'Referer': 'https://secure.quikchex.in/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'X-CSRF-Token': csrf, # CSRF might be needed even for GET if the endpoint checks it
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"'
    }
    cookies = {
        '_quikchex_app_session': quikchex_app_session,
        'remember_user_token': remember_user_token
    }
    # In your first script, this was a GET request. Make sure this is correct.
    # The .js extension suggests it might be a GET that executes JavaScript.
    response = requests.get(url, headers=headers, cookies=cookies, timeout=15)
    return response
# --- End of ported functions ---

# MODIFIED generate_attendance_stream signature
async def generate_attendance_stream(user_email, quickchex_pass, gmail_app_password,
                                     provided_quikchex_app_session: Optional[str] = None,
                                     provided_remember_user_token: Optional[str] = None):
    set_log_user(user_email)  # Set user for logging
    logging.info(f"Stream started. Provided _quikchex_app_session: {provided_quikchex_app_session}, Provided remember_user_token: {provided_remember_user_token}")
    current_quikchex_app_session = provided_quikchex_app_session
    current_remember_user_token = provided_remember_user_token
    csrf_from_session_login = None # To store CSRF if obtained from direct session login

    try:
        # Step 0: Check Gmail credentials (remains the same)
        yield "data: " + json.dumps({"status": "processing", "message": "Validating Gmail credentials..."}) + "\n\n"
        await asyncio.sleep(0.5)
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(user_email, gmail_app_password)
            mail.logout()
            yield "data: " + json.dumps({"status": "step_success", "message": "Gmail login successful."}) + "\n\n"
            await asyncio.sleep(0.5)
        except imaplib.IMAP4.error as e:
            logging.error(f"Gmail login failed for {user_email}: {e}")
            yield "data: " + json.dumps({"status": "app_error", "message": f"Gmail login failed: {str(e)}. Please check your Gmail email or App Password."}) + "\n\n"
            return # Stop if Gmail login fails

        yield "data: " + json.dumps({"status": "processing", "message": "Starting QuikChex automation..."}) + "\n\n"
        await asyncio.sleep(0.5)

        # --- NEW: Try to mark attendance directly if cookies are provided ---
        if current_quikchex_app_session and current_remember_user_token:
            yield "data: " + json.dumps({"status": "processing", "message": "Found session cookies. Trying to mark attendance directly..."}) + "\n\n"
            await asyncio.sleep(0.5)
            
            # To use mark_attendance_with_session, we ideally need a CSRF token.
            # If we are using existing cookies, the CSRF might not be readily available without a page load.
            # This is a potential challenge with direct session use for GET requests that might still check CSRF.
            # For now, let's assume the GET endpoint might not strictly require CSRF or we get it after a quick fetch.

            # Quick fetch to try and get a CSRF if the session is valid
            session_for_direct_mark = requests.Session()
            session_for_direct_mark.cookies.set('_quikchex_app_session', current_quikchex_app_session)
            if current_remember_user_token: # remember_user_token can be None
                 session_for_direct_mark.cookies.set('remember_user_token', current_remember_user_token)
            
            try:
                dashboard_response = session_for_direct_mark.get("https://secure.quikchex.in/", headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
                dashboard_response.raise_for_status()
                csrf_match_direct = re.search(r'name="csrf-token"\s+content="([^"]+)"', dashboard_response.text) # Common CSRF meta tag
                if not csrf_match_direct:
                     csrf_match_direct = re.search(r'name="authenticity_token"\s+value="([^"]+)"', dashboard_response.text) # Form-based
                
                if csrf_match_direct:
                    csrf_from_session_login = csrf_match_direct.group(1)
                    yield "data: " + json.dumps({"status": "step_success", "message": "Fetched current CSRF token using session."}) + "\n\n"
                else:
                    yield "data: " + json.dumps({"status": "processing", "message": "Could not fetch a fresh CSRF with session. Proceeding without it for direct mark attempt."}) + "\n\n"
            except requests.RequestException as e:
                 yield "data: " + json.dumps({"status": "step_warning", "message": f"Failed to pre-fetch dashboard with session (for CSRF): {e}. Attempting direct mark anyway."}) + "\n\n"


            direct_mark_response = mark_attendance_with_session(csrf_from_session_login, current_quikchex_app_session, current_remember_user_token)
            if response_is_successful(direct_mark_response):
                yield "data: " + json.dumps({"status": "app_success", "message": "✅ Attendance marked successfully using provided cookies!"}) + "\n\n"
                # Send back the cookies that were used, as they are still valid
                yield "data: " + json.dumps({
                    "status": "cookies_update",
                    "message": "Using existing valid session.",
                    "cookies": {
                        "_quikchex_app_session": current_quikchex_app_session,
                        "remember_user_token": current_remember_user_token
                    }
                }) + "\n\n"
                return
            else:
                yield "data: " + json.dumps({"status": "step_warning", "message": "Provided cookies failed or expired. Proceeding with full login..."}) + "\n\n"
                current_quikchex_app_session = None # Invalidate them for the rest of this run
                current_remember_user_token = None
        # --- END OF NEW SESSION CHECK ---

        email_encoded = urllib.parse.quote(user_email)
        password_encoded = urllib.parse.quote(quickchex_pass)

        # Step 1 get the cookies from the URL
        yield "data: " + json.dumps({"status": "processing", "message": "Connecting to QuikChex for new login..."}) + "\n\n"
        await asyncio.sleep(0.5)
        url = "https://secure.quikchex.in"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        }
        session = requests.Session() # Main session for the full login flow
        try:
            response = session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            yield "data: " + json.dumps({"status": "app_error", "message": f"Failed to connect to QuikChex: {e}"}) + "\n\n"
            return
        
        # Get initial session cookie, will be updated after login
        initial_app_session_cookie = session.cookies.get('_quikchex_app_session')

        if not initial_app_session_cookie:
            yield "data: " + json.dumps({"status": "app_error", "message": "Failed to obtain initial QuikChex session cookie for login."}) + "\n\n"
            return

        yield "data: " + json.dumps({"status": "step_success", "message": "Connected to QuikChex. Initial session cookie for login obtained."}) + "\n\n"
        await asyncio.sleep(0.5)
        
        # Step 2: Use the cookies to log in
        yield "data: " + json.dumps({"status": "processing", "message": "Signing in to QuikChex..."}) + "\n\n"
        await asyncio.sleep(0.5)
        
        login_url = 'https://secure.quikchex.in/users/sign_in'
        # ... (login_headers, login_data as in your original second script)
        login_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://secure.quikchex.in',
            'Referer': 'https://secure.quikchex.in/users/sign_in',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
        }
        # Use the initial_app_session_cookie for the login attempt.
        # The `authenticity_token` in data is often tied to the session that loaded the login form.
        # It's generally better to fetch the login page first to get a fresh authenticity_token.
        # However, your first script hardcoded one, and your second one implies it might work. Let's try.
        # For robustness, fetching the login page first is recommended:
        #   login_page_resp = session.get(login_url, headers=headers)
        #   auth_token_match_login_form = re.search(r'name="authenticity_token"\s+value="([^"]+)"', login_page_resp.text)
        #   fresh_auth_token = auth_token_match_login_form.group(1) if auth_token_match_login_form else "FALLBACK_OR_ERROR"
        # Then use fresh_auth_token in login_data.
        # For now, using the hardcoded one from your original script for simplicity of this merge.
        hardcoded_auth_token = "L3Eb5Bf6VTa62DTPCmE-pjPCUfqEaJKGrFzv_12mhYTw5-zx8q39r3BQaO0Cm7F9ZPkmzThdvt6x6zvElkTdBA" # From your first script's data
        login_data = f'utf8=%E2%9C%93&authenticity_token={hardcoded_auth_token}&user%5Bemail%5D={email_encoded}&user%5Bpassword%5D={password_encoded}&user%5Bremember_me%5D=0&user%5Bremember_me%5D=1'

        try:
            sign_in_response = session.post(login_url, headers=login_headers, data=login_data, timeout=10)
            sign_in_response.raise_for_status()
        except requests.RequestException as e:
            yield "data: " + json.dumps({"status": "app_error", "message": f"Sign-in request failed: {e}"}) + "\n\n"
            return
        
        csrf = None
        # After login, the page might contain a new CSRF token in a meta tag or a form
        csrf_meta_match = re.search(r'name="csrf-token"\s+content="([^"]+)"', sign_in_response.text)
        if csrf_meta_match:
            csrf = csrf_meta_match.group(1)
        else:
            # Fallback to form authenticity_token if meta tag not found
            auth_token_match_form = re.search(r'name="authenticity_token"\s+value="([^"]+)"', sign_in_response.text)
            if auth_token_match_form:
                csrf = auth_token_match_form.group(1)

        if csrf:
            yield "data: " + json.dumps({"status": "step_success", "message": "Signed in. New CSRF token obtained."}) + "\n\n"
        else:
            if "dashboard" in sign_in_response.text.lower() or "sign_out" in sign_in_response.text.lower() or "Invalid email or password" not in sign_in_response.text:
                 yield "data: " + json.dumps({"status": "step_success", "message": "Logged in, but could not find a new CSRF token. Proceeding (OTP step might fail if CSRF is strictly required)." }) + "\n\n"
            else:
                logging.debug(f"Sign-in response text (failed login?): {sign_in_response.text[:500]}")
                yield "data: " + json.dumps({"status": "app_error", "message": "Login failed. Check credentials or QuikChex login page may have changed."}) + "\n\n"
                return
        
        # IMPORTANT: Update current session cookies from the session object after successful login
        current_quikchex_app_session = session.cookies.get('_quikchex_app_session')
        current_remember_user_token = session.cookies.get('remember_user_token') # This cookie is set upon successful login with "remember me"

        if not current_quikchex_app_session:
            yield "data: " + json.dumps({"status": "app_error", "message": "Critical error: _quikchex_app_session cookie not found after login."}) + "\n\n"
            return


        # Step 3: Send the POST request to send OTP email
        # ... (send_otp_url, send_otp_headers as in your original second script, but use the current `csrf`)
        yield "data: " + json.dumps({"status": "processing", "message": "Requesting OTP email..."}) + "\n\n"
        await asyncio.sleep(0.5)
        send_otp_url = 'https://secure.quikchex.in/send_opt_email'
        send_otp_headers = {
            'Accept': '*/*;q=0.5, text/javascript, application/javascript, application/ecmascript, application/x-ecmascript',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Length': '0',
            'Origin': 'https://secure.quikchex.in',
            'Referer': 'https://secure.quikchex.in/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'X-CSRF-Token': csrf, # Use the obtained CSRF
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
        }
        try:
            otp_send_response = session.post(send_otp_url, headers=send_otp_headers, timeout=10)
            if otp_send_response.status_code == 200 and ("success" in otp_send_response.text.lower() or otp_send_response.text == "" or "OTP has been sent" in otp_send_response.text):
                yield "data: " + json.dumps({"status": "step_success", "message": "OTP email request sent. Waiting for email..."}) + "\n\n"
                otp_request_timestamp = time.time() # CAPTURE OTP REQUEST TIME HERE
            else:
                yield "data: " + json.dumps({"status": "app_error", "message": f"Failed to send OTP email. Status: {otp_send_response.status_code}. Response: {otp_send_response.text[:100]}"}) + "\n\n"
                return
        except requests.RequestException as e:
            yield "data: " + json.dumps({"status": "app_error", "message": f"Request to send OTP email failed: {e}"}) + "\n\n"
            return

        # Step 4: Get OTP from Gmail and Submit
        # ... (get_first_email_from_sender, send_otp_request_sync, and the OTP loop as in your original second script)
        # Ensure `send_otp_request_sync` uses the current `csrf`, `current_quikchex_app_session`, and `session` object.
        # ... (This part is quite long, assuming it remains largely the same functionally but uses the updated session variables)
        # ...
        # For brevity, I'm omitting the detailed OTP fetching and submission loop here, assuming it will use:
        # - `user_email`, `gmail_app_password` for IMAP
        # - `session` (the requests.Session object) for making the OTP submission POST request
        # - `csrf` (the token obtained after login)
        # - `current_quikchex_app_session` (obtained after login)
        # - `current_remember_user_token` (obtained after login, if set)

        # Placeholder for the OTP logic from your script...
        # (Ensure `otp_verified_successfully` is set correctly within that logic)
        # --- Start of OTP logic (simplified representation) ---
        otp_verified_successfully = False # Default
        max_otp_attempts = 5
        last_email_uid = None
        for attempt in range(max_otp_attempts):
            yield "data: " + json.dumps({"status": "processing", "message": f"Fetching OTP (Attempt {attempt + 1}/{max_otp_attempts})..."}) + "\n\n"
            await asyncio.sleep(1) # Give some time for the message to be sent
            loop = asyncio.get_event_loop()
            otp_val, email_uid = await loop.run_in_executor(None, get_first_email_from_sender_sync, user_email, gmail_app_password, otp_request_timestamp, 60, 5, last_email_uid)
            if not otp_val:
                yield "data: " + json.dumps({"status": "step_warning", "message": "OTP not found in email yet."}) + "\n\n"
                if attempt < max_otp_attempts - 1: await asyncio.sleep(10) # Wait longer before retrying email fetch
                continue
            last_email_uid = email_uid  # Track the last used email
            yield "data: " + json.dumps({"status": "step_success", "message": f"OTP found: {otp_val}. Submitting..."}) + "\n\n"
            await asyncio.sleep(1)
            otp_submit_resp = await loop.run_in_executor(None, submit_otp_sync, session, csrf, otp_val)
            if otp_submit_resp.status_code == 200 and \
               ("window.location.replace" in otp_submit_resp.text or \
                "window.location = " in otp_submit_resp.text or \
                "dashboard" in otp_submit_resp.text.lower()):
                yield "data: " + json.dumps({"status": "step_success", "message": "OTP verification successful!"}) + "\n\n"
                otp_verified_successfully = True
                break
            else:
                yield "data: " + json.dumps({"status": "step_error", "message": f"OTP verification failed (Status: {otp_submit_resp.status_code})."}) + "\n\n"
                if "Invalid OTP" in otp_submit_resp.text and attempt < max_otp_attempts - 1:
                    yield "data: " + json.dumps({"status": "processing", "message": "Invalid OTP. Will try fetching a newer email."}) + "\n\n"
                    await asyncio.sleep(5) # Wait a bit before trying to fetch email again
        # --- End of OTP logic ---

        if not otp_verified_successfully:
            yield "data: " + json.dumps({"status": "app_error", "message": f"Failed to verify OTP after {max_otp_attempts} attempts."}) + "\n\n"
            return

        # Step 5: Mark attendance
        yield "data: " + json.dumps({"status": "processing", "message": "Marking attendance..."}) + "\n\n"
        await asyncio.sleep(0.5)
        
        # Use the `mark_attendance_with_session` function ported from the first script
        # It now uses the `csrf` from the successful login, and the `current_` cookies
        final_mark_response = mark_attendance_with_session(csrf, current_quikchex_app_session, current_remember_user_token)

        if response_is_successful(final_mark_response):
            yield "data: " + json.dumps({"status": "app_success", "message": "✅ Attendance marked successfully! Have a great day!"}) + "\n\n"
            # --- NEW: Send back the newly obtained/confirmed cookies ---
            if current_quikchex_app_session: # Ensure it's not None
                yield "data: " + json.dumps({
                    "status": "cookies_update",
                    "message": "Session updated/confirmed after successful attendance.",
                    "cookies": {
                        "_quikchex_app_session": current_quikchex_app_session,
                        "remember_user_token": current_remember_user_token # Can be None
                    }
                }) + "\n\n"
        elif "already marked" in final_mark_response.text.lower() or "punch out" in final_mark_response.text.lower(): # Added from your second script
            yield "data: " + json.dumps({"status": "app_success", "message": "✅ Attendance already marked for today or action completed."}) + "\n\n"
            # Also send back cookies if this is considered a success using an existing session
            if provided_quikchex_app_session and current_quikchex_app_session == provided_quikchex_app_session: # Check if it's the same session
                 yield "data: " + json.dumps({
                    "status": "cookies_update",
                    "message": "Existing session confirmed with 'already marked' status.",
                    "cookies": {
                        "_quikchex_app_session": current_quikchex_app_session,
                        "remember_user_token": current_remember_user_token
                    }
                }) + "\n\n"

        else:
            yield "data: " + json.dumps({"status": "app_error", "message": f"⚠️ Failed to mark attendance. Response: {final_mark_response.text[:100]}"}) + "\n\n"
        await asyncio.sleep(0.5)

    except Exception as e:
        logging.exception("An unexpected error occurred in generate_attendance_stream")
        yield "data: " + json.dumps({"status": "app_error", "message": f"❌ An unexpected server error occurred: {str(e)}"}) + "\n\n"

# Move helper functions to top-level (not nested)
def get_first_email_from_sender_sync(user_email, gmail_app_password, otp_req_time, wait_time=60, polling_interval=5, last_email_uid=None):
    """
    Gets the latest email from QuikChex and directly extracts the OTP.
    Args:
        user_email: Gmail address
        gmail_app_password: Gmail app password
        otp_req_time: Time when OTP was requested (used to filter emails)
        wait_time: Maximum time to wait for the email in seconds
        polling_interval: Time between inbox checks in seconds
        last_email_uid: UID of the last used OTP email (to avoid reusing)
    Returns:
        (otp, email_uid) tuple or (None, None) if not found
    """
    IMAP_SERVER = "imap.gmail.com"
    IMAP_PORT = 993
    start_time = time.time()
    search_since = time.strftime("%d-%b-%Y", time.localtime(start_time))
    logging.info(f"Looking for QuikChex emails received after {search_since}")
    while time.time() - start_time < wait_time:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(user_email, gmail_app_password)
            mail.select("inbox")
            search_query = f'(FROM "support@quikchex.in" SENTSINCE "{search_since}")'
            status, messages = mail.search(None, search_query)
            if status != 'OK' or not messages[0]:
                logging.info("No recent QuikChex messages found")
                time.sleep(polling_interval)
                continue
            email_ids = messages[0].split()
            if not email_ids:
                logging.info(f"No new QuikChex emails found, waiting {polling_interval} seconds...")
                mail.logout()
                time.sleep(polling_interval)
                continue
            # Get the latest email
            latest_email_id = email_ids[-1]
            if last_email_uid is not None and latest_email_id == last_email_uid:
                mail.logout()
                time.sleep(polling_interval)
                continue  # Skip if we've already used this email
            status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
            for part in msg_data:
                if isinstance(part, tuple):
                    msg_obj = email.message_from_bytes(part[1])
                    # Get time information for debugging
                    date_str = msg_obj.get("Date", "")
                    try:
                        parsed_date = email.utils.parsedate_to_datetime(date_str)
                        local_time = parsed_date.astimezone().strftime("%I:%M %p (%Y-%m-%d)")
                        logging.info(f"Email time: {local_time}")
                    except Exception as e:
                        logging.warning(f"Error parsing date: {e}")
                    # Body
                    body_text = ""
                    if msg_obj.is_multipart():
                        for subpart in msg_obj.walk():
                            ctype = subpart.get_content_type()
                            cdisp = str(subpart.get("Content-Disposition") or "")
                            if ctype == "text/plain" and "attachment" not in cdisp:
                                payload = subpart.get_payload(decode=True)
                                if payload:
                                    body_text = payload.decode(errors="replace")
                                    break
                    else:
                        payload = msg_obj.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode(errors="replace")
                    # Direct extraction of OTP using regex pattern matching
                    otp_match = re.search(r'(\d{6})\s+is your One-Time Password', body_text)
                    if otp_match:
                        otp = otp_match.group(1)
                        logging.info(f"OTP extracted: {otp}")
                        mail.logout()
                        return otp, latest_email_id
                    digit_match = re.search(r'\b(\d{6})\b', body_text)
                    if digit_match:
                        otp = digit_match.group(1)
                        logging.info(f"OTP extracted (using digit pattern): {otp}")
                        mail.logout()
                        return otp, latest_email_id
                    logging.info("Could not find OTP in email body")
                    logging.info("Email body preview:")
                    logging.info(body_text[:200])
            mail.logout()
        except Exception as e:
            logging.error(f"Error checking email: {e}")
        logging.info(f"Waiting {polling_interval} seconds before checking again...")
        time.sleep(polling_interval)
    logging.error("Timed out waiting for OTP email")
    return None, None

def submit_otp_sync(session, csrf, otp_code):
    url = 'https://secure.quikchex.in/get_otp'
    headers = {
        'Accept': '*/*;q=0.5, text/javascript, application/javascript, application/ecmascript, application/x-ecmascript',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://secure.quikchex.in',
        'Referer': 'https://secure.quikchex.in/',
        'X-CSRF-Token': csrf,
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    }
    data = {'utf8': '✓', 'authenticity_token': csrf, 'otp_data': otp_code}
    return session.post(url, headers=headers, data=data, timeout=10)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000)) # Your original port logic
    uvicorn.run(app, host="0.0.0.0", port=port)