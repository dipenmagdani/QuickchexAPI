import requests
import os
import base64
import re
import time
# import requests # Duplicate import removed
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import imaplib
import email
import urllib.parse
import json

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your React app URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO, # Changed to INFO for less noise, DEBUG is very verbose
    format="%(asctime)s - %(levelname)s - %(module)s - %(message)s",
    handlers=[
        logging.FileHandler("quikchex_attendance.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Define request model
class AttendanceRequest(BaseModel):
    user_email: str
    quickchex_pass: str
    gmail_app_password: str

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "message": "API is running"}

# Mark attendance endpoint
@app.post("/mark")
async def mark_attendance_endpoint(data: AttendanceRequest): # Renamed for clarity
    return StreamingResponse(
        generate_attendance_stream(
            user_email=data.user_email,
            quickchex_pass=data.quickchex_pass,
            gmail_app_password=data.gmail_app_password
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "text/event-stream",
            "Access-Control-Allow-Origin": "*", # Already set by CORSMiddleware for SSE too
        }
    )

# Constants
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

async def generate_attendance_stream(user_email, quickchex_pass, gmail_app_password):
    # Helper to yield SSE data
    async def send_event(status: str, message: str):
        logger.info(f"Sending SSE: Status: {status}, Message: {message[:100]}") # Log concise message
        yield "data: " + json.dumps({"status": status, "message": message}) + "\n\n"
        await asyncio.sleep(0.25) # Reduced sleep for faster feedback

    try:
        yield await send_event("processing", "Starting QuikChex automation...")
        
        email_encoded = urllib.parse.quote(user_email)
        password_encoded = urllib.parse.quote(quickchex_pass)

        # Step 1: Get initial cookies
        yield await send_event("processing", "Connecting to QuikChex...")
        url_secure = "https://secure.quikchex.in"
        headers_initial = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        }
        session = requests.Session()
        try:
            response_initial = session.get(url_secure, headers=headers_initial, timeout=10)
            response_initial.raise_for_status()
        except requests.RequestException as e:
            yield await send_event("app_error", f"Failed to connect to QuikChex: {e}")
            return
        
        cookies_initial = session.cookies.get_dict()
        quikchex_app_session = cookies_initial.get('_quikchex_app_session')
        if not quikchex_app_session:
            yield await send_event("app_error", "Failed to obtain initial QuikChex session cookie.")
            return
        yield await send_event("processing", "Initial session established. Preparing login...")

        # Step 2: Log in
        url_signin = 'https://secure.quikchex.in/users/sign_in'
        # Simplified headers for login, often fewer are strictly needed
        headers_login = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': url_secure,
            'Referer': url_secure + '/users/sign_in', # More common referer for sign in page
            'User-Agent': headers_initial["User-Agent"],
        }
        # Note: authenticity_token is often page-specific. Hardcoding it (L3Eb5Bf6...) is fragile.
        # Ideally, it should be scraped from the sign-in page just before login.
        # For now, assuming the provided token is somewhat stable or illustrative.
        # A more robust solution would first GET the sign_in page, parse the token, then POST.
        payload_login = f'utf8=%E2%9C%93&authenticity_token=L3Eb5Bf6VTa62DTPCmE-pjPCUfqEaJKGrFzv_12mhYTw5-zx8q39r3BQaO0Cm7F9ZPkmzThdvt6x6zvElkTdBA&user%5Bemail%5D={email_encoded}&user%5Bpassword%5D={password_encoded}&user%5Bremember_me%5D=1'
        
        yield await send_event("processing", "Signing in to QuikChex...")
        try:
            sign_in_response = session.post(url_signin, headers=headers_login, data=payload_login, timeout=10) # Removed explicit cookies, session handles them
            sign_in_response.raise_for_status() # Check for HTTP errors
        except requests.RequestException as e:
            yield await send_event("app_error", f"Sign-in request failed: {e}")
            return

        # Update session cookie if it changed
        if '_quikchex_app_session' in session.cookies:
            quikchex_app_session = session.cookies['_quikchex_app_session']

        # Extract CSRF token from the response body (e.g., a dashboard page after login)
        csrf_token_match = re.search(r'name="csrf-token"\s+content="([^"]+)"', sign_in_response.text) 
        # Or: r'name="authenticity_token"\s+value="([^"]+)"' depending on QuikChex's forms
        if csrf_token_match:
            csrf = csrf_token_match.group(1)
            yield await send_event("step_success", "Authentication token obtained for next steps.")
        else:
            # Check if login was actually successful by looking for keywords or redirection
            if "dashboard" in sign_in_response.text.lower() or "sign_out" in sign_in_response.text.lower():
                 yield await send_event("step_success", "Logged in, but couldn't find a new CSRF token on the landing page. Proceeding cautiously.")
                 # Attempt to find any authenticity_token if a specific csrf-token meta tag is not present
                 auth_token_match_form = re.search(r'name="authenticity_token"\s+value="([^"]+)"', sign_in_response.text)
                 if auth_token_match_form:
                     csrf = auth_token_match_form.group(1)
                     yield await send_event("step_success", "Found a form authenticity_token to use as CSRF.")
                 else:
                    yield await send_event("app_error", "Login seemed successful, but failed to extract necessary token for OTP step.")
                    return
            else:
                yield await send_event("app_error", "Login failed. Check credentials or QuikChex login page changes.")
                logger.debug(f"Sign-in response text (failed login?): {sign_in_response.text[:500]}")
                return
        
        # Step 3: Send OTP email
        yield await send_event("processing", "Requesting OTP email...")
        url_send_otp = 'https://secure.quikchex.in/send_opt_email' # opt not opt
        headers_otp_send = {
            'Accept': '*/*;q=0.5, text/javascript, application/javascript, application/ecmascript, application/x-ecmascript',
            'Origin': url_secure,
            'Referer': url_secure + '/', # Common referer from dashboard
            'User-Agent': headers_initial["User-Agent"],
            'X-CSRF-Token': csrf,
            'X-Requested-With': 'XMLHttpRequest',
        }
        try:
            response_otp_send = session.post(url_send_otp, headers=headers_otp_send, timeout=10)
            # response_otp_send.raise_for_status() # Often returns 200 even if OTP not sent due to issues
            if response_otp_send.status_code == 200 and ("success" in response_otp_send.text.lower() or response_otp_send.text == "") : # Empty response can be success
                yield await send_event("step_success", "OTP email request sent. Waiting for email...")
            else:
                yield await send_event("app_error", f"Failed to send OTP email. Status: {response_otp_send.status_code}. Response: {response_otp_send.text[:100]}")
                return
        except requests.RequestException as e:
            yield await send_event("app_error", f"Request to send OTP email failed: {e}")
            return

        # Step 4: Get OTP from Gmail
        def get_first_email_from_sender_sync(wait_time=60, polling_interval=5): # Renamed to _sync
            # ... (rest of your get_first_email_from_sender function, ensure it's not async here if called with run_in_executor)
            # This function should be synchronous if run with run_in_executor
            start_time = time.time()
            search_since = time.strftime("%d-%b-%Y", time.localtime(start_time - 60*5)) # Look back 5 mins
            logger.info(f"Polling Gmail: Looking for QuikChex emails (FROM support@quikchex.in SINCE {search_since})")
            while time.time() - start_time < wait_time:
                try:
                    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
                    mail.login(user_email, gmail_app_password)
                    mail.select("inbox")
                    # More specific search for unread emails might be better: '(UNSEEN FROM "support@quikchex.in" SINCE "{search_since}")'
                    search_query = f'(FROM "support@quikchex.in" SINCE "{search_since}")'
                    status, messages = mail.search(None, search_query)
                    
                    if status == 'OK' and messages[0]:
                        email_ids = messages[0].split()
                        latest_email_id = email_ids[-1] # Get the latest one
                        
                        # Mark as seen (optional, good practice)
                        # mail.store(latest_email_id, '+FLAGS', '\\Seen')
                        
                        status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
                        for response_part in msg_data:
                            if isinstance(response_part, tuple):
                                msg = email.message_from_bytes(response_part[1])
                                body_text = ""
                                if msg.is_multipart():
                                    for subpart in msg.walk():
                                        if subpart.get_content_type() == "text/plain" and "attachment" not in str(subpart.get("Content-Disposition")):
                                            payload = subpart.get_payload(decode=True)
                                            body_text = payload.decode(errors="replace") if payload else ""
                                            break
                                else:
                                    payload = msg.get_payload(decode=True)
                                    body_text = payload.decode(errors="replace") if payload else ""
                                
                                otp_match = re.search(r'(\d{6})\s+is your One-Time Password', body_text)
                                if otp_match:
                                    otp = otp_match.group(1)
                                    logger.info(f"OTP extracted: {otp}")
                                    mail.logout()
                                    return otp
                                # Fallback for generic 6-digit code if primary pattern fails
                                digit_match = re.search(r'\b(\d{6})\b', body_text) # Simpler regex for any 6 digits
                                if digit_match:
                                    otp = digit_match.group(1)
                                    logger.info(f"OTP extracted (fallback pattern): {otp}")
                                    mail.logout()
                                    return otp
                        mail.logout() # Logout if OTP not found in this email
                    else: # No messages or status not OK
                        logger.debug(f"No new QuikChex emails found. Status: {status}, Messages: {messages}")
                        if mail.state == 'SELECTED': mail.logout() # Logout if no messages found
                except imaplib.IMAP4.error as e: # More specific IMAP errors
                    logger.error(f"IMAP Error (will retry): {e}")
                    # No return here, will retry after sleep
                except Exception as e:
                    logger.error(f"Error checking email (will retry): {e}")
                    # No return here, will retry after sleep

                logger.debug(f"OTP not found yet, sleeping for {polling_interval}s...")
                time.sleep(polling_interval)
            logger.warning("OTP not found within the wait time.")
            return None

        yield await send_event("processing", "Waiting for OTP email (up to 60s)...")
        # Running synchronous IMAP code in a thread to avoid blocking asyncio event loop
        loop = asyncio.get_event_loop()
        otp = None
        attempts = 0
        max_email_fetch_retries = 3 # Total retries for fetching email
        
        while attempts < max_email_fetch_retries and not otp:
            attempts+=1
            yield await send_event("processing", f"Fetching OTP from email (Attempt {attempts}/{max_email_fetch_retries})...")
            try:
                # Each attempt will poll for 60 seconds
                otp = await loop.run_in_executor(None, get_first_email_from_sender_sync, 60, 5)
                if otp:
                    break 
            except Exception as e: # Catch errors from run_in_executor itself
                logger.error(f"Executor error during email fetch: {e}")
                yield await send_event("step_error", f"Error during email fetching attempt: {e}")

            if not otp and attempts < max_email_fetch_retries:
                yield await send_event("step_error", "OTP not found in email yet. Will retry fetching.")
                await asyncio.sleep(5) # Brief pause before full retry of get_first_email_from_sender_sync
        
        if not otp:
            yield await send_event("app_error", "Failed to retrieve OTP from email after multiple attempts.")
            return
        
        yield await send_event("processing", f"OTP found: {otp}. Submitting...")

        # Submit OTP
        url_get_otp = 'https://secure.quikchex.in/get_otp' # Endpoint name is get_otp but it's a POST to submit
        headers_otp_submit = {
            'Accept': '*/*;q=0.5, text/javascript, application/javascript, application/ecmascript, application/x-ecmascript',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': url_secure,
            'Referer': url_secure + '/',
            'User-Agent': headers_initial["User-Agent"],
            'X-CSRF-Token': csrf,
            'X-Requested-With': 'XMLHttpRequest',
        }
        payload_otp_submit = {
            'utf8': '✓',
            'authenticity_token': csrf, # This might be the same CSRF from login or a new one from a form on the OTP page
            'otp_data': otp
        }
        try:
            otp_submit_response = session.post(url_get_otp, headers=headers_otp_submit, data=payload_otp_submit, timeout=10)
            # Successful OTP submission often redirects or returns a script that indicates success
            if otp_submit_response.status_code == 200 and ("window.location.replace" in otp_submit_response.text or "dashboard" in otp_submit_response.text.lower()):
                yield await send_event("step_success", "OTP verification successful!")
            else:
                yield await send_event("app_error", f"OTP verification failed. Status: {otp_submit_response.status_code}. Response: {otp_submit_response.text[:100]}")
                return
        except requests.RequestException as e:
            yield await send_event("app_error", f"OTP submission request failed: {e}")
            return

        # Step 5: Mark attendance
        yield await send_event("processing", "Marking attendance...")
        # IMPORTANT: The company ID and employee ID in this URL are specific.
        # These should ideally be discovered dynamically after login or configured per user.
        url_mark_attendance = 'https://secure.quikchex.in/companies/6268eafc22a8cf2f200000c6/employees/677b6f9cf866bc2cda7fe1c3/employee_daily_attendances/create_attendance_record.js?from_dashboard=true'
        headers_mark = {
            'Accept': '*/*', # Expecting JS response
            'Referer': url_secure + '/',
            'User-Agent': headers_initial["User-Agent"],
            'X-CSRF-Token': csrf, # CSRF token likely needed
            'X-Requested-With': 'XMLHttpRequest',
        }
        try:
            marking_response = session.get(url_mark_attendance, headers=headers_mark, timeout=15) # It's a GET
            # Successful marking often returns JS that updates the page, check for keywords
            if marking_response.status_code == 200 and ("success" in marking_response.text.lower() or "already" in marking_response.text.lower()):
                # Check if already marked
                if "already marked" in marking_response.text.lower() or "punch out" in marking_response.text.lower() : # check for phrases indicating already marked or next action is punch out
                     yield await send_event("app_success", "✅ Attendance already marked for today or action completed.")
                else:
                     yield await send_event("app_success", "✅ Attendance marked successfully! Have a great day!")
            else:
                yield await send_event("app_error", f"⚠️ Failed to mark attendance. Status: {marking_response.status_code}. Response: {marking_response.text[:100]}")
        except requests.RequestException as e:
            yield await send_event("app_error", f"Attendance marking request failed: {e}")
            return

    except Exception as e:
        logger.exception("An unexpected error occurred in generate_attendance_stream") # Log full traceback
        yield await send_event("app_error", f"❌ An unexpected server error occurred: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    # It's good practice to get PORT from environment for deployment flexibility
    port = int(os.getenv("PORT", 8001)) # Changed default to 8001 if 8000 is common
    host = os.getenv("HOST", "0.0.0.0")
    logger.info(f"Starting Uvicorn server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
