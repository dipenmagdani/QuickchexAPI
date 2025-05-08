import requests
import os.path
import base64
import re
import time
import requests
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
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("quikchex_attendance.log"),
        logging.StreamHandler()
    ]
)

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
async def mark_attendance(data: AttendanceRequest):
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
            "Access-Control-Allow-Origin": "*",
        }
    )

# Constants
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

async def generate_attendance_stream(user_email, quickchex_pass, gmail_app_password):
    try:
        yield "data: " + json.dumps({"status": "processing", "message": "Starting QuikChex automation..."}) + "\n\n"
        await asyncio.sleep(0.5)
        
        email_encoded = urllib.parse.quote(user_email)
        password_encoded = urllib.parse.quote(quickchex_pass)

        # Step 1 get the cookies from the URL
        yield "data: " + json.dumps({"status": "processing", "message": "Connecting to QuikChex..."}) + "\n\n"
        await asyncio.sleep(0.5)
        url = "https://secure.quikchex.in"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        }
        session = requests.Session()
        try:
            response = session.get(url, headers=headers, timeout=10)
            response.raise_for_status() # Check for HTTP errors
        except requests.RequestException as e:
            yield "data: " + json.dumps({"status": "app_error", "message": f"Failed to connect to QuikChex: {e}"}) + "\n\n"
            await asyncio.sleep(0.5)
            return
        
        cookies = session.cookies.get_dict()
        quikchex_app_session = cookies.get('_quikchex_app_session')

        if not quikchex_app_session:
            yield "data: " + json.dumps({"status": "app_error", "message": "Failed to obtain initial QuikChex session cookie."}) + "\n\n"
            await asyncio.sleep(0.5)
            return

        yield "data: " + json.dumps({"status": "step_success", "message": "Connected to QuikChex. Initial session cookie obtained."}) + "\n\n"
        await asyncio.sleep(0.5)

        yield "data: " + json.dumps({"status": "processing", "message": "Preparing for login..."}) + "\n\n"
        await asyncio.sleep(0.5)
        # This step is now combined with the connection success

        # Step 2: Use the cookies to log in
        yield "data: " + json.dumps({"status": "processing", "message": "Signing in to QuikChex..."}) + "\n\n"
        await asyncio.sleep(0.5)
        
        login_url = 'https://secure.quikchex.in/users/sign_in'
        login_headers = { # Using a more specific name for headers
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
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36', # User agent from user's code
            'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
        }
        login_cookies = { # Using a more specific name for cookies
            '_quikchex_app_session': quikchex_app_session,
            # User's GA cookies - it's better practice to let the session handle these if possible or ensure they are fresh
            '_ga': 'GA1.2.1477413030.1746601456',
            '_gid': 'GA1.2.164039213.1746601456',
            '_ga_PT2EQQ4DC6': 'GS2.2.s1746601456$o1$g1$t1746601456$j0$l0$h0'
        }
        login_data = f'utf8=%E2%9C%93&authenticity_token=L3Eb5Bf6VTa62DTPCmE-pjPCUfqEaJKGrFzv_12mhYTw5-zx8q39r3BQaO0Cm7F9ZPkmzThdvt6x6zvElkTdBA&user%5Bemail%5D={email_encoded}&user%5Bpassword%5D={password_encoded}&user%5Bremember_me%5D=0&user%5Bremember_me%5D=1'
        
        try:
            # Using session.post here to maintain cookie persistence from the initial GET
            sign_in_response = session.post(login_url, headers=login_headers, data=login_data, timeout=10) # Removed explicit cookies, session handles them
            sign_in_response.raise_for_status()
        except requests.RequestException as e:
            yield "data: " + json.dumps({"status": "app_error", "message": f"Sign-in request failed: {e}"}) + "\n\n"
            await asyncio.sleep(0.5)
            return
        
        csrf = None
        match = re.search(r'name="authenticity_token"\s+value="([^"]+)"', sign_in_response.text)
        if match:
            csrf = match.group(1)
            yield "data: " + json.dumps({"status": "step_success", "message": "Signed in. Authentication token obtained."}) + "\n\n"
            await asyncio.sleep(0.5)
        else:
            # Check if login was actually successful by looking for keywords or redirection
            if "dashboard" in sign_in_response.text.lower() or "sign_out" in sign_in_response.text.lower():
                 yield "data: " + json.dumps({"status": "step_success", "message": "Logged in, but couldn't find a new CSRF token on the landing page. Proceeding cautiously."}) + "\n\n"
                 await asyncio.sleep(0.5)
                 # Attempt to find any authenticity_token if a specific csrf-token meta tag is not present
                 auth_token_match_form = re.search(r'name="authenticity_token"\s+value="([^"]+)"', sign_in_response.text)
                 if auth_token_match_form:
                     csrf = auth_token_match_form.group(1)
                     yield "data: " + json.dumps({"status": "step_success", "message": "Found a form authenticity_token to use as CSRF."}) + "\n\n"
                     await asyncio.sleep(0.5)
                 else:
                    yield "data: " + json.dumps({"status": "app_error", "message": "Login seemed successful, but failed to extract necessary token for OTP step."}) + "\n\n"
                    await asyncio.sleep(0.5)
                    return
            else:
                logging.debug(f"Sign-in response text (failed login?): {sign_in_response.text[:500]}")
                yield "data: " + json.dumps({"status": "app_error", "message": "Sign-in failed. Check credentials or QuikChex login page changes."}) + "\n\n"
                await asyncio.sleep(0.5)
                return
        
        # Update session cookie if it changed after login
        if '_quikchex_app_session' in session.cookies:
            quikchex_app_session = session.cookies['_quikchex_app_session']

        # Step 3: Send the POST request to send OTP email
        yield "data: " + json.dumps({"status": "processing", "message": "Requesting OTP email..."}) + "\n\n"
        await asyncio.sleep(0.5)
        
        send_otp_url = 'https://secure.quikchex.in/send_opt_email'
        send_otp_headers = {
            'Accept': '*/*;q=0.5, text/javascript, application/javascript, application/ecmascript, application/x-ecmascript',
            'Accept-Language': 'en-US,en;q=0.9', # From user's code
            'Connection': 'keep-alive', # From user's code
            'Content-Length': '0', # From user's code for POST with no body
            'Origin': 'https://secure.quikchex.in',
            'Referer': 'https://secure.quikchex.in/', 
            'Sec-Fetch-Dest': 'empty', # From user's code
            'Sec-Fetch-Mode': 'cors', # From user's code
            'Sec-Fetch-Site': 'same-origin', # From user's code
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', # User agent from user's code
            'X-CSRF-Token': csrf,
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"', # From user's code
            'sec-ch-ua-mobile': '?0', # From user's code
            'sec-ch-ua-platform': '"Linux"', # From user's code
        }
        # Cookies for send_otp are managed by the session object
        try:
            # Using session.post
            otp_send_response = session.post(send_otp_url, headers=send_otp_headers, timeout=10)
            # otp_send_response.raise_for_status() # Often returns 200 even if OTP not sent
            
            # The user's code had: Response: {response.text}. This can be verbose.
            # logging.debug(f"OTP Send Response: {otp_send_response.text[:200]}")
            
            if otp_send_response.status_code == 200 and ("success" in otp_send_response.text.lower() or otp_send_response.text == ""): # Previous logic
                yield "data: " + json.dumps({"status": "step_success", "message": "OTP email request sent. Waiting for email..."}) + "\n\n"
                await asyncio.sleep(0.5)
            else:
                yield "data: " + json.dumps({"status": "app_error", "message": f"Failed to send OTP email. Status: {otp_send_response.status_code}. Response: {otp_send_response.text[:100]}"}) + "\n\n"
                await asyncio.sleep(0.5)
                return
        except requests.RequestException as e:
            yield "data: " + json.dumps({"status": "app_error", "message": f"Request to send OTP email failed: {e}"}) + "\n\n"
            await asyncio.sleep(0.5)
            return

        # Step 4: Get OTP from Gmail and Submit
        # get_first_email_from_sender and send_otp_request are synchronous as per user's latest code.
        # This will block the event loop. For SSE event changes, I'm not changing this back to run_in_executor.
        
        def get_first_email_from_sender(wait_time=60, polling_interval=5): # User's sync function
            start_time = time.time()
            search_since = time.strftime("%d-%b-%Y", time.localtime(start_time)) # User's version
            print(f"Looking for QuikChex emails received after {search_since}") # User's print
            while time.time() - start_time < wait_time:
                try:
                    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
                    mail.login(user_email, gmail_app_password)
                    mail.select("inbox")
                    search_query = f'(FROM "support@quikchex.in" SINCE "{search_since}")'
                    status, messages = mail.search(None, search_query)
                    if status != 'OK' or not messages[0]:
                        print("No recent QuikChex messages found") # User's print
                        time.sleep(polling_interval)
                        mail.logout() # Logout if no messages
                        continue
                    email_ids = messages[0].split()
                    if not email_ids:
                        print(f"No new QuikChex emails found, waiting {polling_interval} seconds...") # User's print
                        mail.logout()
                        time.sleep(polling_interval)
                        continue
                    latest_email_id = email_ids[-1]
                    status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
                    for part in msg_data:
                        if isinstance(part, tuple):
                            msg = email.message_from_bytes(part[1])
                            body_text = ""
                            if msg.is_multipart():
                                for subpart in msg.walk():
                                    ctype = subpart.get_content_type()
                                    cdisp = str(subpart.get("Content-Disposition") or "")
                                    if ctype == "text/plain" and "attachment" not in cdisp:
                                        payload = subpart.get_payload(decode=True)
                                        if payload:
                                            body_text = payload.decode(errors="replace")
                                        break
                            else:
                                payload = msg.get_payload(decode=True)
                                if payload:
                                    body_text = payload.decode(errors="replace")
                            
                            otp_match = re.search(r'(\d{6})\s+is your One-Time Password', body_text)
                            if otp_match:
                                otp_val = otp_match.group(1)
                                print(f"OTP extracted: {otp_val}") # User's print
                                mail.logout()
                                return otp_val
                            
                            digit_match = re.search(r'\b(\d{6})\b', body_text)
                            if digit_match:
                                otp_val = digit_match.group(1)
                                print(f"OTP extracted (using digit pattern): {otp_val}") # User's print
                                mail.logout()
                                return otp_val
                    mail.logout()
                except Exception as e:
                    print(f"Error checking email: {e}") # User's print
                time.sleep(polling_interval)
            return None

        def send_otp_request_sync(current_session, otp_to_submit, current_csrf, current_session_cookie): # Added current_session
            submit_otp_url = 'https://secure.quikchex.in/get_otp'
            submit_otp_headers = {
                'Accept': '*/*;q=0.5, text/javascript, application/javascript, application/ecmascript, application/x-ecmascript',
                'Accept-Language': 'en-US,en;q=0.9', # From user's code
                'Connection': 'keep-alive', # From user's code
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://secure.quikchex.in',
                'Referer': 'https://secure.quikchex.in/',
                'Sec-Fetch-Dest': 'empty', # From user's code
                'Sec-Fetch-Mode': 'cors', # From user's code
                'Sec-Fetch-Site': 'same-origin', # From user's code
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', # User agent
                'X-CSRF-Token': current_csrf,
                'X-Requested-With': 'XMLHttpRequest',
                'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"', # From user's code
                'sec-ch-ua-mobile': '?0', # From user's code
                'sec-ch-ua-platform': '"Linux"', # From user's code
            }
            submit_otp_data = {
                'utf8': '✓',
                'authenticity_token': current_csrf,
                'otp_data': otp_to_submit
            }
            # Using session.post here as well
            # return requests.post(submit_otp_url, headers=submit_otp_headers, data=submit_otp_data, timeout=10) # OLD
            return current_session.post(submit_otp_url, headers=submit_otp_headers, data=submit_otp_data, timeout=10) # NEW, using passed session


        max_otp_attempts = 5 # User's max_retries
        otp_loop_attempts = 0
        otp_value_found = None
        
        yield "data: " + json.dumps({"status": "processing", "message": f"Starting OTP retrieval process (up to {max_otp_attempts} attempts)..."}) + "\n\n"
        await asyncio.sleep(0.5)

        while otp_loop_attempts < max_otp_attempts:
            otp_loop_attempts += 1
            yield "data: " + json.dumps({"status": "processing", "message": f"Fetching OTP from email (Attempt {otp_loop_attempts}/{max_otp_attempts})..."}) + "\n\n"
            await asyncio.sleep(0.5) # Give client time to see message before blocking call

            loop = asyncio.get_event_loop()
            try:
                 # Running synchronous email fetching in executor
                otp_value_found = await loop.run_in_executor(None, get_first_email_from_sender)
            except Exception as e:
                yield "data: " + json.dumps({"status": "step_error", "message": f"Error during email fetching: {e}"}) + "\n\n"
                await asyncio.sleep(0.5)
                if otp_loop_attempts < max_otp_attempts:
                    await asyncio.sleep(5) # User's wait_seconds
                    continue
                else:
                    break # Exhausted attempts due to email fetch error

            if not otp_value_found:
                yield "data: " + json.dumps({"status": "step_error", "message": "OTP not found in email on this attempt."}) + "\n\n"
                await asyncio.sleep(0.5)
                if otp_loop_attempts < max_otp_attempts:
                    user_wait_seconds = 5 # From user's code (wait_seconds)
                    yield "data: " + json.dumps({"status": "processing", "message": f"Retrying OTP fetch in {user_wait_seconds}s..."}) + "\n\n"
                    await asyncio.sleep(user_wait_seconds)
                    continue
                else:
                    break # Exhausted attempts

            yield "data: " + json.dumps({"status": "step_success", "message": f"OTP found: {otp_value_found}. Submitting..."}) + "\n\n"
            await asyncio.sleep(0.5)
            yield "data: " + json.dumps({"status": "processing", "message": f"Submitting OTP (Attempt {otp_loop_attempts}/{max_otp_attempts})..."}) + "\n\n"
            await asyncio.sleep(0.5)

            try:
                # Running synchronous OTP submission in executor
                otp_submit_response = await loop.run_in_executor(None, send_otp_request_sync, session, otp_value_found, csrf, quikchex_app_session) # Added session

                if otp_submit_response.status_code == 200 and ("window.location.replace" in otp_submit_response.text or "dashboard" in otp_submit_response.text.lower() or "https://secure.quikchex.in/" in otp_submit_response.text): # User's success condition + previous
                    yield "data: " + json.dumps({"status": "step_success", "message": "OTP verification successful!"}) + "\n\n"
                    await asyncio.sleep(0.5)
                    otp_verified = True # New flag to signal overall success
                    break # Exit the while loop for OTP attempts
                elif otp_submit_response.status_code == 200 and "$('.error').show();" in otp_submit_response.text: # Specific error case
                     err_msg = "OTP verification failed (QuikChex error: $('.error').show();)."
                     yield "data: " + json.dumps({"status": "step_error", "message": err_msg}) + "\n\n"
                     await asyncio.sleep(0.5)
                else: # Other OTP submission failure
                    err_msg = f"OTP verification failed. Status: {otp_submit_response.status_code}. Response: {otp_submit_response.text[:100]}"
                    yield "data: " + json.dumps({"status": "step_error", "message": err_msg }) + "\n\n"
            
            except requests.RequestException as e:
                yield "data: " + json.dumps({"status": "step_error", "message": f"OTP submission request failed: {e}"}) + "\n\n"
                await asyncio.sleep(0.5)
            except Exception as e: # Catch other errors from run_in_executor for send_otp_request_sync
                yield "data: " + json.dumps({"status": "step_error", "message": f"Error during OTP submission: {e}"}) + "\n\n"
                await asyncio.sleep(0.5)

            if otp_loop_attempts < max_otp_attempts:
                user_wait_seconds = 5 # From user's code
                yield "data: " + json.dumps({"status": "processing", "message": f"Retrying entire OTP process in {user_wait_seconds}s..."}) + "\n\n"
                await asyncio.sleep(user_wait_seconds)
            else: # All attempts used up
                break
        
        # After the OTP loop
        otp_verified = False # Initialize before loop, set true on success
        # Re-check success condition from user's logic:
        # The loop above should set otp_verified = True and break on success.
        # Need to re-evaluate this logic based on the loop structure.
        # The user had `otp_found = True` and `if not otp_found:`
        # I'll use `otp_verified` flag.

        # Let's adjust the loop for OTP verification.
        # The previous loop structure was based on user's combined fetch & submit attempt.
        # The following is a more structured version for OTP process
        
        otp_verified_successfully = False # Flag for overall OTP success
        for attempt_num in range(1, max_otp_attempts + 1):
            yield "data: " + json.dumps({"status": "processing", "message": f"OTP Process Attempt {attempt_num}/{max_otp_attempts}: Fetching email..."}) + "\n\n"
            await asyncio.sleep(0.5)
            
            loop = asyncio.get_event_loop() # Get event loop inside for safety if it's called multiple times
            current_otp = None
            try:
                current_otp = await loop.run_in_executor(None, get_first_email_from_sender)
            except Exception as e:
                yield "data: " + json.dumps({"status": "step_error", "message": f"Error fetching email (Attempt {attempt_num}): {e}"}) + "\n\n"
                await asyncio.sleep(0.5)
                if attempt_num < max_otp_attempts: await asyncio.sleep(5); continue
                break

            if not current_otp:
                yield "data: " + json.dumps({"status": "step_error", "message": f"OTP not found in email (Attempt {attempt_num})."}) + "\n\n"
                await asyncio.sleep(0.5)
                if attempt_num < max_otp_attempts: await asyncio.sleep(5); continue # User's wait_seconds logic
                break

            yield "data: " + json.dumps({"status": "step_success", "message": f"OTP found: {current_otp}. Submitting..."}) + "\n\n"
            await asyncio.sleep(0.5)
            yield "data: " + json.dumps({"status": "processing", "message": f"Submitting OTP (Attempt {attempt_num})..."}) + "\n\n"
            await asyncio.sleep(0.5)

            try:
                otp_submit_response = await loop.run_in_executor(None, send_otp_request_sync, session, current_otp, csrf, quikchex_app_session)
                
                if otp_submit_response.status_code == 200 and \
                   ("window.location.replace" in otp_submit_response.text or \
                    "dashboard" in otp_submit_response.text.lower() or \
                    "https://secure.quikchex.in/" in otp_submit_response.text): # Combined success checks
                    yield "data: " + json.dumps({"status": "step_success", "message": "OTP verification successful!"}) + "\n\n"
                    await asyncio.sleep(0.5)
                    otp_verified_successfully = True
                    break # OTP verified, exit retry loop
                elif otp_submit_response.status_code == 200 and "$('.error').show();" in otp_submit_response.text:
                    msg = "OTP verification failed (QuikChex error: $('.error').show();)."
                    yield "data: " + json.dumps({"status": "step_error", "message": f"{msg} (Attempt {attempt_num})" }) + "\n\n"
                else:
                    msg = f"OTP verification failed. Status: {otp_submit_response.status_code}. Response: {otp_submit_response.text[:100]}"
                    yield "data: " + json.dumps({"status": "step_error", "message": f"{msg} (Attempt {attempt_num})" }) + "\n\n"
            except requests.RequestException as e:
                yield "data: " + json.dumps({"status": "step_error", "message": f"OTP submission request error (Attempt {attempt_num}): {e}"}) + "\n\n"
            except Exception as e: # Other errors from executor
                yield "data: " + json.dumps({"status": "step_error", "message": f"OTP submission internal error (Attempt {attempt_num}): {e}"}) + "\n\n"
            
            await asyncio.sleep(0.5)
            if attempt_num < max_otp_attempts and not otp_verified_successfully: # Only sleep and continue if not last attempt and not successful
                await asyncio.sleep(5) # Wait before retrying the whole OTP process
            
        if not otp_verified_successfully:
            yield "data: " + json.dumps({"status": "app_error", "message": f"Failed to verify OTP after {max_otp_attempts} attempts."}) + "\n\n"
            await asyncio.sleep(0.5)
            return

        # Step 5: Mark attendance
        yield "data: " + json.dumps({"status": "processing", "message": "Marking attendance..."}) + "\n\n"
        await asyncio.sleep(0.5)
        
        mark_attendance_url = 'https://secure.quikchex.in/companies/6268eafc22a8cf2f200000c6/employees/677b6f9cf866bc2cda7fe1c3/employee_daily_attendances/create_attendance_record.js?from_dashboard=true'
        mark_headers = { # From user's code, with X-CSRF-Token
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'If-None-Match': 'W/"37e48715a85fea3ae2eaac9c66e4381d"', # From user's code
            'Referer': 'https://secure.quikchex.in/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'X-CSRF-Token': csrf,
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"'
        }
        # Cookies for mark_attendance are managed by the session object
        try:
            # Using session.get
            marking_response = session.get(mark_attendance_url, headers=mark_headers, timeout=15)
            marking_response.raise_for_status() # Check for HTTP errors first

            if "already marked" in marking_response.text.lower() or "punch out" in marking_response.text.lower():
                 yield "data: " + json.dumps({"status": "app_success", "message": "✅ Attendance already marked for today or action completed."}) + "\n\n"
            elif "success" in marking_response.text.lower(): # General success
                 yield "data: " + json.dumps({"status": "app_success", "message": "✅ Attendance marked successfully! Have a great day!"}) + "\n\n"
            else:
                 # Status was 200, but content doesn't indicate success or already marked
                 yield "data: " + json.dumps({"status": "app_error", "message": f"⚠️ Failed to mark attendance. Unexpected response: {marking_response.text[:100]}"}) + "\n\n"

        except requests.RequestException as e:
             yield "data: " + json.dumps({"status": "app_error", "message": f"⚠️ Failed to mark attendance (request error): {e}"}) + "\n\n"
        await asyncio.sleep(0.5)

    except Exception as e:
        logging.exception("An unexpected error occurred in generate_attendance_stream") # Keep detailed server log
        yield "data: " + json.dumps({"status": "app_error", "message": f"❌ An unexpected server error occurred: {str(e)}"}) + "\n\n"
        await asyncio.sleep(0.5)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)