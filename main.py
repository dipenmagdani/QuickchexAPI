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
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncio
import imaplib
import email
import urllib.parse
from pydantic import BaseModel

# Define request model
class AttendanceRequest(BaseModel):
    email: str
    quickchex_pass: str
    gmail_app_password: str

app = FastAPI()

# Create templates directory if it doesn't exist
os.makedirs("templates", exist_ok=True)

# Setup templates
templates = Jinja2Templates(directory="templates")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("quikchex_attendance.log"),
        logging.StreamHandler()
    ]
)

# Global variables to store credentials
EMAIL = ""
QUICKCHECKX_PASS = ""
GMAIL_APP_PASSWORD = ""

IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

# This function will generate and yield messages for our streaming response
async def generate_attendance_stream(user_email, quickchex_pass, gmail_app_password):
    try:
        yield "Starting QuikChex automation...\n"
        await asyncio.sleep(0.5)
        
        email_encoded = urllib.parse.quote(user_email)
        password_encoded = urllib.parse.quote(quickchex_pass)

        # Step 1 get the cookies from the URL
        url = "https://secure.quikchex.in"
        yield "Connecting to QuikChex...\n"

        # Set headers to mimic a browser
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        }

        # Make the request
        session = requests.Session()
        response = session.get(url, headers=headers)
        await asyncio.sleep(0.5)

        # Extract cookies
        cookies = session.cookies.get_dict()

        # Specifically print _quikchex_app_session if available
        quikchex_app_session = cookies.get('_quikchex_app_session')

        yield f"Session initialized, preparing login...\n"
        await asyncio.sleep(0.5)

        # Step 2: Use the cookies to log in
        url = 'https://secure.quikchex.in/users/sign_in'

        headers = {
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

        cookies = {
            '_quikchex_app_session': quikchex_app_session,
            '_ga': 'GA1.2.1477413030.1746601456',
            '_gid': 'GA1.2.164039213.1746601456',
            '_ga_PT2EQQ4DC6': 'GS2.2.s1746601456$o1$g1$t1746601456$j0$l0$h0'
        }

        data = f'utf8=%E2%9C%93&authenticity_token=L3Eb5Bf6VTa62DTPCmE-pjPCUfqEaJKGrFzv_12mhYTw5-zx8q39r3BQaO0Cm7F9ZPkmzThdvt6x6zvElkTdBA&user%5Bemail%5D={email_encoded}&user%5Bpassword%5D={password_encoded}&user%5Bremember_me%5D=0&user%5Bremember_me%5D=1'

        yield "Signing in to QuikChex...\n"
        sign_in_response = requests.post(url, headers=headers, cookies=cookies, data=data)
        await asyncio.sleep(0.5)
        
        csrf = None
        match = re.search(r'name="authenticity_token"\s+value="([^"]+)"', sign_in_response.text)
        if match:
            token = match.group(1)
            csrf = token
            yield "Authentication token obtained.\n"
        else:
            yield "Failed to get authentication token.\n"
            return
            
        for cookie in sign_in_response.cookies:
            if cookie.name == '_quikchex_app_session':
                quikchex_app_session = cookie.value

        # Step 3: Send the POST request to send OTP email
        yield "Requesting OTP email...\n"
        url = 'https://secure.quikchex.in/send_opt_email'

        headers = {
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
            'X-CSRF-Token': csrf,
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
        }

        cookies = {
            '_ga': 'GA1.2.1695919117.1746602525',
            '_gid': 'GA1.2.1822993054.1746602525',
            '_ga_PT2EQQ4DC6': 'GS2.2.s1746602524$o1$g1$t1746603500$j0$l0$h0',
            '_quikchex_app_session': quikchex_app_session,
            '_gat': '1'
        }

        # No data payload, just a POST with headers and cookies
        response = requests.post(url, headers=headers, cookies=cookies)
        yield f"Response: {response.text}\n"
        # await asyncio.sleep(0.5)

        if response.status_code == 200:
            yield "OTP email sent successfully. Waiting for email...\n"
        else:
            yield f"Error sending OTP email. Status code: {response.status_code}\n"
            return

        def get_first_email_from_sender(wait_time=60, polling_interval=5):
            """
            Gets the latest email from QuikChex and directly extracts the OTP.
            Args:
                wait_time: Maximum time to wait for the email in seconds
                polling_interval: Time between inbox checks in seconds`
            Returns:
                The extracted OTP code or None if not found
            """
            # Record the current time to search for newer emails
            start_time = time.time()
            search_since = time.strftime("%d-%b-%Y", time.localtime(start_time))
            print(f"Looking for QuikChex emails received after {search_since}")
            while time.time() - start_time < wait_time:
                try:
                    # Connect to the IMAP server
                    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
                    mail.login(user_email, gmail_app_password)
                    mail.select("inbox")
                    # Search for recent emails from QuikChex
                    search_query = f'(FROM "support@quikchex.in" SINCE "{search_since}")'
                    status, messages = mail.search(None, search_query)
                    if status != 'OK' or not messages[0]:
                        print("No recent QuikChex messages found")
                        time.sleep(polling_interval)
                        continue
                    email_ids = messages[0].split()
                    if not email_ids:
                        print(f"No new QuikChex emails found, waiting {polling_interval} seconds...")
                        mail.logout()
                        time.sleep(polling_interval)
                        continue
                    # Get the latest email
                    latest_email_id = email_ids[-1]
                    status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
                    for part in msg_data:
                        if isinstance(part, tuple):
                            msg = email.message_from_bytes(part[1])
                            # Get time information for debugging
                            date_str = msg.get("Date", "")
                            try:
                                # Parse email date format
                                parsed_date = email.utils.parsedate_to_datetime(date_str)
                                local_time = parsed_date.astimezone().strftime("%I:%M %p (%Y-%m-%d)")
                                print(f"Email time: {local_time}")
                            except Exception as e:
                                print(f"Error parsing date: {e}")
                            # Body
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
                            # Direct extraction of OTP using regex pattern matching
                            # Looking for patterns like "123456 is your One-Time Password"
                            otp_match = re.search(r'(\d{6})\s+is your One-Time Password', body_text)
                            if otp_match:
                                otp = otp_match.group(1)
                                print(f"OTP extracted: {otp}")
                                mail.logout()
                                return otp
                            # If regex didn't match, try a simpler approach
                            # Look for any 6-digit number in the email body
                            digit_match = re.search(r'\b(\d{6})\b', body_text)
                            if digit_match:
                                otp = digit_match.group(1)
                                print(f"OTP extracted (using digit pattern): {otp}")
                                mail.logout()
                                return otp
                            print("Could not find OTP in email body")
                            print("Email body preview:")
                            print(body_text[:200])
                    mail.logout()
                except Exception as e:
                    print(f"Error checking email: {e}")
                print(f"Waiting {polling_interval} seconds before checking again...")
                time.sleep(polling_interval)
            print("Timed out waiting for OTP email")
            return None

        def send_otp_request(otp, csrf, quikchex_app_session):
            url = 'https://secure.quikchex.in/get_otp'
            headers = {
                'Accept': '*/*;q=0.5, text/javascript, application/javascript, application/ecmascript, application/x-ecmascript',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://secure.quikchex.in',
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
            cookies = {
                '_ga': 'GA1.2.131216700.1746604931',
                '_gid': 'GA1.2.2013768816.1746604931',
                '_gat': '1',
                'remember_user_token': 'eyJfcmFpbHMiOnsibWVzc2FnZSI6Ilcxc2lOamMzWWpabU9XTm1PRFkyWW1NeVkyUmhOMlpsTVdNMklsMHNJaVF5WVNReE1DUndiV0U0UkhkbFFsTjVTM0pWT1dkNFNETllTVE4xSWl3aU1UYzBOall3TlRReU5pNDJOVEF5TXpnNElsMD0iLCJleHAiOiIyMDI1LTA1LTIxVDA4OjEwOjI2LjY1MFoiLCJwdXIiOm51bGx9fQ%3D%3D--0e0fe57416bfa47029ae2c46d34f6bac04531d93',
                '_quikchex_app_session': quikchex_app_session,
                '_ga_PT2EQQ4DC6': 'GS2.2.s1746604931$o1$g1$t1746605427$j0$l0$h0'
            }
            data = {
                'utf8': '✓',
                'authenticity_token': csrf,
                'otp_data': otp
            }
            return requests.post(url, headers=headers, cookies=cookies, data=data)

        # Main loop with retry
        max_retries = 5
        wait_seconds = 5
        attempts = 0
        yield "Waiting for OTP email...\n"
        await asyncio.sleep(5)  # Initial wait to allow for email delivery
        otp_found = False
        
        while attempts < max_retries:
            yield f"Attempt {attempts + 1} to fetch OTP...\n"
            otp = get_first_email_from_sender()
            if not otp:
                yield "OTP not found in email. Retrying...\n"
                await asyncio.sleep(wait_seconds)
                attempts += 1
                continue

            yield f"OTP found: {otp}. Submitting...\n"
            otp_response = send_otp_request(otp, csrf=csrf, quikchex_app_session=quikchex_app_session)
            
            if otp_response.status_code == 200 and "https://secure.quikchex.in/" in otp_response.text:
                yield "OTP verification successful!\n"
                otp_found = True
                break
            else:
                yield "OTP verification failed. Retrying...\n"
                await asyncio.sleep(wait_seconds)
                attempts += 1

        if not otp_found:
             yield "Failed to verify OTP after multiple attempts.\n"
             return

        # Step 5: Mark attendance
        yield "Marking attendance...\n"
        url = 'https://secure.quikchex.in/companies/6268eafc22a8cf2f200000c6/employees/677b6f9cf866bc2cda7fe1c3/employee_daily_attendances/create_attendance_record.js?from_dashboard=true'

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'If-None-Match': 'W/"37e48715a85fea3ae2eaac9c66e4381d"',
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

        cookies = {
            '_ga': 'GA1.2.131216700.1746604931',
            '_gid': 'GA1.2.2013768816.1746604931',
            '_quikchex_app_session': quikchex_app_session,
            '_ga_PT2EQQ4DC6': 'GS2.2.s1746604931$o1$g1$t1746605439$j0$l0$h0'
        }

        marking_response = requests.get(url, headers=headers, cookies=cookies)
        await asyncio.sleep(0.5)

        if marking_response.status_code == 200:
             yield "✅ Attendance marked successfully! Have a great day!\n"
        else:
             yield f"⚠️ Failed to mark attendance. Status code: {marking_response.status_code}\n"

    except Exception as e:
        yield f"❌ An error occurred: {str(e)}\n"# Create HTML template file# Create the main index pag

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "message": "API is running"}

# Mark attendance endpoint - get credentials from global variables
@app.post("/mark")
async def mark_attendance(data: AttendanceRequest):
    return StreamingResponse(
        generate_attendance_stream(
            user_email=data.email,
            quickchex_pass=data.quickchex_pass,
            gmail_app_password=data.gmail_app_password
        ),
        media_type="text/plain"
    )
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9003)