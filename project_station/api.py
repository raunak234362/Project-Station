import random, string, frappe
from frappe.auth import LoginManager
from datetime import datetime, timedelta

@frappe.whitelist(allow_guest = True)
def customLogin(usr,pwd):
        login_manager = LoginManager()
        login_manager.authenticate(usr,pwd)
        login_manager.post_login()
        if frappe.response['message'] == 'Logged In':
                user = login_manager.user
                frappe.response['key_details'] = generate_key(user)
                frappe.response['user_details'] = get_user_details(user)
        else:
                return False

def generate_key(user):
        user_details = frappe.get_doc("User", user)
        api_secret = api_key = ''
        if not user_details.api_key and not user_details.api_secret:
                api_secret = frappe.generate_hash(length=15)
                api_key = frappe.generate_hash(length=15)
                user_details.api_key = api_key
                user_details.api_secret = api_secret
                user_details.save(ignore_permissions = True)
        else:
                api_secret = user_details.get_password('api_secret')
                api_key = user_details.get('api_key')
        return {"api_secret": api_secret,"api_key": api_key}

def get_user_details(user):
        user_details = frappe.get_all("User",filters={"name":user},fields=["name","first_name","last_name","email","mobile_no","gender","role_profile_name"])
        if user_details:
                return user_details

@frappe.whitelist(allow_guest = True)
def generate_otp(email):
        otp = ''.join(random.choices(string.digits, k=6))
        expiry_time = datetime.now() + timedelta(minutes=5)  # OTP valid for 5 minutes

    # Save OTP in the database
        frappe.get_doc({
            'doctype': 'OTP Management',
            'email': email,
            'otp': otp,
            'expiry': expiry_time
        }).insert(ignore_permissions=True)

            # Send OTP via email
        send_otp_email(email, otp)


@frappe.whitelist(allow_guest = True)
def send_otp_email(email, otp):
        subject = "Your OTP for Verification"
        message = f"Your OTP is {otp}. It is valid for 5 minutes."
        frappe.sendmail(recipients=email, subject=subject, message=message)


@frappe.whitelist(allow_guest = True)
def verify_otp(email, entered_otp):
    # Fetch OTP details from the database
        otp_doc = frappe.get_all('OTP Management', filters={'email': email}, fields=['otp', 'expiry'], order_by="creation desc", limit_page_length=1)
        if not otp_doc:
                return {'status': 'failure', 'message': 'OTP not found'}

        otp_data = otp_doc[0]
        if datetime.now() > otp_data['expiry']:
                return {'status': 'failure', 'message': 'OTP has expired'}

        if entered_otp != otp_data['otp']:
                return {'status': 'failure', 'message': 'Invalid OTP'}

        return {'status': 'success', 'message': 'OTP verified successfully'}