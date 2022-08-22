import getpass
from urllib import request
from ldap3 import Server, Connection,  ALL
from ldap3 import Tls
import random
import string
import requests
import re
import os
import pickle
# Gmail API utils
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
# for encoding/decoding messages in base64
from base64 import urlsafe_b64decode, urlsafe_b64encode
# for dealing with attachement MIME types
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from mimetypes import guess_type as guess_mime_type

SCOPES = ['https://mail.google.com/']
MAIL_ADDRESS = 'codewizardmfa@gmail.com'


def gmail_authenticate():
    creds = None
    # the file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    # if there are no (valid) credentials availablle, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('gmail_token.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # save the credentials for the next run
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)

def add_attachment(message, filename):
    content_type, encoding = guess_mime_type(filename)
    if content_type is None or encoding is not None:
        content_type = 'application/octet-stream'
    main_type, sub_type = content_type.split('/', 1)
    if main_type == 'text':
        fp = open(filename, 'rb')
        msg = MIMEText(fp.read().decode(), _subtype=sub_type)
        fp.close()
    elif main_type == 'image':
        fp = open(filename, 'rb')
        msg = MIMEImage(fp.read(), _subtype=sub_type)
        fp.close()
    elif main_type == 'audio':
        fp = open(filename, 'rb')
        msg = MIMEAudio(fp.read(), _subtype=sub_type)
        fp.close()
    else:
        fp = open(filename, 'rb')
        msg = MIMEBase(main_type, sub_type)
        msg.set_payload(fp.read())
        fp.close()
    filename = os.path.basename(filename)
    msg.add_header('Content-Disposition', 'attachment', filename=filename)
    message.attach(msg)

def build_message(destination, obj, body, attachments=[]):
    if not attachments: # no attachments given
        message = MIMEText(body)
        message['to'] = destination
        message['from'] = MAIL_ADDRESS
        message['subject'] = obj
    else:
        message = MIMEMultipart()
        message['to'] = destination
        message['from'] = MAIL_ADDRESS
        message['subject'] = obj
        message.attach(MIMEText(body))
        for filename in attachments:
            add_attachment(message, filename)
    return {'raw': urlsafe_b64encode(message.as_bytes()).decode()}

def send_message(service, destination, obj, body, attachments=[]):
    return service.users().messages().send(
      userId="me",
      body=build_message(destination, obj, body, attachments)
    ).execute()


SERVER_NAME = '127.0.0.1'
DN = "dc=code,dc=Wizard"
USERNAME = input("Enter user name: ")
PASSWORD = getpass.getpass(prompt="Enter password: ")
USER="cn="+USERNAME+",dc=code,dc=Wizard"
RO_USER = "cn=readonly,dc=code,dc=Wizard"
s = Server(SERVER_NAME, port=389, get_info=ALL)
c = Connection(s, user=USER, password=PASSWORD, check_names=True, lazy=False, raise_exceptions=False)
c.open()
c.bind()

if c.result["description"]=='success':
     c = Connection(s, user=RO_USER, password="readonly", check_names=True, lazy=False, raise_exceptions=False)
     c.open()
     c.bind()
     c.search(search_base=DN, search_filter="(cn="+USERNAME+")",attributes=['mail','entryUUID'])
     secretCode = ''.join(random.choice(string.ascii_letters) for i in range(8))
     reqUrl = "https://www.authenticatorApi.com/pair.aspx?AppName=codeWizardMfa&AppInfo="+str(c.entries[0]['entryUUID'])+"&SecretCode="+secretCode
     response = requests.get(reqUrl)
     p=re.search("Manually pair with (.*)' href.*src='(.*)'", response.text)
     print(str(p.group(1)))
     service = gmail_authenticate()
     send_message(service, str(c.entries[0]['mail']), "codeWizard MFA Verification", 
            "The Authentication code is: "+ p.group(1) + "\nyou can also verified by the QRCODE on the link: "+ p.group(2))
     OTP = input("Enter The Verification code from your email: ")
     verUrl = "https://www.authenticatorApi.com/Validate.aspx?Pin="+OTP+"&SecretCode="+ secretCode
     verResponse = requests.get(verUrl)
     if(verResponse.text=="True"):
          print("You succesfully authenticated:)")
     else:
          print("authentication failed on MFA:(")
else: 
     print("authentication to LDAP failed:(")

     

 
