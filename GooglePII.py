from __future__ import print_function
from io import BytesIO
import PyPDF2._utils
import os
import re

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly', 
          'https://www.googleapis.com/auth/drive']

#function for authentication of scopes/credentials
def authentication():
    """Shows basic usage of the Drive v3 API.
    Prints the names and ids of the first 10 files the user has access to.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('drive', 'v3', credentials=creds)
    return service

#returns a dictionary with information about a specific number of files
def list_files(api, number_of_files):
    try:
        # Call the Drive v3 API
        results = api.files().list(
            pageSize=number_of_files, fields="nextPageToken, files(id, name, mimeType, owners, size)").execute()
        file_info = results.get('files', [])
        
        if not file_info:
            print('No files found.')
            return
        
        return file_info

    except HttpError as error:
        # TODO(developer) - Handle errors from drive API.
        print(f'An error occurred: {error}')

def view_file_contents(api, FILE_ID, MIME_TYPE, types):
    if MIME_TYPE in types.keys():
        content_test = api.files().export(fileId=FILE_ID, mimeType=types[MIME_TYPE]).execute()
        return content_test.decode('utf-8')
    elif MIME_TYPE == 'application/pdf':
        pdf_content = parse_pdf_content(api, FILE_ID)
        return pdf_content
    else: return

def has_pii_content(content):
   # Regular expressions to match different types of PII
   # phone_regex = r"\b(\d{3}-\d{3}-\d{4}|\(\d{3}\)\s*\d{3}-\d{4}|\d{10})\b"
   # email_regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    dob_regex = r"\b(birth|birthdate|birthday|dob|born)\w(\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})\b"
    ssn_regex = r"\b(\d{3}-\d{2}-\d{4}|\d{9})\b"
    credit_card_regex = r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b"
    bank_account_regex = r"^[a-zA-Z]{4}[a-zA-Z]{2}[a-zA-Z0-9]{2}[XXX0-9]{0,3}"
    
    

    # Search for different types of PII in the content
    # phone_match = re.search(phone_regex, content)
    # email_match = re.search(email_regex, content)
    dob_match = re.search(dob_regex, content)
    ssn_match = re.search(ssn_regex, content)
    credit_card_match = re.search(credit_card_regex, content)
    bank_account_match = re.search(bank_account_regex, content)
    

    if ssn_match:
        return re.findall(ssn_regex, content)
    elif credit_card_match:
        return re.findall(credit_card_regex, content)
    elif bank_account_match:
        return re.findall(bank_account_regex, content)
    elif dob_match:
        return re.findall(dob_regex, content)
    else: 
        return "none"
   # or dob_match:
       # return True
   # else:
       # return False

def parse_pdf_content(api, file_id):
    try:
        # Download the PDF file from Google Drive
        response = api.files().get_media(fileId=file_id).execute()
        content = response

        # Parse the PDF contents using PyPDF2
        pdf_reader = PyPDF2.PdfReader(BytesIO(content))

        parsed_text = ""
        for page in pdf_reader.pages:
            parsed_text += page.extract_text()

        return parsed_text

    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def main():
    api = authentication()

    #mimetypes
    types = {"application/vnd.google-apps.document":'text/plain', 
             "application/vnd.google-apps.presentation": 'text/plain', 
             "application/vnd.google-apps.spreadsheet":'text/csv'}
    
    #contains information about a number of files
    file_info = list_files(api, 300)
    count = 0
    unsupported_files = []

    #prints out file information followed by their contents
    print('File List:')
    print('_____________________________________________________________________________________________')

    for file in file_info:
        if (file['mimeType'] in types.keys() or file['mimeType'] == 'application/pdf') and ('size' in file.keys()):
            count += 1
            print(u'File Name: {0} \nID: ({1})\nType:  ({2})\nSize: ({3})\nOnwer: ({4})'.format(file['name'], file['id'], file['mimeType'], file['size'], file['owners'][0]['emailAddress']))

            #limit on the size of the file that is parsed
            if (int(file['size']) < 1000000):
                #print(view_file_contents(api, file['id'], file['mimeType'], types))
                file_content = view_file_contents(api, file['id'], file['mimeType'], types)
                print("Contains PII: " + str(has_pii_content(file_content)))
            else:
                print("File exceeds 1GB, time consuming to parse")

            print('_____________________________________________________________________________________________')
        else:
            unsupported_files.append(file)
    
    print('=============================================================================================')
    print('=============================================================================================')
    print('Number of Files Displayed: ' + str(count))

    #prints out unsupported files
    print('Unsupported Files: Folders, jpg, etc. \n')
    for file in unsupported_files:
        print(u'File Name: {0} \nID: ({1})\nType: ({2})\nOnwer: \
        {3})'.format(file['name'], file['id'], file['mimeType'], file['owners'][0]['emailAddress']))
        print('_____________________________________________________________________________________________')
    
    #filters out folders and shortcuts
    #print('Filtered out for Folders and shortcuts \n')
    #for name in unsupported_files.keys():
    #    if unsupported_files[name][1]  != 'application/vnd.google-apps.folder' and \
    #    unsupported_files[name][1] != 'application/vnd.google-apps.shortcut':
    #        print(name + ": " + str(unsupported_files[name]))

    
if __name__ == '__main__':
    main()
