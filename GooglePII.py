import google.auth
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import re

# Authenticate using your Google Workspace API credentials
creds, project = google.auth.default(scopes=['https://www.googleapis.com/auth/drive.metadata.readonly'])

# Define the Google Drive API service
service = build('drive', 'v3', credentials=creds)

# Define a list of sensitive keywords to search for
sensitive_keywords = ['social security number', 'credit card', 'passport number']

# Define the regex pattern to match PII data
pattern = r"\b\d{3}-?\d{2}-?\d{4}\b|\b\d{4}-?\d{4}-?\d{4}-?\d{4}\b|\b\d{9}\b"

# Retrieve all shared drives in your Google Workspace domain
drives = service.drives().list().execute()

# Iterate through each shared drive and search for sensitive data in the files
for drive in drives['drives']:
    query = f"'{drive['id']}' in parents" # Search for files in the shared drive
    try:
        results = service.files().list(q=query, fields="nextPageToken, files(id, name, webViewLink)").execute()
        items = results.get('files', [])
        while True:
            for item in items:
                fileId = item['id']
                file_name = item['name']
                file_link = item['webViewLink']
                try:
                    file_metadata = service.files().get(fileId=fileId).execute()
                    file_content = service.files().export(fileId=fileId, mimeType='text/plain').execute()
                    content_str = file_content.decode('utf-8')
                    # Search for sensitive data using keywords and regex pattern
                    for keyword in sensitive_keywords:
                        if keyword in content_str:
                            print(f"{keyword} found in file {file_name} ({file_link})")
                    match = re.findall(pattern, content_str)
                    if match:
                        print(f"PII data found in file {file_name} ({file_link}): {', '.join(match)}")
                except HttpError as error:
                    print(f"An error occurred: {error}")
            page_token = results.get('nextPageToken', None)
            if page_token is None:
                break
            results = service.files().list(q=query, fields="nextPageToken, files(id, name, webViewLink)", pageToken=page_token).execute()
            items = results.get('files', [])
    except HttpError as error:
        print(f"An error occurred: {error}")
