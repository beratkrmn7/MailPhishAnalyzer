import os.path
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]  # mail oku + label ekle

class GmailClient:
    def __init__(self, credentials_file="credentials.json", token_file="token.json"):
        self.creds = None
        if os.path.exists(token_file):
            self.creds = Credentials.from_authorized_user_file(token_file, SCOPES)

        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
                self.creds = flow.run_local_server(port=0)
            with open(token_file, "w", encoding="utf-8") as token:
                token.write(self.creds.to_json())

        self.service = build("gmail", "v1", credentials=self.creds)

    def list_message_ids(self, query, max_results=25):
        res = self.service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
        msgs = res.get("messages", [])
        return [m["id"] for m in msgs]

    def get_message(self, msg_id):
        return self.service.users().messages().get(userId="me", id=msg_id, format="full").execute()

    def get_or_create_label_id(self, label_name):
        labels = self.service.users().labels().list(userId="me").execute().get("labels", [])
        for lb in labels:
            if lb.get("name") == label_name:
                return lb["id"]

        created = self.service.users().labels().create(
            userId="me",
            body={
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        ).execute()
        return created["id"]

    def add_label(self, msg_id, label_id):
        self.service.users().messages().modify(
            userId="me",
            id=msg_id,
            body={"addLabelIds": [label_id], "removeLabelIds": []},
        ).execute()