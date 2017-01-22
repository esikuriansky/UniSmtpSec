import email
import smtpd
import asyncore
import requests
import binascii
import hashlib
import os

# ==========================================================
#                   VirusTotal details
# ==========================================================
REQUEST_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
RESPONSE_URL = "https://www.virustotal.com/vtapi/v2/file/report"

API_KEY = open("secureSMTP/VT_APIKEY", "r").read()


class SecureSMTPServer(smtpd.SMTPServer):
    """
    """

    def response_virustotal(self, scan_id):
        """
        Await virus total to finish checking
        Returns true in file is safe false otherwise.
        """
        params = {'apikey': API_KEY, 'resource': scan_id}
        resonse_ready = False
        while not resonse_ready:
            try:
                response = requests.get(RESPONSE_URL, params=params)
                json_response = response.json()
                if json_response['response_code'] == 1:
                    resonse_ready = True
            except ValueError:
                pass
        return json_response['positives'] == 0

    def request_virustotal(self, file_name):
        """
        Run online virus scan on www.virustotal.com
        """
        params = {'apikey': API_KEY}
        files = {'file': (file_name, open(file_name, 'rb'))}
        response = requests.post(REQUEST_URL, files=files, params=params)
        json_response = response.json()
        scan_id = json_response['scan_id']
        return self.response_virustotal(scan_id)

    def check_sha1(self, file):
        """
        Check file sha1
        Returns true in file is safe false otherwise.
        """
        data = open(file, 'rb').read()
        hash_object = hashlib.sha1(data)
        hex_dig = hash_object.hexdigest()

        # check is sha1 is in local sha1's file
        with open("secureSMTP/infected_sha1s", "r") as f:
            virus_sha1s = map(lambda line: line.replace('\n', ''), f.readlines())
        return hex_dig not in virus_sha1s

    def check_signatures(self, file_name):
        """
        Returns true in file is safe false otherwise.
        """
        with open(file_name, 'rb') as f, open('secureSMTP/known_signatures', 'rb') as sigs:
            signatures = sigs.readlines()
            file_bytes = f.read()

        for signature in signatures:
            if signature in file_bytes:
                return False

        return True

    def handle_attachment(self, file_attach):
        """
        write attachment to file and run
        detections mechanism to verify the file.
        """
        file_name = "temp.txt"
        with open(file_name, 'wb') as file:
            file.write(file_attach)

        is_infected = self.check_sha1("temp.txt") \
                      and self.check_signatures("temp.txt") \
                      and self.request_virustotal("temp.txt")

        return not is_infected

    def process_message(self, peer, mailfrom, rcpttos, data):
        """
        """
        print "=" * 50
        print '[*] Receiving message from:', peer
        print '[*] Message addressed from:', mailfrom
        print '[*] Message addressed to  :', rcpttos

        malicious = False

        msg = email.message_from_string(data)
        for part in msg.walk():
            """
            """
            ctype = part.get_content_type()
            if ctype == 'multipart/mixed':
                continue
            if "attachment" in str(part.get('Content-Disposition')):
                filename = os.path.basename(part.get_filename())
                # now part is a attachment
                file_data = part.get_payload(decode=True)
                is_mal = self.handle_attachment(file_data)
                print "[*] File [{}], mallicious: {}".format(filename, is_mal)
                # delete temp file
                os.remove("temp.txt")
                if is_mal:
                    malicious = True



        if malicious:
            print "[*] Mail is malicious. Returning error code 550 ..."
            return '550 Aborted'

        return


server = SecureSMTPServer(('127.0.0.1', 2000), None)
print "[*] Starting SecureSMTPServer ... "
asyncore.loop()
