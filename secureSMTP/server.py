import email
import smtpd
import asyncore
import requests
import hashlib
import os

# ==========================================================
#                   VirusTotal details
# ==========================================================
REQUEST_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
API_KEY = open("secureSMTP/VT_APIKEY", "r").read()


class SecureSMTPServer(smtpd.SMTPServer):
    def gets_online_db_check(self, scan_id):
        """
        Await virus total to finish checking
        """
        pass

    def check_virustotal(self, file_name):
        """
        Run online virus scan on www.virustotal.com
        Returns true in file is safe false otherwise.
        """
        params = {'apikey': API_KEY}
        files = {'file': (file_name, open(file_name, 'rb'))}
        response = requests.post(REQUEST_URL, files=files, params=params)
        json_response = response.json()
        print json_response

    def check_sha1(self, file):
        """
        Check file sha1
        """
        data = open(file, 'rb').read()
        hash_object = hashlib.sha1(data)
        hex_dig = hash_object.hexdigest()

        # check is sha1 is in local sha1's file
        with open("secureSMTP/infected_sha1s", "r") as f:
            virus_sha1s = map(lambda line: line.replace('\n', ''), f.readlines())

        return hex_dig in virus_sha1s

    def check_signatures(self, file):
        """
        Returns true in file is safe false otherwise.
        """
        pass

    def handle_attachment(self, file_attach):
        """
        write attachment to file and run
        detections mechanism to verify the file.
        """
        file_name = "temp.txt"
        with open(file_name, 'wb') as file:
            file.write(file_attach)

        # is_infected = self.send_online_db_check("temp.txt") \
        #               and self.check_signatures("temp.txt") \
        #               and self.check_sha1("temp.txt")
        is_infected = self.check_sha1(file_name)
        return is_infected

    def process_message(self, peer, mailfrom, rcpttos, data):
        # print 'Receiving message from:', peer
        # print 'Message addressed from:', mailfrom
        # print 'Message addressed to  :', rcpttos
        msg = email.message_from_string(data)

        for part in msg.walk():
            """
            """
            ctype = part.get_content_type()
            if ctype == 'multipart/mixed':
                continue
            if "attachment" in str(part.get('Content-Disposition')):
                # now part is a attachment
                file_data = part.get_payload(decode=True)
                print self.handle_attachment(file_data)
        return


server = SecureSMTPServer(('127.0.0.1', 2000), None)
print "[*] Starting SecureSMTPServer ... "
asyncore.loop()
