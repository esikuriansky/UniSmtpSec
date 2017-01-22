import smtplib
from os.path import basename
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, COMMASPACE
from email.mime.application import MIMEApplication

# This is the code for the malicious sender


RECIPIENT = 'innocentStudent88@uni.com'
SENDER = 'luckywinner@sweepstakes2017.gg'
SUBJECT = 'Your the special winner'
INFO = [RECIPIENT, SENDER, SUBJECT]


def attach_str(filename):
    return 'attachment; filename="{}"'.format(filename)


def create_message(send_from, send_to, subject, body, files=None):
    """
    Create with link to spoof website.
    msg_body : String containing Mail main text body.
    attachments: A list of files to be attached.
    """
    # Create the message
    msg = MIMEMultipart()
    msg['To'] = formataddr(('Recipient', COMMASPACE.join(send_to)))
    msg['From'] = formataddr(('Author', send_from))
    msg['Subject'] = subject
    msg.attach(MIMEText(body))

    # Add all files
    for filename in files:
        with open(filename, 'rb') as file:
            attachment = MIMEApplication(file.read())
            attachment['Content-Disposition'] = attach_str(filename)
            msg.attach(attachment)
    return msg


if __name__ == '__main__':
    """
    The hacker side code.
    Send the malicious file.
    """

    print "[*] Client started."
    print "[*] Creating message."

    msg = create_message(SENDER, [RECIPIENT], SUBJECT, "BOdy", ["files/ThEViRuS", "files/CleanFile"])

    print "[*] Starting server.."
    server = smtplib.SMTP('127.0.0.1', 2000)
    server.set_debuglevel(False)

    try:
        print "[*] Sending mail with two file attachments."
        print "[*] One malicious file 'ThEViRus'"
        print "[*] One clean file 'CleanFile'"
        server.sendmail(SENDER, [RECIPIENT], msg.as_string())
        print "[*] Sent."
    finally:
        server.quit()
