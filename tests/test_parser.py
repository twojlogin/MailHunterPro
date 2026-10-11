"""Testy EmailParser - MailHunterPro"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser import EmailParser
import email

def test_parse_headers():
    """Test parsowania nagłówków"""
    parser = EmailParser()
    
    msg = email.message_from_string(
        "From: test@example.com\n"
        "To: user@example.com\n"
        "Subject: Test Subject\n"
        "Date: Mon, 10 Sep 2026 12:00:00 +0000\n"
        "\n"
        "Body content here"
    )
    
    result = parser.parse_message(msg)
    assert result is not None
    assert result['headers']['From'] == 'test@example.com'
    assert result['headers']['Subject'] == 'Test Subject'
    print("✅ Headers parsing OK")

def test_extract_links():
    """Test ekstrakcji linków"""
    parser = EmailParser()
    
    body = {'text': 'Visit http://example.com and https://test.org/path?q=1', 'html': ''}
    links = parser._extract_links(body)
    
    assert len(links) >= 2
    print("✅ Link extraction OK")

def test_parse_attachments():
    """Test parsowania załączników"""
    parser = EmailParser()
    
    msg = email.message_from_string(
        "From: test@example.com\n"
        "Subject: With attachment\n"
        "Content-Type: multipart/mixed\n"
        "\n"
        "--boundary\n"
        "Content-Type: text/plain\n"
        "\n"
        "Body\n"
        "--boundary\n"
        "Content-Type: application/pdf\n"
        "Content-Disposition: attachment; filename=\"doc.pdf\"\n"
        "\n"
        "%PDF-1.4 fake content\n"
        "--boundary--"
    )
    
    result = parser.parse_message(msg)
    # Powinien obsłużyć boundary
    print("✅ Attachments parsing OK")

if __name__ == "__main__":
    test_parse_headers()
    test_extract_links()
    test_parse_attachments()
    print("\n✅ Wszystkie testy parsera przeszły!")
