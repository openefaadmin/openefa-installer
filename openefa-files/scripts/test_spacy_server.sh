#!/bin/bash
# Test script for SpaCy Email Filter Server
# Run this on the SpaCy server where email_filter.py is located

echo "=== SpaCy Email Filter Server Test ==="
echo "Testing authentication abuse detection in email_filter.py"
echo ""

# Test 1: Victoria Chavez with perfect authentication (should trigger auth abuse)
echo "Test 1: Victoria Chavez with perfect Salesforce authentication"
cat > /tmp/victoria_spacy_test.eml << 'EOF'
Return-Path: <bounce-12345_HTML-67890_ABC-123@bounce.s2.mc.pd25.com>
Delivered-To: scott@securedata247.com
Received: from mc.pd25.com (mc.pd25.com [192.0.2.100])
	by spacy.covereddata.com (Postfix) with ESMTP id 12345
	for <scott@securedata247.com>; Mon, 22 Jul 2025 15:30:00 -0700 (PDT)
Authentication-Results: mc.pd25.com;
	spf=pass (mc.pd25.com: domain of bounce-12345_HTML-67890_ABC-123@bounce.s2.mc.pd25.com designates 192.0.2.100 as permitted sender);
	dkim=pass header.d=pd25.com header.s=selector1;
	dmarc=pass (p=quarantine sp=quarantine pct=100)
From: "Victoria Chavez" <v.chavez@freshfinspartners.com>
Reply-To: v.chavez@freshfinspartners.com
To: scott@securedata247.com
Subject: Re: $250K Operational Funds Approved
Date: Mon, 22 Jul 2025 15:30:00 -0700
Message-ID: <victoria.test.123@freshfinspartners.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Scott,

Your business has been approved for $250K in operational capital.
This funding opportunity expires today and requires immediate action.

Please contact me to finalize your approval.

Best regards,
Victoria Chavez
Fresh Finance Partners
v.chavez@freshfinspartners.com
EOF

echo "Running email_filter.py on Victoria Chavez test email..."
echo ""

# Test the email filter
if [ -f "/opt/spacyserver/email_filter.py" ]; then
    echo "Found email_filter.py, running test..."
    /opt/spacyserver/venv/bin/python3 /opt/spacyserver/email_filter.py < /tmp/victoria_spacy_test.eml > /tmp/victoria_output.eml 2>/tmp/victoria_errors.log
    
    echo "=== SpaCy Processing Results ==="
    echo "1. Authentication Abuse Detection:"
    grep -E "X-Auth-Abuse" /tmp/victoria_output.eml || echo "   No X-Auth-Abuse headers found"
    
    echo ""
    echo "2. BEC Detection:"
    grep -E "X-BEC" /tmp/victoria_output.eml || echo "   No X-BEC headers found"
    
    echo ""
    echo "3. Funding Spam Detection:"
    grep -E "X-Funding" /tmp/victoria_output.eml || echo "   No X-Funding headers found"
    
    echo ""
    echo "4. SpaCy Spam Score:"
    grep -E "X-SpaCy-Spam-Score" /tmp/victoria_output.eml || echo "   No SpaCy spam score found"
    
    echo ""
    echo "5. Processing Errors (if any):"
    if [ -s /tmp/victoria_errors.log ]; then
        echo "   Errors found:"
        cat /tmp/victoria_errors.log
    else
        echo "   No processing errors"
    fi
    
    echo ""
    echo "=== Expected Results ==="
    echo "Should see:"
    echo "  - X-Auth-Abuse-Detected: true"
    echo "  - X-Auth-Abuse-Score: 20.0+ (for Salesforce Marketing abuse)"
    echo "  - X-Auth-Abuse-Reason: Salesforce Marketing abuse for financial scams"
    echo "  - High SpaCy spam score due to abuse penalty"
    
else
    echo "ERROR: email_filter.py not found at /opt/spacyserver/email_filter.py"
    echo "Please check the file location and permissions"
fi

echo ""
echo "================================"
echo ""

# Test 2: Normal legitimate email (should NOT trigger auth abuse)
echo "Test 2: Legitimate Datto email (should NOT trigger auth abuse)"
cat > /tmp/datto_test.eml << 'EOF'
Return-Path: <reporting@dattobackup.com>
Delivered-To: scott@securedata247.com
Received: from dattobackup.com (dattobackup.com [192.0.2.200])
	by spacy.covereddata.com (Postfix) with ESMTP id 54321
	for <scott@securedata247.com>; Mon, 22 Jul 2025 15:30:00 -0700 (PDT)
Authentication-Results: dattobackup.com;
	spf=pass;
	dkim=pass header.d=dattobackup.com;
	dmarc=pass
From: "Datto Backup Reports" <reporting@dattobackup.com>
To: scott@securedata247.com
Subject: Backup Report - SecureData247 - Success
Date: Mon, 22 Jul 2025 15:30:00 -0700
Message-ID: <datto.test.123@dattobackup.com>

Your backup completed successfully.
Backup size: 500GB
Duration: 2 hours 15 minutes
EOF

if [ -f "/opt/spacyserver/email_filter.py" ]; then
    echo "Testing legitimate email (should NOT trigger auth abuse)..."
    /opt/spacyserver/venv/bin/python3 /opt/spacyserver/email_filter.py < /tmp/datto_test.eml > /tmp/datto_output.eml 2>/tmp/datto_errors.log
    
    echo "Auth Abuse Detection for Datto:"
    grep -E "X-Auth-Abuse" /tmp/datto_output.eml || echo "   No auth abuse detected (GOOD)"
    
    echo "SpaCy Score for Datto:"
    grep -E "X-SpaCy-Spam-Score" /tmp/datto_output.eml || echo "   No spam score found"
fi

echo ""
echo "================================"
echo ""

echo "Next Steps:"
echo "1. If auth abuse detection is working, copy the output file to MailGuard:"
echo "   scp /tmp/victoria_output.eml mailguard:/tmp/"
echo ""
echo "2. Then run the MailGuard test script on the SpamAssassin server"
echo ""
echo "3. The combined results will show the full email processing pipeline"

# Clean up
rm -f /tmp/victoria_spacy_test.eml /tmp/datto_test.eml
# Keep output files for MailGuard testing
# rm -f /tmp/victoria_output.eml /tmp/datto_output.eml /tmp/victoria_errors.log /tmp/datto_errors.log
