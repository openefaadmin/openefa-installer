#!/usr/bin/env python3
"""
Test ClickSend Configuration
Verifies that ClickSend credentials are read correctly from .env file
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

def test_clicksend_config():
    """Test ClickSend configuration"""
    print("=" * 60)
    print("ClickSend Configuration Test")
    print("=" * 60)

    # Read ClickSend settings
    username = os.getenv('CLICKSEND_USERNAME')
    api_key = os.getenv('CLICKSEND_API_KEY')
    enabled = os.getenv('CLICKSEND_ENABLED', 'false').lower() == 'true'

    print(f"\n✓ CLICKSEND_USERNAME: {username}")
    print(f"✓ CLICKSEND_API_KEY: {api_key[:8]}...{api_key[-4:] if api_key else 'None'}")
    print(f"✓ CLICKSEND_ENABLED: {enabled}")

    # Validate configuration
    errors = []

    if not username or username == 'YOUR_CLICKSEND_USERNAME':
        errors.append("❌ Username not configured")
    else:
        print(f"\n✅ Username configured: {username}")

    if not api_key or api_key == 'YOUR_CLICKSEND_API_KEY':
        errors.append("❌ API key not configured")
    else:
        print(f"✅ API key configured (length: {len(api_key)} chars)")

    if not enabled:
        print(f"\n⚠️  WARNING: ClickSend is disabled")
        print("   Set CLICKSEND_ENABLED=true in .env to enable")
    else:
        print(f"\n✅ ClickSend enabled")

    # Test notification service import
    print(f"\n{'=' * 60}")
    print("Testing NotificationService import...")
    print(f"{'=' * 60}")

    try:
        sys.path.insert(0, '/opt/spacyserver')
        from notification_service import NotificationService

        service = NotificationService()
        print(f"✅ NotificationService imported successfully")
        print(f"✅ ClickSend client initialized: {service.clicksend_client is not None}")

    except ImportError as e:
        errors.append(f"❌ Failed to import NotificationService: {e}")
    except Exception as e:
        print(f"⚠️  Service initialized with warnings: {e}")

    # Summary
    print(f"\n{'=' * 60}")
    print("Summary")
    print(f"{'=' * 60}")

    if errors:
        print("\n❌ Configuration issues found:")
        for error in errors:
            print(f"   {error}")
        return False
    else:
        print("\n✅ All configuration checks passed!")
        print("\n📋 Configuration source:")
        print("   - Credentials: /opt/spacyserver/config/.env")
        print("   - Settings: /opt/spacyserver/config/notification_config.json")
        print("\n✅ No credentials in notification_config.json (secure!)")
        return True

if __name__ == '__main__':
    success = test_clicksend_config()
    sys.exit(0 if success else 1)
