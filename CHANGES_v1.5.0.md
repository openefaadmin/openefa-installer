# OpenEFA Installer v1.5.0 - Changes Summary

**Release Date:** October 18, 2025
**Previous Version:** 1.4.0

## Critical Bug Fixes

### 1. Spam Score Headers Not Stored in Database (HIGH SEVERITY)
**Problem:** Comprehensive spam score headers were added to emails but not appearing in the database.

**Root Cause:** Database storage happened BEFORE headers were added in email_filter.py

**Fix:** 
- Moved `store_email_analysis_via_queue()` call from line 2738 to line 2827
- Now executes AFTER all spam score headers are added
- All comprehensive headers now properly stored in raw_email field

**Impact:** Users can now see complete spam score breakdown in email headers stored in database

### 2. Duplicate Spam Score Headers
**Problem:** Two headers showing the same value:
- X-SpaCy-Spam-Score: 6.0 (legacy)
- X-Spam-Score-Total: 6.0 (new)

**Fix:** 
- Removed duplicate X-SpaCy-Spam-Score header
- Kept X-Spam-Score-Total as single source of truth

**Impact:** Cleaner, non-redundant email headers

### 3. Misleading Thread Analysis Header
**Problem:** Header showed "X-Thread-Analysis: disabled" even when thread analysis was fully functional

**Fix:**
- Removed misleading legacy fallback code (lines 2798-2809)
- Thread analysis headers now accurately reflect actual status

**Impact:** Thread analysis status properly displayed; confirmed all thread features working:
- Thread continuity checking
- Fake reply detection  
- Thread trust scoring
- Spam score adjustments for legitimate/fake replies

## Features from v1.4.0 (Included)

### Email Retention & Cleanup System
- 30-day automated email retention
- Configurable cleanup settings via GUI
- System settings table for centralized config
- Deleted email recovery within retention window
- Optional spam release prevention

### Mark as Not Spam Fix
- Properly updates spam_score and email_category
- Removes red spam indicator in UI

### Spam Score Breakdown Display
- Comprehensive breakdown card in email detail page
- Color-coded risk levels for each module
- Summary breakdown header

## Files Modified

### Core Email Processing
- `openefa-files/email_filter.py` - Header order fix, duplicate removal, thread cleanup
- `openefa-files/cleanup_expired_emails.py` - Automated cleanup script

### Web Interface
- `openefa-files/web/app.py` - Mark as not spam fix, cleanup routes
- `openefa-files/web/templates/email_detail.html` - Spam breakdown display
- `openefa-files/web/templates/config_dashboard.html` - Cleanup settings card

### Database Schema
- `sql/schema_v1.sql` - System settings table with retention config

## Testing Performed

✅ Spam headers stored in database correctly
✅ No duplicate headers in new emails  
✅ Thread analysis functioning properly
✅ Fake reply detection working (95% confidence)
✅ Email cleanup system operational
✅ Mark as not spam updates UI

## Upgrade Notes

This release includes critical bug fixes that improve email header visibility and accuracy. 

**Note:** Emails processed BEFORE this upgrade will not have X-Spam-Score-Total headers in their stored raw_email. Only emails processed AFTER upgrade will have complete headers.

## Installation

Run the installer on target server to apply all v1.5.0 changes.
