#!/usr/bin/env python3
"""
ClamAV Antivirus Scanner Module for OpenEFA
Integrates with email_filter.py to scan email attachments for viruses

Author: OpenEFA Project
License: GPL-3.0
"""

import json
import logging
import os
import sys
from datetime import datetime
from email.message import EmailMessage
from typing import Dict, Any, Optional, List

# Setup logging
logger = logging.getLogger(__name__)

# Configuration file path
CONFIG_FILE = '/opt/spacyserver/config/antivirus_config.json'

# Try to import pyclamd
try:
    import pyclamd
    PYCLAMD_AVAILABLE = True
except ImportError:
    PYCLAMD_AVAILABLE = False
    logger.warning("pyclamd not available - antivirus scanning disabled")


class AntivirusScanner:
    """ClamAV antivirus scanner for email attachments"""

    def __init__(self, config_file: str = CONFIG_FILE):
        """Initialize antivirus scanner with configuration"""
        self.config = self._load_config(config_file)
        self.enabled = self.config.get('enabled', True) and PYCLAMD_AVAILABLE
        self.clamd_socket = self.config.get('clamd_socket', '/var/run/clamav/clamd.ctl')
        self.timeout = self.config.get('timeout', 120)
        self.max_file_size = self.config.get('max_file_size_mb', 50) * 1024 * 1024  # Convert to bytes
        self.cd = None

        if self.enabled:
            self._connect_to_clamd()

    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_file}, using defaults")
            return self._default_config()
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing config file: {e}, using defaults")
            return self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'enabled': True,
            'clamd_socket': '/var/run/clamav/clamd.ctl',
            'timeout': 120,
            'max_file_size_mb': 50,
            'scan_archives': True,
            'scan_pdf': True,
            'actions': {
                'virus_detected': 'quarantine',
                'scan_failed': 'pass_through'
            },
            'scoring': {
                'virus_detected': 20.0,
                'scan_error': 0.0
            }
        }

    def _connect_to_clamd(self) -> bool:
        """Connect to ClamAV daemon via Unix socket"""
        if not PYCLAMD_AVAILABLE:
            return False

        try:
            # Try Unix socket first
            if os.path.exists(self.clamd_socket):
                self.cd = pyclamd.ClamdUnixSocket(self.clamd_socket)
            else:
                # Fallback to network socket
                logger.warning(f"Socket {self.clamd_socket} not found, trying localhost:3310")
                self.cd = pyclamd.ClamdNetworkSocket('localhost', 3310)

            # Test connection
            if self.cd.ping():
                logger.info("Successfully connected to ClamAV daemon")
                return True
            else:
                logger.error("ClamAV daemon not responding to ping")
                self.enabled = False
                return False

        except Exception as e:
            logger.error(f"Failed to connect to ClamAV daemon: {e}")
            self.enabled = False
            return False

    def scan_email(self, msg: EmailMessage, performance_monitor=None) -> Dict[str, Any]:
        """
        Scan email for viruses

        Args:
            msg: EmailMessage object to scan
            performance_monitor: Optional performance monitoring object

        Returns:
            Dictionary with scan results
        """
        results = {
            'detected': False,
            'virus_name': None,
            'infected_files': [],
            'scanned_files': 0,
            'score_penalty': 0.0,
            'action': 'pass',
            'scan_errors': []
        }

        # Check if scanning is enabled
        if not self.enabled:
            logger.debug("Antivirus scanning disabled")
            return results

        # Reconnect if connection lost
        if self.cd is None or not self.cd.ping():
            logger.warning("ClamAV connection lost, attempting reconnect")
            if not self._connect_to_clamd():
                results['scan_errors'].append("ClamAV daemon unavailable")
                return results

        start_time = datetime.now() if performance_monitor else None

        # Get all attachments
        attachments = self._extract_attachments(msg)

        if not attachments:
            logger.debug("No attachments to scan")
            return results

        logger.info(f"Scanning {len(attachments)} attachment(s)")

        # Scan each attachment
        for filename, data in attachments:
            try:
                scan_result = self._scan_attachment(filename, data)
                results['scanned_files'] += 1

                if scan_result['detected']:
                    results['detected'] = True
                    results['virus_name'] = scan_result['virus_name']
                    results['infected_files'].append({
                        'filename': filename,
                        'virus': scan_result['virus_name'],
                        'size': len(data)
                    })
                    logger.warning(f"Virus detected in {filename}: {scan_result['virus_name']}")

            except Exception as e:
                logger.error(f"Error scanning {filename}: {e}")
                results['scan_errors'].append(f"{filename}: {str(e)}")

        # Set score penalty if virus detected
        if results['detected']:
            results['score_penalty'] = self.config.get('scoring', {}).get('virus_detected', 20.0)
            results['action'] = self.config.get('actions', {}).get('virus_detected', 'quarantine')

        # Log performance
        if performance_monitor and start_time:
            elapsed = (datetime.now() - start_time).total_seconds() * 1000
            logger.debug(f"Antivirus scan completed in {elapsed:.2f}ms")

        return results

    def _extract_attachments(self, msg: EmailMessage) -> List[tuple]:
        """
        Extract all attachments from email

        Returns:
            List of (filename, data) tuples
        """
        attachments = []

        for part in msg.walk():
            # Skip multipart containers
            if part.get_content_maintype() == 'multipart':
                continue

            # Skip text/html content
            if part.get_content_type() in ['text/plain', 'text/html']:
                continue

            # Get filename
            filename = part.get_filename()
            if not filename:
                # Generate filename for unnamed attachments
                ext = self._guess_extension(part.get_content_type())
                filename = f"unnamed_attachment{ext}"

            # Get attachment data
            try:
                data = part.get_payload(decode=True)
                if data:
                    # Check size limit
                    if len(data) > self.max_file_size:
                        logger.warning(f"Attachment {filename} exceeds size limit ({len(data)} bytes)")
                        continue

                    attachments.append((filename, data))
            except Exception as e:
                logger.error(f"Error extracting attachment {filename}: {e}")

        return attachments

    def _guess_extension(self, content_type: str) -> str:
        """Guess file extension from content type"""
        type_map = {
            'application/pdf': '.pdf',
            'application/zip': '.zip',
            'application/x-zip-compressed': '.zip',
            'application/msword': '.doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
            'application/vnd.ms-excel': '.xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif'
        }
        return type_map.get(content_type, '.bin')

    def _scan_attachment(self, filename: str, data: bytes) -> Dict[str, Any]:
        """
        Scan individual attachment

        Args:
            filename: Name of the file
            data: File content as bytes

        Returns:
            Dictionary with scan result
        """
        result = {
            'detected': False,
            'virus_name': None
        }

        try:
            # Scan buffer
            scan_result = self.cd.scan_stream(data)

            if scan_result:
                # scan_result format: {'stream': ('FOUND', 'Virus.Name')}
                for item in scan_result.values():
                    if item[0] == 'FOUND':
                        result['detected'] = True
                        result['virus_name'] = item[1]
                        break

        except Exception as e:
            logger.error(f"ClamAV scan error for {filename}: {e}")
            raise

        return result

    def get_version(self) -> Optional[str]:
        """Get ClamAV version"""
        if not self.enabled or self.cd is None:
            return None

        try:
            return self.cd.version()
        except Exception as e:
            logger.error(f"Error getting ClamAV version: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Get ClamAV statistics"""
        if not self.enabled or self.cd is None:
            return {
                'enabled': False,
                'daemon_status': 'not_connected'
            }

        try:
            stats = self.cd.stats()
            return {
                'enabled': True,
                'daemon_status': 'connected',
                'version': self.get_version(),
                'stats': stats
            }
        except Exception as e:
            logger.error(f"Error getting ClamAV stats: {e}")
            return {
                'enabled': True,
                'daemon_status': 'error',
                'error': str(e)
            }


# Module-level function for easy integration
def scan_email(msg: EmailMessage, performance_monitor=None) -> Dict[str, Any]:
    """
    Scan email for viruses (module-level function)

    Args:
        msg: EmailMessage object to scan
        performance_monitor: Optional performance monitoring object

    Returns:
        Dictionary with scan results
    """
    scanner = AntivirusScanner()
    return scanner.scan_email(msg, performance_monitor)


# Test function
if __name__ == "__main__":
    # Test with EICAR test file
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email import encoders

    # EICAR test string (harmless test file that all AV should detect)
    EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    # Create test email
    msg = MIMEMultipart()
    msg['Subject'] = 'Test Email with EICAR'
    msg['From'] = 'test@example.com'
    msg['To'] = 'recipient@example.com'

    # Add EICAR as attachment
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(EICAR)
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="eicar.com"')
    msg.attach(part)

    # Scan
    print("Testing ClamAV scanner...")
    result = scan_email(msg)

    print(f"Scan complete:")
    print(f"  Detected: {result['detected']}")
    print(f"  Virus: {result['virus_name']}")
    print(f"  Files scanned: {result['scanned_files']}")
    print(f"  Score penalty: {result['score_penalty']}")
