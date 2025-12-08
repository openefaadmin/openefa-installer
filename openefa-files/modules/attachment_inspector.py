#!/usr/bin/env python3
"""
Attachment Inspector Module

Uses libmagic to detect:
- File type mismatches (claimed vs actual)
- Disguised executables
- Dangerous file types
- Archive bombs
- HTML form submitters
- Macro-enabled documents

Returns spam score and detailed analysis.
"""

import magic
import os
import re
import zipfile
import tarfile
import py7zr
import logging
from email.message import EmailMessage
from typing import Dict, List, Tuple, Optional
from io import BytesIO

logger = logging.getLogger(__name__)


class AttachmentInspector:
    """Inspector for deep attachment analysis using libmagic"""

    def __init__(self):
        """Initialize libmagic"""
        try:
            self.magic_mime = magic.Magic(mime=True)
            self.magic_desc = magic.Magic()
        except Exception as e:
            logger.error(f"Failed to initialize libmagic: {e}")
            self.magic_mime = None
            self.magic_desc = None

        # Dangerous file extensions (case-insensitive)
        self.dangerous_extensions = {
            'exe', 'com', 'bat', 'cmd', 'scr', 'pif', 'vbs', 'vbe',
            'js', 'jse', 'wsf', 'wsh', 'ps1', 'msi', 'app', 'deb',
            'rpm', 'dmg', 'pkg', 'dll', 'sys', 'drv', 'lnk', 'hta',
            'cpl', 'msc', 'jar', 'apk', 'ipa'
        }

        # Dangerous MIME types
        self.dangerous_mime_types = {
            'application/x-executable',
            'application/x-msdownload',
            'application/x-msdos-program',
            'application/x-sh',
            'application/x-shellscript',
            'application/x-perl',
            'application/x-python',
            'application/x-ruby',
            'application/x-wine-extension-ini',
            'application/java-archive',
            'application/vnd.android.package-archive',
        }

        # Macro-enabled Office documents
        self.macro_extensions = {
            'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm',
            'xlam', 'ppam', 'xlsb'
        }

        # Compressed archive types
        self.archive_types = {
            'application/zip',
            'application/x-rar',
            'application/x-7z-compressed',
            'application/x-tar',
            'application/gzip',
            'application/x-bzip2',
            'application/x-xz',
        }

    def analyze_attachments(self, msg: EmailMessage) -> Dict:
        """
        Analyze all attachments in an email message

        Args:
            msg: EmailMessage object

        Returns:
            Dict with analysis results and spam score
        """
        results = {
            'total_attachments': 0,
            'inspected_attachments': [],
            'mismatches': [],
            'dangerous_files': [],
            'archive_bombs': [],
            'html_forms': [],
            'macro_documents': [],
            'spam_score': 0.0,
            'details': []
        }

        if not self.magic_mime or not self.magic_desc:
            logger.warning("libmagic not initialized, skipping attachment inspection")
            return results

        try:
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    results['total_attachments'] += 1

                    filename = part.get_filename()
                    if not filename:
                        filename = f"unnamed_attachment_{results['total_attachments']}"

                    # Get attachment content
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue

                    # Inspect this attachment
                    inspection = self._inspect_attachment(filename, payload, part.get_content_type())
                    inspection['filename'] = filename
                    results['inspected_attachments'].append(inspection)

                    # Categorize findings
                    if inspection['type_mismatch']:
                        results['mismatches'].append({
                            'filename': filename,
                            'declared': inspection['declared_type'],
                            'actual': inspection['actual_type']
                        })
                        results['spam_score'] += 3.0  # Type mismatch is suspicious

                    if inspection['is_dangerous']:
                        results['dangerous_files'].append({
                            'filename': filename,
                            'reason': inspection['danger_reason']
                        })
                        results['spam_score'] += 8.0  # Dangerous file = high spam score

                    if inspection['is_archive_bomb']:
                        results['archive_bombs'].append(filename)
                        results['spam_score'] += 10.0  # Archive bomb = very high score

                    if inspection['has_html_form']:
                        results['html_forms'].append(filename)
                        results['spam_score'] += 4.0  # HTML forms can be phishing

                    if inspection['is_macro_doc']:
                        results['macro_documents'].append(filename)
                        results['spam_score'] += 5.0  # Macro docs are risky

                    # Add details
                    if inspection['warnings']:
                        results['details'].extend(inspection['warnings'])

        except Exception as e:
            logger.error(f"Error analyzing attachments: {e}")
            results['error'] = str(e)

        # Cap total spam score at reasonable maximum
        results['spam_score'] = min(results['spam_score'], 15.0)

        return results

    def _inspect_attachment(self, filename: str, content: bytes, declared_mime: str) -> Dict:
        """
        Inspect a single attachment using libmagic

        Args:
            filename: Name of the file
            content: File content as bytes
            declared_mime: MIME type declared in email headers

        Returns:
            Dict with inspection results
        """
        result = {
            'filename': filename,
            'size': len(content),
            'declared_type': declared_mime,
            'actual_type': None,
            'actual_description': None,
            'extension': self._get_extension(filename),
            'type_mismatch': False,
            'is_dangerous': False,
            'danger_reason': None,
            'is_archive_bomb': False,
            'has_html_form': False,
            'is_macro_doc': False,
            'warnings': []
        }

        try:
            # Detect actual file type using libmagic
            actual_mime = self.magic_mime.from_buffer(content)
            actual_desc = self.magic_desc.from_buffer(content)

            result['actual_type'] = actual_mime
            result['actual_description'] = actual_desc

            # Check for type mismatch
            if not self._mime_types_match(declared_mime, actual_mime):
                result['type_mismatch'] = True
                result['warnings'].append(
                    f"Type mismatch: '{filename}' claims to be {declared_mime} but is actually {actual_mime}"
                )

            # Check for dangerous file types
            ext_lower = result['extension'].lower()

            # 1. Executable disguised as document
            if self._is_executable(actual_mime, actual_desc):
                if ext_lower not in self.dangerous_extensions:
                    result['is_dangerous'] = True
                    result['danger_reason'] = f"Executable disguised as {result['extension']}"
                    result['warnings'].append(
                        f"DANGER: '{filename}' is an executable file disguised with .{result['extension']} extension"
                    )
                else:
                    result['is_dangerous'] = True
                    result['danger_reason'] = f"Executable file (.{ext_lower})"
                    result['warnings'].append(
                        f"DANGER: '{filename}' is an executable file"
                    )

            # 2. Script files
            if self._is_script(actual_mime, actual_desc):
                result['is_dangerous'] = True
                result['danger_reason'] = "Script file"
                result['warnings'].append(f"DANGER: '{filename}' contains executable script")

            # 3. Macro-enabled documents
            if ext_lower in self.macro_extensions:
                result['is_macro_doc'] = True
                result['warnings'].append(f"Macro-enabled document: '{filename}'")

            # 4. Check for archive bombs
            if actual_mime in self.archive_types:
                is_bomb, compression_ratio = self._check_archive_bomb(content, actual_mime)
                if is_bomb:
                    result['is_archive_bomb'] = True
                    result['warnings'].append(
                        f"ARCHIVE BOMB: '{filename}' has suspicious compression ratio {compression_ratio}:1"
                    )

                # 4b. Extract and scan archive contents
                archive_threats = self._scan_archive_contents(content, actual_mime, filename)
                if archive_threats:
                    result['archive_contents_dangerous'] = True
                    result['warnings'].extend(archive_threats)
                    # Mark as dangerous if executables found inside
                    for threat in archive_threats:
                        if 'executable' in threat.lower() or 'script' in threat.lower():
                            result['is_dangerous'] = True
                            result['danger_reason'] = "Dangerous file inside archive"
                            break

            # 5. Check HTML attachments for forms
            if 'html' in actual_mime.lower() or 'html' in actual_desc.lower():
                if self._has_html_form(content):
                    result['has_html_form'] = True
                    result['warnings'].append(
                        f"HTML form found in '{filename}' - possible phishing"
                    )

            # 6. Double extension trick (e.g., file.pdf.exe)
            if self._has_double_extension(filename):
                result['warnings'].append(
                    f"Suspicious filename: '{filename}' has multiple extensions"
                )
                result['spam_score'] = result.get('spam_score', 0) + 2.0

        except Exception as e:
            logger.error(f"Error inspecting attachment {filename}: {e}")
            result['error'] = str(e)

        return result

    def _get_extension(self, filename: str) -> str:
        """Extract file extension"""
        if '.' in filename:
            return filename.rsplit('.', 1)[1]
        return ''

    def _mime_types_match(self, declared: str, actual: str) -> bool:
        """Check if declared and actual MIME types match (with some tolerance)"""
        if not declared or not actual:
            return True

        declared_lower = declared.lower()
        actual_lower = actual.lower()

        # Exact match
        if declared_lower == actual_lower:
            return True

        # Common variants that are OK
        variants = {
            'application/octet-stream': True,  # Generic binary - accept anything
            'text/plain': ['text/html', 'text/x-c', 'text/x-script'],  # Text variants
            'application/pdf': ['application/x-pdf'],
            'application/zip': ['application/x-zip-compressed'],
        }

        if declared_lower in variants:
            if variants[declared_lower] is True:
                return True
            if actual_lower in variants[declared_lower]:
                return True

        # Check if base types match (e.g., text/* matches text/plain)
        declared_base = declared_lower.split('/')[0]
        actual_base = actual_lower.split('/')[0]

        return declared_base == actual_base

    def _is_executable(self, mime_type: str, description: str) -> bool:
        """Check if file is an executable"""
        mime_lower = mime_type.lower()
        desc_lower = description.lower()

        # Check MIME type
        if mime_lower in self.dangerous_mime_types:
            return True

        # Check description for executable indicators
        exec_indicators = [
            'executable', 'pe32', 'pe32+', 'ms-dos executable',
            'elf ', 'mach-o', 'com executable', 'batch'
        ]

        return any(indicator in desc_lower for indicator in exec_indicators)

    def _is_script(self, mime_type: str, description: str) -> bool:
        """Check if file is a script"""
        script_indicators = [
            'script', 'shellscript', 'python', 'perl', 'ruby',
            'javascript', 'vbscript', 'powershell'
        ]

        desc_lower = description.lower()
        return any(indicator in desc_lower for indicator in script_indicators)

    def _check_archive_bomb(self, content: bytes, mime_type: str) -> Tuple[bool, float]:
        """
        Check if archive is a bomb (excessive compression ratio)

        Returns:
            (is_bomb, compression_ratio)
        """
        try:
            compressed_size = len(content)
            uncompressed_size = 0

            # Check ZIP files
            if 'zip' in mime_type:
                try:
                    with zipfile.ZipFile(BytesIO(content)) as zf:
                        for info in zf.infolist():
                            uncompressed_size += info.file_size

                            # Stop counting if we already detect a bomb
                            if uncompressed_size > compressed_size * 100:
                                break
                except Exception as e:
                    logger.debug(f"Could not inspect ZIP archive: {e}")
                    return False, 0.0

            # Check 7z files
            elif '7z' in mime_type or 'x-7z' in mime_type:
                try:
                    with py7zr.SevenZipFile(BytesIO(content), mode='r') as szf:
                        for info in szf.list():
                            uncompressed_size += info.uncompressed

                            # Stop counting if we already detect a bomb
                            if uncompressed_size > compressed_size * 100:
                                break
                except Exception as e:
                    logger.debug(f"Could not inspect 7z archive: {e}")
                    return False, 0.0

            if uncompressed_size > 0 and compressed_size > 0:
                ratio = uncompressed_size / compressed_size

                # Flag as bomb if ratio > 100:1
                if ratio > 100:
                    return True, ratio

                return False, ratio

        except Exception as e:
            logger.debug(f"Error checking archive bomb: {e}")

        return False, 0.0

    def _scan_archive_contents(self, content: bytes, mime_type: str, archive_name: str) -> List[str]:
        """
        Extract and scan files inside ZIP/7z archive for threats

        Args:
            content: Archive file content as bytes
            mime_type: MIME type of archive
            archive_name: Name of the archive file

        Returns:
            List of threat warning strings
        """
        threats = []
        max_files_to_scan = 50  # Safety limit
        max_file_size = 10 * 1024 * 1024  # 10MB per file
        files_scanned = 0

        try:
            # Scan ZIP files
            if 'zip' in mime_type.lower():
                threats.extend(self._scan_zip_contents(content, archive_name, max_files_to_scan, max_file_size))

            # Scan 7z files
            elif '7z' in mime_type.lower() or 'x-7z' in mime_type.lower():
                threats.extend(self._scan_7z_contents(content, archive_name, max_files_to_scan, max_file_size))

        except Exception as e:
            logger.debug(f"Error scanning archive contents: {e}")

        return threats

    def _scan_zip_contents(self, content: bytes, archive_name: str, max_files: int, max_size: int) -> List[str]:
        """Scan ZIP archive contents"""
        threats = []
        files_scanned = 0

        try:
            with zipfile.ZipFile(BytesIO(content)) as zf:
                for file_info in zf.infolist():
                    # Skip directories
                    if file_info.is_dir():
                        continue

                    # Safety limits
                    if files_scanned >= max_files:
                        threats.append(f"ZIP '{archive_name}': Too many files, stopped scanning at {max_files}")
                        break

                    if file_info.file_size > max_size:
                        # Check filename extension for large files
                        ext = file_info.filename.rsplit('.', 1)[-1].lower() if '.' in file_info.filename else ''
                        if ext in self.dangerous_extensions:
                            threats.append(
                                f"🔴 ZIP '{archive_name}': Contains LARGE EXECUTABLE '{file_info.filename}' ({file_info.file_size / 1024 / 1024:.1f}MB) - TOO LARGE TO SCAN SAFELY"
                            )
                        else:
                            threats.append(f"ZIP '{archive_name}': Skipped large file '{file_info.filename}' ({file_info.file_size / 1024 / 1024:.1f}MB)")
                        continue

                    try:
                        # Extract file content
                        extracted_content = zf.read(file_info.filename)
                        files_scanned += 1

                        # Scan with libmagic
                        actual_type = self.magic_mime.from_buffer(extracted_content)
                        actual_desc = self.magic_desc.from_buffer(extracted_content)

                        # Check if dangerous
                        is_exec = self._is_executable(actual_type, actual_desc)
                        is_script = self._is_script(actual_type, actual_desc)

                        if is_exec:
                            threats.append(
                                f"🔴 ZIP '{archive_name}': Contains EXECUTABLE '{file_info.filename}' ({actual_type})"
                            )
                        elif is_script:
                            threats.append(
                                f"🔴 ZIP '{archive_name}': Contains SCRIPT '{file_info.filename}' ({actual_desc})"
                            )

                        # Check for macro documents
                        ext = file_info.filename.rsplit('.', 1)[-1].lower() if '.' in file_info.filename else ''
                        if ext in self.macro_extensions:
                            threats.append(
                                f"📄 ZIP '{archive_name}': Contains MACRO document '{file_info.filename}'"
                            )

                        # Check for nested archives
                        if actual_type in self.archive_types:
                            threats.append(
                                f"📦 ZIP '{archive_name}': Contains nested archive '{file_info.filename}'"
                            )

                    except Exception as e:
                        logger.debug(f"Error scanning file '{file_info.filename}' in ZIP: {e}")
                        continue

        except zipfile.BadZipFile:
            logger.debug(f"Bad ZIP file: {archive_name}")
        except Exception as e:
            logger.debug(f"Error scanning ZIP contents: {e}")

        return threats

    def _scan_7z_contents(self, content: bytes, archive_name: str, max_files: int, max_size: int) -> List[str]:
        """Scan 7z archive contents"""
        import tempfile
        import shutil

        threats = []
        files_scanned = 0
        temp_dir = None

        try:
            # Create temporary directory for extraction
            temp_dir = tempfile.mkdtemp()

            with py7zr.SevenZipFile(BytesIO(content), mode='r') as szf:
                # Get file list first
                all_files = szf.list()

                # Build list of files to extract (excluding large ones and directories)
                files_to_extract = []
                for info in all_files:
                    if info.is_directory:
                        continue

                    if len(files_to_extract) >= max_files:
                        threats.append(f"7Z '{archive_name}': Too many files, stopped scanning at {max_files}")
                        break

                    if info.uncompressed > max_size:
                        ext = info.filename.rsplit('.', 1)[-1].lower() if '.' in info.filename else ''
                        if ext in self.dangerous_extensions:
                            threats.append(
                                f"🔴 7Z '{archive_name}': Contains LARGE EXECUTABLE '{info.filename}' ({info.uncompressed / 1024 / 1024:.1f}MB) - TOO LARGE TO SCAN SAFELY"
                            )
                        else:
                            threats.append(f"7Z '{archive_name}': Skipped large file '{info.filename}' ({info.uncompressed / 1024 / 1024:.1f}MB)")
                        continue

                    files_to_extract.append(info.filename)

                # Extract all files at once
                if files_to_extract:
                    szf.extract(targets=files_to_extract, path=temp_dir)

            # Now scan extracted files
            for filename in files_to_extract:
                try:
                    extracted_path = os.path.join(temp_dir, filename)

                    if not os.path.exists(extracted_path):
                        logger.debug(f"Extracted file not found: {extracted_path}")
                        continue

                    # Read file content
                    with open(extracted_path, 'rb') as f:
                        extracted_content = f.read()

                    files_scanned += 1

                    # Scan with libmagic
                    actual_type = self.magic_mime.from_buffer(extracted_content)
                    actual_desc = self.magic_desc.from_buffer(extracted_content)

                    # Check if dangerous
                    is_exec = self._is_executable(actual_type, actual_desc)
                    is_script = self._is_script(actual_type, actual_desc)

                    if is_exec:
                        threats.append(
                            f"🔴 7Z '{archive_name}': Contains EXECUTABLE '{filename}' ({actual_type})"
                        )
                    elif is_script:
                        threats.append(
                            f"🔴 7Z '{archive_name}': Contains SCRIPT '{filename}' ({actual_desc})"
                        )

                    # Check for macro documents
                    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                    if ext in self.macro_extensions:
                        threats.append(
                            f"📄 7Z '{archive_name}': Contains MACRO document '{filename}'"
                        )

                    # Check for nested archives
                    if actual_type in self.archive_types:
                        threats.append(
                            f"📦 7Z '{archive_name}': Contains nested archive '{filename}'"
                        )

                except Exception as e:
                    logger.debug(f"Error scanning file '{filename}' in 7z: {e}")
                    continue

        except Exception as e:
            logger.debug(f"Error scanning 7z contents: {e}")
        finally:
            # Clean up temp directory
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

        return threats

    def _has_html_form(self, content: bytes) -> bool:
        """Check if HTML content contains a form (phishing indicator)"""
        try:
            # Decode content
            text = content.decode('utf-8', errors='ignore')

            # Look for form tags
            if re.search(r'<form[^>]*>', text, re.IGNORECASE):
                return True

            # Look for common phishing form patterns
            phishing_patterns = [
                r'<input[^>]*type=["\']password["\']',
                r'<input[^>]*type=["\']email["\']',
                r'action=["\']https?://',
            ]

            for pattern in phishing_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return True

        except Exception as e:
            logger.debug(f"Error checking HTML form: {e}")

        return False

    def _has_double_extension(self, filename: str) -> bool:
        """Check for double extension tricks (file.pdf.exe)"""
        # Get all parts after removing spaces
        parts = filename.replace(' ', '').split('.')

        # If more than 2 parts and last part is dangerous
        if len(parts) > 2:
            last_ext = parts[-1].lower()
            if last_ext in self.dangerous_extensions:
                return True

        return False


def analyze_attachments(msg: EmailMessage) -> Dict:
    """
    Main entry point for attachment inspection

    Args:
        msg: EmailMessage object

    Returns:
        Dict with inspection results and spam score
    """
    inspector = AttachmentInspector()
    return inspector.analyze_attachments(msg)


# For testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    print("Attachment Inspector Test")
    print("=" * 60)

    # Test basic libmagic
    inspector = AttachmentInspector()

    # Test 1: Fake PDF (text file)
    fake_pdf = b"This is not a PDF file"
    result = inspector._inspect_attachment("document.pdf", fake_pdf, "application/pdf")
    print(f"\nTest 1 - Fake PDF:")
    print(f"  Type mismatch: {result['type_mismatch']}")
    print(f"  Declared: {result['declared_type']}")
    print(f"  Actual: {result['actual_type']}")

    # Test 2: Real PDF
    real_pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\ntest"
    result = inspector._inspect_attachment("invoice.pdf", real_pdf, "application/pdf")
    print(f"\nTest 2 - Real PDF:")
    print(f"  Type mismatch: {result['type_mismatch']}")
    print(f"  Actual: {result['actual_type']}")

    print("\n" + "=" * 60)
    print("✓ Attachment Inspector module created successfully")
