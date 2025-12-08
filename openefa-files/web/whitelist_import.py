#!/usr/bin/env python3
"""
Whitelist Import Routes for OpenEFA
Super Admin only - Import whitelists from CSV or JSON
"""

import os
import json
import csv
import tempfile
from datetime import datetime
from flask import Blueprint, render_template_string, request, flash, redirect, url_for, send_file, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import sys

# Add scripts directory to path
sys.path.insert(0, '/opt/spacyserver/scripts')
from import_efa_v5_whitelist import EFAv5Importer

whitelist_import_bp = Blueprint('whitelist_import', __name__)

ALLOWED_EXTENSIONS = {'csv', 'json'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def require_super_admin(f):
    """Decorator to require super admin role ONLY - no domain admins"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        # ONLY allow 'superadmin' role - NOT domain_admin or regular admin
        if current_user.role != 'superadmin':
            flash('Access denied. Super admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@whitelist_import_bp.route('/admin/whitelist/import', methods=['GET'])
@login_required
@require_super_admin
def import_page():
    """Whitelist import page"""
    return render_template_string(IMPORT_PAGE_TEMPLATE)

@whitelist_import_bp.route('/admin/whitelist/import/template')
@login_required
@require_super_admin
def download_template():
    """Download CSV template"""
    template_path = '/opt/spacyserver/templates/whitelist_import_template.csv'
    return send_file(template_path, as_attachment=True, download_name='whitelist_import_template.csv')

@whitelist_import_bp.route('/admin/whitelist/import/guide')
@login_required
@require_super_admin
def download_guide():
    """Download import guide"""
    guide_path = '/opt/spacyserver/templates/WHITELIST_IMPORT_GUIDE.txt'
    return send_file(guide_path, as_attachment=True, download_name='WHITELIST_IMPORT_GUIDE.txt')

@whitelist_import_bp.route('/admin/whitelist/import/preview', methods=['POST'])
@login_required
@require_super_admin
def preview_import():
    """Preview what will be imported"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only CSV and JSON allowed.'}), 400

    try:
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, filename)
        file.save(temp_path)

        # Check file size
        if os.path.getsize(temp_path) > MAX_FILE_SIZE:
            os.remove(temp_path)
            os.rmdir(temp_dir)
            return jsonify({'error': 'File too large. Maximum 10MB.'}), 400

        # Parse file to preview
        is_csv = filename.lower().endswith('.csv')
        preview_data = {
            'filename': filename,
            'file_type': 'CSV' if is_csv else 'JSON',
            'entries': [],
            'stats': {'senders': 0, 'domains': 0, 'errors': 0},
            'temp_path': temp_path
        }

        if is_csv:
            with open(temp_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row_num, row in enumerate(reader, start=2):
                    entry_type = row.get('entry_type', '').strip().lower()
                    value = row.get('value', '').strip()
                    for_domain = row.get('for_domain', '').strip()
                    description = row.get('description', '').strip()

                    entry = {
                        'row': row_num,
                        'type': entry_type,
                        'value': value,
                        'for_domain': for_domain,
                        'description': description,
                        'status': 'ok'
                    }

                    # Validate
                    if not entry_type or not value or not for_domain:
                        entry['status'] = 'error'
                        entry['error'] = 'Missing required fields'
                        preview_data['stats']['errors'] += 1
                    elif entry_type not in ['sender', 'domain']:
                        entry['status'] = 'error'
                        entry['error'] = 'Invalid entry_type'
                        preview_data['stats']['errors'] += 1
                    elif entry_type == 'sender' and '@' not in value:
                        entry['status'] = 'error'
                        entry['error'] = 'Invalid email format'
                        preview_data['stats']['errors'] += 1
                    else:
                        if entry_type == 'sender':
                            preview_data['stats']['senders'] += 1
                        else:
                            preview_data['stats']['domains'] += 1

                    preview_data['entries'].append(entry)

        else:  # JSON
            with open(temp_path, 'r') as f:
                data = json.load(f)

            domain = data.get('domain', 'Unknown')
            db_whitelists = data.get('whitelist_infrastructure', {}).get('database_whitelists', [])

            for idx, entry in enumerate(db_whitelists, start=1):
                from_address = entry.get('from_address', '')
                description = entry.get('description', '')

                if '@' in from_address:
                    preview_data['stats']['senders'] += 1
                    entry_type = 'sender'
                else:
                    preview_data['stats']['domains'] += 1
                    entry_type = 'domain'

                preview_data['entries'].append({
                    'row': idx,
                    'type': entry_type,
                    'value': from_address,
                    'for_domain': domain,
                    'description': description,
                    'status': 'ok'
                })

        # Store temp path in session for actual import
        # For now, we'll return it in the response (in production, use session)
        session_key = os.path.basename(temp_path)

        return jsonify({
            'success': True,
            'preview': preview_data,
            'session_key': session_key
        })

    except Exception as e:
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

@whitelist_import_bp.route('/admin/whitelist/import/execute', methods=['POST'])
@login_required
@require_super_admin
def execute_import():
    """Execute the actual import"""
    data = request.json
    temp_path = data.get('temp_path')

    if not temp_path or not os.path.exists(temp_path):
        return jsonify({'error': 'Invalid or expired import session'}), 400

    try:
        # Execute import
        importer = EFAv5Importer(temp_path)
        is_csv = temp_path.lower().endswith('.csv')

        if is_csv:
            importer.import_csv(temp_path)
        else:
            export_data = importer.load_export()
            importer.import_whitelists(export_data)

        # Log the import
        log_import(current_user.email, temp_path, importer.stats)

        # Cleanup temp file
        os.remove(temp_path)
        os.rmdir(os.path.dirname(temp_path))

        return jsonify({
            'success': True,
            'stats': importer.stats,
            'message': f'Successfully imported {importer.stats["whitelisted_senders"]} senders and {importer.stats["whitelisted_domains"]} domains'
        })

    except Exception as e:
        return jsonify({'error': f'Import failed: {str(e)}'}), 500

def log_import(admin_email, filename, stats):
    """Log whitelist import to audit log"""
    log_path = '/opt/spacyserver/logs/whitelist_import_audit.log'
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] IMPORT by {admin_email} | File: {os.path.basename(filename)} | Senders: {stats['whitelisted_senders']} | Domains: {stats['whitelisted_domains']} | Skipped: {stats['skipped']}\n"

    try:
        with open(log_path, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Warning: Could not write to import audit log: {e}")


# HTML Template for import page
IMPORT_PAGE_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Whitelist Import{% endblock %}

{% block extra_css %}
<style nonce="{{ csp_nonce }}">
    .preview-banner {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 0.75rem 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }

    .import-card {
        border: none;
        border-radius: 0.5rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
    }
</style>
{% endblock %}

{% block content %}
<div class="container-fluid px-4 py-2">
    <!-- Header Banner -->
    <div class="preview-banner mb-2">
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <h4 class="mb-1"><i class="fas fa-file-import me-2"></i>Whitelist Import</h4>
                <p class="mb-0 small">Import whitelists from CSV or JSON files (EFA v5 compatible)</p>
            </div>
            <div>
                <a href="{{ url_for('config_dashboard') }}" class="btn btn-light btn-sm">
                    <i class="fas fa-arrow-left"></i> Back to Config
                </a>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-4">
            <div class="card import-card">
                <div class="card-header bg-white border-bottom">
                    <h6 class="mb-0"><i class="fas fa-download"></i> Download Templates</h6>
                </div>
                <div class="card-body">
                    <p class="small">Download templates to prepare your import:</p>
                    <a href="{{ url_for('whitelist_import.download_template') }}" class="btn btn-primary btn-sm w-100 mb-2">
                        <i class="fas fa-file-csv"></i> CSV Template
                    </a>
                    <a href="{{ url_for('whitelist_import.download_guide') }}" class="btn btn-secondary btn-sm w-100">
                        <i class="fas fa-book"></i> Import Guide
                    </a>
                </div>
            </div>

            <div class="card import-card">
                <div class="card-header bg-white border-bottom">
                    <h6 class="mb-0"><i class="fas fa-info-circle"></i> Supported Formats</h6>
                </div>
                <div class="card-body">
                    <ul class="small mb-0">
                        <li><strong>CSV:</strong> General whitelist imports</li>
                        <li><strong>JSON:</strong> EFA v5 exports</li>
                        <li><strong>Max Size:</strong> 10MB</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="col-md-8">
            <div class="card import-card">
                <div class="card-header bg-white border-bottom">
                    <h6 class="mb-0"><i class="fas fa-upload"></i> Upload Import File</h6>
                </div>
                <div class="card-body">
                    <form id="uploadForm" enctype="multipart/form-data">
                        <div class="mb-3">
                            <label for="importFile" class="form-label">Select CSV or JSON file:</label>
                            <input type="file" class="form-control" id="importFile" accept=".csv,.json" required>
                            <small class="form-text text-muted">Only .csv and .json files are accepted (max 10MB)</small>
                        </div>
                        <button type="submit" class="btn btn-primary btn-sm">
                            <i class="fas fa-search"></i> Preview Import
                        </button>
                    </form>
                </div>
            </div>

            <div id="previewSection" class="card import-card" style="display: none;">
                <div class="card-header bg-white border-bottom">
                    <h6 class="mb-0"><i class="fas fa-eye"></i> Import Preview</h6>
                </div>
                <div class="card-body">
                    <div id="previewStats" class="alert alert-info"></div>
                    <div id="previewTable" class="table-responsive" style="max-height: 400px; overflow-y: auto;"></div>
                    <div id="previewActions" class="mt-3">
                        <button id="confirmImport" class="btn btn-success btn-sm">
                            <i class="fas fa-check"></i> Confirm Import
                        </button>
                        <button id="cancelImport" class="btn btn-secondary btn-sm">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                    </div>
                </div>
            </div>

            <div id="resultSection" class="card import-card" style="display: none;">
                <div class="card-header bg-white border-bottom">
                    <h6 class="mb-0"><i class="fas fa-check-circle"></i> Import Complete</h6>
                </div>
                <div class="card-body">
                    <div id="resultMessage"></div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
let previewData = null;

document.getElementById('uploadForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const fileInput = document.getElementById('importFile');
    const file = fileInput.files[0];

    if (!file) {
        alert('Please select a file');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('{{ url_for("whitelist_import.preview_import") }}', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Preview failed');
        }

        previewData = result.preview;
        displayPreview(result.preview);

    } catch (error) {
        alert('Error: ' + error.message);
    }
});

function displayPreview(preview) {
    const statsHtml = `
        <strong>File:</strong> ${preview.filename} (${preview.file_type})<br>
        <strong>Total Entries:</strong> ${preview.entries.length}<br>
        <strong>Senders:</strong> ${preview.stats.senders} |
        <strong>Domains:</strong> ${preview.stats.domains} |
        <strong>Errors:</strong> ${preview.stats.errors}
    `;
    document.getElementById('previewStats').innerHTML = statsHtml;

    let tableHtml = `
        <table class="table table-sm table-striped">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>Value</th>
                    <th>For Domain</th>
                    <th>Description</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
    `;

    preview.entries.forEach(entry => {
        const statusBadge = entry.status === 'ok'
            ? '<span class="badge badge-success">OK</span>'
            : `<span class="badge badge-danger" title="${entry.error}">Error</span>`;

        tableHtml += `
            <tr>
                <td>${entry.row}</td>
                <td><span class="badge badge-${entry.type === 'sender' ? 'primary' : 'info'}">${entry.type}</span></td>
                <td>${entry.value}</td>
                <td>${entry.for_domain}</td>
                <td>${entry.description || '-'}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    });

    tableHtml += '</tbody></table>';
    document.getElementById('previewTable').innerHTML = tableHtml;

    document.getElementById('previewSection').style.display = 'block';
    document.getElementById('resultSection').style.display = 'none';
}

document.getElementById('confirmImport').addEventListener('click', async function() {
    if (!previewData) {
        alert('No preview data available');
        return;
    }

    if (previewData.stats.errors > 0) {
        if (!confirm(`There are ${previewData.stats.errors} errors. Continue anyway? (Errors will be skipped)`)) {
            return;
        }
    }

    if (!confirm(`Import ${previewData.stats.senders} senders and ${previewData.stats.domains} domains?`)) {
        return;
    }

    try {
        const response = await fetch('{{ url_for("whitelist_import.execute_import") }}', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({temp_path: previewData.temp_path})
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Import failed');
        }

        document.getElementById('previewSection').style.display = 'none';
        document.getElementById('resultSection').style.display = 'block';
        document.getElementById('resultMessage').innerHTML = `
            <div class="alert alert-success">
                <h6><i class="fas fa-check-circle"></i> ${result.message}</h6>
                <ul>
                    <li>Whitelisted Senders: ${result.stats.whitelisted_senders}</li>
                    <li>Whitelisted Domains: ${result.stats.whitelisted_domains}</li>
                    <li>Skipped: ${result.stats.skipped}</li>
                </ul>
                <a href="{{ url_for('whitelist_import.import_page') }}" class="btn btn-primary btn-sm mt-2">Import Another</a>
            </div>
        `;

        // Reset form
        document.getElementById('uploadForm').reset();

    } catch (error) {
        alert('Import Error: ' + error.message);
    }
});

document.getElementById('cancelImport').addEventListener('click', function() {
    document.getElementById('previewSection').style.display = 'none';
    document.getElementById('uploadForm').reset();
    previewData = null;
});
</script>
{% endblock %}
'''
