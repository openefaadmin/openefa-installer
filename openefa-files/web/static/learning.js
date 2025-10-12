// Learning Dashboard JavaScript
console.log('Learning.js loaded');

function feedEmailToLearning() {
    const messageId = document.getElementById('messageId').value.trim();
    const overrideScore = document.getElementById('overrideScore').value.trim();
    
    if (!messageId) {
        alert('Please enter a Message-ID');
        return;
    }
    
    console.log('Feeding email:', messageId);
    
    const resultDiv = document.getElementById('feedResult');
    resultDiv.innerHTML = '<div class="alert alert-info">Processing... Please wait.</div>';
    
    // Make AJAX request
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/learning/feed', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
    xhr.onload = function() {
        console.log('Response received:', xhr.status);
        if (xhr.status === 200) {
            try {
                const data = JSON.parse(xhr.responseText);
                if (data.success) {
                    resultDiv.innerHTML = '<div class="alert alert-success">✅ ' + data.message + 
                        '<br><small>From: ' + (data.details.sender || 'Unknown') +
                        '<br>Subject: ' + (data.details.subject || 'N/A') +
                        '<br>Score: ' + (data.details.spam_score || 'N/A') + '</small></div>';
                    document.getElementById('feedForm').reset();
                } else {
                    resultDiv.innerHTML = '<div class="alert alert-danger">❌ ' + data.error + '</div>';
                }
            } catch (e) {
                resultDiv.innerHTML = '<div class="alert alert-danger">Error parsing response</div>';
            }
        } else if (xhr.status === 302 || xhr.status === 401) {
            resultDiv.innerHTML = '<div class="alert alert-warning">Session expired. Please refresh and log in.</div>';
        } else {
            resultDiv.innerHTML = '<div class="alert alert-danger">Error: HTTP ' + xhr.status + '</div>';
        }
    };
    
    xhr.onerror = function() {
        resultDiv.innerHTML = '<div class="alert alert-danger">Network error occurred</div>';
    };
    
    const params = 'message_id=' + encodeURIComponent(messageId) + '&override_score=' + encodeURIComponent(overrideScore);
    xhr.send(params);
}

function searchEmails() {
    const searchTerm = document.getElementById('searchTerm').value.trim();
    
    if (!searchTerm) {
        alert('Please enter a search term');
        return;
    }
    
    const resultsDiv = document.getElementById('searchResults');
    resultsDiv.innerHTML = '<div class="alert alert-info">Searching...</div>';
    
    fetch('/learning/search?q=' + encodeURIComponent(searchTerm), {
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success && data.emails.length > 0) {
            let html = '<div class="list-group">';
            data.emails.forEach(email => {
                html += '<div class="list-group-item p-2">' +
                    '<small class="text-muted">' + email.time + '</small><br>' +
                    '<strong>' + email.sender + '</strong><br>' +
                    '<small>' + email.subject + '</small><br>' +
                    '<button class="btn btn-sm btn-primary mt-2" onclick="feedFromSearch(\'' + 
                    email.message_id + '\', ' + email.spam_score + ')">Feed to Learning</button>' +
                    '</div>';
            });
            html += '</div>';
            resultsDiv.innerHTML = html;
        } else {
            resultsDiv.innerHTML = '<div class="alert alert-info">No emails found</div>';
        }
    })
    .catch(error => {
        resultsDiv.innerHTML = '<div class="alert alert-danger">Search error: ' + error.message + '</div>';
    });
}

function feedFromSearch(messageId, originalScore) {
    const override = prompt('Override spam score? (0-10, or leave blank for ' + originalScore + ')');
    document.getElementById('messageId').value = messageId;
    if (override) {
        document.getElementById('overrideScore').value = override;
    }
    feedEmailToLearning();
}