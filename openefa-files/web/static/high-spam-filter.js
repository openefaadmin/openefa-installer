/**
 * High Spam Filter - Hide emails with spam score >= 40
 * Works on /emails and /quarantine pages
 */

// Cookie helper functions
function setCookie(name, value, days) {
    const expires = new Date();
    expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
    document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Lax`;
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

// Toggle high spam filter
function toggleHighSpamFilter() {
    const checkbox = document.getElementById('hide_high_spam');
    const isHidden = checkbox.checked;

    // Save preference to cookie (365 days)
    setCookie('spacy_hide_high_spam', isHidden ? '1' : '0', 365);

    // Apply filter
    applyHighSpamFilter(isHidden);
}

// Apply the filter to table rows or email cards
function applyHighSpamFilter(shouldHide) {
    let hiddenCount = 0;

    // Check for table layout (emails page)
    const table = document.querySelector('.email-table tbody');
    if (table) {
        const rows = table.querySelectorAll('tr');
        rows.forEach(row => {
            // Get spam score from the spam score cell
            const spamScoreCell = row.querySelector('.spam-score');
            if (!spamScoreCell) return;

            // Extract numeric value from the spam score cell
            const spamScoreText = spamScoreCell.textContent.trim();
            const spamScore = parseFloat(spamScoreText);

            // Hide if score >= 40 and filter is enabled
            if (shouldHide && !isNaN(spamScore) && spamScore >= 40) {
                row.classList.add('spam-filter-hidden');
                row.setAttribute('data-hidden-by-filter', 'true');
                hiddenCount++;
            } else {
                row.classList.remove('spam-filter-hidden');
                row.removeAttribute('data-hidden-by-filter');
            }
        });
    }

    // Check for card layout (quarantine page)
    const emailCards = document.querySelectorAll('.email-card');
    if (emailCards.length > 0) {
        emailCards.forEach(card => {
            // Get spam score from badge (badge-spam-high, badge-spam-medium, badge-spam-low)
            const spamBadge = card.querySelector('.badge-spam-high, .badge-spam-medium, .badge-spam-low');
            if (!spamBadge) return;

            // Extract numeric value from badge text
            const spamScoreText = spamBadge.textContent.trim();
            const spamScore = parseFloat(spamScoreText);

            // Hide if score >= 40 and filter is enabled
            if (shouldHide && !isNaN(spamScore) && spamScore >= 40) {
                card.classList.add('spam-filter-hidden');
                card.setAttribute('data-hidden-by-filter', 'true');
                hiddenCount++;
            } else {
                card.classList.remove('spam-filter-hidden');
                card.removeAttribute('data-hidden-by-filter');
            }
        });
    }

    // Update hidden count badge
    updateHiddenCountBadge(hiddenCount);
}

// Update the badge showing how many emails are hidden
function updateHiddenCountBadge(count) {
    const badge = document.getElementById('hidden_spam_count');
    if (!badge) return;

    if (count > 0) {
        badge.textContent = `${count} hidden`;
        badge.classList.remove('d-none');
        badge.classList.add('d-inline-block');
    } else {
        badge.classList.remove('d-inline-block');
        badge.classList.add('d-none');
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    const checkbox = document.getElementById('hide_high_spam');
    if (!checkbox) return;

    // Add event listener for checkbox changes
    checkbox.addEventListener('change', toggleHighSpamFilter);

    // Read cookie preference
    const savedPref = getCookie('spacy_hide_high_spam');
    const shouldHide = savedPref === '1';

    // Set checkbox state
    checkbox.checked = shouldHide;

    // Apply filter on page load
    if (shouldHide) {
        applyHighSpamFilter(true);
    }

    // Re-apply filter after any dynamic table/card updates
    // (in case new emails are loaded via AJAX)
    const observer = new MutationObserver(function(mutations) {
        if (checkbox.checked) {
            applyHighSpamFilter(true);
        }
    });

    // Watch table for emails page
    const table = document.querySelector('.email-table tbody');
    if (table) {
        observer.observe(table, { childList: true, subtree: true });
    }

    // Watch container for quarantine page cards
    const cardContainer = document.querySelector('.mb-4');
    if (cardContainer && document.querySelectorAll('.email-card').length > 0) {
        observer.observe(cardContainer, { childList: true, subtree: true });
    }
});
