document.addEventListener('DOMContentLoaded', () => {
    // Get URL parameters with fallbacks
    const params = new URLSearchParams(window.location.search);
    const reason = params.get('reason') || 'Suspicious patterns detected';
    const url = params.get('url') || 'unknown URL';
    const tabId = parseInt(params.get('tabId'));
    const score = params.get('score');

    // Set the warning content
    const reasonElement = document.getElementById('reason');
    if (reasonElement) {
        reasonElement.innerHTML = `
            <strong>Blocked URL:</strong> <span class="url">${url}</span><br><br>
            <strong>Reason:</strong> ${reason}<br>
            ${score ? `<strong>Confidence:</strong> ${score}/100` : ''}
        `;
    }

    // Button event handlers with enhanced functionality
    document.getElementById('goBack').addEventListener('click', () => {
        if (!isNaN(tabId)) {
            // Send analytics before action
            chrome.runtime.sendMessage({
                action: "phishWarningAction",
                type: "goBack",
                url,
                tabId
            });
            
            chrome.tabs.goBack(tabId).catch(error => {
                console.error("Go back failed:", error);
                chrome.tabs.create({ url: "chrome://newtab" });
            });
        }
        window.close();
    });

    // Enhanced warning animation
    const icon = document.querySelector('.warning-icon');
    if (icon) {
        let pulseState = 0;
        const pulse = () => {
            pulseState = (pulseState + 0.05) % (Math.PI * 2);
            const scale = 1 + (Math.sin(pulseState) * 0.1);
            icon.style.transform = `scale(${scale})`;
            requestAnimationFrame(pulse);
        };
        pulse();
    }

    // Send view event to background script
    chrome.runtime.sendMessage({
        action: "phishWarningViewed",
        url,
        tabId
    }).catch(error => {
        console.debug("Could not send view event:", error);
    });
});