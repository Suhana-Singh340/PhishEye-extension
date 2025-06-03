chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "showPhishingWarning") {
      showInlineWarning(request.url, request.reason);
    }
  });
  
  function showInlineWarning(url, reason) {
    const warningDiv = document.createElement('div');
    warningDiv.style.position = 'fixed';
    warningDiv.style.top = '0';
    warningDiv.style.left = '0';
    warningDiv.style.width = '100%';
    warningDiv.style.backgroundColor = '#ff4444';
    warningDiv.style.color = 'white';
    warningDiv.style.padding = '10px';
    warningDiv.style.zIndex = '9999';
    warningDiv.style.textAlign = 'center';
    warningDiv.innerHTML = `
      ⚠️ Phishing Warning: ${reason} - 
      <a href="#" style="color:white;text-decoration:underline;" id="phish-more-info">More Info</a> | 
      <a href="#" style="color:white;text-decoration:underline;" id="phish-close">Close</a>
    `;
    
    document.body.prepend(warningDiv);
    
    document.getElementById('phish-more-info').addEventListener('click', (e) => {
      e.preventDefault();
      chrome.runtime.sendMessage({action: "openFullWarning", url});
    });
    
    document.getElementById('phish-close').addEventListener('click', (e) => {
      e.preventDefault();
      warningDiv.remove();
    });
  }