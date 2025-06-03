document.addEventListener('DOMContentLoaded', async () => {
  const response = await new Promise(resolve => {
    chrome.runtime.sendMessage({ action: "getStats" }, resolve);
  });

  const stats = response?.stats || { totalScans: 0, threatsBlocked: 0 };

  document.getElementById('totalScans').textContent = stats.totalScans;
  document.getElementById('threatsFound').textContent = stats.threatsBlocked;

  initChart(stats);

  // Real-time updates
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.phisheyeStats) {
      updateUI(changes.phisheyeStats.newValue);
    }
  });
});

function updateUI(stats) {
  document.getElementById('totalScans').textContent = stats.totalScans;
  document.getElementById('threatsFound').textContent = stats.threatsBlocked;
  updateChart(stats);
}

function initChart(stats) {
  const ctx = document.getElementById('metricsChart').getContext('2d');
  window.phisheyeChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Safe URLs', 'Threats Blocked'],
      datasets: [{
        data: [stats.totalScans - stats.threatsBlocked, stats.threatsBlocked],
        backgroundColor: ['#4CAF50', '#F44336'],
        borderWidth: 0
      }]
    },
    options: {
      cutout: '70%',
      plugins: {
        legend: { position: 'bottom' },
        tooltip: { enabled: false }
      }
    }
  });
}

function updateChart(stats) {
  if (window.phisheyeChart) {
    window.phisheyeChart.data.datasets[0].data = [
      stats.totalScans - stats.threatsBlocked,
      stats.threatsBlocked
    ];
    window.phisheyeChart.update();
  }
}

document.getElementById('viewDetails').addEventListener('click', async () => {
  const log = await new Promise(resolve => {
    chrome.runtime.sendMessage({ action: "getDetectionLog" }, resolve);
  });

  // Render detection log in a modal or console
  showDetectionLog(log);
});

function showDetectionLog(log) {
  // Basic rendering to console
  console.log("Detection Log:", log);

  // Optional: Render to a modal or alert
  const formatted = log.map((entry, i) => {
    return `${i + 1}. ${entry.url}\nReason: ${entry.reason}\nTime: ${entry.timestamp}\n\n`;
  }).join("");

  alert("Detection Log:\n\n" + formatted);
}
