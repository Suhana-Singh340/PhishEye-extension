document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('runTests').addEventListener('click', runAllTests);
  });
  
  async function runAllTests() {
    const response = await fetch('test-urls.json');
    const { tests } = await response.json();
    const results = [];
    
    for (const test of tests) {
      const startTime = performance.now();
      const isPhishy = await testUrl(test.url);
      const endTime = performance.now();
      
      results.push({
        ...test,
        actual: isPhishy ? 'phishing' : 'safe',
        detectionTime: endTime - startTime
      });
    }
    
    displayResults(results);
    calculateMetrics(results);
  }
  
  async function testUrl(url) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { action: 'checkUrl', url },
        (response) => resolve(response.isPhishy)
      );
    });
  }
  
  function displayResults(results) {
    const container = document.getElementById('testResults');
    container.innerHTML = '';
    
    results.forEach(test => {
      const resultDiv = document.createElement('div');
      resultDiv.className = `test-case ${test.expected} ${
        test.expected === test.actual ? 'correct' : 'incorrect'
      }`;
      
      resultDiv.innerHTML = `
        <strong>${test.description}</strong><br>
        URL: ${test.url}<br>
        Expected: ${test.expected.toUpperCase()} | 
        Actual: ${test.actual.toUpperCase()} | 
        Time: ${test.detectionTime.toFixed(2)}ms
      `;
      
      container.appendChild(resultDiv);
    });
  }
  
  function calculateMetrics(results) {
    const metrics = {
      total: results.length,
      truePositives: 0,
      falsePositives: 0,
      trueNegatives: 0,
      falseNegatives: 0
    };
  
    results.forEach(test => {
      if (test.expected === 'phishing' && test.actual === 'phishing') metrics.truePositives++;
      if (test.expected === 'safe' && test.actual === 'safe') metrics.trueNegatives++;
      if (test.expected === 'safe' && test.actual === 'phishing') metrics.falsePositives++;
      if (test.expected === 'phishing' && test.actual === 'safe') metrics.falseNegatives++;
    });
  
    const accuracy = ((metrics.truePositives + metrics.trueNegatives) / metrics.total) * 100;
    const precision = metrics.truePositives / (metrics.truePositives + metrics.falsePositives) * 100;
    const recall = metrics.truePositives / (metrics.truePositives + metrics.falseNegatives) * 100;
    const f1Score = 2 * (precision * recall) / (precision + recall);
  
    document.getElementById('metrics').innerHTML = `
      <h3>Test Metrics</h3>
      <p>Accuracy: ${accuracy.toFixed(1)}%</p>
      <p>Precision: ${precision.toFixed(1)}%</p>
      <p>Recall: ${recall.toFixed(1)}%</p>
      <p>F1 Score: ${f1Score.toFixed(2)}</p>
      <p>False Positives: ${metrics.falsePositives}</p>
      <p>False Negatives: ${metrics.falseNegatives}</p>
    `;
  }