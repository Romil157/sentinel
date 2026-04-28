const API_BASE_URL = 'http://127.0.0.1:5000/api/v1';

document.addEventListener('DOMContentLoaded', () => {
    
    // UI Elements
    const scanTextBtn = document.getElementById('scanTextBtn');
    const textInput = document.getElementById('textInput');
    const scanUrlBtn = document.getElementById('scanUrlBtn');
    const urlInput = document.getElementById('urlInput');
    
    const resultsSection = document.getElementById('resultsSection');
    const resultStatus = document.getElementById('resultStatus');
    const resultConfidence = document.getElementById('resultConfidence');
    const explainabilityContent = document.getElementById('explainabilityContent');

    // Stats Elements
    const statTotal = document.getElementById('statTotal');
    const statThreats = document.getElementById('statThreats');
    const statAccuracy = document.getElementById('statAccuracy');

    // Scan Text
    scanTextBtn.addEventListener('click', async () => {
        const text = textInput.value.trim();
        if (!text) return alert("Please enter some text to scan.");
        
        scanTextBtn.innerText = "Analyzing...";
        scanTextBtn.disabled = true;
        
        try {
            const response = await fetch(`${API_BASE_URL}/predict/text`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text })
            });
            
            const data = await response.json();
            displayResults(data);
        } catch (error) {
            console.error(error);
            alert("Failed to connect to the analysis engine. Is the backend running?");
        } finally {
            scanTextBtn.innerText = "Analyze Text";
            scanTextBtn.disabled = false;
        }
    });

    // Scan URL
    scanUrlBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) return alert("Please enter a URL to scan.");
        
        scanUrlBtn.innerText = "Analyzing...";
        scanUrlBtn.disabled = true;
        
        try {
            const response = await fetch(`${API_BASE_URL}/predict/url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            
            const data = await response.json();
            displayResults(data);
        } catch (error) {
            console.error(error);
            alert("Failed to connect to the analysis engine. Is the backend running?");
        } finally {
            scanUrlBtn.innerText = "Analyze URL";
            scanUrlBtn.disabled = false;
        }
    });

    function displayResults(data) {
        resultsSection.classList.remove('d-none');
        
        const isThreat = data.prediction.includes("Scam") || data.prediction.includes("Phishing");
        
        resultStatus.innerText = data.prediction;
        resultStatus.className = isThreat ? "mb-0 text-danger" : "mb-0 text-success";
        
        const pct = Math.round(data.confidence * 100);
        resultConfidence.innerText = `${pct}%`;
        resultConfidence.className = pct > 50 ? "mb-0 text-danger" : "mb-0 text-success";
        
        explainabilityContent.innerHTML = "";
        
        let tags = [];
        if (data.explainability.keywords) tags = data.explainability.keywords;
        if (data.explainability.flags) tags = data.explainability.flags;
        
        if (tags.length === 0) {
            explainabilityContent.innerHTML = "<span class='text-muted small'>No specific suspicious indicators found.</span>";
        } else {
            tags.forEach(tag => {
                const badge = document.createElement('span');
                badge.className = 'explain-badge';
                badge.innerText = tag;
                explainabilityContent.appendChild(badge);
            });
        }
        
        // Update mock stats for demo effect
        updateMockStats();
    }

    function updateMockStats() {
        let t = parseInt(statTotal.innerText.replace(/,/g, '')) || 1250;
        let th = parseInt(statThreats.innerText.replace(/,/g, '')) || 342;
        
        statTotal.innerText = (t + 1).toLocaleString();
        
        if (resultStatus.innerText !== "Safe") {
            statThreats.innerText = (th + 1).toLocaleString();
        }
    }

    // Initialize Chart.js
    const ctx = document.getElementById('threatChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Threats Blocked',
                data: [12, 19, 15, 25, 22, 30, 28],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
    
    // Load initial stats
    fetchAnalytics();
    
    async function fetchAnalytics() {
        try {
            // Note: In real app, this needs JWT token. We fallback to mock if auth fails.
            const response = await fetch(`${API_BASE_URL}/analytics/summary`);
            if(response.ok) {
                const data = await response.json();
                statTotal.innerText = data.total_scanned.toLocaleString();
                statThreats.innerText = data.threats_detected.toLocaleString();
                statAccuracy.innerText = data.accuracy_rate + "%";
            } else {
                // Fallback demo values
                statTotal.innerText = "1,250";
                statThreats.innerText = "342";
                statAccuracy.innerText = "94.2%";
            }
        } catch (e) {
            statTotal.innerText = "1,250";
            statThreats.innerText = "342";
            statAccuracy.innerText = "94.2%";
        }
    }
});
