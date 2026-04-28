const API_BASE_URL = 'http://127.0.0.1:5000/api/v1';

document.addEventListener('DOMContentLoaded', () => {
    
    // --- 1. SPA ROUTING ---
    const views = document.querySelectorAll('.view-section');
    const navLinks = document.querySelectorAll('.nav-link-custom');
    const pageTitle = document.getElementById('pageTitle');
    const pageSubtitle = document.getElementById('pageSubtitle');
    
    const viewTitles = {
        'scanner': { title: 'New Scan', sub: 'Analyze text, URLs, and emails for advanced threats.' },
        'history': { title: 'Scan History', sub: 'Review past analysis results.' },
        'feed': { title: 'Global Feed', sub: 'Latest cybersecurity intelligence and threats.' },
        'analytics': { title: 'Analytics', sub: 'Platform usage and detection metrics.' },
        'apikeys': { title: 'API Keys', sub: 'Manage your application access tokens.' },
        'settings': { title: 'Settings', sub: 'Manage profile and preferences.' }
    };

    function handleRoute() {
        let hash = window.location.hash.substring(1) || 'scanner';
        if (!viewTitles[hash]) hash = 'scanner';
        
        // Update DOM Views
        views.forEach(v => v.classList.remove('active'));
        document.getElementById(`view-${hash}`).classList.add('active');
        
        // Update Sidebar Active State
        navLinks.forEach(link => {
            link.classList.remove('active');
            if(link.getAttribute('data-route') === hash) {
                link.classList.add('active');
            }
        });
        
        // Update Header
        pageTitle.innerText = viewTitles[hash].title;
        pageSubtitle.innerText = viewTitles[hash].sub;
        
        // Trigger specific view logic
        if(hash === 'history') loadHistory();
        if(hash === 'feed') loadFeed();
        if(hash === 'analytics') loadAnalytics();
        if(hash === 'apikeys') loadApiKeys();
        if(hash === 'settings') loadSettings();
    }
    
    window.addEventListener('hashchange', handleRoute);
    handleRoute(); // initial load

    // --- 2. THEME TOGGLE ---
    const themeToggle = document.getElementById('themeToggle');
    const htmlEl = document.documentElement;
    const themeIcon = themeToggle.querySelector('i');
    
    // Check saved theme or default to light
    const savedTheme = localStorage.getItem('sentinel_theme') || 'light';
    setTheme(savedTheme);
    
    function setTheme(theme) {
        htmlEl.setAttribute('data-theme', theme);
        themeIcon.setAttribute('data-lucide', theme === 'light' ? 'moon' : 'sun');
        localStorage.setItem('sentinel_theme', theme);
        lucide.createIcons();
    }
    
    themeToggle.addEventListener('click', () => {
        setTheme(htmlEl.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
    });

    // --- 3. SCANNER MODULE ---
    const tabBtns = document.querySelectorAll('#scanTabs button');
    const textWrapper = document.getElementById('textInputWrapper');
    const urlWrapper = document.getElementById('urlInputWrapper');
    let currentMode = 'text';

    tabBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            tabBtns.forEach(b => {
                b.classList.remove('active');
                b.style.color = 'var(--text-secondary)';
            });
            e.target.classList.add('active');
            e.target.style.color = 'var(--text-primary)';
            currentMode = e.target.getAttribute('data-target');
            if (currentMode === 'text') {
                textWrapper.classList.remove('d-none');
                urlWrapper.classList.add('d-none');
            } else {
                urlWrapper.classList.remove('d-none');
                textWrapper.classList.add('d-none');
            }
        });
    });

    const startScanBtn = document.getElementById('startScanBtn');
    const textInput = document.getElementById('textInput');
    const urlInput = document.getElementById('urlInput');
    const emptyState = document.getElementById('emptyState');
    const progressState = document.getElementById('progressState');
    const finalState = document.getElementById('finalState');
    
    startScanBtn.addEventListener('click', async () => {
        let payload = {};
        let endpoint = currentMode === 'text' ? '/predict/text' : '/predict/url';
        const rawContent = currentMode === 'text' ? textInput.value : urlInput.value;
        
        if (!rawContent.trim()) return alert(`Please enter a ${currentMode} to scan.`);

        payload = currentMode === 'text' ? { text: rawContent } : { url: rawContent };

        startScanBtn.disabled = true;
        emptyState.classList.add('d-none');
        finalState.classList.add('d-none');
        progressState.classList.remove('d-none');
        
        const stages = [
            document.getElementById('stage1'),
            document.getElementById('stage2'),
            document.getElementById('stage3'),
            document.getElementById('stage4')
        ];
        
        stages.forEach(s => {
            s.className = 'scan-stage';
            s.innerHTML = `<i data-lucide="circle" width="16"></i> ${s.innerText}`;
        });
        lucide.createIcons();
        
        let scanResult = null, scanError = null;
        
        fetch(`${API_BASE_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }).then(res => res.json())
          .then(data => { scanResult = data; })
          .catch(err => { scanError = err; });

        await updateStage(stages[0]); await delay(600);
        await updateStage(stages[1]); await delay(800);
        await updateStage(stages[2]); await delay(700);
        await updateStage(stages[3]); await delay(400);

        progressState.classList.add('d-none');
        startScanBtn.disabled = false;

        if (scanError) {
            emptyState.classList.remove('d-none');
            alert("Analysis failed."); return;
        }

        if (scanResult) renderFinalResult(scanResult, rawContent);
    });

    async function updateStage(el) {
        const prev = document.querySelector('.scan-stage.active');
        if (prev) {
            prev.className = 'scan-stage done';
            prev.innerHTML = `<i data-lucide="check-circle-2" width="16"></i> ${prev.innerText}`;
        }
        el.className = 'scan-stage active';
        el.innerHTML = `<div class="spinner"></div> ${el.innerText}`;
        lucide.createIcons();
    }
    const delay = ms => new Promise(res => setTimeout(res, ms));

    function renderFinalResult(data, rawInput) {
        finalState.classList.remove('d-none');
        document.getElementById('resSeverity').innerText = data.severity_level;
        document.getElementById('resSeverity').className = `badge-severity sev-${data.severity_level.toLowerCase().replace(' ', '-')}`;
        document.getElementById('resConfidence').innerText = `${Math.round(data.confidence_score * 100)}%`;
        
        const indEl = document.getElementById('resIndicators');
        indEl.innerHTML = '';
        if (data.indicators && data.indicators.length > 0) {
            data.indicators.forEach(ind => {
                indEl.innerHTML += `<span class="indicator-tag"><i data-lucide="alert-triangle" width="14" style="color:var(--sev-suspicious-text)"></i> ${ind}</span>`;
            });
        } else {
            indEl.innerHTML = '<span class="text-secondary small">No anomalies detected.</span>';
        }

        const xaiBlock = document.getElementById('xaiBlock');
        if (data.input_type === 'text' && data.explainability.keyword_heatmap) {
            xaiBlock.classList.remove('d-none');
            const resHeatmap = document.getElementById('resHeatmap');
            resHeatmap.innerHTML = '';
            rawInput.split(/\s+/).forEach(w => {
                const cleanW = w.toLowerCase().replace(/[^a-z0-9]/g, '');
                let span = `<span class="heatmap-word" style="`;
                if (data.explainability.keyword_heatmap[cleanW]) {
                    let heat = data.explainability.keyword_heatmap[cleanW];
                    span += `background-color: rgba(239, 68, 68, ${heat}); ${heat>0.5?'color:#fff':''}`;
                }
                span += `">${w} </span>`;
                resHeatmap.innerHTML += span;
            });
        } else {
            xaiBlock.classList.add('d-none');
        }
        lucide.createIcons();
    }

    // --- 4. HISTORY MODULE ---
    async function loadHistory() {
        const tbody = document.querySelector('#historyTable tbody');
        const empty = document.getElementById('historyEmpty');
        
        try {
            const res = await fetch(`${API_BASE_URL}/history`);
            const data = await res.json();
            
            tbody.innerHTML = '';
            if (data.items.length === 0) {
                empty.classList.remove('d-none');
            } else {
                empty.classList.add('d-none');
                data.items.forEach(item => {
                    const snippet = item.input_data.length > 40 ? item.input_data.substring(0,40) + '...' : item.input_data;
                    const sevClass = `sev-${item.severity_level.toLowerCase().replace(' ', '-')}`;
                    tbody.innerHTML += `
                        <tr>
                            <td>${new Date(item.created_at).toLocaleDateString()}</td>
                            <td class="text-uppercase" style="font-size:0.8rem; letter-spacing:0.05em">${item.input_type}</td>
                            <td class="font-monospace small">${snippet}</td>
                            <td><span class="badge-severity ${sevClass}">${item.severity_level}</span></td>
                            <td class="fw-bold">${Math.round(item.confidence_score * 100)}%</td>
                            <td class="text-end">
                                <button class="btn-icon text-danger" onclick="deleteHistory(${item.id})"><i data-lucide="trash-2" width="16"></i></button>
                            </td>
                        </tr>
                    `;
                });
            }
            lucide.createIcons();
        } catch (e) {
            console.error(e);
        }
    }
    
    window.deleteHistory = async (id) => {
        if(!confirm("Delete this scan record?")) return;
        await fetch(`${API_BASE_URL}/history/${id}`, { method: 'DELETE' });
        loadHistory();
    };

    // --- 5. FEED MODULE ---
    async function loadFeed() {
        const container = document.getElementById('feedContainer');
        try {
            const res = await fetch(`${API_BASE_URL}/feed`);
            const data = await res.json();
            
            container.innerHTML = '';
            data.forEach(item => {
                const colorMap = { 'Critical': 'danger', 'High': 'warning', 'Medium': 'info', 'Low': 'secondary' };
                container.innerHTML += `
                    <div class="feed-card">
                        <div class="d-flex justify-content-between mb-2">
                            <span class="badge bg-${colorMap[item.risk_level]} bg-opacity-10 text-${colorMap[item.risk_level]} text-uppercase" style="font-size:0.7rem; letter-spacing:0.05em; font-weight:700;">${item.risk_level} RISK</span>
                            <span class="small text-secondary">${new Date(item.timestamp).toLocaleString()}</span>
                        </div>
                        <h5 class="fw-bold mb-2">${item.title}</h5>
                        <p class="mb-3" style="color:var(--text-secondary); font-size:0.95rem">${item.description}</p>
                        <div class="d-flex gap-2">
                            <span class="indicator-tag"><i data-lucide="tag" width="14"></i> ${item.category}</span>
                            <span class="indicator-tag"><i data-lucide="globe" width="14"></i> Source: ${item.source}</span>
                        </div>
                    </div>
                `;
            });
            lucide.createIcons();
        } catch (e) { console.error(e); }
    }

    // --- 6. ANALYTICS MODULE ---
    let chartInstance = null;
    async function loadAnalytics() {
        try {
            const overRes = await fetch(`${API_BASE_URL}/analytics/overview`);
            const overData = await overRes.json();
            document.getElementById('statTotalScans').innerText = overData.total_scanned.toLocaleString();
            document.getElementById('statThreats').innerText = overData.threats_detected.toLocaleString();
            document.getElementById('statAccuracy').innerText = overData.accuracy_rate + '%';
            
            const trendRes = await fetch(`${API_BASE_URL}/analytics/trends`);
            const trendData = await trendRes.json();
            
            const ctx = document.getElementById('analyticsChart').getContext('2d');
            if (chartInstance) chartInstance.destroy();
            
            chartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: trendData.labels,
                    datasets: [
                        { label: 'Safe Scans', data: trendData.datasets[0].data, borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.1)', fill: true, tension: 0.4 },
                        { label: 'Threats Blocked', data: trendData.datasets[1].data, borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', fill: true, tension: 0.4 }
                    ]
                },
                options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
            });
        } catch (e) { console.error(e); }
    }

    // --- 7. API KEYS MODULE ---
    async function loadApiKeys() {
        const tbody = document.querySelector('#keysTable tbody');
        try {
            const res = await fetch(`${API_BASE_URL}/apikeys`);
            const data = await res.json();
            
            tbody.innerHTML = '';
            data.forEach(item => {
                tbody.innerHTML += `
                    <tr>
                        <td class="fw-medium">${item.name}</td>
                        <td class="font-monospace small"><div class="api-key-box">${item.prefix}**********</div></td>
                        <td>${new Date(item.created_at).toLocaleDateString()}</td>
                        <td class="text-end">
                            <button class="btn-icon text-danger" onclick="revokeKey(${item.id})"><i data-lucide="trash-2" width="16"></i></button>
                        </td>
                    </tr>
                `;
            });
            lucide.createIcons();
        } catch (e) { console.error(e); }
    }

    document.getElementById('createKeyBtn').addEventListener('click', async () => {
        const name = prompt("Enter a name for this API Key:", "Production Env");
        if(!name) return;
        
        try {
            const res = await fetch(`${API_BASE_URL}/apikeys`, {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({name})
            });
            const data = await res.json();
            prompt("IMPORTANT: Copy your raw API key now. You will not be able to see it again.", data.raw_key);
            loadApiKeys();
        } catch(e) { console.error(e); }
    });

    window.revokeKey = async (id) => {
        if(!confirm("Revoke this API Key? Applications using it will fail.")) return;
        await fetch(`${API_BASE_URL}/apikeys/${id}`, { method: 'DELETE' });
        loadApiKeys();
    };

    // --- 8. SETTINGS MODULE ---
    async function loadSettings() {
        try {
            const res = await fetch(`${API_BASE_URL}/settings/profile`);
            const data = await res.json();
            
            document.getElementById('set-username').value = data.username;
            document.getElementById('set-notifications').value = data.notifications_enabled.toString();
        } catch (e) { console.error(e); }
    }

    document.getElementById('settingsForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            username: document.getElementById('set-username').value,
            notifications_enabled: document.getElementById('set-notifications').value === 'true'
        };
        
        try {
            await fetch(`${API_BASE_URL}/settings/profile`, {
                method: 'PUT',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify(payload)
            });
            const msg = document.getElementById('settingsMsg');
            msg.classList.remove('d-none');
            setTimeout(() => msg.classList.add('d-none'), 3000);
        } catch(e) { console.error(e); }
    });
});
