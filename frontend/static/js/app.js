const API_BASE_URL = 'http://127.0.0.1:5000/api/v1';

document.addEventListener('DOMContentLoaded', () => {
    
    // Theme Toggle
    const themeToggle = document.getElementById('themeToggle');
    const htmlEl = document.documentElement;
    const themeIcon = themeToggle.querySelector('i');
    
    themeToggle.addEventListener('click', () => {
        if(htmlEl.getAttribute('data-theme') === 'light') {
            htmlEl.setAttribute('data-theme', 'dark');
            themeIcon.setAttribute('data-lucide', 'sun');
        } else {
            htmlEl.setAttribute('data-theme', 'light');
            themeIcon.setAttribute('data-lucide', 'moon');
        }
        lucide.createIcons();
    });

    // Tab Switching
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

    // Elements
    const startScanBtn = document.getElementById('startScanBtn');
    const textInput = document.getElementById('textInput');
    const urlInput = document.getElementById('urlInput');
    
    const emptyState = document.getElementById('emptyState');
    const progressState = document.getElementById('progressState');
    const finalState = document.getElementById('finalState');
    
    const resSeverity = document.getElementById('resSeverity');
    const resConfidence = document.getElementById('resConfidence');
    const resIndicators = document.getElementById('resIndicators');
    
    const xaiBlock = document.getElementById('xaiBlock');
    const resHeatmap = document.getElementById('resHeatmap');

    startScanBtn.addEventListener('click', async () => {
        let payload = {};
        let endpoint = '';
        const rawContent = currentMode === 'text' ? textInput.value : urlInput.value;
        
        if (!rawContent.trim()) {
            return alert(`Please enter a ${currentMode} to scan.`);
        }

        if (currentMode === 'text') {
            payload = { text: rawContent };
            endpoint = '/predict/text';
        } else {
            payload = { url: rawContent };
            endpoint = '/predict/url';
        }

        // Start UI Pipeline
        startScanBtn.disabled = true;
        emptyState.classList.add('d-none');
        finalState.classList.add('d-none');
        progressState.classList.remove('d-none');
        
        // Reset stages
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
        
        // Fetch Data in background while animating UI
        let scanResult = null;
        let scanError = null;
        
        fetch(`${API_BASE_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }).then(res => res.json())
          .then(data => { scanResult = data; })
          .catch(err => { scanError = err; });

        // Simulate Progressive Scanning Experience
        await updateStage(stages[0]);
        await delay(600);
        await updateStage(stages[1]);
        await delay(800);
        await updateStage(stages[2]);
        await delay(700);
        await updateStage(stages[3]);
        await delay(400);

        progressState.classList.add('d-none');
        startScanBtn.disabled = false;

        if (scanError) {
            emptyState.classList.remove('d-none');
            alert("Analysis failed. Backend might be unreachable.");
            return;
        }

        if (scanResult) renderFinalResult(scanResult, rawContent);
    });

    async function updateStage(el) {
        // Mark previous as done
        const prev = document.querySelector('.scan-stage.active');
        if (prev) {
            prev.className = 'scan-stage done';
            prev.innerHTML = `<i data-lucide="check-circle-2" width="16"></i> ${prev.innerText}`;
        }
        // Set current to active
        el.className = 'scan-stage active';
        el.innerHTML = `<div class="spinner"></div> ${el.innerText}`;
        lucide.createIcons();
    }

    function delay(ms) {
        return new Promise(res => setTimeout(res, ms));
    }

    function renderFinalResult(data, rawInput) {
        finalState.classList.remove('d-none');
        
        // Render Severity
        resSeverity.innerText = data.severity_level;
        resSeverity.className = 'badge-severity';
        
        const sevClassMap = {
            'Safe': 'sev-safe',
            'Low Risk': 'sev-low',
            'Suspicious': 'sev-suspicious',
            'High Risk': 'sev-high',
            'Critical Threat': 'sev-critical'
        };
        resSeverity.classList.add(sevClassMap[data.severity_level] || 'sev-safe');

        // Render Confidence
        resConfidence.innerText = `${Math.round(data.confidence_score * 100)}%`;
        
        // Render Indicators
        resIndicators.innerHTML = '';
        if (data.indicators && data.indicators.length > 0) {
            data.indicators.forEach(ind => {
                const span = document.createElement('span');
                span.className = 'indicator-tag';
                span.innerHTML = `<i data-lucide="alert-triangle" width="14" style="color:var(--sev-suspicious-text)"></i> ${ind}`;
                resIndicators.appendChild(span);
            });
        } else {
            resIndicators.innerHTML = '<span class="text-secondary small">No anomalies detected.</span>';
        }

        // Render Heatmap (Text Only)
        if (data.input_type === 'text' && data.explainability.keyword_heatmap) {
            xaiBlock.classList.remove('d-none');
            resHeatmap.innerHTML = '';
            
            const words = rawInput.split(/\s+/);
            const hm = data.explainability.keyword_heatmap;
            
            words.forEach(w => {
                const cleanW = w.toLowerCase().replace(/[^a-z0-9]/g, '');
                const span = document.createElement('span');
                span.innerText = w + ' ';
                
                if (hm[cleanW]) {
                    const heat = hm[cleanW]; // 0.0 to 1.0
                    // Convert heat to an rgba red highlight
                    span.style.backgroundColor = `rgba(239, 68, 68, ${heat})`;
                    if (heat > 0.5) span.style.color = '#fff';
                    span.className = 'heatmap-word';
                }
                resHeatmap.appendChild(span);
            });
        } else {
            xaiBlock.classList.add('d-none');
        }

        lucide.createIcons();
    }
});
