const API_BASE = "http://127.0.0.1:8000";

// ====================================
// STATE & REFERENCES
// ====================================
let cpuChart;
let ramChart;

let cpuHistory = [];
let ramHistory = [];
let labels = [];

let isOffline = false;
let selectedPid = null;
let currentProcesses = [];

// ====================================
// INITIALIZE DASHBOARD
// ====================================
document.addEventListener("DOMContentLoaded", () => {
    // Start Clock
    initClock();
    
    // Initialize Three.js Background
    initThreeBackground();

    // Initialize Charts
    initializeCharts();

    // Initial Telemetry Fetch
    loadDashboard();

    // Regular Telemetry Polling (every 5 seconds)
    setInterval(loadDashboard, 5000);

    // ====================================
    // VIEW SWITCHING
    // ====================================
    const navDashboard     = document.getElementById("navDashboard");
    const navThreatMonitor = document.getElementById("navThreatMonitor");
    const dashboardView    = document.getElementById("dashboardView");
    const threatView       = document.getElementById("threatView");

    function switchView(show, hide, navOn, navOff) {
        show.classList.remove("hidden");
        hide.classList.add("hidden");
        navOn.classList.add("active");
        navOff.classList.remove("active");
    }

    navDashboard.addEventListener("click", e => {
        e.preventDefault();
        switchView(dashboardView, threatView, navDashboard, navThreatMonitor);
    });

    navThreatMonitor.addEventListener("click", e => {
        e.preventDefault();
        switchView(threatView, dashboardView, navThreatMonitor, navDashboard);
    });

    // Initial Processes Fetch
    loadProcesses();

    // Poll processes alongside dashboard telemetry (every 5 seconds)
    setInterval(loadProcesses, 5000);

    // ====================================
    // THREAT ACTION BUTTONS
    // ====================================
    const btnOpenLocation = document.getElementById("btnOpenLocation");
    const btnAnalyze      = document.getElementById("btnAnalyze");
    const analyzeModal    = document.getElementById("analyzeModal");
    const closeModal      = document.getElementById("closeModal");

    // Open Location
    btnOpenLocation.addEventListener("click", async () => {
        const proc = currentProcesses.find(p => p.pid === selectedPid);
        if (!proc) return;

        try {
            const res = await fetch(`${API_BASE}/open-location`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ path: proc.exe })
            });
            const data = await res.json();
            if (data.success) {
                showToast("📂 File location opened successfully.", "success");
            } else {
                showToast("⚠️ Failed to open file location.", "error");
            }
        } catch (err) {
            console.error("Open location error:", err);
            showToast("❌ Could not reach the backend.", "error");
        }
    });

    // Analyze
    btnAnalyze.addEventListener("click", async () => {
        if (!selectedPid) return;

        // Show modal with loading state
        const modalContent = document.getElementById("modalContent");
        modalContent.innerHTML = `
            <div class="modal-loading">
                <div class="modal-spinner"></div>
                <span>Analyzing process — this may take a moment…</span>
            </div>
        `;
        analyzeModal.classList.remove("hidden");

        try {
            const res = await fetch(`${API_BASE}/analyze/${selectedPid}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            if (data.error) {
                modalContent.innerHTML = `
                    <div class="modal-error">
                        <div class="modal-error-icon">⚠️</div>
                        <div>${data.error}</div>
                    </div>
                `;
                return;
            }

            // VirusTotal badge
            const vt = data.virustotal;
            let vtBadgeHtml = `<span class="vt-badge vt-unknown">⚪ Not checked</span>`;

            if (vt && typeof vt === "object" && !("error" in vt)) {
                // Valid result from VirusTotal
                const malicious  = vt.malicious  || 0;
                const suspicious = vt.suspicious || 0;
                const harmless   = vt.harmless   || 0;
                const undetected = vt.undetected || 0;
                const total      = malicious + suspicious + harmless + undetected;

                if (malicious > 0) {
                    vtBadgeHtml = `<span class="vt-badge vt-malicious">🔴 ${malicious}/${total} engines flagged malicious</span>`;
                } else if (suspicious > 0) {
                    vtBadgeHtml = `<span class="vt-badge vt-suspicious">🟡 ${suspicious}/${total} engines flagged suspicious</span>`;
                } else if (total > 0) {
                    vtBadgeHtml = `<span class="vt-badge vt-clean">✅ Clean — 0/${total} detections</span>`;
                } else {
                    vtBadgeHtml = `<span class="vt-badge vt-unknown">⚪ No scan data available</span>`;
                }
            } else if (vt && "error" in vt) {
                // Error response — show human-readable message
                const code = vt.error;
                let vtMsg;
                if (code === 404) {
                    vtMsg = "No VirusTotal report found — hash not in database";
                } else if (code === 401 || code === 403) {
                    vtMsg = "API key invalid or missing";
                } else if (code === 429) {
                    vtMsg = "VirusTotal rate limit reached — try again later";
                } else if (typeof code === "string") {
                    vtMsg = "Lookup failed — " + code;
                } else {
                    vtMsg = `Lookup failed (HTTP ${code})`;
                }
                vtBadgeHtml = `<span class="vt-badge vt-unknown">⚪ ${vtMsg}</span>`;
            }

            // Signature status
            const sigStatus = data.signature_status || "Unknown";
            const sigClass = sigStatus.toLowerCase().includes("valid") ? "sig-valid"
                           : sigStatus.toLowerCase().includes("invalid") ? "sig-invalid"
                           : "sig-unknown";

            // Trust score
            let trustHtml = `<span class="modal-value" style="color:#64748b;">Not available</span>`;
            if (data.trust_score !== undefined && data.trust_score !== null) {
                const score = Math.max(0, Math.min(100, data.trust_score));
                const barClass = score >= 70 ? "trust-bar-high" : score >= 40 ? "trust-bar-medium" : "trust-bar-low";
                const scoreColor = score >= 70 ? "var(--success)" : score >= 40 ? "var(--warning)" : "var(--danger)";
                trustHtml = `
                    <div class="trust-score-wrap">
                        <div class="trust-score-label">
                            <span style="color:#64748b; font-size:0.72rem;">Trust Level</span>
                            <span class="trust-score-value" style="color:${scoreColor}">${score}/100</span>
                        </div>
                        <div class="trust-bar-track">
                            <div class="trust-bar-fill ${barClass}" id="trustBarFill" style="width: 0%"></div>
                        </div>
                    </div>
                `;
            }

            modalContent.innerHTML = `
    <div class="modal-grid">
        <div class="modal-row">
            <span class="modal-label">Process Name</span>
            <span class="modal-value" style="color:#fff; font-weight:700;">${data.process_name || "N/A"}</span>
        </div>

        <div class="modal-row">
            <span class="modal-label">Publisher</span>
            <span class="modal-value">${data.publisher || "Unknown / Unsigned"}</span>
        </div>

        <div class="modal-row">
            <span class="modal-label">Signature Status</span>
            <span class="modal-value ${sigClass}">${sigStatus}</span>
        </div>

        <div class="modal-row">
            <span class="modal-label">SHA-256</span>
            <span class="modal-value font-mono" title="${data.sha256 || ""}">
                ${data.sha256 ? data.sha256.substring(0, 32) + "…" : "N/A"}
            </span>
        </div>

        <div class="modal-row">
            <span class="modal-label">VirusTotal Results</span>
            ${vtBadgeHtml}
        </div>

        <div class="modal-row">
            <span class="modal-label">Verdict</span>
            <span class="modal-value">${data.verdict || "Unknown"}</span>
        </div>

        <div class="modal-row">
            <span class="modal-label">Trust Score</span>
            ${trustHtml}
        </div>
    </div>
`;

            // Animate trust bar after DOM paint
            if (data.trust_score !== undefined && data.trust_score !== null) {
                requestAnimationFrame(() => {
                    const fill = document.getElementById("trustBarFill");
                    if (fill) fill.style.width = Math.max(0, Math.min(100, data.trust_score)) + "%";
                });
            }

        } catch (err) {
            console.error("Analyze error:", err);
            document.getElementById("modalContent").innerHTML = `
                <div class="modal-error">
                    <div class="modal-error-icon">❌</div>
                    <div>Analysis failed: ${err.message}</div>
                </div>
            `;
        }
    });

    // Close modal — X button
    closeModal.addEventListener("click", () => {
        analyzeModal.classList.add("hidden");
    });

    // Close modal — backdrop click
    analyzeModal.addEventListener("click", (e) => {
        if (e.target === analyzeModal) {
            analyzeModal.classList.add("hidden");
        }
    });

    // Close modal — Escape key
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && !analyzeModal.classList.contains("hidden")) {
            analyzeModal.classList.add("hidden");
        }
    });
});

// ====================================
// LIVE SYSTEM CLOCK (UTC)
// ====================================
function initClock() {
    const clockEl = document.getElementById("liveClock");
    if (!clockEl) return;
    
    function update() {
        const now = new Date();
        const hrs = String(now.getUTCHours()).padStart(2, '0');
        const mins = String(now.getUTCMinutes()).padStart(2, '0');
        const secs = String(now.getUTCSeconds()).padStart(2, '0');
        clockEl.textContent = `${hrs}:${mins}:${secs}`;
    }
    update();
    setInterval(update, 1000);
}

// ====================================
// LOAD ALL DATA FROM BACKEND API
// ====================================
async function loadDashboard() {
    try {
        const summaryRes = await fetch(`${API_BASE}/summary`);
        const systemRes = await fetch(`${API_BASE}/system_stats`);
        const suspiciousRes = await fetch(`${API_BASE}/suspicious`);

        if (!summaryRes.ok || !systemRes.ok || !suspiciousRes.ok) {
            throw new Error("HTTP connection error");
        }

        const summary = await summaryRes.json();
        const system = await systemRes.json();
        const suspicious = await suspiciousRes.json();

        if (isOffline) {
            isOffline = false;
            document.getElementById("offlineOverlay").classList.add("hidden");
        }

        currentProcesses = suspicious;

        // Update UI components
        updateSummary(summary);
        updateSystemStats(system);
        updateThreatTable(suspicious);
        updateDetailsPanel();

    } catch (error) {
        console.error("Phoenix Monitor Connection Lost:", error);
        
        if (!isOffline) {
            isOffline = true;
            document.getElementById("offlineOverlay").classList.remove("hidden");
        }
    }
}

// ====================================
// SUMMARY CARDS & SYSTEM STATUS
// ====================================
function updateSummary(data) {
    animateNumber("totalProcesses", data.total_processes || 0);
    animateNumber("threatCount", data.suspicious_processes || 0);
    animateNumber("highRisk", data.high_risk || 0);

    const statusPanel = document.getElementById("systemStatusPanel");
    const statusText = document.getElementById("statusText");

    // Status based on actual threat counts:
    // HIGH threats > 0 -> DANGER
    // MEDIUM threats > 0 -> WARNING
    // No threats -> SECURE
    if (data.high_risk > 0) {
        statusPanel.className = "status-panel danger";
        statusText.textContent = "SYSTEM DANGER";
    } else if (data.medium_risk > 0 || data.suspicious_processes > 0) {
        statusPanel.className = "status-panel warning";
        statusText.textContent = "SYSTEM WARNING";
    } else {
        statusPanel.className = "status-panel secure";
        statusText.textContent = "SYSTEM SECURE";
    }
}

// ====================================
// SYSTEM STATS & CHARTS UPDATES
// ====================================
function updateSystemStats(data) {
    const cpu = Math.round(data.cpu || 0);
    const ram = Math.round(data.ram || 0);

    document.getElementById("cpuGauge").textContent = `${cpu}%`;
    document.getElementById("ramGauge").textContent = `${ram}%`;

    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    labels.push(time);
    cpuHistory.push(cpu);
    ramHistory.push(ram);

    if (labels.length > 15) {
        labels.shift();
        cpuHistory.shift();
        ramHistory.shift();
    }

    cpuChart.data.labels = labels;
    cpuChart.data.datasets[0].data = cpuHistory;

    ramChart.data.labels = labels;
    ramChart.data.datasets[0].data = ramHistory;

    cpuChart.update('none');
    ramChart.update('none');
}

// ====================================
// LIVE THREAT TABLE RENDERING
// ====================================
function updateThreatTable(data) {
    const table = document.getElementById("threatTable");
    if (!table) return;

    table.innerHTML = "";

    if (!data || data.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 6;
        cell.className = "empty-cell";
        cell.textContent = "Phoenix has detected no active threats.";
        row.appendChild(cell);
        table.appendChild(row);
        return;
    }

    data.forEach(proc => {
        const row = document.createElement("tr");
        
        if (selectedPid === proc.pid) {
            row.className = "selected-row";
        }

        const threatClass = getThreatClass(proc.threat_level);
        const locClass = proc.location_classification || "Unknown";
        const locBadgeClass = getLocationClass(locClass);

        row.innerHTML = `
            <td class="font-mono" style="color: #64748b;">${proc.pid}</td>
            <td class="font-mono" style="font-weight: 500; color: #fff;">${proc.name}</td>
            <td class="font-mono text-cyan" style="font-weight: 600;">${proc.risk_score}</td>
            <td>
                <span class="threat-badge ${threatClass}">${proc.threat_level}</span>
            </td>
            <td>
                <span class="threat-badge ${locBadgeClass}">${locClass}</span>
            </td>
            <td class="font-mono" style="color: #64748b; font-size: 0.7rem;">${proc.exe || "N/A"}</td>
        `;

        row.addEventListener("click", () => {
            const rows = table.querySelectorAll("tr");
            rows.forEach(r => r.classList.remove("selected-row"));
            
            selectedPid = proc.pid;
            row.classList.add("selected-row");
            updateDetailsPanel();
        });

        table.appendChild(row);
    });
}

// ====================================
// THREAT DETAILS PANEL RENDERER
// ====================================
function updateDetailsPanel() {
    const container = document.getElementById("detailsContent");
    if (!container) return;

    if (!selectedPid) {
        updateActionButtons(false);
        container.innerHTML = `
            <div class="details-empty">
                No active threats detected.<br><br>Process details will appear here when a suspicious process is identified.
            </div>
        `;
        return;
    }

    // Find selected process in current pool
    const proc = currentProcesses.find(p => p.pid === selectedPid);

    if (!proc) {
        selectedPid = null;
        updateActionButtons(false);
        container.innerHTML = `
            <div class="details-empty">
                No active threats detected.<br><br>Process details will appear here when a suspicious process is identified.
            </div>
        `;
        return;
    }

    const threatClass = getThreatClass(proc.threat_level);
    const locClass = proc.location_classification || "Unknown";
    const locBadgeClass = getLocationClass(locClass);
    const cpuVal = proc.cpu_percent ? proc.cpu_percent.toFixed(1) : "0.0";
    const ramVal = proc.memory_percent ? proc.memory_percent.toFixed(1) : "0.0";

    container.innerHTML = `
        <div class="details-grid">
            <div class="detail-item">
                <span class="detail-label">Process Name</span>
                <span class="detail-value font-mono" style="color: #fff; font-weight: 600;">${proc.name}</span>
            </div>
            
            <div class="detail-item">
                <span class="detail-label">PID</span>
                <span class="detail-value font-mono">${proc.pid}</span>
            </div>
            
            <div class="detail-item">
                <span class="detail-label">CPU Usage</span>
                <span class="detail-value font-mono">${cpuVal}%</span>
            </div>
            
            <div class="detail-item">
                <span class="detail-label">Memory Usage</span>
                <span class="detail-value font-mono">${ramVal}%</span>
            </div>

            <div class="detail-item">
                <span class="detail-label">Risk Score</span>
                <span class="detail-value font-mono" style="font-weight: 600; color: var(--primary);">${proc.risk_score}</span>
            </div>
            
            <div class="detail-item">
                <span class="detail-label">Threat Level</span>
                <div class="detail-value">
                    <span class="threat-badge ${threatClass}">${proc.threat_level}</span>
                </div>
            </div>

            <div class="detail-item full-width">
                <span class="detail-label">Location Classification</span>
                <div class="detail-value">
                    <span class="threat-badge ${locBadgeClass}">${locClass}</span>
                </div>
            </div>

            <div class="detail-item full-width">
                <span class="detail-label">Executable Path</span>
                <span class="detail-value font-mono" style="color: #94a3b8; font-size: 0.7rem;">${proc.exe || "N/A"}</span>
            </div>

            <div class="detail-item full-width">
                <span class="detail-label">Detection Reasons</span>
                <ul class="reasons-list">
                    ${proc.reasons && proc.reasons.length > 0 
                        ? proc.reasons.map(reason => `<li>${reason}</li>`).join('') 
                        : "<li>No specific risk identifiers flagged.</li>"}
                </ul>
            </div>
        </div>
    `;

    // Enable action buttons now that a process is selected
    updateActionButtons(true);
}

// ====================================
// ACTION BUTTON STATE MANAGEMENT
// ====================================
function updateActionButtons(enabled) {
    const btnOpenLocation = document.getElementById("btnOpenLocation");
    const btnAnalyze      = document.getElementById("btnAnalyze");
    if (!btnOpenLocation || !btnAnalyze) return;
    btnOpenLocation.disabled = !enabled;
    btnAnalyze.disabled      = !enabled;
}

// Helpers
function getThreatClass(level) {
    if (level === "HIGH") return "threat-high";
    if (level === "MEDIUM") return "threat-medium";
    return "threat-low";
}

function getLocationClass(location) {
    if (location === "Trusted") return "threat-low";
    if (location === "Suspicious") return "threat-high";
    return "threat-medium";
}

// ====================================
// NUMBER ANIMATION EASE
// ====================================
function animateNumber(elementId, target) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const start = parseInt(element.textContent) || 0;
    if (start === target) return;

    const duration = 500;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const ease = progress * (2 - progress); // outQuad
        const current = Math.floor(start + (target - start) * ease);

        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent = target;
        }
    }
    requestAnimationFrame(update);
}

// ====================================
// CHART CONFIGURATIONS
// ====================================
function initializeCharts() {
    const gridStyle = {
        color: "rgba(255, 255, 255, 0.02)",
        borderColor: "rgba(255, 255, 255, 0.05)"
    };
    
    const fontStyle = {
        family: "'Inter', sans-serif",
        size: 9,
        color: "#64748b"
    };

    // CPU Chart
    const cpuCtx = document.getElementById("cpuChart");
    if (cpuCtx) {
        cpuChart = new Chart(cpuCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    borderColor: "#0ea5e9",
                    backgroundColor: "rgba(14, 165, 233, 0.02)",
                    borderWidth: 1.5,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 0,
                    pointHoverRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: gridStyle,
                        ticks: { display: false }
                    },
                    y: {
                        min: 0,
                        max: 100,
                        grid: gridStyle,
                        ticks: { color: "#64748b", font: fontStyle }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // RAM Chart
    const ramCtx = document.getElementById("ramChart");
    if (ramCtx) {
        ramChart = new Chart(ramCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    borderColor: "#8b5cf6",
                    backgroundColor: "rgba(139, 92, 246, 0.02)",
                    borderWidth: 1.5,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 0,
                    pointHoverRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: gridStyle,
                        ticks: { display: false }
                    },
                    y: {
                        min: 0,
                        max: 100,
                        grid: gridStyle,
                        ticks: { color: "#64748b", font: fontStyle }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
}

// ====================================
// THREE.JS HIGH PERFORMANCE BACKGROUND
// ====================================
function initThreeBackground() {
    const container = document.getElementById("three-container");
    if (!container) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 1, 1000);
    camera.position.z = 300;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    renderer.setSize(window.innerWidth, window.innerHeight);
    container.appendChild(renderer.domElement);

    // Create particles nodes
    const count = 65;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(count * 3);
    const velocities = [];

    const boundX = 250;
    const boundY = 150;
    const boundZ = 120;

    for (let i = 0; i < count; i++) {
        positions[i * 3] = (Math.random() - 0.5) * boundX * 2;
        positions[i * 3 + 1] = (Math.random() - 0.5) * boundY * 2;
        positions[i * 3 + 2] = (Math.random() - 0.5) * boundZ * 2;

        velocities.push({
            x: (Math.random() - 0.5) * 0.22,
            y: (Math.random() - 0.5) * 0.22,
            z: (Math.random() - 0.5) * 0.1
        });
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const material = new THREE.PointsMaterial({
        color: 0x0ea5e9,
        size: 2,
        transparent: true,
        opacity: 0.5
    });

    const particles = new THREE.Points(geometry, material);
    scene.add(particles);

    // Node link connections line segments
    const maxLinks = 120;
    const connectionRange = 85;
    const lineGeo = new THREE.BufferGeometry();
    const linePos = new Float32Array(maxLinks * 2 * 3);
    const lineCol = new Float32Array(maxLinks * 2 * 3);

    lineGeo.setAttribute('position', new THREE.BufferAttribute(linePos, 3));
    lineGeo.setAttribute('color', new THREE.BufferAttribute(lineCol, 3));

    const lineMat = new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0.1
    });

    const lines = new THREE.LineSegments(lineGeo, lineMat);
    scene.add(lines);

    // Mouse movement listeners
    let mouseX = 0, mouseY = 0;
    document.addEventListener('mousemove', (e) => {
        mouseX = (e.clientX - window.innerWidth / 2) * 0.02;
        mouseY = (e.clientY - window.innerHeight / 2) * 0.02;
    });

    function animate() {
        requestAnimationFrame(animate);

        // Smooth camera track parallax
        camera.position.x += (mouseX - camera.position.x) * 0.04;
        camera.position.y += (-mouseY - camera.position.y) * 0.04;
        camera.lookAt(scene.position);

        const pos = particles.geometry.attributes.position.array;

        // Move nodes
        for (let i = 0; i < count; i++) {
            pos[i * 3] += velocities[i].x;
            pos[i * 3 + 1] += velocities[i].y;
            pos[i * 3 + 2] += velocities[i].z;

            // Bounce boundary constraints
            if (pos[i * 3] < -boundX || pos[i * 3] > boundX) velocities[i].x *= -1;
            if (pos[i * 3 + 1] < -boundY || pos[i * 3 + 1] > boundY) velocities[i].y *= -1;
            if (pos[i * 3 + 2] < -boundZ || pos[i * 3 + 2] > boundZ) velocities[i].z *= -1;
        }
        particles.geometry.attributes.position.needsUpdate = true;

        // Connections calculations
        let linkIdx = 0;
        const linePosArr = lines.geometry.attributes.position.array;
        const lineColArr = lines.geometry.attributes.color.array;

        for (let i = 0; i < count; i++) {
            const x1 = pos[i * 3];
            const y1 = pos[i * 3 + 1];
            const z1 = pos[i * 3 + 2];

            for (let j = i + 1; j < count; j++) {
                const x2 = pos[j * 3];
                const y2 = pos[j * 3 + 1];
                const z2 = pos[j * 3 + 2];

                const dx = x1 - x2;
                const dy = y1 - y2;
                const dz = z1 - z2;
                const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);

                if (dist < connectionRange && linkIdx < maxLinks) {
                    const idx = linkIdx * 6;
                    linePosArr[idx] = x1;
                    linePosArr[idx + 1] = y1;
                    linePosArr[idx + 2] = z1;

                    linePosArr[idx + 3] = x2;
                    linePosArr[idx + 4] = y2;
                    linePosArr[idx + 5] = z2;

                    const opacity = 1.0 - (dist / connectionRange);

                    // Dual blend nodes path color
                    lineColArr[idx] = 0.05 * opacity;      // R
                    lineColArr[idx + 1] = 0.65 * opacity;  // G
                    lineColArr[idx + 2] = 0.91 * opacity;  // B

                    lineColArr[idx + 3] = 0.54 * opacity;  // R
                    lineColArr[idx + 4] = 0.36 * opacity;  // G
                    lineColArr[idx + 5] = 0.96 * opacity;  // B

                    linkIdx++;
                }
            }
        }

        lines.geometry.setDrawRange(0, linkIdx * 2);
        lines.geometry.attributes.position.needsUpdate = true;
        lines.geometry.attributes.color.needsUpdate = true;

        particles.rotation.y += 0.0003;
        lines.rotation.y += 0.0003;

        renderer.render(scene, camera);
    }
    animate();

    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}

// ====================================
// RUNNING PROCESSES TABLE
// ====================================
async function loadProcesses() {
    try {
        const res = await fetch(`${API_BASE}/processes`);
        if (!res.ok) throw new Error("HTTP error");
        const data = await res.json();
        renderProcessesTable(data);
    } catch (e) {
        console.error("Phoenix Monitor — Failed to load processes:", e);
    }
}

function renderProcessesTable(data) {
    const tbody = document.getElementById("processesTable");
    if (!tbody) return;

    // Build a Set of suspicious PIDs for O(1) status lookup
    const suspiciousPids = new Set(currentProcesses.map(p => p.pid));

    tbody.innerHTML = "";

    if (!data || data.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 5;
        cell.className = "empty-cell";
        cell.textContent = "No running processes found.";
        row.appendChild(cell);
        tbody.appendChild(row);
        return;
    }

    // Show all rows — .processes-table-wrapper provides scroll
    data.forEach(proc => {
        const isMonitoring = suspiciousPids.has(proc.pid);
        const statusClass  = isMonitoring ? "status-monitoring" : "status-safe";
        const statusText   = isMonitoring ? "Monitoring" : "Safe";

        const row = document.createElement("tr");
        row.innerHTML = `
            <td class="font-mono" style="color: #64748b;">${proc.pid}</td>
            <td class="font-mono" style="font-weight: 500; color: #fff;">${proc.name}</td>
            <td class="font-mono" style="color: var(--primary);">${(proc.cpu_percent || 0).toFixed(1)}%</td>
            <td class="font-mono" style="color: var(--purple);">${(proc.memory_percent || 0).toFixed(1)}%</td>
            <td><span class="threat-badge ${statusClass}">${statusText}</span></td>
        `;
        tbody.appendChild(row);
    });
}

// ====================================
// TOAST NOTIFICATIONS
// ====================================
function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const iconMap = { success: "✅", error: "❌", info: "ℹ️" };
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${iconMap[type] || "ℹ️"}</span>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    // Auto-dismiss after 3.5s with slide-out animation
    setTimeout(() => {
        toast.style.animation = "toastFadeOut 0.35s ease forwards";
        setTimeout(() => toast.remove(), 350);
    }, 3500);
}
