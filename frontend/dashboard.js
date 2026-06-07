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
