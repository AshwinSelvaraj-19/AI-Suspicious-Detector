const scanMessages = [
    "Initializing Phoenix Security Core...",
    "Loading Neural Threat Profiles...",
    "Scanning Active Processes...",
    "Analyzing Process Telemetry...",
    "Computing Threat Heat Index...",
    "Deploying Cyber Resilience Shield...",
    "Verifying Self-Healing Cycles...",
    "Finalizing Command Deck..."
];

// ==========================
// DOM ELEMENTS
// ==========================
const statusText = document.getElementById("phase-text");
const progressText = document.getElementById("ring-percent");
const progressCircle = document.getElementById("progress-arc");
const logStream = document.getElementById("log-stream");
const sessionInfo = document.getElementById("session-id");
const timeEl = document.getElementById("scan-time");

if (!statusText || !progressText || !progressCircle) {
    console.error("Required scan elements not found.");
    throw new Error("Scan UI initialization failed.");
}

// Generate a random Neural Link Session ID
if (sessionInfo) {
    const chars = "ABCDEF0123456789";
    let sid = "PHX-";
    for (let i = 0; i < 8; i++) {
        sid += chars[Math.floor(Math.random() * chars.length)];
    }
    sessionInfo.textContent = sid;
}

// ==========================
// PROGRESS SETTINGS
// ==========================
let progress = 0;
let currentMessage = 0;
const radius = 110;
const circumference = 2 * Math.PI * radius;

progressCircle.style.strokeDasharray = circumference;
progressCircle.style.strokeDashoffset = circumference;

// ==========================
// UPDATE RING
// ==========================
function updateProgress(percent) {
    const offset = circumference - (percent / 100) * circumference;
    progressCircle.style.strokeDashoffset = offset;
    progressText.innerHTML = `${percent}<span>%</span>`;
}

// Add logs dynamically
function addLog(text, type = "") {
    if (!logStream) return;
    const entry = document.createElement("div");
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    logStream.appendChild(entry);
    if (logStream.children.length > 5) {
        logStream.removeChild(logStream.firstChild);
    }
}

// Start timer
let seconds = 0;
setInterval(() => {
    seconds++;
    const m = String(Math.floor(seconds / 60)).padStart(2, '0');
    const s = String(seconds % 60).padStart(2, '0');
    if (timeEl) timeEl.textContent = `${m}:${s}`;
}, 1000);

// Set active stage visual
function updateStages(progressVal) {
    const stages = document.querySelectorAll(".stages .stage");
    let currentStageIndex = Math.min(Math.floor(progressVal / 20), 4);
    
    stages.forEach((stage, idx) => {
        const fill = stage.querySelector(".stage-fill");
        const pct = stage.querySelector(".stage-pct");
        const icon = stage.querySelector(".stage-icon");
        
        if (idx < currentStageIndex) {
            stage.className = "stage done";
            if (fill) fill.style.width = "100%";
            if (pct) pct.textContent = "100%";
            if (icon) icon.textContent = "✓";
        } else if (idx === currentStageIndex) {
            stage.className = "stage active";
            const stagePct = ((progressVal % 20) / 20) * 100;
            if (fill) fill.style.width = `${stagePct}%`;
            if (pct) pct.textContent = `${Math.round(stagePct)}%`;
            if (icon) icon.textContent = "⌬";
        } else {
            stage.className = "stage";
            if (fill) fill.style.width = "0%";
            if (pct) pct.textContent = "0%";
            if (icon) icon.textContent = "◯";
        }
    });
}

// ==========================
// START SCAN
// ==========================
const scanInterval = setInterval(() => {
    progress += 2;
    if (progress > 100) progress = 100;

    updateProgress(progress);
    updateStages(progress);

    // Update messages
    const messageIndex = Math.min(Math.floor(progress / 13.5), scanMessages.length - 1);
    if (messageIndex !== currentMessage) {
        currentMessage = messageIndex;
        statusText.textContent = scanMessages[currentMessage];
        addLog(`Phase shift: ${scanMessages[currentMessage]}`, "accent");
    }

    // Dynamic logging decoration
    if (progress % 6 === 0 && progress < 100) {
        const mocks = [
            "Mounting PHOENIX Neural Core components...",
            "Hooking system interrupts...",
            "Running memory heuristics scan...",
            "Tracing system processes...",
            "Calculating entropy values...",
            "Validating system integrity keys...",
            "Adaptive Intelligence thresholds adjusted."
        ];
        addLog(mocks[Math.floor(Math.random() * mocks.length)]);
    }

    // Scan completed
    if (progress >= 100) {
        clearInterval(scanInterval);
        statusText.textContent = "Rebirth Complete. Launching Command Deck.";
        addLog("Phoenix Security Core fully online.", "success");

        setTimeout(() => {
            window.location.href = "dashboard.html";
        }, 1200);
    }
}, 100);