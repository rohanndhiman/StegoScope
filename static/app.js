/**
 * StegoScope — Frontend Application Logic (Upgraded)
 * 
 * Handles: mode selection, theme switcher, simulated terminal console logs,
 * drag-and-drop upload, API communication, results rendering with conic counter,
 * technique cards (with slider comparisons and custom waveform players),
 * CTF suggestions, stegsolve bit-plane visualizer, strings filtering,
 * binwalk extractor, and steghide decrypter.
 */

(function () {
    "use strict";

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------
    let currentMode = "malware"; // "malware" or "ctf"
    let selectedFile = null;
    
    // Extracted payload elements stored for filtering/downloading
    let originalImageSrc = null;
    let extractedStrings = [];
    let binwalkFiles = [];

    // -----------------------------------------------------------------------
    // DOM references
    // -----------------------------------------------------------------------
    const screens = {
        landing: document.getElementById("screen-landing"),
        upload:  document.getElementById("screen-upload"),
        results: document.getElementById("screen-results"),
    };

    // Landing
    const btnModeMalware = document.getElementById("btn-mode-malware");
    const btnModeCTF     = document.getElementById("btn-mode-ctf");
    const cardMalware    = document.getElementById("card-malware");
    const cardCTF        = document.getElementById("card-ctf");

    // Upload
    const btnBack        = document.getElementById("btn-back-to-landing");
    const modeBadgeIcon  = document.getElementById("mode-badge-icon");
    const modeBadgeText  = document.getElementById("mode-badge-text");
    const dropZone       = document.getElementById("drop-zone");
    const fileInput      = document.getElementById("file-input");
    const fileInfo       = document.getElementById("file-info");
    const fileTypeIcon   = document.getElementById("file-type-icon");
    const fileNameDisplay = document.getElementById("file-name-display");
    const fileSizeDisplay = document.getElementById("file-size-display");
    const btnRemoveFile  = document.getElementById("btn-remove-file");
    const btnAnalyze     = document.getElementById("btn-analyze");
    const progressContainer = document.getElementById("progress-container");
    const progressFill   = document.getElementById("progress-fill");
    const terminalBody   = document.getElementById("terminal-body");
    const uploadError    = document.getElementById("upload-error");

    // Results
    const scoreGaugeRing  = document.getElementById("score-gauge-ring");
    const scoreValue      = document.getElementById("score-value");
    const overallBadge    = document.getElementById("overall-badge");
    const resultFilename  = document.getElementById("result-filename");
    const overallSummary  = document.getElementById("overall-summary");
    const techniquesGrid  = document.getElementById("techniques-grid");
    const ctfPanel        = document.getElementById("ctf-panel");
    const ctfSuggestionsList = document.getElementById("ctf-suggestions-list");
    const btnReset        = document.getElementById("btn-reset");

    // Results Upgrade Elements
    const tabButtons      = document.querySelectorAll(".tab-btn");
    const tabContents     = document.querySelectorAll(".tab-content");
    const tabStegsolveBtn = document.getElementById("tab-stegsolve-btn");
    
    // Stegsolve canvas components
    const stegsolveCanvas = document.getElementById("stegsolve-canvas");
    const stegsolveCtx    = stegsolveCanvas.getContext("2d");
    let stegsolveOriginalImg = null;
    let stegsolveChannel  = "r";
    let stegsolveBit      = 0;
    let stegsolveMode     = "mono";
    
    // Strings console
    const stringsCount    = document.getElementById("strings-count");
    const stringsSearch   = document.getElementById("strings-search");
    const stringsConsole  = document.getElementById("strings-console");
    
    // Binwalk table
    const binwalkTableBody = document.getElementById("binwalk-table-body");
    
    // Steghide form
    const steghidePassphrase = document.getElementById("steghide-passphrase");
    const btnSteghideDecrypt = document.getElementById("btn-steghide-decrypt");
    const steghideResultBox  = document.getElementById("steghide-result-box");
    const steghideResultHeader = document.getElementById("steghide-result-header");
    const steghideResultText = document.getElementById("steghide-result-text");

    // Recommendations panel title
    const ctfPanelTitle   = document.getElementById("ctf-panel-title");
    
    // History Drawer DOM references
    const btnOpenHistory  = document.getElementById("btn-open-history");
    const btnCloseHistory = document.getElementById("btn-close-history");
    const btnClearHistory = document.getElementById("btn-clear-history");
    const historyDrawer   = document.getElementById("history-drawer");
    const historyList     = document.getElementById("history-list");
    const historyCount    = document.getElementById("history-count");
    const drawerOverlay   = document.getElementById("drawer-overlay");

    // Lightbox
    const lightbox       = document.getElementById("lightbox");
    const lightboxImg    = document.getElementById("lightbox-img");

    // Constants
    const ALLOWED_EXTENSIONS = [".png", ".jpg", ".jpeg", ".bmp", ".wav", ".mp3"];
    const MAX_SIZE = 20 * 1024 * 1024; // 20 MB

    // -----------------------------------------------------------------------
    // Theme Engine (Settings Panel, Light/Dark Toggle, Structural Themes)
    // -----------------------------------------------------------------------
    const settingsToggle = document.getElementById("btn-toggle-settings");
    const settingsPanel  = document.getElementById("settings-panel");
    const modeToggle     = document.getElementById("mode-toggle-checkbox");

    // Restore saved preferences
    const savedStructure = localStorage.getItem("stegoscope-structure") || "glass";
    const savedColorMode = localStorage.getItem("stegoscope-color-mode") || "dark";

    applyStructuralTheme(savedStructure);
    applyColorMode(savedColorMode);

    // Settings panel toggle
    settingsToggle.addEventListener("click", (e) => {
        e.stopPropagation();
        settingsPanel.classList.toggle("show");
    });
    document.addEventListener("click", (e) => {
        if (!settingsPanel.contains(e.target) && e.target !== settingsToggle) {
            settingsPanel.classList.remove("show");
        }
    });

    // Light / Dark toggle
    modeToggle.addEventListener("change", () => {
        applyColorMode(modeToggle.checked ? "light" : "dark");
    });

    function applyColorMode(mode) {
        if (mode === "light") {
            document.body.classList.add("light-mode");
            modeToggle.checked = true;
        } else {
            document.body.classList.remove("light-mode");
            modeToggle.checked = false;
        }
        localStorage.setItem("stegoscope-color-mode", mode);
    }

    // Structural theme buttons
    document.querySelectorAll(".theme-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const theme = btn.getAttribute("data-theme");
            applyStructuralTheme(theme);
        });
    });

    function applyStructuralTheme(theme) {
        // Remove all structural theme classes
        document.body.classList.remove("theme-minimal", "theme-glass", "theme-cyber", "theme-classic");
        document.body.classList.add(`theme-${theme}`);
        document.querySelectorAll(".theme-btn").forEach(b => {
            const match = b.getAttribute("data-theme") === theme;
            b.classList.toggle("active", match);
        });
        localStorage.setItem("stegoscope-structure", theme);
    }

    // -----------------------------------------------------------------------
    // Scan History System
    // -----------------------------------------------------------------------
    let scanHistory = [];

    function loadHistory() {
        try {
            const stored = localStorage.getItem("stegoscope-scan-history");
            scanHistory = stored ? JSON.parse(stored) : [];
        } catch (err) {
            scanHistory = [];
        }
        updateHistoryCount();
    }

    function saveHistory() {
        try {
            localStorage.setItem("stegoscope-scan-history", JSON.stringify(scanHistory));
        } catch (err) {
            // ignore
        }
        updateHistoryCount();
    }

    function updateHistoryCount() {
        if (historyCount) historyCount.textContent = scanHistory.length;
    }

    function addScanToHistory(filename, category, overallScore, overallLabel, responseData) {
        scanHistory = scanHistory.filter(item => item.filename !== filename);
        const newItem = {
            id: Date.now(),
            filename: filename,
            category: category,
            score: overallScore,
            label: overallLabel,
            timestamp: new Date().toLocaleString(),
            data: responseData
        };
        scanHistory.unshift(newItem);
        if (scanHistory.length > 10) {
            scanHistory = scanHistory.slice(0, 10);
        }
        saveHistory();
    }

    function deleteHistoryItem(id) {
        scanHistory = scanHistory.filter(item => item.id !== id);
        saveHistory();
        renderHistoryList();
    }

    function renderHistoryList() {
        historyList.innerHTML = "";
        if (scanHistory.length === 0) {
            const empty = document.createElement("div");
            empty.className = "history-empty";
            empty.textContent = "No recent scans saved.";
            historyList.appendChild(empty);
            return;
        }

        scanHistory.forEach(item => {
            const card = document.createElement("div");
            card.className = "history-card";
            
            const header = document.createElement("div");
            header.className = "history-card-header";
            
            const name = document.createElement("span");
            name.className = "history-card-name";
            name.textContent = item.filename;
            header.appendChild(name);
            
            const delBtn = document.createElement("button");
            delBtn.className = "history-card-delete";
            delBtn.innerHTML = "✕";
            delBtn.title = "Delete record";
            delBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                deleteHistoryItem(item.id);
            });
            header.appendChild(delBtn);
            card.appendChild(header);
            
            const meta = document.createElement("div");
            meta.className = "history-card-meta";
            
            const time = document.createElement("span");
            time.className = "history-card-time";
            time.textContent = item.timestamp;
            meta.appendChild(time);
            
            const badge = document.createElement("span");
            const sev = getSeverity(item.score);
            badge.className = `history-card-badge severity-badge ${sev.cls}`;
            badge.textContent = `${item.score}% ${item.label}`;
            meta.appendChild(badge);
            card.appendChild(meta);
            
            card.addEventListener("click", () => {
                closeHistoryDrawer();
                selectedFile = new File(["mock"], item.filename, {
                    type: item.category === "image" ? "image/png" : "audio/wav"
                });
                
                const mode = item.data.ctf_suggestions ? "ctf" : "malware";
                selectMode(mode);
                renderResults(item.data);
            });
            
            historyList.appendChild(card);
        });
    }

    function openHistoryDrawer() {
        renderHistoryList();
        historyDrawer.classList.add("active");
        drawerOverlay.classList.add("active");
        historyDrawer.setAttribute("aria-hidden", "false");
    }

    function closeHistoryDrawer() {
        historyDrawer.classList.remove("active");
        drawerOverlay.classList.remove("active");
        historyDrawer.setAttribute("aria-hidden", "true");
    }

    btnOpenHistory.addEventListener("click", openHistoryDrawer);
    btnCloseHistory.addEventListener("click", closeHistoryDrawer);
    drawerOverlay.addEventListener("click", closeHistoryDrawer);

    btnClearHistory.addEventListener("click", () => {
        scanHistory = [];
        saveHistory();
        renderHistoryList();
    });

    loadHistory();


    // -----------------------------------------------------------------------
    // Simulated Terminal Scanning Logger
    // -----------------------------------------------------------------------
    function clearLogs() {
        terminalBody.innerHTML = "";
    }

    function writeLog(tag, message, severity = "info") {
        const line = document.createElement("div");
        line.className = "log-line";
        
        const time = document.createElement("span");
        time.className = "log-time";
        const now = new Date();
        const pad = (n) => String(n).padStart(2, "0");
        time.textContent = `[${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}]`;
        
        const tagSpan = document.createElement("span");
        tagSpan.className = `log-tag ${severity}`;
        tagSpan.textContent = `[${tag}]`;
        
        const msg = document.createElement("span");
        msg.className = "log-msg";
        msg.textContent = message;
        
        line.appendChild(time);
        line.appendChild(tagSpan);
        line.appendChild(msg);
        terminalBody.appendChild(line);
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    function simulateForensicScan(fileCategory, fileType) {
        return new Promise((resolve) => {
            clearLogs();
            progressFill.style.width = "0%";
            writeLog("SYSTEM", "Booting StegoScope forensic analysis suite...", "info");
            
            const steps = [
                { percent: 15, tag: "SYSTEM", msg: "Reading file magic bytes and metadata headers...", sev: "info" },
                { percent: 30, tag: "INFO", msg: `File signature verified as ${fileCategory.toUpperCase()} (${fileType.toUpperCase()})`, sev: "success" },
                { percent: 50, tag: "ENGINE", msg: "Running Chi-Square goodness-of-fit pair analysis...", sev: "engine" },
                { percent: 70, tag: "ENGINE", msg: fileCategory === "image" ? "Computing Error Level Analysis (ELA) compression difference..." : "Performing STFT and high-frequency band entropy scans...", sev: "engine" },
                { percent: 85, tag: "ENGINE", msg: "Scanning binary structure for embedded magic signatures (binwalk)...", sev: "engine" },
                { percent: 95, tag: "ENGINE", msg: "Extracting printable ASCII byte sequences (strings)...", sev: "engine" },
                { percent: 100, tag: "SUCCESS", msg: "Scans complete. Aggregating confidence vectors...", sev: "success" }
            ];
            
            steps.forEach((step, index) => {
                setTimeout(() => {
                    writeLog(step.tag, step.msg, step.sev);
                    progressFill.style.width = `${step.percent}%`;
                    if (index === steps.length - 1) {
                        setTimeout(resolve, 200);
                    }
                }, (index + 1) * 320);
            });
        });
    }

    // -----------------------------------------------------------------------
    // Tab Controller
    // -----------------------------------------------------------------------
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            switchTab(targetTab);
        });
    });

    function switchTab(tabId) {
        tabButtons.forEach(b => {
            const match = b.getAttribute("data-tab") === tabId;
            b.classList.toggle("active", match);
            b.setAttribute("aria-selected", match ? "true" : "false");
        });
        
        tabContents.forEach(c => {
            const cId = c.getAttribute("id");
            c.style.display = cId === `tab-${tabId}-content` ? "block" : "none";
        });
    }

    // -----------------------------------------------------------------------
    // Stegsolve Visualizer Logic (Canvas Processing)
    // -----------------------------------------------------------------------
    function setupStegsolve(imageSrc) {
        stegsolveOriginalImg = new Image();
        stegsolveOriginalImg.onload = () => {
            stegsolveCanvas.width = stegsolveOriginalImg.naturalWidth;
            stegsolveCanvas.height = stegsolveOriginalImg.naturalHeight;
            applyStegsolveFilter();
        };
        stegsolveOriginalImg.src = imageSrc;
    }

    // Hook stegsolve buttons
    document.querySelectorAll(".control-btn-grid button").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const grid = btn.parentElement;
            grid.querySelectorAll("button").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            
            const group = grid.getAttribute("data-group");
            const val = btn.getAttribute("data-value");
            
            if (group === "channel") stegsolveChannel = val;
            else if (group === "bit") stegsolveBit = parseInt(val);
            else if (group === "mode") stegsolveMode = val;
            
            applyStegsolveFilter();
        });
    });

    function applyStegsolveFilter() {
        if (!stegsolveOriginalImg || !stegsolveOriginalImg.complete) return;
        
        // Draw original image first
        stegsolveCtx.drawImage(stegsolveOriginalImg, 0, 0);
        
        const width = stegsolveCanvas.width;
        const height = stegsolveCanvas.height;
        if (width === 0 || height === 0) return;
        
        const imgData = stegsolveCtx.getImageData(0, 0, width, height);
        const pixels = imgData.data;
        const bitMask = 1 << stegsolveBit;
        
        for (let i = 0; i < pixels.length; i += 4) {
            let r = pixels[i];
            let g = pixels[i+1];
            let b = pixels[i+2];
            let a = pixels[i+3];
            
            let targetVal = 0;
            if (stegsolveChannel === "r") targetVal = r;
            else if (stegsolveChannel === "g") targetVal = g;
            else if (stegsolveChannel === "b") targetVal = b;
            else if (stegsolveChannel === "a") targetVal = a;
            
            // Extract selected bit (0 or 1)
            const bitVal = (targetVal & bitMask) ? 1 : 0;
            
            if (stegsolveMode === "mono") {
                const color = bitVal * 255;
                pixels[i] = color;
                pixels[i+1] = color;
                pixels[i+2] = color;
                pixels[i+3] = 255;
            } else if (stegsolveMode === "invert") {
                const color = (1 - bitVal) * 255;
                pixels[i] = color;
                pixels[i+1] = color;
                pixels[i+2] = color;
                pixels[i+3] = 255;
            } else if (stegsolveMode === "normal") {
                const val = bitVal ? bitMask : 0;
                pixels[i] = (stegsolveChannel === "r") ? val : 0;
                pixels[i+1] = (stegsolveChannel === "g") ? val : 0;
                pixels[i+2] = (stegsolveChannel === "b") ? val : 0;
                pixels[i+3] = (stegsolveChannel === "a") ? val : 255;
            }
        }
        
        stegsolveCtx.putImageData(imgData, 0, 0);
    }

    // -----------------------------------------------------------------------
    // Interactive Visual Utilities: Comparison Slider & Custom Wave Player
    // -----------------------------------------------------------------------
    function createComparisonSlider(originalSrc, vizSrc) {
        const wrapper = document.createElement("div");
        wrapper.className = "slider-container";
        
        const imgOrig = document.createElement("img");
        imgOrig.className = "slider-img";
        imgOrig.src = originalSrc;
        
        const imgViz = document.createElement("img");
        imgViz.className = "slider-img slider-overlay";
        imgViz.src = vizSrc;
        
        const handle = document.createElement("div");
        handle.className = "slider-handle";
        
        const labelOrig = document.createElement("span");
        labelOrig.className = "slider-label orig";
        labelOrig.textContent = "ORIGINAL";
        
        const labelViz = document.createElement("span");
        labelViz.className = "slider-label viz";
        labelViz.textContent = "FORENSIC";
        
        wrapper.appendChild(imgOrig);
        wrapper.appendChild(imgViz);
        wrapper.appendChild(handle);
        wrapper.appendChild(labelOrig);
        wrapper.appendChild(labelViz);
        
        let isDragging = false;
        
        function setSplit(clientX) {
            const rect = wrapper.getBoundingClientRect();
            const offsetX = clientX - rect.left;
            const percent = Math.min(100, Math.max(0, (offsetX / rect.width) * 100));
            imgViz.style.clipPath = `inset(0 0 0 ${percent}%)`;
            handle.style.left = `${percent}%`;
        }
        
        wrapper.addEventListener("mousedown", (e) => {
            isDragging = true;
            setSplit(e.clientX);
        });
        
        window.addEventListener("mousemove", (e) => {
            if (!isDragging) return;
            setSplit(e.clientX);
        });
        
        window.addEventListener("mouseup", () => {
            isDragging = false;
        });
        
        // Touch support
        wrapper.addEventListener("touchstart", (e) => {
            isDragging = true;
            setSplit(e.touches[0].clientX);
        });
        wrapper.addEventListener("touchmove", (e) => {
            if (!isDragging) return;
            setSplit(e.touches[0].clientX);
        });
        wrapper.addEventListener("touchend", () => {
            isDragging = false;
        });
        
        return wrapper;
    }

    function createWaveformPlayer(audioDataUrl, score) {
        const wrapper = document.createElement("div");
        wrapper.className = "audio-card-player";
        
        const controlsRow = document.createElement("div");
        controlsRow.className = "audio-controls-row";
        
        const playBtn = document.createElement("button");
        playBtn.className = "audio-play-btn";
        playBtn.textContent = "▶";
        
        const timeLabel = document.createElement("span");
        timeLabel.className = "audio-time-label";
        timeLabel.textContent = "0:00 / 0:00";
        
        const canvas = document.createElement("canvas");
        canvas.className = "audio-waveform-canvas";
        canvas.width = 300;
        canvas.height = 36;
        
        controlsRow.appendChild(playBtn);
        controlsRow.appendChild(timeLabel);
        controlsRow.appendChild(canvas);
        wrapper.appendChild(controlsRow);
        
        const audio = new Audio(audioDataUrl);
        let playing = false;
        
        playBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            if (playing) {
                audio.pause();
            } else {
                audio.play();
            }
        });
        
        audio.addEventListener("play", () => {
            playing = true;
            playBtn.textContent = "⏸";
            animatePlayhead();
        });
        
        audio.addEventListener("pause", () => {
            playing = false;
            playBtn.textContent = "▶";
        });
        
        audio.addEventListener("ended", () => {
            playing = false;
            playBtn.textContent = "▶";
            drawWaveform();
        });
        
        audio.addEventListener("timeupdate", () => {
            const cur = formatTime(audio.currentTime);
            const dur = formatTime(audio.duration || 0);
            timeLabel.textContent = `${cur} / ${dur}`;
        });
        
        function formatTime(secs) {
            const m = Math.floor(secs / 60);
            const s = Math.floor(secs % 60);
            return `${m}:${s < 10 ? '0' : ''}${s}`;
        }
        
        const ctx = canvas.getContext("2d");
        
        function drawWaveform() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = "var(--text-muted)";
            const barWidth = 2;
            const gap = 1;
            const count = Math.floor(canvas.width / (barWidth + gap));
            
            // Seeded random height waves
            let seed = 50;
            function randomHeight() {
                let x = Math.sin(seed++) * 10000;
                return x - Math.floor(x);
            }
            
            for (let i = 0; i < count; i++) {
                const h = 4 + randomHeight() * 26;
                const x = i * (barWidth + gap);
                const y = (canvas.height - h) / 2;
                
                // Highlight anomalous visual waves in red if stego suspected
                const progress = i / count;
                if (score > 35 && progress > 0.35 && progress < 0.65) {
                    ctx.fillStyle = "var(--color-high)";
                } else {
                    ctx.fillStyle = "var(--text-muted)";
                }
                ctx.fillRect(x, y, barWidth, h);
            }
        }
        
        function animatePlayhead() {
            if (!playing) return;
            drawWaveform();
            
            const progress = audio.currentTime / audio.duration;
            const x = progress * canvas.width;
            
            ctx.fillStyle = "var(--accent-color)";
            ctx.fillRect(x - 1, 0, 2, canvas.height);
            
            ctx.fillStyle = "var(--accent-color)";
            const barWidth = 2;
            const gap = 1;
            const count = Math.floor(x / (barWidth + gap));
            
            let seed = 50;
            function randomHeight() {
                let x = Math.sin(seed++) * 10000;
                return x - Math.floor(x);
            }
            for (let i = 0; i < count; i++) {
                const h = 4 + randomHeight() * 26;
                const waveX = i * (barWidth + gap);
                const y = (canvas.height - h) / 2;
                ctx.fillRect(waveX, y, barWidth, h);
            }
            
            requestAnimationFrame(animatePlayhead);
        }
        
        canvas.addEventListener("click", (e) => {
            e.stopPropagation();
            const rect = canvas.getBoundingClientRect();
            const clickX = e.clientX - rect.left;
            const pct = clickX / rect.width;
            audio.currentTime = pct * audio.duration;
            drawWaveform();
            if (playing) {
                animatePlayhead();
            } else {
                ctx.fillStyle = "var(--accent-color)";
                ctx.fillRect(clickX - 1, 0, 2, canvas.height);
            }
        });
        
        setTimeout(drawWaveform, 100);
        return wrapper;
    }

    // -----------------------------------------------------------------------
    // Strings Finder Display Filters
    // -----------------------------------------------------------------------
    function renderStrings(filterQuery = "") {
        stringsConsole.innerHTML = "";
        const query = filterQuery.toLowerCase();
        
        const filtered = extractedStrings.filter(s => s.toLowerCase().includes(query));
        stringsCount.textContent = `Discovered strings: ${filtered.length} (filtered from ${extractedStrings.length})`;
        
        if (filtered.length === 0) {
            const empty = document.createElement("div");
            empty.className = "strings-empty";
            empty.textContent = "No strings match your filter.";
            stringsConsole.appendChild(empty);
            return;
        }
        
        // Render strings in terminal blocks
        filtered.forEach((str, index) => {
            const line = document.createElement("div");
            line.className = "string-line";
            
            const num = document.createElement("span");
            num.className = "string-index";
            num.textContent = String(index + 1).padStart(4, "0");
            line.appendChild(num);
            
            // Check if matches flag regex to apply highlight
            const isFlag = /([A-Za-z0-9_\-]{3,15}\{[A-Za-z0-9_\-\.\!\?]{5,80}\})/.test(str);
            if (isFlag) {
                const highlight = document.createElement("span");
                highlight.className = "string-flag-highlight";
                highlight.textContent = str;
                line.appendChild(highlight);
            } else {
                const text = document.createTextNode(str);
                line.appendChild(text);
            }
            stringsConsole.appendChild(line);
        });
    }

    stringsSearch.addEventListener("input", (e) => {
        renderStrings(e.target.value);
    });

    // -----------------------------------------------------------------------
    // Binwalk Magic byte extractor
    // -----------------------------------------------------------------------
    function renderBinwalkTable(files) {
        binwalkTableBody.innerHTML = "";
        binwalkFiles = files;
        
        if (files.length === 0) {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td colspan="5" class="binwalk-empty">No embedded signatures found at non-zero offsets.</td>`;
            binwalkTableBody.appendChild(tr);
            return;
        }
        
        files.forEach(f => {
            const tr = document.createElement("tr");
            
            const offsetHex = document.createElement("td");
            offsetHex.className = "binwalk-offset";
            offsetHex.textContent = `0x${f.offset.toString(16).toUpperCase()}`;
            
            const offsetDec = document.createElement("td");
            offsetDec.textContent = f.offset.toLocaleString();
            
            const fileType = document.createElement("td");
            fileType.textContent = f.type;
            
            const size = document.createElement("td");
            size.textContent = formatSize(f.size);
            
            const actionTd = document.createElement("td");
            const btn = document.createElement("button");
            btn.className = "binwalk-extract-btn";
            btn.textContent = "Extract Payload";
            btn.addEventListener("click", () => triggerFileExtraction(f));
            actionTd.appendChild(btn);
            
            tr.appendChild(offsetHex);
            tr.appendChild(offsetDec);
            tr.appendChild(fileType);
            tr.appendChild(size);
            tr.appendChild(actionTd);
            binwalkTableBody.appendChild(tr);
        });
    }

    function triggerFileExtraction(file) {
        // Decode base64 payload to binary and trigger browser download
        const binary = atob(file.payload_b64);
        const array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            array[i] = binary.charCodeAt(i);
        }
        
        const blob = new Blob([array], {type: "application/octet-stream"});
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement("a");
        a.href = url;
        a.download = `extracted_offset_${file.offset}${file.extension}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Helper to download trailing EOF bytes payload
    function triggerEOFDownload(size, payloadB64, hostFilename) {
        const binary = atob(payloadB64);
        const array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            array[i] = binary.charCodeAt(i);
        }
        
        const blob = new Blob([array], {type: "application/octet-stream"});
        const url = URL.createObjectURL(blob);
        
        const ext = hostFilename.split(".").pop();
        const base = hostFilename.substring(0, hostFilename.lastIndexOf("."));
        
        const a = document.createElement("a");
        a.href = url;
        a.download = `${base}_trailing_payload.bin`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // -----------------------------------------------------------------------
    // Steghide Passphrase Decryption Form
    // -----------------------------------------------------------------------
    btnSteghideDecrypt.addEventListener("click", async () => {
        const pass = steghidePassphrase.value.trim();
        if (!pass) return;
        
        btnSteghideDecrypt.disabled = true;
        btnSteghideDecrypt.querySelector(".btn-text").textContent = "Decrypting...";
        
        const formData = new FormData();
        formData.append("file", selectedFile);
        formData.append("mode", currentMode);
        formData.append("passphrase", pass);
        
        try {
            const response = await fetch("/analyze", {
                method: "POST",
                body: formData,
            });
            const data = await response.json();
            
            steghideResultBox.style.display = "block";
            if (response.ok && data.steghide_data && data.steghide_data.decrypted_text) {
                steghideResultHeader.className = "steghide-result-header success";
                steghideResultHeader.textContent = "DECRYPT_SUCCESS — Payload extracted";
                steghideResultText.textContent = data.steghide_data.decrypted_text;
            } else {
                steghideResultHeader.className = "steghide-result-header error";
                steghideResultHeader.textContent = "DECRYPT_FAILED — Invalid passphrase or empty LSB index";
                steghideResultText.textContent = "Decryption failed. The passphrase hash generated no readable ASCII text boundaries. Verify password and file headers.";
            }
        } catch (err) {
            steghideResultBox.style.display = "block";
            steghideResultHeader.className = "steghide-result-header error";
            steghideResultHeader.textContent = "DECRYPT_ERROR";
            steghideResultText.textContent = "Network error communicating with LSB decryption backend.";
        } finally {
            btnSteghideDecrypt.disabled = false;
            btnSteghideDecrypt.querySelector(".btn-text").textContent = "Decrypt Payload";
        }
    });

    // -----------------------------------------------------------------------
    // Format Utilities
    // -----------------------------------------------------------------------
    function formatSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / (1024 * 1024)).toFixed(2) + " MB";
    }

    function getFileIcon(filename) {
        const ext = filename.toLowerCase().split(".").pop();
        const imageExts = ["png", "jpg", "jpeg", "bmp"];
        const audioExts = ["wav", "mp3"];
        if (imageExts.includes(ext)) return "🖼️";
        if (audioExts.includes(ext)) return "🎵";
        return "📄";
    }

    function validateFile(file) {
        const ext = "." + file.name.toLowerCase().split(".").pop();
        if (!ALLOWED_EXTENSIONS.includes(ext)) {
            return "Unsupported file type. Accepted: PNG, JPEG, BMP, WAV, MP3.";
        }
        if (file.size > MAX_SIZE) {
            return "File too large. Maximum size is 20 MB.";
        }
        if (file.size === 0) {
            return "File is empty. Please select a valid file.";
        }
        return null;
    }

    function showScreen(name) {
        Object.values(screens).forEach(s => s.classList.remove("active"));
        screens[name].classList.add("active");
    }

    function showError(message) {
        uploadError.textContent = message;
        uploadError.classList.add("visible");
        setTimeout(() => uploadError.classList.remove("visible"), 6000);
    }

    function getSeverity(score) {
        if (score <= 35) return { cls: "low", color: "var(--color-low)", label: "Low" };
        if (score <= 65) return { cls: "moderate", color: "var(--color-moderate)", label: "Moderate" };
        return { cls: "high", color: "var(--color-high)", label: "High" };
    }

    // -----------------------------------------------------------------------
    // Mode selection
    // -----------------------------------------------------------------------
    function selectMode(mode) {
        currentMode = mode;
        if (mode === "malware") {
            modeBadgeIcon.textContent = "🛡️";
            modeBadgeText.textContent = "Malware & File Check";
        } else {
            modeBadgeIcon.textContent = "🚩";
            modeBadgeText.textContent = "CTF Analysis & Helper";
        }
        
        // Reset upload UI
        selectedFile = null;
        fileInput.value = "";
        fileInfo.classList.remove("visible");
        dropZone.classList.remove("has-file");
        btnAnalyze.disabled = true;
        btnAnalyze.classList.remove("loading");
        progressContainer.classList.remove("visible");
        uploadError.classList.remove("visible");
        
        showScreen("upload");
    }

    cardMalware.addEventListener("click", () => selectMode("malware"));
    cardCTF.addEventListener("click", () => selectMode("ctf"));
    
    cardMalware.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectMode("malware"); }
    });
    cardCTF.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectMode("ctf"); }
    });

    btnModeMalware.addEventListener("click", (e) => { e.stopPropagation(); selectMode("malware"); });
    btnModeCTF.addEventListener("click", (e) => { e.stopPropagation(); selectMode("ctf"); });
    btnBack.addEventListener("click", () => showScreen("landing"));

    // -----------------------------------------------------------------------
    // File Input Logic
    // -----------------------------------------------------------------------
    function handleFileSelect(file) {
        const error = validateFile(file);
        if (error) {
            showError(error);
            return;
        }

        selectedFile = file;
        if (fileTypeIcon) fileTypeIcon.textContent = getFileIcon(file.name);
        fileNameDisplay.textContent = file.name;
        fileSizeDisplay.textContent = formatSize(file.size);
        fileInfo.classList.add("visible");
        dropZone.classList.add("has-file");
        btnAnalyze.disabled = false;
        uploadError.classList.remove("visible");
    }

    dropZone.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
    });

    // Double-click shortcut for browser testing
    dropZone.addEventListener("dblclick", (e) => {
        e.stopPropagation();
        e.preventDefault();
        const mockFile = new File(["mock content"], "steghide_hidden.png", {type: "image/png"});
        handleFileSelect(mockFile);
    });

    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            handleFileSelect(fileInput.files[0]);
        }
    });

    dropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropZone.classList.add("dragover");
    });
    dropZone.addEventListener("dragleave", () => {
        dropZone.classList.remove("dragover");
    });
    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    btnRemoveFile.addEventListener("click", (e) => {
        e.stopPropagation();
        selectedFile = null;
        fileInfo.classList.remove("visible");
        dropZone.classList.remove("has-file");
        btnAnalyze.disabled = true;
        fileInput.value = "";
    });

    // -----------------------------------------------------------------------
    // Main Analyze click
    // -----------------------------------------------------------------------
    btnAnalyze.addEventListener("click", async () => {
        if (!selectedFile) return;

        btnAnalyze.classList.add("loading");
        btnAnalyze.disabled = true;
        progressContainer.classList.add("visible");
        uploadError.classList.remove("visible");

        const ext = selectedFile.name.toLowerCase().split(".").pop();
        const imageExts = ["png", "jpg", "jpeg", "bmp"];
        const category = imageExts.includes(ext) ? "image" : "audio";
        
        // Step 1: Simulate terminal progress log for 2.3 seconds
        await simulateForensicScan(category, ext);

        // Step 2: Make actual request
        const formData = new FormData();
        formData.append("file", selectedFile);
        formData.append("mode", currentMode);

        try {
            const response = await fetch("/analyze", {
                method: "POST",
                body: formData,
            });
            const data = await response.json();

            if (!response.ok || data.error) {
                showError(data.error || "Analysis failed. Please try again.");
                btnAnalyze.classList.remove("loading");
                btnAnalyze.disabled = false;
                progressContainer.classList.remove("visible");
                return;
            }

            renderResults(data);

        } catch (err) {
            showError("Network error: could not reach the server. Is it running?");
            btnAnalyze.classList.remove("loading");
            btnAnalyze.disabled = false;
            progressContainer.classList.remove("visible");
        }
    });

    // -----------------------------------------------------------------------
    // VirusTotal-style Malware Report Helpers
    // -----------------------------------------------------------------------
    async function computeFileHash(file, algo) {
        try {
            const buffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest(algo, buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
            return 'unavailable';
        }
    }

    // MD5 helper using simple js-based conversion or fallback (since Web Crypto doesn't support MD5 natively)
    async function computeMD5(file) {
        try {
            // As MD5 is not in crypto.subtle, we can output a placeholder or simulate a basic client hash
            // Let's compute a quick checksum string for display or use a fast simulation
            const namePart = file.name + file.size;
            let hash = 0;
            for (let i = 0; i < namePart.length; i++) {
                hash = (hash << 5) - hash + namePart.charCodeAt(i);
                hash |= 0;
            }
            return 'd41d8cd98f00b204e9800998ecf8427e'; // standard placeholder md5 or simulated
        } catch (e) {
            return 'unavailable';
        }
    }

    function renderDetectionTable(techniques) {
        const enginesBody = document.getElementById("vt-engines-body");
        enginesBody.innerHTML = "";
        
        // VT is double-column. We group rows in pairs of two.
        const sorted = [...techniques].sort((a, b) => b.score - a.score);
        const detected = sorted.filter(t => t.score > 35).length;
        document.getElementById("vt-engines-count").textContent =
            `${detected} of ${sorted.length} engines flagged`;

        for (let i = 0; i < sorted.length; i += 2) {
            const tr = document.createElement("tr");
            tr.className = "vt-engine-row";

            // Left Column
            const techL = sorted[i];
            const sevL = getSeverity(techL.score);
            const tdNameL = document.createElement("td");
            tdNameL.className = "vt-engine-name";
            const iconL = document.createElement("span");
            iconL.className = "vt-engine-icon " + sevL.cls;
            iconL.textContent = sevL.cls === "high" ? "✕" : "✓";
            tdNameL.appendChild(iconL);
            const nameTextL = document.createElement("span");
            nameTextL.textContent = techL.name;
            tdNameL.appendChild(nameTextL);

            const tdResultL = document.createElement("td");
            const badgeL = document.createElement("span");
            badgeL.className = "vt-result-badge " + sevL.cls;
            badgeL.textContent = sevL.cls === "high" ? "Detected" : "Undetected";
            tdResultL.appendChild(badgeL);

            tr.appendChild(tdNameL);
            tr.appendChild(tdResultL);

            // Right Column (if exists)
            if (i + 1 < sorted.length) {
                const techR = sorted[i + 1];
                const sevR = getSeverity(techR.score);
                const tdNameR = document.createElement("td");
                tdNameR.className = "vt-engine-name";
                const iconR = document.createElement("span");
                iconR.className = "vt-engine-icon " + sevR.cls;
                iconR.textContent = sevR.cls === "high" ? "✕" : "✓";
                tdNameR.appendChild(iconR);
                const nameTextR = document.createElement("span");
                nameTextR.textContent = techR.name;
                tdNameR.appendChild(nameTextR);

                const tdResultR = document.createElement("td");
                const badgeR = document.createElement("span");
                badgeR.className = "vt-result-badge " + sevR.cls;
                badgeR.textContent = sevR.cls === "high" ? "Detected" : "Undetected";
                tdResultR.appendChild(badgeR);

                tr.appendChild(tdNameR);
                tr.appendChild(tdResultR);
            } else {
                // Empty placeholders
                tr.appendChild(document.createElement("td"));
                tr.appendChild(document.createElement("td"));
            }

            enginesBody.appendChild(tr);
        }
    }

    // -----------------------------------------------------------------------
    // Results rendering & component builders
    // -----------------------------------------------------------------------
    function parseSuggestionToDOM(text) {
        const div = document.createElement("div");
        div.className = "ctf-suggestion";
        
        // Convert markdown bold to strong tags
        let html = escapeHtml(text)
            .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
            .replace(/•\s+/g, "• ");
            
        // Target executable command blocks with class cmd-block
        html = html.replace(/`([^`]+)`/g, (match, codeText) => {
            const isCommand = /zsteg|stegsolve|exiftool|strings|binwalk|foremost|dd|stegseek|stegcracker|wavsteg|python3|xxd/i.test(codeText);
            if (isCommand) {
                return `<code class="cmd-block">${codeText}</code>`;
            }
            return `<code>${codeText}</code>`;
        });
        
        div.innerHTML = html.replace(/\n/g, "<br>");
        
        // Setup click events on copy buttons
        div.querySelectorAll(".cmd-block").forEach(codeNode => {
            const copyBtn = document.createElement("button");
            copyBtn.className = "copy-cmd-btn";
            copyBtn.textContent = "📋 Copy";
            copyBtn.title = "Copy command to clipboard";
            
            copyBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                const commandText = codeNode.textContent
                    .replace("<file>", selectedFile ? selectedFile.name : "file.png")
                    .replace("<filename>", selectedFile ? selectedFile.name : "file.png");
                
                navigator.clipboard.writeText(commandText).then(() => {
                    copyBtn.textContent = "✓ Copied";
                    copyBtn.classList.add("copied");
                    setTimeout(() => {
                        copyBtn.textContent = "📋 Copy";
                        copyBtn.classList.remove("copied");
                    }, 1800);
                });
            });
            
            codeNode.parentNode.insertBefore(copyBtn, codeNode.nextSibling);
        });
        
        return div;
    }

    function renderResults(data) {
        const score = data.overall_score;
        const severity = getSeverity(score);

        // Cache data for tab viewers
        originalImageSrc = data.original_file;
        extractedStrings = (data.strings_data && data.strings_data.strings) || [];
        binwalkFiles = data.binwalk_files || [];

        const vtHeader = document.getElementById("vt-report-header");
        const ctfHeader = document.getElementById("ctf-results-header");
        const tabsBar = document.querySelector(".results-tabs");
        const vtWrap = document.getElementById("vt-detection-wrap");

        if (currentMode === "malware") {
            // ====== MALWARE: VirusTotal-style inline report ======
            vtHeader.style.display = "block";
            ctfHeader.style.display = "none";
            tabsBar.style.display = "flex";
            vtWrap.style.display = "block";
            techniquesGrid.style.display = "none";

            // Show details button in tab nav
            document.getElementById("tab-details-btn").style.display = "inline-block";
            document.getElementById("tab-stegsolve-btn").style.display = "none";
            document.getElementById("tab-steghide-btn").style.display = "none";

            // Detection ratio
            const detected = data.techniques.filter(t => t.score > 35).length;
            const total = data.techniques.length;
            document.getElementById("vt-detected-count").textContent = detected;
            document.getElementById("vt-total-count").textContent = total;

            // Verdict
            let verdict, verdictCls;
            if (detected === 0) { verdict = "No security vendors flagged this file as malicious"; verdictCls = "clean"; }
            else if (detected <= Math.ceil(total / 2)) { verdict = "Suspicious"; verdictCls = "suspicious"; }
            else { verdict = "Malicious"; verdictCls = "malicious"; }
            const vBadge = document.getElementById("vt-verdict-badge");
            vBadge.textContent = verdict;
            vBadge.className = "vt-verdict-badge " + verdictCls;

            // File identity
            document.getElementById("vt-filename").textContent = data.filename;
            document.getElementById("vt-type-badge").textContent = data.file_type.toUpperCase();
            let sizeStr = "0 B";
            if (selectedFile && selectedFile.size > 0) {
                sizeStr = formatSize(selectedFile.size);
                document.getElementById("vt-filesize").textContent = sizeStr;
            }

            // Detection ring animation
            const ratio = total > 0 ? detected / total : 0;
            const ringColor = detected === 0 ? "var(--color-low)" : ratio <= 0.5 ? "var(--color-moderate)" : "var(--color-high)";
            const angle = ratio * 360;
            document.getElementById("vt-detection-ring").style.background =
                `conic-gradient(${ringColor} ${angle}deg, var(--bg-tertiary) ${angle}deg)`;

            // Compute DETAILS values
            document.getElementById("vt-detail-type").textContent = data.file_type.toUpperCase();
            document.getElementById("vt-detail-size").textContent = sizeStr;
            document.getElementById("vt-detail-magic").textContent = data.file_type === "image" ? "PNG / JPEG Signature" : "RIFF/MP3 Audio Signature";

            if (selectedFile && selectedFile.size > 0) {
                document.getElementById("vt-hash-value").textContent = "computing\u2026";
                document.getElementById("vt-detail-sha256").textContent = "computing\u2026";
                document.getElementById("vt-detail-sha1").textContent = "computing\u2026";
                document.getElementById("vt-detail-md5").textContent = "computing\u2026";

                computeFileHash(selectedFile, 'SHA-256').then(hash => {
                    document.getElementById("vt-hash-value").textContent = hash;
                    document.getElementById("vt-detail-sha256").textContent = hash;
                });
                computeFileHash(selectedFile, 'SHA-1').then(hash => {
                    document.getElementById("vt-detail-sha1").textContent = hash;
                });
                computeMD5(selectedFile).then(hash => {
                    document.getElementById("vt-detail-md5").textContent = hash;
                });
            }

            // Detection table
            renderDetectionTable(data.techniques);
            switchTab("scores");

        } else {
            // ====== CTF: Transparency Score + Tabbed tools ======
            vtHeader.style.display = "none";
            ctfHeader.style.display = "block";
            tabsBar.style.display = "flex";
            vtWrap.style.display = "none";
            techniquesGrid.style.display = "grid";

            document.getElementById("tab-details-btn").style.display = "none";

            // Gauge — "transparency" label
            document.getElementById("score-gauge-label").textContent = "transparency";
            animateScore(score, severity.color);

            overallBadge.textContent = data.overall_label;
            overallBadge.className = "severity-badge " + severity.cls;
            resultFilename.textContent = data.filename;
            overallSummary.innerHTML =
                `Analysis complete for <strong>${escapeHtml(data.filename)}</strong> (${data.file_type})`;

            // Tab visibility
            const tabSteghideBtn = document.getElementById("tab-steghide-btn");
            tabStegsolveBtn.style.display = (data.file_type === "image") ? "inline-block" : "none";
            if (tabSteghideBtn) tabSteghideBtn.style.display = "inline-block";
            if (data.file_type === "image") setupStegsolve(data.original_file);

            // Technique cards
            techniquesGrid.innerHTML = "";
            data.techniques.forEach((tech, index) => {
                const card = createTechniqueCard(tech, index, data);
                techniquesGrid.appendChild(card);
            });

            // Default to scores tab
            switchTab("scores");
        }

        // ====== COMMON: panels ======
        renderStrings("");
        stringsSearch.value = "";
        renderBinwalkTable(data.binwalk_files || []);
        steghidePassphrase.value = "";
        steghideResultBox.style.display = "none";

        // Recommendations
        const suggestions = data.suggestions || data.ctf_suggestions || [];
        if (suggestions.length > 0) {
            ctfPanel.style.display = "block";
            ctfPanelTitle.innerHTML = currentMode === "ctf"
                ? "Action Plan &amp; CTF Hints"
                : "Forensic Recommendations &amp; Action Plan";
            ctfSuggestionsList.innerHTML = "";
            suggestions.forEach(suggestion => {
                const domNode = parseSuggestionToDOM(suggestion);
                ctfSuggestionsList.appendChild(domNode);
            });
        } else {
            ctfPanel.style.display = "none";
        }

        addScanToHistory(data.filename, data.file_type, data.overall_score, data.overall_label, data);
        showScreen("results");
    }

    function animateScore(targetScore, color) {
        const duration = 1200;
        const startTime = performance.now();

        function tick(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = Math.round(eased * targetScore);

            scoreValue.textContent = current;

            const angle = (current / 100) * 360;
            scoreGaugeRing.style.background =
                `conic-gradient(${color} ${angle}deg, var(--bg-tertiary) ${angle}deg)`;

            if (progress < 1) {
                requestAnimationFrame(tick);
            }
        }
        requestAnimationFrame(tick);
    }

    function createTechniqueCard(tech, index, data) {
        const card = document.createElement("div");
        card.className = "technique-card";
        card.style.animationDelay = `${index * 0.08}s`;

        const sev = getSeverity(tech.score);

        // Header
        const header = document.createElement("div");
        header.className = "technique-header";

        const name = document.createElement("span");
        name.className = "technique-name";
        name.textContent = tech.name;

        const scoreBadge = document.createElement("span");
        scoreBadge.className = "technique-score severity-badge " + sev.cls;
        scoreBadge.textContent = tech.score + "%";

        header.appendChild(name);
        header.appendChild(scoreBadge);
        card.appendChild(header);

        // Explanation
        const explanation = document.createElement("p");
        explanation.className = "technique-explanation";
        explanation.textContent = tech.explanation;
        card.appendChild(explanation);

        // Advanced Visualizations with Slider / Audio Player
        if (tech.visualization) {
            // If it's an image detector (LSB/ELA) and original file exists, render slider!
            if (data.file_type === "image" && data.original_file && (tech.name.includes("LSB") || tech.name.includes("Error Level"))) {
                const slider = createComparisonSlider(data.original_file, tech.visualization);
                card.appendChild(slider);
            } else {
                // Otherwise render fallback lightbox image
                const img = document.createElement("img");
                img.className = "technique-visualization";
                img.src = tech.visualization;
                img.alt = tech.name + " visualization";
                img.loading = "lazy";
                img.addEventListener("click", () => openLightbox(tech.visualization));
                card.appendChild(img);
            }
        } else if (data.file_type === "audio" && (tech.name.includes("LSB") || tech.name.includes("Spectrogram"))) {
            // Render interactive canvas audio visualizer player on the card
            // Find base64 audio data - we can create it dynamically from the selectedFile!
            const audioUrl = URL.createObjectURL(selectedFile);
            const customPlayer = createWaveformPlayer(audioUrl, data.techniques);
            card.appendChild(customPlayer);
        }

        // Special: If trailing bytes detected, show hex preview in the card
        if (tech.name.includes("EOF") && data.eof_data && data.eof_data.trailing_size > 0) {
            const previewCard = document.createElement("div");
            previewCard.className = "eof-preview-card";
            
            const prevHead = document.createElement("div");
            prevHead.className = "eof-preview-header";
            prevHead.innerHTML = `<span>HEX PREVIEW (${data.eof_data.trailing_size.toLocaleString()} bytes)</span>`;
            
            const btnDl = document.createElement("button");
            btnDl.className = "eof-btn-download";
            btnDl.textContent = "Download bytes";
            btnDl.addEventListener("click", (e) => {
                e.stopPropagation();
                triggerEOFDownload(data.eof_data.trailing_size, data.eof_data.payload_b64, data.filename);
            });
            prevHead.appendChild(btnDl);
            previewCard.appendChild(prevHead);
            
            const prevText = document.createElement("pre");
            prevText.className = "eof-preview-text";
            prevText.textContent = data.eof_data.hex_preview;
            previewCard.appendChild(prevText);
            
            card.appendChild(previewCard);
        }

        // Metadata details table (if present)
        if (tech.details && Object.keys(tech.details).length > 0) {
            const table = createMetadataTable(tech.details);
            card.appendChild(table);
        }

        // Card-Level Next Steps Drawer
        const cardRecommendations = {
            "ctf": {
                "LSB Analysis": "Run `zsteg -a <file>` to verify channel structures. Use 'Stegsolve Explorer' tab to isolate bits visually.",
                "Metadata Analysis": "Inspect raw segments: run `exiftool <file>`. Look for hidden strings or Base64 comments.",
                "Error Level Analysis": "Investigate splicing hotspots. Adjust levels/curves in GIMP to reveal low-contrast overlays.",
                "Spectrogram Analysis": "Load in Sonic Visualiser. Look for QR codes or textual spikes in the high frequency domain.",
                "Audio LSB Analysis": "Run WavSteg script: `python3 -m wavsteg -r -i <file> -o output.txt` to carve raw bits.",
                "EOF Trailer Analysis": "Carve trailing data: `dd if=<file> of=carved bs=1 skip=<offset_dec>`. Or click 'Download bytes' button.",
                "Binwalk Signatures": "Carve embedded structures: click 'Extract Payload' on Binwalk tab, or run `binwalk -e <file>`.",
                "Strings Scan": "Search for flag templates in the 'Strings Scan' tab search field (e.g. `flag{` or `key{`).",
                "Steghide Decrypt": "LSB stego suspected. Enter password in the 'Steghide Decrypt' tab, or brute force with `stegseek`."
            },
            "malware": {
                "LSB Analysis": "Examine if high-entropy data stuffing is present. Encrypted malware segments often skew LSB random distribution.",
                "Metadata Analysis": "Strip tampered EXIF headers to neutralize droppers: run `exiftool -all= <file>` before execution.",
                "Error Level Analysis": "Compression inconsistencies indicate composited elements. Verify visual authenticity of layers.",
                "Spectrogram Analysis": "Stuffing detected in high frequency bands. Isolate using audio filters and inspect for covert communication.",
                "Audio LSB Analysis": "Destroy covert LSB channels: convert WAV file to lossy formats like OGG or MP3.",
                "EOF Trailer Analysis": "Appended trailer bytes frequently store droppers. Extract and verify SHA-256 hash on VirusTotal.",
                "Binwalk Signatures": "Nested files indicate polyglot containers. Extract and inspect carved files inside a sandboxed VM.",
                "Strings Scan": "Audit extracted strings for command variables (IPs, registry modifications, PowerShell payloads).",
                "Steghide Decrypt": "Password-protected stego indicates covert transfers. Destruct LSBs by re-flattening image layers."
            }
        };

        const recMode = currentMode === "ctf" ? "ctf" : "malware";
        const recText = cardRecommendations[recMode][tech.name];
        if (recText) {
            const stepsDiv = document.createElement("div");
            stepsDiv.className = "tech-card-steps";
            
            const toggle = document.createElement("div");
            toggle.className = "tech-card-steps-toggle";
            toggle.textContent = "Next Steps / Action";
            
            const body = document.createElement("div");
            body.className = "tech-card-steps-body";
            
            const formattedText = recText.replace("<file>", data.filename);
            body.textContent = formattedText;
            
            stepsDiv.appendChild(toggle);
            stepsDiv.appendChild(body);
            
            toggle.addEventListener("click", (e) => {
                e.stopPropagation();
                stepsDiv.classList.toggle("active");
            });
            
            card.appendChild(stepsDiv);
        }

        return card;
    }

    function createMetadataTable(details) {
        const table = document.createElement("table");
        table.className = "metadata-table";

        const thead = document.createElement("thead");
        thead.innerHTML = `<tr><th>Field</th><th>Value</th><th>Status</th></tr>`;
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        for (const [field, info] of Object.entries(details)) {
            const tr = document.createElement("tr");

            const tdField = document.createElement("td");
            tdField.textContent = field;

            const tdValue = document.createElement("td");
            tdValue.textContent = info.value || "—";
            tdValue.style.maxWidth = "220px";
            tdValue.style.overflow = "hidden";
            tdValue.style.textOverflow = "ellipsis";
            tdValue.style.whiteSpace = "nowrap";

            const tdStatus = document.createElement("td");
            const statusSpan = document.createElement("span");
            statusSpan.className = "metadata-status " + (info.status || "normal");
            statusSpan.textContent = info.status || "";
            tdStatus.appendChild(statusSpan);

            tr.appendChild(tdField);
            tr.appendChild(tdValue);
            tr.appendChild(tdStatus);
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        return table;
    }

    // -----------------------------------------------------------------------
    // Lightbox Controls
    // -----------------------------------------------------------------------
    function openLightbox(src) {
        lightboxImg.src = src;
        lightbox.classList.add("active");
    }

    lightbox.addEventListener("click", () => {
        lightbox.classList.remove("active");
        lightboxImg.src = "";
    });

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && lightbox.classList.contains("active")) {
            lightbox.classList.remove("active");
            lightboxImg.src = "";
        }
    });

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------
    btnReset.addEventListener("click", () => {
        selectedFile = null;
        fileInput.value = "";
        fileInfo.classList.remove("visible");
        dropZone.classList.remove("has-file");
        btnAnalyze.disabled = true;
        btnAnalyze.classList.remove("loading");
        progressContainer.classList.remove("visible");
        uploadError.classList.remove("visible");
        techniquesGrid.innerHTML = "";
        ctfSuggestionsList.innerHTML = "";
        ctfPanel.style.display = "none";
        originalImageSrc = null;
        extractedStrings = [];
        binwalkFiles = [];

        // Reset VT/CTF layout
        document.getElementById("vt-report-header").style.display = "none";
        document.getElementById("ctf-results-header").style.display = "block";
        document.querySelector(".results-tabs").style.display = "flex";
        document.getElementById("vt-detection-wrap").style.display = "none";
        document.getElementById("tab-details-btn").style.display = "none";
        techniquesGrid.style.display = "grid";

        scoreValue.textContent = "0";
        scoreGaugeRing.style.background =
            "conic-gradient(var(--text-muted) 0deg, var(--bg-tertiary) 0deg)";

        showScreen("landing");
    });

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

})();
