/**
 * Champs Analysis tab logic (Step 10.3 - extracted from index.html).
 * Enhanced with video game dashboard effects: animations, particles, real-time updates.
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, authState, Chart, loadStats, loadLiveFeed.
 * Exposes: loadChampsAnalysis, startChampsTickerPolling, champsSpotlightChart.
 */
(function(global) {
    'use strict';

    let champsLeaderboardData = [];
    let champsPreviousLeaderboard = [];
    let champsSpotlightChart = null;
    let champsTickerMessages = [];
    let champsTickerPollInterval = null;
    let champsLeaderboardPollInterval = null;
    let champsPresencePollInterval = null;
    let champsMispVisible = false;
    let champsMispData = null;
    let champsParticlesCanvas = null;
    let champsParticlesCtx = null;
    let champsParticlesAnimationId = null;
    let champsParticles = [];

    const champsBadgeDescriptions = {
        on_fire: '5-day submission streak', warm_streak: '3-4 day streak', night_owl: 'Activity between 22:00-04:00',
        early_bird: 'Activity between 05:00-07:00', weekend_warrior: 'Activity on Friday or Saturday',
        rare_find: 'First-ever in system: new country, TLD, or email domain', dedicated: '30+ IOCs total', veteran: '80+ IOCs total',
        clean_slate: 'Removed at least one expired IOC', janitor: '5+ expired IOCs removed', cleanup_crew: '15+ expired IOCs removed',
        team_player: 'At least one IOC linked to a campaign', campaign_master: '10+ IOCs linked to campaigns',
        yara_rookie: 'Uploaded at least one YARA rule', yara_master: '3+ YARA rules', yara_legend: '8+ YARA rules',
        hash_hunter: '10+ hashes', domain_scout: '15+ domains', ip_tracker: '25+ IPs', url_surfer: '10+ URLs', phish_buster: '5+ emails',
        triple_threat: 'Submitted at least 3 IOC types', all_rounder: 'Submitted all 5 IOC types',
        consistent: 'Activity on 7+ different days (last 30)', ever_present: 'Activity on 15+ different days'
    };

    const BADGE_LABELS = {
        on_fire: '🔥 On Fire', night_owl: '🦉 Night Owl', rare_find: '💎 Rare Find', janitor: '🧹 Janitor',
        warm_streak: '🌡️ Warm Streak', early_bird: '🌞 Early Bird', weekend_warrior: '🗓️ Weekend Warrior',
        dedicated: '💪 Dedicated', veteran: '🎖️ Veteran', clean_slate: '✨ Clean Slate', cleanup_crew: '🧼 Cleanup Crew',
        team_player: '🤝 Team Player', campaign_master: '🎯 Campaign Master',
        yara_rookie: '📜 YARA Rookie', yara_master: '👑 YARA Master', yara_legend: '🏆 YARA Legend',
        hash_hunter: '🔐 Hash Hunter', domain_scout: '🌐 Domain Scout', ip_tracker: '📍 IP Tracker',
        url_surfer: '🏄 URL Surfer', phish_buster: '🎣 Phish Buster',
        triple_threat: '🎪 Triple Threat', all_rounder: '🌟 All-Rounder',
        consistent: '📅 Consistent', ever_present: '⚡ Ever Present'
    };

    const BADGE_CLASSES = {
        on_fire: 'champs-badge-fire', night_owl: 'champs-badge-owl', rare_find: 'champs-badge-rare', janitor: 'champs-badge-janitor',
        warm_streak: 'champs-badge-warm', early_bird: 'champs-badge-early', weekend_warrior: 'champs-badge-weekend',
        dedicated: 'champs-badge-dedicated', veteran: 'champs-badge-veteran', clean_slate: 'champs-badge-clean', cleanup_crew: 'champs-badge-cleanup',
        team_player: 'champs-badge-team', campaign_master: 'champs-badge-campaign',
        yara_rookie: 'champs-badge-yara-r', yara_master: 'champs-badge-yara-m', yara_legend: 'champs-badge-yara-l',
        hash_hunter: 'champs-badge-hash', domain_scout: 'champs-badge-domain', ip_tracker: 'champs-badge-ip',
        url_surfer: 'champs-badge-url', phish_buster: 'champs-badge-phish',
        triple_threat: 'champs-badge-triple', all_rounder: 'champs-badge-allround',
        consistent: 'champs-badge-consistent', ever_present: 'champs-badge-ever'
    };

    const BADGE_NAMES = {
        on_fire: 'On Fire', night_owl: 'Night Owl', rare_find: 'Rare Find', janitor: 'Janitor',
        warm_streak: 'Warm Streak', early_bird: 'Early Bird', weekend_warrior: 'Weekend Warrior',
        dedicated: 'Dedicated', veteran: 'Veteran', clean_slate: 'Clean Slate', cleanup_crew: 'Cleanup Crew',
        team_player: 'Team Player', campaign_master: 'Campaign Master',
        yara_rookie: 'YARA Rookie', yara_master: 'YARA Master', yara_legend: 'YARA Legend',
        hash_hunter: 'Hash Hunter', domain_scout: 'Domain Scout', ip_tracker: 'IP Tracker',
        url_surfer: 'URL Surfer', phish_buster: 'Phish Buster',
        triple_threat: 'Triple Threat', all_rounder: 'All-Rounder',
        consistent: 'Consistent', ever_present: 'Ever Present'
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Enhanced Score Odometer Animation with Sound-like Visual
    // ═══════════════════════════════════════════════════════════════════════════
    function animateScore(element, targetValue, duration) {
        if (!element) return;
        duration = duration || 1500;
        const startValue = 0;
        const startTime = performance.now();
        element.classList.add('champs-score-animating');
        
        // Add glow effect during animation
        element.style.textShadow = '0 0 20px currentColor, 0 0 40px currentColor';
        
        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing with bounce at end
            let easeOut;
            if (progress < 0.9) {
                easeOut = 1 - Math.pow(1 - (progress / 0.9), 3);
            } else {
                const bounceProgress = (progress - 0.9) / 0.1;
                easeOut = 1 + Math.sin(bounceProgress * Math.PI) * 0.02;
            }
            
            const currentValue = Math.floor(startValue + (targetValue - startValue) * Math.min(easeOut, 1));
            element.textContent = currentValue.toLocaleString();
            
            // Pulsing glow during count
            const glowIntensity = 20 + Math.sin(elapsed * 0.02) * 10;
            element.style.textShadow = `0 0 ${glowIntensity}px currentColor, 0 0 ${glowIntensity * 2}px currentColor`;
            
            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                element.textContent = targetValue.toLocaleString();
                element.classList.remove('champs-score-animating');
                // Final flash
                element.style.textShadow = '0 0 40px currentColor, 0 0 60px currentColor, 0 0 80px currentColor';
                setTimeout(() => {
                    element.style.textShadow = '';
                }, 300);
            }
        }
        requestAnimationFrame(update);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Animated Stat Cards Counter
    // ═══════════════════════════════════════════════════════════════════════════
    function animateStatCards() {
        const statCards = document.querySelectorAll('.champs-stat-card .font-mono');
        statCards.forEach((el, index) => {
            const value = parseInt(el.textContent.replace(/,/g, ''), 10);
            if (!isNaN(value) && value > 0) {
                el.textContent = '0';
                setTimeout(() => {
                    animateSmallNumber(el, value, 800);
                }, index * 150);
            }
        });
    }

    function animateSmallNumber(element, targetValue, duration) {
        const startTime = performance.now();
        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const easeOut = 1 - Math.pow(1 - progress, 2);
            element.textContent = Math.floor(targetValue * easeOut);
            if (progress < 1) requestAnimationFrame(update);
            else element.textContent = targetValue;
        }
        requestAnimationFrame(update);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Confetti Explosion
    // ═══════════════════════════════════════════════════════════════════════════
    function triggerConfetti() {
        let canvas = document.getElementById('champsConfettiCanvas');
        if (!canvas) {
            canvas = document.createElement('canvas');
            canvas.id = 'champsConfettiCanvas';
            document.body.appendChild(canvas);
        }
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const ctx = canvas.getContext('2d');
        const confetti = [];
        const colors = ['#00ff41', '#00d4ff', '#fbbf24', '#f59e0b', '#ec4899', '#8b5cf6', '#06b6d4'];
        
        for (let i = 0; i < 150; i++) {
            confetti.push({
                x: Math.random() * canvas.width,
                y: -20 - Math.random() * 100,
                w: 8 + Math.random() * 6,
                h: 4 + Math.random() * 4,
                color: colors[Math.floor(Math.random() * colors.length)],
                vx: (Math.random() - 0.5) * 8,
                vy: 3 + Math.random() * 5,
                rotation: Math.random() * 360,
                rotationSpeed: (Math.random() - 0.5) * 15
            });
        }
        
        let frame = 0;
        function animate() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            let active = false;
            confetti.forEach(c => {
                if (c.y < canvas.height + 50) {
                    active = true;
                    c.x += c.vx;
                    c.y += c.vy;
                    c.vy += 0.15;
                    c.vx *= 0.99;
                    c.rotation += c.rotationSpeed;
                    
                    ctx.save();
                    ctx.translate(c.x, c.y);
                    ctx.rotate(c.rotation * Math.PI / 180);
                    ctx.fillStyle = c.color;
                    ctx.fillRect(-c.w / 2, -c.h / 2, c.w, c.h);
                    ctx.restore();
                }
            });
            frame++;
            if (active && frame < 300) {
                requestAnimationFrame(animate);
            } else {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }
        animate();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - RANK UP Overlay
    // ═══════════════════════════════════════════════════════════════════════════
    function showRankUpEffect(newRank, isTop3) {
        let overlay = document.querySelector('.champs-rankup-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.className = 'champs-rankup-overlay';
            document.body.appendChild(overlay);
        }
        overlay.innerHTML = `
            <div class="champs-rankup-content">
                <span class="champs-rankup-text">${isTop3 ? '🏆 TOP 3!' : 'RANK UP!'}</span>
                <span class="champs-rankup-rank">#${newRank}</span>
            </div>`;
        
        requestAnimationFrame(() => {
            overlay.classList.add('active');
            if (isTop3) triggerConfetti();
        });
        
        setTimeout(() => {
            overlay.classList.remove('active');
            setTimeout(() => overlay.remove(), 500);
        }, 2500);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Enhanced Floating Particles with Glow
    // ═══════════════════════════════════════════════════════════════════════════
    function initChampsParticles() {
        const tabEl = document.getElementById('tab-champs');
        if (!tabEl) return;
        
        if (document.getElementById('champsParticlesCanvas')) return;
        
        champsParticlesCanvas = document.createElement('canvas');
        champsParticlesCanvas.id = 'champsParticlesCanvas';
        tabEl.insertBefore(champsParticlesCanvas, tabEl.firstChild);
        champsParticlesCtx = champsParticlesCanvas.getContext('2d');
        
        function resize() {
            if (!champsParticlesCanvas) return;
            champsParticlesCanvas.width = tabEl.offsetWidth;
            champsParticlesCanvas.height = tabEl.offsetHeight;
        }
        resize();
        window.addEventListener('resize', resize);
        
        champsParticles = [];
        const colors = [
            '0, 212, 255',    // cyan
            '0, 255, 65',     // green
            '251, 191, 36',   // gold
            '139, 92, 246',   // purple
            '236, 72, 153'    // pink
        ];
        
        for (let i = 0; i < 60; i++) {
            champsParticles.push({
                x: Math.random() * champsParticlesCanvas.width,
                y: Math.random() * champsParticlesCanvas.height,
                size: 1 + Math.random() * 3,
                speedY: -0.3 - Math.random() * 0.7,
                speedX: (Math.random() - 0.5) * 0.5,
                opacity: 0.3 + Math.random() * 0.5,
                color: colors[Math.floor(Math.random() * colors.length)],
                pulse: Math.random() * Math.PI * 2,
                pulseSpeed: 0.02 + Math.random() * 0.03
            });
        }
        
        function animateParticles() {
            if (!champsParticlesCtx || !champsParticlesCanvas) return;
            const tabVisible = !document.getElementById('tab-champs')?.classList.contains('hidden');
            if (!tabVisible) {
                champsParticlesAnimationId = requestAnimationFrame(animateParticles);
                return;
            }
            
            champsParticlesCtx.clearRect(0, 0, champsParticlesCanvas.width, champsParticlesCanvas.height);
            
            champsParticles.forEach(p => {
                p.y += p.speedY;
                p.x += p.speedX;
                p.pulse += p.pulseSpeed;
                
                const pulseFactor = 0.5 + Math.sin(p.pulse) * 0.5;
                const currentOpacity = p.opacity * (0.6 + pulseFactor * 0.4);
                const currentSize = p.size * (0.8 + pulseFactor * 0.4);
                
                if (p.y < -10) {
                    p.y = champsParticlesCanvas.height + 10;
                    p.x = Math.random() * champsParticlesCanvas.width;
                }
                if (p.x < -10) p.x = champsParticlesCanvas.width + 10;
                if (p.x > champsParticlesCanvas.width + 10) p.x = -10;
                
                // Outer glow
                const gradient = champsParticlesCtx.createRadialGradient(
                    p.x, p.y, 0,
                    p.x, p.y, currentSize * 4
                );
                gradient.addColorStop(0, `rgba(${p.color}, ${currentOpacity})`);
                gradient.addColorStop(0.3, `rgba(${p.color}, ${currentOpacity * 0.5})`);
                gradient.addColorStop(1, `rgba(${p.color}, 0)`);
                
                champsParticlesCtx.beginPath();
                champsParticlesCtx.arc(p.x, p.y, currentSize * 4, 0, Math.PI * 2);
                champsParticlesCtx.fillStyle = gradient;
                champsParticlesCtx.fill();
                
                // Core
                champsParticlesCtx.beginPath();
                champsParticlesCtx.arc(p.x, p.y, currentSize, 0, Math.PI * 2);
                champsParticlesCtx.fillStyle = `rgba(${p.color}, ${currentOpacity})`;
                champsParticlesCtx.fill();
                
                // Bright center
                champsParticlesCtx.beginPath();
                champsParticlesCtx.arc(p.x, p.y, currentSize * 0.5, 0, Math.PI * 2);
                champsParticlesCtx.fillStyle = `rgba(255, 255, 255, ${currentOpacity * 0.8})`;
                champsParticlesCtx.fill();
            });
            
            champsParticlesAnimationId = requestAnimationFrame(animateParticles);
        }
        animateParticles();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - 3D Card Tilt (DISABLED BY USER REQUEST)
    // ═══════════════════════════════════════════════════════════════════════════
    function init3DCardTilt() {
        // Disabled - user preferred without this effect
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Screen Flash on Activity
    // ═══════════════════════════════════════════════════════════════════════════
    function triggerActivityFlash() {
        const tabEl = document.getElementById('tab-champs');
        if (!tabEl) return;
        tabEl.classList.remove('champs-activity-flash');
        void tabEl.offsetWidth;
        tabEl.classList.add('champs-activity-flash');
        setTimeout(() => tabEl.classList.remove('champs-activity-flash'), 500);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Glitch Text Effect
    // ═══════════════════════════════════════════════════════════════════════════
    function applyGlitchEffect(element) {
        if (!element) return;
        const text = element.textContent;
        element.setAttribute('data-text', text);
        element.classList.add('champs-ticker-glitch');
        
        setTimeout(() => {
            element.classList.remove('champs-ticker-glitch');
        }, 2000);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Fire Effect for Streak Users
    // ═══════════════════════════════════════════════════════════════════════════
    function applyFireEffectToStreaks() {
        const rows = document.querySelectorAll('.champs-ladder-row');
        rows.forEach((row, index) => {
            const data = champsLeaderboardData[index];
            if (data && data.streak_days >= 3) {
                const nameEl = row.querySelector('.font-bold');
                if (nameEl && !nameEl.classList.contains('champs-fire-effect')) {
                    nameEl.classList.add('champs-fire-effect');
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Floating Combat Text (for score changes)
    // ═══════════════════════════════════════════════════════════════════════════
    function showFloatingText(text, x, y, color) {
        const floater = document.createElement('div');
        floater.className = 'champs-floating-text';
        floater.textContent = text;
        floater.style.cssText = `
            position: fixed;
            left: ${x}px;
            top: ${y}px;
            font-size: 1.5rem;
            font-weight: 800;
            color: ${color || '#00ff41'};
            text-shadow: 0 0 10px currentColor, 0 0 20px currentColor;
            pointer-events: none;
            z-index: 10000;
            animation: champs-float-up 1.5s ease-out forwards;
        `;
        
        // Add keyframes if not exists
        if (!document.getElementById('champs-float-keyframes')) {
            const style = document.createElement('style');
            style.id = 'champs-float-keyframes';
            style.textContent = `
                @keyframes champs-float-up {
                    0% { transform: translateY(0) scale(0.5); opacity: 0; }
                    20% { transform: translateY(-10px) scale(1.2); opacity: 1; }
                    100% { transform: translateY(-80px) scale(0.8); opacity: 0; }
                }
            `;
            document.head.appendChild(style);
        }
        
        document.body.appendChild(floater);
        setTimeout(() => floater.remove(), 1500);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Achievement Popup
    // ═══════════════════════════════════════════════════════════════════════════
    function showAchievementPopup(title, description, icon) {
        let popup = document.querySelector('.champs-achievement-popup');
        if (!popup) {
            popup = document.createElement('div');
            popup.className = 'champs-achievement-popup';
            popup.style.cssText = `
                position: fixed;
                top: 20px;
                right: -400px;
                width: 350px;
                padding: 20px;
                background: linear-gradient(135deg, rgba(0, 40, 60, 0.98) 0%, rgba(0, 60, 40, 0.98) 100%);
                border: 2px solid rgba(251, 191, 36, 0.6);
                border-radius: 12px;
                box-shadow: 0 0 40px rgba(251, 191, 36, 0.4), inset 0 0 30px rgba(251, 191, 36, 0.1);
                z-index: 10001;
                transition: right 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
                font-family: var(--champs-ui-font);
            `;
            document.body.appendChild(popup);
        }
        
        popup.innerHTML = `
            <div style="display: flex; align-items: center; gap: 15px;">
                <span style="font-size: 3rem; filter: drop-shadow(0 0 10px rgba(251, 191, 36, 0.8));">${icon || '🏆'}</span>
                <div>
                    <div style="font-size: 0.75rem; color: #fbbf24; text-transform: uppercase; letter-spacing: 0.2em; margin-bottom: 4px;">Achievement Unlocked!</div>
                    <div style="font-size: 1.25rem; font-weight: 800; color: #fff; text-shadow: 0 0 10px rgba(251, 191, 36, 0.5);">${title}</div>
                    <div style="font-size: 0.875rem; color: rgba(255,255,255,0.7); margin-top: 4px;">${description}</div>
                </div>
            </div>
        `;
        
        setTimeout(() => popup.style.right = '20px', 100);
        setTimeout(() => popup.style.right = '-400px', 4000);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // REAL-TIME LIFE ANIMATIONS
    // ═══════════════════════════════════════════════════════════════════════════

    let lastTickerMessageCount = 0;
    let lastLeaderboardHash = '';
    let mexicanWaveInterval = null;
    let activityLevel = 'low';
    let recentActivityCount = 0;
    let previousScores = {};  // Track scores for change detection

    // RT-1: Active Analyst Indicator - Show green dot for analysts currently online
    function updateActiveIndicators(leaderboardData) {
        if (!leaderboardData) return;
        
        document.querySelectorAll('.champs-active-indicator').forEach(el => el.remove());
        
        leaderboardData.forEach((analyst, index) => {
            // Check if user is currently online (has open session)
            if (analyst.is_online) {
                const row = document.querySelector(`.champs-ladder-row[data-index="${index}"]`);
                if (row) {
                    const nameEl = row.querySelector('.font-bold');
                    if (nameEl && !nameEl.querySelector('.champs-active-indicator')) {
                        const dot = document.createElement('span');
                        dot.className = 'champs-active-indicator';
                        dot.title = 'Online now';
                        nameEl.appendChild(dot);
                    }
                }
            }
        });
    }

    // RT-2: Live IOC Counter - Shows total IOC count with animation on change
    function createLiveCounter() {
        const existingCounter = document.getElementById('champsLiveCounter');
        if (existingCounter) return existingCounter;
        
        const statsEl = document.getElementById('champsHeroStats');
        if (!statsEl) return null;
        
        const counter = document.createElement('div');
        counter.id = 'champsLiveCounter';
        counter.className = 'champs-live-counter';
        counter.innerHTML = `
            <span class="champs-live-counter-label">Total IOCs</span>
            <span class="champs-live-counter-value" id="champsLiveCounterValue">0</span>
        `;
        statsEl.appendChild(counter);
        return counter;
    }

    function updateLiveCounter(newValue) {
        const valueEl = document.getElementById('champsLiveCounterValue');
        if (!valueEl) return;
        
        const currentValue = parseInt(valueEl.textContent, 10) || 0;
        if (newValue > currentValue && currentValue > 0) {
            valueEl.classList.add('champs-counter-bump');
            setTimeout(() => valueEl.classList.remove('champs-counter-bump'), 300);
            
            // Spawn particles
            spawnScoreParticles(valueEl, Math.min(newValue - currentValue, 5));
            
            // Increment activity count for heatmap
            recentActivityCount++;
            updateActivityHeatmap();
        }
        valueEl.textContent = newValue;
    }

    // RT-3: Last Activity Timestamp
    function createLastActivityDisplay() {
        const existingDisplay = document.getElementById('champsLastActivity');
        if (existingDisplay) return existingDisplay;
        
        const statsEl = document.getElementById('champsHeroStats');
        if (!statsEl) return null;
        
        const display = document.createElement('div');
        display.id = 'champsLastActivity';
        display.className = 'champs-last-activity';
        display.innerHTML = '<span>Last activity: just now</span>';
        statsEl.appendChild(display);
        return display;
    }

    function updateLastActivity(timestamp) {
        const display = document.getElementById('champsLastActivity');
        if (!display) return;
        
        const now = Date.now();
        const diff = now - (timestamp || now);
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        
        let text = 'just now';
        if (minutes > 0) {
            text = minutes === 1 ? '1 minute ago' : `${minutes} minutes ago`;
        } else if (seconds > 10) {
            text = `${seconds} seconds ago`;
        }
        
        display.innerHTML = `<span>Last activity: ${text}</span>`;
    }

    // RT-4: Ticker Flash on New Message
    function flashTicker() {
        const ticker = document.getElementById('champsTicker');
        if (!ticker) return;
        
        ticker.classList.remove('champs-ticker-new-message');
        void ticker.offsetWidth;
        ticker.classList.add('champs-ticker-new-message');
    }

    // RT-5: Mexican Wave Effect
    function startMexicanWave() {
        if (mexicanWaveInterval) clearInterval(mexicanWaveInterval);
        
        mexicanWaveInterval = setInterval(() => {
            const tabEl = document.getElementById('tab-champs');
            if (!tabEl || tabEl.classList.contains('hidden')) return;
            
            triggerMexicanWave();
        }, 45000); // Every 45 seconds
    }

    function triggerMexicanWave() {
        const rows = document.querySelectorAll('.champs-ladder-row');
        rows.forEach((row, index) => {
            setTimeout(() => {
                row.classList.add('champs-wave');
                setTimeout(() => row.classList.remove('champs-wave'), 600);
            }, index * 80);
        });
    }

    // RT-6: Hot Right Now Badge - Show "HOT" badge for analyst with positive trend
    function updateHotBadges(leaderboardData) {
        if (!leaderboardData) return;
        
        document.querySelectorAll('.champs-hot-badge').forEach(el => el.remove());
        
        // Find analysts with positive trend (rank improved)
        leaderboardData.forEach((analyst, index) => {
            // Skip top 3 (they already have medals)
            if (analyst.rank <= 3) return;
            
            // Check for positive trend (like "+2" meaning rank improved by 2)
            const trendStr = String(analyst.trend || '');
            if (trendStr.startsWith('+')) {
                const trendVal = parseInt(trendStr.replace(/[^0-9]/g, ''), 10) || 0;
                if (trendVal >= 2) {  // Only show for significant improvement
                    const row = document.querySelector(`.champs-ladder-row[data-index="${index}"]`);
                    if (row) {
                        const nameEl = row.querySelector('.font-bold');
                        if (nameEl && !nameEl.querySelector('.champs-hot-badge')) {
                            const badge = document.createElement('span');
                            badge.className = 'champs-hot-badge';
                            badge.textContent = 'HOT';
                            nameEl.appendChild(badge);
                        }
                    }
                }
            }
        });
    }

    // RT-7: Progress Ring for Team Goal
    function createProgressRing(percent) {
        const circumference = 2 * Math.PI * 25; // radius = 25
        const offset = circumference - (percent / 100) * circumference;
        
        return `
            <div class="champs-progress-ring">
                <svg viewBox="0 0 60 60">
                    <defs>
                        <linearGradient id="champs-ring-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" style="stop-color:#00d4ff"/>
                            <stop offset="100%" style="stop-color:#00ff41"/>
                        </linearGradient>
                    </defs>
                    <circle class="champs-progress-ring-bg" cx="30" cy="30" r="25"/>
                    <circle class="champs-progress-ring-fill" cx="30" cy="30" r="25" style="stroke-dashoffset: ${offset}"/>
                </svg>
                <div class="champs-progress-ring-text">${percent}%</div>
            </div>
        `;
    }

    // RT-8: Leaderboard Shake
    function shakeLeaderboard() {
        const ladder = document.getElementById('champsLadder');
        if (!ladder) return;
        
        ladder.classList.add('champs-shake');
        setTimeout(() => ladder.classList.remove('champs-shake'), 500);
    }

    // RT-9: Score Particles
    function spawnScoreParticles(element, count) {
        if (!element) return;
        
        const rect = element.getBoundingClientRect();
        const colors = ['#00ff41', '#00d4ff', '#fbbf24', '#ec4899'];
        
        for (let i = 0; i < Math.min(count, 10); i++) {
            const particle = document.createElement('div');
            particle.className = 'champs-score-particle';
            particle.style.cssText = `
                left: ${rect.left + rect.width / 2 + (Math.random() - 0.5) * 30}px;
                top: ${rect.top}px;
                background: ${colors[Math.floor(Math.random() * colors.length)]};
                --tx: ${(Math.random() - 0.5) * 60}px;
            `;
            document.body.appendChild(particle);
            setTimeout(() => particle.remove(), 1000);
        }
    }

    // RT-10: Milestone Celebration
    function showMilestoneCelebration(value, type) {
        const existing = document.querySelector('.champs-milestone-celebration');
        if (existing) existing.remove();
        
        const icons = {
            ioc: '📊',
            yara: '📜',
            streak: '🔥',
            rank: '🏆'
        };
        
        const celebration = document.createElement('div');
        celebration.className = 'champs-milestone-celebration';
        celebration.innerHTML = `
            <div class="champs-milestone-icon">${icons[type] || '🎉'}</div>
            <div class="champs-milestone-title">MILESTONE REACHED!</div>
            <div class="champs-milestone-value">${value}</div>
        `;
        document.body.appendChild(celebration);
        
        triggerConfetti();
        
        setTimeout(() => {
            celebration.style.animation = 'champs-milestone-appear 0.3s ease-in reverse forwards';
            setTimeout(() => celebration.remove(), 300);
        }, 3000);
    }

    // RT-11: Activity Heatmap
    function updateActivityHeatmap() {
        const tabEl = document.getElementById('tab-champs');
        if (!tabEl) return;
        
        tabEl.classList.remove('champs-activity-low', 'champs-activity-medium', 'champs-activity-high', 'champs-activity-extreme');
        
        if (recentActivityCount >= 10) {
            tabEl.classList.add('champs-activity-extreme');
            activityLevel = 'extreme';
        } else if (recentActivityCount >= 5) {
            tabEl.classList.add('champs-activity-high');
            activityLevel = 'high';
        } else if (recentActivityCount >= 2) {
            tabEl.classList.add('champs-activity-medium');
            activityLevel = 'medium';
        } else {
            tabEl.classList.add('champs-activity-low');
            activityLevel = 'low';
        }
        
        // Decay activity count over time
        setTimeout(() => {
            recentActivityCount = Math.max(0, recentActivityCount - 1);
        }, 10000);
    }

    // RT-12: Typing Indicator
    function showTypingIndicator(analystName) {
        const existing = document.querySelector('.champs-typing-indicator');
        if (existing) existing.remove();
        
        const heroEl = document.querySelector('.champs-hero');
        if (!heroEl) return;
        
        const indicator = document.createElement('div');
        indicator.className = 'champs-typing-indicator';
        indicator.innerHTML = `
            <span>${analystName} is adding IOCs</span>
            <div class="champs-typing-dots">
                <span class="champs-typing-dot"></span>
                <span class="champs-typing-dot"></span>
                <span class="champs-typing-dot"></span>
            </div>
        `;
        indicator.style.cssText = 'position: absolute; bottom: -30px; left: 20px;';
        heroEl.appendChild(indicator);
        
        setTimeout(() => indicator.remove(), 5000);
    }

    // RT-13: Sound Wave Visual
    function showSoundWave() {
        const existing = document.querySelector('.champs-sound-wave');
        if (existing) existing.remove();
        
        const wave = document.createElement('div');
        wave.className = 'champs-sound-wave';
        wave.innerHTML = `
            <div class="champs-sound-bar"></div>
            <div class="champs-sound-bar"></div>
            <div class="champs-sound-bar"></div>
            <div class="champs-sound-bar"></div>
        `;
        document.body.appendChild(wave);
        
        setTimeout(() => wave.remove(), 2000);
    }

    // RT-14: Mark New Entries
    function markNewEntries(oldData, newData) {
        if (!oldData || !newData) return;
        
        const oldIds = new Set(oldData.map(a => a.user_id || a.analyst));
        
        newData.forEach((analyst, index) => {
            const id = analyst.user_id || analyst.analyst;
            if (!oldIds.has(id)) {
                const row = document.querySelector(`.champs-ladder-row[data-index="${index}"]`);
                if (row) {
                    row.classList.add('champs-new-entry');
                    setTimeout(() => row.classList.remove('champs-new-entry'), 2000);
                }
            }
        });
    }

    // RT-15: Live Badge
    function createLiveBadge() {
        const existingBadge = document.querySelector('.champs-live-badge');
        if (existingBadge) return;
        
        const titleEl = document.querySelector('.champs-title');
        if (!titleEl) return;
        
        const badge = document.createElement('span');
        badge.className = 'champs-live-badge';
        badge.textContent = 'LIVE';
        titleEl.appendChild(badge);
    }

    // Initialize all real-time features
    function initRealTimeFeatures() {
        createLiveCounter();
        createLastActivityDisplay();
        createLiveBadge();
        startMexicanWave();
        updateActivityHeatmap();
        
        // Setup refresh button
        const refreshBtn = document.getElementById('champsRefreshBtn');
        if (refreshBtn && !refreshBtn.dataset.initialized) {
            refreshBtn.dataset.initialized = 'true';
            refreshBtn.addEventListener('click', () => {
                // Spin animation
                const icon = refreshBtn.querySelector('svg');
                if (icon) {
                    icon.style.animation = 'spin 0.5s linear';
                    setTimeout(() => icon.style.animation = '', 500);
                }
                // Force refresh
                loadChampsAnalysis(false, true);
            });
        }

        // Presence heartbeat (keeps "online now" accurate)
        if (!champsPresencePollInterval) {
            const ping = async () => {
                try {
                    const tabEl = document.getElementById('tab-champs');
                    if (!tabEl || tabEl.classList.contains('hidden')) return;
                    if (document.hidden) return;
                    await fetch('/api/champs/ping', { method: 'POST' });
                } catch (e) { /* ignore */ }
            };
            ping();
            champsPresencePollInterval = setInterval(ping, 25000);
        }
    }

    // Handle real-time updates - detect changes between old and new leaderboard data
    function handleRealtimeUpdate(oldData, newData, tickerMessages) {
        if (!oldData || !newData || oldData.length === 0) return;
        
        let hasChanges = false;
        
        // Check for score changes
        newData.forEach(analyst => {
            const id = analyst.user_id || analyst.analyst;
            const oldAnalyst = oldData.find(a => (a.user_id || a.analyst) === id);
            
            if (oldAnalyst) {
                // Score increased
                if (analyst.score > oldAnalyst.score) {
                    hasChanges = true;
                    console.log(`[Champs Live] ${analyst.display_name || analyst.analyst}: score ${oldAnalyst.score} → ${analyst.score}`);
                }
                
                // IOC count increased
                if (analyst.total_iocs > oldAnalyst.total_iocs) {
                    hasChanges = true;
                    
                    // Check for milestones
                    const milestones = [50, 100, 200, 500, 1000];
                    milestones.forEach(m => {
                        if (analyst.total_iocs >= m && oldAnalyst.total_iocs < m) {
                            showMilestoneCelebration(`${m} IOCs!`, 'ioc');
                        }
                    });
                }
                
                // Rank changed significantly
                if (oldAnalyst.rank && analyst.rank && Math.abs(oldAnalyst.rank - analyst.rank) >= 2) {
                    hasChanges = true;
                    shakeLeaderboard();
                }
            }
        });
        
        if (hasChanges) {
            recentActivityCount++;
            updateActivityHeatmap();
            updateLastActivity(Date.now());
            flashTicker();
        }
        
        // Mark new entries
        markNewEntries(oldData, newData);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Streak Meter
    // ═══════════════════════════════════════════════════════════════════════════
    function updateStreakMeter(streakDays) {
        let meter = document.getElementById('champsStreakMeter');
        if (!meter && streakDays >= 3) {
            const tabEl = document.getElementById('tab-champs');
            if (!tabEl) return;
            
            meter = document.createElement('div');
            meter.id = 'champsStreakMeter';
            meter.style.cssText = `
                position: absolute;
                top: 10px;
                right: 10px;
                padding: 8px 16px;
                background: linear-gradient(135deg, rgba(249, 115, 22, 0.2) 0%, rgba(234, 88, 12, 0.3) 100%);
                border: 1px solid rgba(249, 115, 22, 0.5);
                border-radius: 20px;
                font-family: var(--champs-ui-font);
                font-size: 0.875rem;
                font-weight: 700;
                color: #fb923c;
                text-shadow: 0 0 10px rgba(249, 115, 22, 0.5);
                z-index: 100;
                animation: champs-streak-pulse 2s ease-in-out infinite;
            `;
            tabEl.appendChild(meter);
            
            if (!document.getElementById('champs-streak-keyframes')) {
                const style = document.createElement('style');
                style.id = 'champs-streak-keyframes';
                style.textContent = `
                    @keyframes champs-streak-pulse {
                        0%, 100% { box-shadow: 0 0 10px rgba(249, 115, 22, 0.3); }
                        50% { box-shadow: 0 0 25px rgba(249, 115, 22, 0.6); }
                    }
                `;
                document.head.appendChild(style);
            }
        }
        
        if (meter && streakDays >= 3) {
            meter.innerHTML = `🔥 ${streakDays} Day Streak!`;
            meter.style.display = 'block';
        } else if (meter) {
            meter.style.display = 'none';
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Overtake Toast
    // ═══════════════════════════════════════════════════════════════════════════
    function showOvertakeToast(overtakerName, overtakenName, newRank) {
        const message = `🎉 ${overtakerName} overtook ${overtakenName}! Now #${newRank}`;
        if (typeof showToast === 'function') {
            const toastEl = showToast(message, 'success');
            if (toastEl && toastEl.classList) {
                toastEl.classList.add('toast-overtake');
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VIDEO GAME EFFECTS - Real-time Leaderboard Updates with Animations
    // ═══════════════════════════════════════════════════════════════════════════
    function detectRankChanges(oldData, newData) {
        const changes = [];
        const oldMap = {};
        oldData.forEach((a, i) => { oldMap[a.user_id || a.analyst] = { rank: a.rank, index: i }; });
        
        newData.forEach((a, newIndex) => {
            const key = a.user_id || a.analyst;
            const old = oldMap[key];
            if (old) {
                const rankDiff = old.rank - a.rank;
                if (rankDiff > 0) {
                    changes.push({ key, type: 'up', oldRank: old.rank, newRank: a.rank, diff: rankDiff, analyst: a });
                } else if (rankDiff < 0) {
                    changes.push({ key, type: 'down', oldRank: old.rank, newRank: a.rank, diff: Math.abs(rankDiff), analyst: a });
                }
            }
        });
        return changes;
    }

    function applyRankChangeAnimations(changes) {
        const authState = global.authState || {};
        const currentUserId = authState.user_id;
        
        changes.forEach(change => {
            const rows = document.querySelectorAll('.champs-ladder-row');
            rows.forEach(row => {
                const index = parseInt(row.getAttribute('data-index'), 10);
                const data = champsLeaderboardData[index];
                if (!data) return;
                
                const key = data.user_id || data.analyst;
                if (key === change.key) {
                    row.classList.remove('champs-rank-changed-up', 'champs-rank-changed-down', 'champs-moving-up', 'champs-moving-down', 'champs-just-overtook');
                    void row.offsetWidth;
                    
                    if (change.type === 'up') {
                        row.classList.add('champs-rank-changed-up', 'champs-moving-up', 'champs-just-overtook');
                        
                        if (String(change.key) === String(currentUserId)) {
                            const isTop3 = change.newRank <= 3;
                            showRankUpEffect(change.newRank, isTop3);
                            if (change.diff >= 1) {
                                triggerConfetti();
                            }
                            // Show achievement popup for significant rank changes
                            if (change.newRank === 1) {
                                showAchievementPopup('Champion!', 'You reached the #1 spot!', '👑');
                            } else if (isTop3) {
                                showAchievementPopup('Podium Finish!', `You reached #${change.newRank}!`, '🏆');
                            } else if (change.diff >= 3) {
                                showAchievementPopup('Rapid Rise!', `You jumped ${change.diff} ranks!`, '🚀');
                            }
                            // Show floating text
                            const rect = row.getBoundingClientRect();
                            showFloatingText(`+${change.diff}`, rect.right - 50, rect.top, '#00ff41');
                        }
                    } else {
                        row.classList.add('champs-rank-changed-down', 'champs-moving-down');
                    }
                    
                    setTimeout(() => {
                        row.classList.remove('champs-rank-changed-up', 'champs-rank-changed-down', 'champs-moving-up', 'champs-moving-down');
                    }, 1500);
                    setTimeout(() => {
                        row.classList.remove('champs-just-overtook');
                    }, 3000);
                }
            });
        });
        
        changes.forEach(change => {
            if (change.type === 'up' && change.diff >= 1) {
                const overtakenAnalysts = champsPreviousLeaderboard.filter(a => {
                    const aRank = a.rank;
                    return aRank < change.oldRank && aRank >= change.newRank;
                });
                if (overtakenAnalysts.length > 0) {
                    const overtakerName = change.analyst.display_name || change.analyst.username || change.analyst.analyst;
                    const overtakenName = overtakenAnalysts[0].display_name || overtakenAnalysts[0].username || overtakenAnalysts[0].analyst;
                    showOvertakeToast(overtakerName, overtakenName, change.newRank);
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MAIN LOAD FUNCTION
    // ═══════════════════════════════════════════════════════════════════════════
    async function loadChampsAnalysis(skipAnimations, fresh) {
        const listEl = document.getElementById('champsLadderList');
        if (!listEl) return;
        
        initChampsParticles();
        initRealTimeFeatures();
        
        try {
            listEl.querySelectorAll('.champs-ladder-row').forEach(b => b.classList.remove('champs-ladder-selected'));
            const url = fresh ? '/api/champs/leaderboard?fresh=1' : '/api/champs/leaderboard';
            const response = await fetch(url);
            const result = await response.json();
            if (result.success && result.leaderboard && result.leaderboard.length > 0) {
                const oldData = [...champsLeaderboardData];
                champsLeaderboardData = result.leaderboard;
                
                listEl.innerHTML = result.leaderboard.map((a, i) => {
                    const rankClass = a.rank === 1 ? 'champs-rank-1' : a.rank === 2 ? 'champs-rank-2' : a.rank === 3 ? 'champs-rank-3' : '';
                    const trendUp = a.trend && (String(a.trend).startsWith('+') || String(a.trend).includes('▲'));
                    const trendDown = a.trend && (String(a.trend).startsWith('-') || String(a.trend).includes('▼'));
                    const trendNum = a.trend ? String(a.trend).replace(/[^0-9]/g, '') || '' : '';
                    const trendHtml = trendUp
                        ? `<span class="champs-trend-pill champs-trend-up" title="Rank improved"><span class="champs-trend-arrow" aria-hidden="true">↑</span><span class="champs-trend-delta">${escapeHtml(trendNum || a.trend)}</span></span>`
                        : trendDown
                            ? `<span class="champs-trend-pill champs-trend-down" title="Rank dropped"><span class="champs-trend-arrow" aria-hidden="true">↓</span><span class="champs-trend-delta">${escapeHtml(trendNum || a.trend)}</span></span>`
                            : '<span class="champs-trend-pill champs-trend-same" aria-hidden="true">—</span>';
                    const medal = a.medal || '';
                    const rankText = `#${a.rank}`;
                    const avatarUrl = a.avatar_url || '';
                    const displayName = escapeHtml(a.display_name || a.username || a.analyst);
                    const avatarSize = 'w-11 h-11';
                    const isInactive = a.is_active === false;
                    const avatarInactiveClass = isInactive ? ' grayscale opacity-70' : '';
                    const avatarHtml = avatarUrl
                        ? `<img src="${escapeAttr(avatarUrl)}" alt="" class="w-full h-full object-cover" onerror="this.onerror=null;this.parentElement.innerHTML='<span class=\\'text-lg\\'>👤</span>'">`
                        : '<span class="text-sm">👤</span>';
                    const rankSlot = a.rank <= 3
                        ? `<span class="champs-medal-circle champs-medal-circle-${a.rank} champs-rank-slot flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center text-2xl border-2" title="Rank ${a.rank}">${medal}</span>`
                        : `<span class="champs-rank-slot champs-rank-num flex-shrink-0 w-12 h-12 flex items-center justify-center font-extrabold text-secondary text-lg">${a.rank}</span>`;
                    return `
                        <button type="button" class="champs-ladder-row ${rankClass} w-full flex items-center gap-3 px-3 py-2.5 rounded-xl border border-transparent hover:border-white/10 hover:bg-white/5 transition-all text-left" data-index="${i}" data-user-id="${a.user_id || ''}" title="${a.score} pts${isInactive ? ' (inactive)' : ''}">
                            ${rankSlot}
                            <span class="flex-shrink-0 ${avatarSize} rounded-full overflow-hidden bg-slate-600/50 flex items-center justify-center ring-2 ring-white/5${avatarInactiveClass}">
                                ${avatarHtml}
                            </span>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center gap-1.5 flex-wrap">
                                    <span class="font-bold text-sm truncate">${displayName}</span>
                                </div>
                                <div class="flex items-center gap-2 mt-1 flex-wrap">
                                    <span class="text-sm font-semibold opacity-90">${rankText}</span>
                                    ${trendHtml}
                                </div>
                            </div>
                        </button>
                    `;
                }).join('');
                
                listEl.querySelectorAll('.champs-ladder-row').forEach(btn => {
                    btn.addEventListener('click', () => {
                        listEl.querySelectorAll('.champs-ladder-row').forEach(b => b.classList.remove('champs-ladder-selected'));
                        btn.classList.add('champs-ladder-selected');
                        showChampsSpotlight(parseInt(btn.getAttribute('data-index'), 10));
                    });
                });
                
                if (!skipAnimations && oldData.length > 0) {
                    const changes = detectRankChanges(oldData, champsLeaderboardData);
                    if (changes.length > 0) {
                        applyRankChangeAnimations(changes);
                        triggerActivityFlash();
                    }
                    // Handle real-time updates
                    handleRealtimeUpdate(oldData, champsLeaderboardData, champsTickerMessages);
                }
                
                // Apply fire effect to streak users
                setTimeout(() => applyFireEffectToStreaks(), 600);
                
                // Update real-time indicators
                updateActiveIndicators(champsLeaderboardData);
                updateHotBadges(champsLeaderboardData);
                
                // Calculate total IOCs for live counter
                const totalIOCs = champsLeaderboardData.reduce((sum, a) => sum + (a.total_iocs || 0), 0);
                updateLiveCounter(totalIOCs);
                
                champsPreviousLeaderboard = [...champsLeaderboardData];
            } else {
                const t = global.t || (k => k);
                listEl.innerHTML = `<div class="text-secondary text-sm py-4 text-center">${t('champs.no_data') || 'No analyst data yet'}</div>`;
            }
        } catch (error) {
            console.error('Error loading champs leaderboard:', error);
            listEl.innerHTML = `<div class="text-red-400 text-sm py-4 text-center">Error loading data</div>`;
        }
        loadChampsTeamHud();
        loadChampsTicker();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // REAL-TIME POLLING
    // ═══════════════════════════════════════════════════════════════════════════
    function startChampsLeaderboardPolling() {
        if (champsLeaderboardPollInterval) clearInterval(champsLeaderboardPollInterval);
        champsLeaderboardPollInterval = setInterval(() => {
            const tabEl = document.getElementById('tab-champs');
            if (!tabEl || tabEl.classList.contains('hidden')) return;
            if (document.hidden) return;
            loadChampsAnalysis(false, true);  // Pass fresh=true to bypass cache
        }, 30000);
    }

    function stopChampsLeaderboardPolling() {
        if (champsLeaderboardPollInterval) {
            clearInterval(champsLeaderboardPollInterval);
            champsLeaderboardPollInterval = null;
        }
    }

    (function initChampsGoalModal() {
        const btn = document.getElementById('champsSetGoalBtn');
        const modal = document.getElementById('champsGoalModal');
        const cancelBtn = document.getElementById('champsGoalCancel');
        const form = document.getElementById('champsGoalForm');
        async function openGoalModal() {
            try {
                const r = await fetch('/api/champs/team-goal');
                const j = await r.json();
                const g = j.success && j.goal ? j.goal : null;
                const setVal = (id, value) => {
                    const el = document.getElementById(id);
                    if (el) el.value = (value != null && value !== '') ? String(value) : '';
                };
                setVal('champsGoalTitle', g ? g.title : '');
                setVal('champsGoalDescription', g ? (g.description || '') : '');
                setVal('champsGoalTarget', g && g.target_value != null ? g.target_value : '');
                setVal('champsGoalType', g && g.goal_type ? g.goal_type : 'ioc_add');
                setVal('champsGoalPeriod', g && g.period ? g.period : 'weekly');
                setVal('champsGoalUnit', g ? (g.unit || '') : '');
            } catch (e) { /* leave fields empty on error */ }
            if (modal) modal.classList.remove('hidden');
        }
        if (btn) btn.addEventListener('click', openGoalModal);
        if (cancelBtn) cancelBtn.addEventListener('click', () => { if (modal) modal.classList.add('hidden'); });
        if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.add('hidden'); });
        if (form) form.addEventListener('submit', async (e) => {
            e.preventDefault();
            try {
                const r = await fetch('/api/champs/team-goal', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title: document.getElementById('champsGoalTitle').value.trim(),
                        description: (document.getElementById('champsGoalDescription') && document.getElementById('champsGoalDescription').value.trim()) || undefined,
                        target_value: parseInt(document.getElementById('champsGoalTarget').value, 10),
                        goal_type: document.getElementById('champsGoalType').value,
                        period: document.getElementById('champsGoalPeriod').value,
                        unit: (document.getElementById('champsGoalUnit') && document.getElementById('champsGoalUnit').value.trim()) || undefined
                    })
                });
                const j = await r.json();
                if (j.success) {
                    modal.classList.add('hidden');
                    loadChampsTeamHud();
                    loadChampsAnalysis(true);
                    showToast(j.message || 'Goal set', 'success');
                } else showToast(j.message || 'Failed', 'error');
            } catch (err) { showToast('Failed to set goal', 'error'); }
        });
        const descEl = document.getElementById('champsGoalDescription');
        if (descEl && typeof window.detectDir === 'function') {
            descEl.addEventListener('input', function () { this.setAttribute('dir', window.detectDir(this.value)); });
            descEl.addEventListener('keyup', function () { this.setAttribute('dir', window.detectDir(this.value)); });
        }
    })();

    (function initChampsTickerMsgModal() {
        const ROWS = 5;
        const btn = document.getElementById('champsTickerMsgSettingsBtn');
        const modal = document.getElementById('champsTickerMsgModal');
        const rowsContainer = document.getElementById('champsTickerMsgRows');
        const rowTpl = document.getElementById('champsTickerMsgRowTpl');
        const cancelBtn = document.getElementById('champsTickerMsgCancel');
        const saveBtn = document.getElementById('champsTickerMsgSave');
        if (!modal || !rowsContainer || !rowTpl) return;
        function ensureRows() {
            rowsContainer.innerHTML = '';
            for (let i = 0; i < ROWS; i++) {
                const row = rowTpl.content.cloneNode(true);
                const textInp = row.querySelector('.champs-ticker-msg-text');
                const colorInp = row.querySelector('.champs-ticker-msg-color');
                if (textInp) {
                    textInp.setAttribute('data-idx', i);
                    if (typeof applyAutoDir === 'function') applyAutoDir(textInp);
                }
                if (colorInp) colorInp.setAttribute('data-idx', i);
                rowsContainer.appendChild(row);
            }
        }
        ensureRows();
        async function openMsgModal() {
            try {
                const r = await fetch('/api/champs/ticker-messages');
                const j = await r.json();
                const messages = (j.messages || []).slice(0, ROWS);
                const bd = (j.banner_direction || 'rtl') === 'ltr' ? 'ltr' : 'rtl';
                modal.querySelectorAll('input[name="champsTickerBannerDir"]').forEach((rad) => {
                    rad.checked = rad.value === bd;
                });
                rowsContainer.querySelectorAll('.champs-ticker-msg-text').forEach((inp, i) => {
                    inp.value = (messages[i] && messages[i].text) || '';
                    if (typeof detectTextDir === 'function') inp.dir = detectTextDir(inp.value);
                });
                rowsContainer.querySelectorAll('.champs-ticker-msg-color').forEach((inp, i) => {
                    inp.value = (messages[i] && messages[i].color) || '#ffffff';
                });
            } catch (e) { /* leave empty */ }
            modal.classList.remove('hidden');
        }
        if (btn) btn.addEventListener('click', openMsgModal);
        if (cancelBtn) cancelBtn.addEventListener('click', () => { modal.classList.add('hidden'); });
        if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.add('hidden'); });
        if (saveBtn) saveBtn.addEventListener('click', async () => {
            const messages = [];
            rowsContainer.querySelectorAll('.champs-ticker-msg-row').forEach((row, i) => {
                const textInp = row.querySelector('.champs-ticker-msg-text');
                const colorInp = row.querySelector('.champs-ticker-msg-color');
                const text = (textInp && textInp.value) ? textInp.value.trim() : '';
                const color = (colorInp && colorInp.value) ? colorInp.value : '#ffffff';
                const dir = (typeof detectTextDir === 'function') ? detectTextDir(text) : 'ltr';
                messages.push({ text: text, color: color, dir: dir });
            });
            const bannerDirEl = modal.querySelector('input[name="champsTickerBannerDir"]:checked');
            const banner_direction = (bannerDirEl && bannerDirEl.value === 'ltr') ? 'ltr' : 'rtl';
            try {
                const r = await fetch('/api/champs/ticker-messages', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ messages: messages, banner_direction: banner_direction })
                });
                const j = await r.json();
                const t = global.t || (k => k);
                if (j.success) {
                    modal.classList.add('hidden');
                    loadChampsTicker();
                    showToast(typeof t === 'function' && t('champs.msg_settings_saved') ? t('champs.msg_settings_saved') : 'Ticker messages saved', 'success');
                } else showToast(j.message || 'Failed', 'error');
            } catch (err) { showToast('Failed to save', 'error'); }
        });
    })();

    async function loadChampsTeamHud() {
        const authState = global.authState || {};
        const t = global.t || (k => k);
        const hud = document.getElementById('champsTeamHud');
        const setBtn = document.getElementById('champsSetGoalBtn');
        const barArea = document.getElementById('champsTeamHudBarArea');
        if (!hud) return;
        try {
            const r = await fetch('/api/champs/team-goal');
            const j = await r.json();
            if (setBtn) setBtn.classList.toggle('hidden', !authState.is_admin);
            const msgSettingsBtn = document.getElementById('champsTickerMsgSettingsBtn');
            if (msgSettingsBtn) msgSettingsBtn.classList.toggle('hidden', !authState.is_admin);
            if (!j.success || !j.goal) {
                if (barArea) barArea.style.display = 'none';
                const subEl = document.getElementById('champsTeamHudSub');
                if (subEl) subEl.textContent = '';
                document.getElementById('champsTeamHudTitle').textContent = authState.is_admin ? (t('champs.no_goal') || 'No team goal - Set one') : '';
                if (!authState.is_admin) hud.style.display = 'none';
                else hud.style.display = 'block';
                return;
            }
            hud.style.display = 'block';
            const g = j.goal;
            if (barArea) barArea.style.display = 'flex';
            const titleEl = document.getElementById('champsTeamHudTitle');
            titleEl.textContent = g.title;
            if (g.description) {
                titleEl.setAttribute('title', g.description);
            } else {
                titleEl.removeAttribute('title');
            }
            const pct = g.percent != null ? Number(g.percent) : 0;
            document.getElementById('champsTeamHudBar').style.width = Math.min(100, pct) + '%';
            document.getElementById('champsTeamHudPercent').textContent = pct + '%';
            document.getElementById('champsTeamHudSub').textContent = (g.current_value || 0) + ' / ' + (g.target_value || 0) + ' ' + (g.unit || '');
        } catch (e) { if (barArea) barArea.style.display = 'none'; }
    }

    function champsTickerHighlightKeywords(text) {
        if (!text) return '';
        const escaped = escapeHtml(text);
        return escaped
            .replace(/#(\d+)/g, '<span class="champs-ticker-kw">#$1</span>')
            .replace(/(\d+)%/g, '<span class="champs-ticker-kw">$1%</span>')
            .replace(/\b(overtook|rose|reached|added|uploaded|removed|goal|Team goal|new IOC|YARA rule)\b/gi, '<span class="champs-ticker-kw">$&</span>');
    }

    function applyChampsTickerBannerDirection(scrollEl, bannerDirection) {
        if (!scrollEl) return;
        const ltr = (bannerDirection || 'rtl') === 'ltr';
        scrollEl.classList.toggle('champs-ticker-marquee-reversed', ltr);
    }

    async function loadChampsTicker() {
        const t = global.t || (k => k);
        const stripEl = document.getElementById('champsTickerStrip');
        const scrollEl = document.getElementById('champsTickerScroll');
        if (!stripEl || !scrollEl) return;
        const sep = '<span class="champs-ticker-sep"> | </span>';
        try {
            const r = await fetch('/api/champs/ticker?limit=10');
            const j = await r.json();
            applyChampsTickerBannerDirection(scrollEl, j.banner_direction);
            if (j.source === 'custom' && j.messages && j.messages.length > 0) {
                champsTickerMessages = j.messages.map(m => ({
                    text: m.text || '',
                    color: m.color || '#ffffff',
                    dir: (m.dir || m.direction || 'ltr') === 'rtl' ? 'rtl' : 'ltr'
                }));
                stripEl.classList.remove('champs-ticker-placeholder');
                scrollEl.classList.add('champs-ticker-marquee');
                const parts = champsTickerMessages.map(m => {
                    const color = (m.color || '#ffffff').replace(/"/g, '&quot;');
                    const dirAttr = m.dir === 'rtl' ? ' dir="rtl"' : ' dir="ltr"';
                    return '<span class="champs-ticker-msg champs-ticker-custom" style="color:' + color + '"' + dirAttr + '>' + escapeHtml(m.text) + '</span>';
                });
                const oneStrip = parts.join(sep);
                stripEl.innerHTML = oneStrip + sep + oneStrip;
                return;
            }
            champsTickerMessages = (j.messages || []).map(m => ({ text: m.text || '', category: m.category || 'analyst_success' }));
            if (champsTickerMessages.length === 0) {
                const placeholder = (typeof t === 'function' && t('champs.ticker_no_activity')) ? t('champs.ticker_no_activity') : 'No recent activity - new submissions, rank changes and goal updates will appear here.';
                stripEl.innerHTML = '<span class="champs-ticker-msg">' + escapeHtml(placeholder) + '</span>';
                stripEl.classList.add('champs-ticker-placeholder');
                scrollEl.classList.remove('champs-ticker-marquee');
                scrollEl.classList.remove('champs-ticker-marquee-reversed');
                return;
            }
            stripEl.classList.remove('champs-ticker-placeholder');
            scrollEl.classList.add('champs-ticker-marquee');
            const catClass = (c) => {
                if (c === 'team') return 'champs-ticker-team';
                if (c === 'important' || c === 'warning') return 'champs-ticker-warning';
                if (c === 'negative') return 'champs-ticker-negative';
                return 'champs-ticker-success';
            };
            const parts = champsTickerMessages.map(m => '<span class="champs-ticker-msg ' + catClass(m.category) + '">' + champsTickerHighlightKeywords(m.text) + '</span>');
            const oneStrip = parts.join(sep);
            stripEl.innerHTML = oneStrip + sep + oneStrip;
        } catch (e) {
            stripEl.innerHTML = '<span class="champs-ticker-msg">' + escapeHtml((typeof t === 'function' && t('champs.ticker_error')) ? t('champs.ticker_error') : 'Could not load activity.') + '</span>';
            scrollEl.classList.remove('champs-ticker-marquee');
            scrollEl.classList.remove('champs-ticker-marquee-reversed');
        }
    }

    function startChampsTickerPolling() {
        loadChampsTicker();
        startChampsLeaderboardPolling();
        if (champsTickerPollInterval) clearInterval(champsTickerPollInterval);
        champsTickerPollInterval = setInterval(() => {
            if (!document.getElementById('tab-champs') || document.getElementById('tab-champs').classList.contains('hidden')) return;
            loadChampsTicker();
        }, 10000);
    }

    async function showChampsSpotlight(index) {
        const data = champsLeaderboardData[index];
        const placeholder = document.getElementById('champsSpotlightPlaceholder');
        const content = document.getElementById('champsSpotlightContent');
        if (!data || !placeholder || !content) return;
        placeholder.classList.add('hidden');
        content.classList.remove('hidden');
        content.innerHTML = '<div class="text-secondary">Loading...</div>';
        const uid = data.user_id;
        if (uid != null && uid !== '') {
            try {
                const r = await fetch('/api/champs/analyst/' + uid);
                const j = await r.json();
                if (j.success && j.analyst) {
                    renderChampsSpotlightFull(content, j.analyst, data);
                    return;
                }
            } catch (e) { console.warn('Analyst detail fetch failed:', e); }
        }
        renderChampsSpotlightBasic(content, data);
    }

    function renderChampsSpotlightBasic(content, data) {
        const streakText = (data.streak_days || 0) >= 3 ? ` 🔥 ${data.streak_days}d` : '';
        const avatarHtml = data.avatar_url ? `<img src="${escapeAttr(data.avatar_url)}" alt="" class="w-full h-full object-cover" onerror="this.parentElement.innerHTML='<span class=\\'text-2xl\\'>👤</span>'">` : '<span class="text-2xl">👤</span>';
        const name = escapeHtml(data.display_name || data.username || data.analyst);
        const nicknamePart = data.nickname_emoji ? data.nickname_emoji + ' ' + escapeHtml(data.nickname || '') : escapeHtml(data.nickname || '');
        const roleDesc = (data.role_description || '').trim();
        const nameLineHtml = nicknamePart
            ? `<div class="flex items-baseline gap-2 flex-wrap min-w-0"><h3 class="text-2xl font-extrabold accent-blue truncate">${name}</h3><span class="text-secondary font-medium text-base whitespace-nowrap">${nicknamePart}</span></div>`
            : `<h3 class="text-2xl font-extrabold accent-blue truncate">${name}</h3>`;
        const roleDescHtml = roleDesc ? `<p class="text-secondary font-medium mt-0.5">${escapeHtml(roleDesc)}</p>` : '';
        const spotlightInactiveClass = data.is_active === false ? ' grayscale opacity-70' : '';
        const scoreValue = data.score != null ? data.score : 0;
        content.innerHTML = `
            <div class="champs-spotlight-card rounded-lg border border-white/10 bg-tertiary/80 p-4 flex-1 min-h-0 flex flex-col overflow-auto">
                <div class="champs-spotlight-header flex items-stretch gap-4 mb-4 flex-shrink-0">
                    <span class="champs-spotlight-avatar w-20 h-20 rounded-full overflow-hidden bg-slate-600/50 flex items-center justify-center ring-4 ring-cyan-500/30 flex-shrink-0${spotlightInactiveClass}">${avatarHtml}</span>
                    <div class="min-w-0 flex-1 flex flex-col justify-center">
                        ${nameLineHtml}
                        ${roleDescHtml}
                        <p class="text-secondary font-medium mt-1">Rank <span class="font-bold text-white">#${data.rank}</span>${streakText ? ' ' + streakText : ''}</p>
                    </div>
                    <div class="champs-spotlight-points-hero flex-shrink-0 flex flex-col items-start justify-center">
                        <span class="champs-spotlight-points-label">Points</span>
                        <span class="champs-spotlight-points-value" id="champsScoreBasic">0</span>
                    </div>
                </div>
                <div class="champs-stats-grid grid grid-cols-2 gap-3">
                    <div class="champs-stat-card rounded-lg p-4 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-1">IOCs</span><span class="font-mono text-lg font-bold accent-green">${data.total_iocs || 0}</span></div>
                    <div class="champs-stat-card rounded-lg p-4 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-1">YARA</span><span class="font-mono text-lg font-bold text-amber-400">${data.yara_count || 0}</span></div>
                </div>
            </div>`;
        
        setTimeout(() => {
            const scoreEl = document.getElementById('champsScoreBasic');
            if (scoreEl) animateScore(scoreEl, scoreValue);
        }, 100);
        
        renderChampsTrophyCabinet([]);
    }

    function renderChampsTrophyCabinet(badgeKeys) {
        const listEl = document.getElementById('champsTrophyCabinetList');
        const placeholderEl = document.getElementById('champsTrophyCabinetPlaceholder');
        if (!listEl) return;
        if (!badgeKeys || badgeKeys.length === 0) {
            listEl.innerHTML = '<div id="champsTrophyCabinetPlaceholder" class="w-full py-8 text-center text-secondary text-sm">Select an analyst</div>';
            return;
        }
        const items = badgeKeys.map(key => {
            const label = BADGE_LABELS[key] || key;
            const name = BADGE_NAMES[key] || key;
            const cls = BADGE_CLASSES[key] || '';
            const tooltip = champsBadgeDescriptions[key] || '';
            return `<div class="champs-trophy-item ${cls}" title="${escapeAttr(tooltip)}">
                <span class="champs-trophy-symbol">${escapeHtml(label.split(' ')[0] || label)}</span>
                <span class="champs-trophy-label">${escapeHtml(name)}</span>
            </div>`;
        }).join('');
        listEl.innerHTML = (placeholderEl ? '<div id="champsTrophyCabinetPlaceholder" class="hidden w-full py-8 text-center text-secondary text-sm">Select an analyst</div>' : '') + items;
    }

    function renderChampsSpotlightFull(content, a, ladderData) {
        const name = escapeHtml(a.display_name || a.nickname || a.analyst || '');
        const nicknamePart = a.nickname_emoji ? a.nickname_emoji + ' ' + escapeHtml(a.nickname || '') : escapeHtml(a.nickname || '');
        const roleDesc = (a.role_description || '').trim();
        const nameLineHtml = nicknamePart
            ? `<div class="flex items-baseline gap-2 flex-wrap min-w-0"><h3 class="text-2xl font-extrabold accent-blue truncate">${name}</h3><span class="text-secondary font-medium text-base whitespace-nowrap">${nicknamePart}</span></div>`
            : `<h3 class="text-2xl font-extrabold accent-blue truncate">${name}</h3>`;
        const roleDescHtml = roleDesc ? `<p class="text-secondary font-medium mt-0.5">${escapeHtml(roleDesc)}</p>` : '';
        const xpPct = a.level_width ? Math.min(100, 100 * (a.xp_in_level || 0) / a.level_width) : 0;
        const badges = (a.badges || []).map(b => ({ key: b, label: BADGE_LABELS[b] || b, cls: BADGE_CLASSES[b] || '' })).filter(x => x.label);
        const avatarHtml = a.avatar_url ? `<img src="${escapeAttr(a.avatar_url)}" alt="" class="w-full h-full object-cover" onerror="this.parentElement.innerHTML='<span class=\\'text-2xl\\'>👤</span>'">` : '<span class="text-2xl">👤</span>';
        const fullSpotlightInactiveClass = a.is_active === false ? ' grayscale opacity-70' : '';
        const analystChartName = (a.display_name || a.nickname || a.analyst || 'You').trim() || 'You';
        const scoreValue = a.score != null ? a.score : 0;
        let chartHtml = '';
        champsMispData = (a.misp_per_day && a.misp_per_day.length > 0) ? a.misp_per_day : null;
        champsMispVisible = false;
        if (a.activity_per_day && a.activity_per_day.length > 0 && typeof Chart !== 'undefined') {
            const mispBtnHtml = champsMispData
                ? ' <button type="button" id="champsMispToggle" class="champs-misp-toggle" title="Toggle MISP sync overlay">'
                  + '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" xmlns="http://www.w3.org/2000/svg">'
                  + '<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/>'
                  + '<circle cx="12" cy="8" r="2" fill="currentColor"/>'
                  + '<circle cx="7" cy="15" r="2" fill="currentColor"/>'
                  + '<circle cx="17" cy="15" r="2" fill="currentColor"/>'
                  + '<line x1="12" y1="10" x2="7" y2="13" stroke="currentColor" stroke-width="1.2"/>'
                  + '<line x1="12" y1="10" x2="17" y2="13" stroke="currentColor" stroke-width="1.2"/>'
                  + '<line x1="7" y1="15" x2="17" y2="15" stroke="currentColor" stroke-width="1.2" stroke-dasharray="2 2"/>'
                  + '</svg></button>'
                : '';
            chartHtml = '<div class="champs-activity-block flex-1 min-h-0 flex flex-col mt-4 p-4 rounded-xl bg-black/20 border border-white/5">'
                + '<div class="flex items-center justify-between mb-3 flex-shrink-0">'
                + '<h4 class="text-xs font-bold text-secondary uppercase tracking-wider">Activity (30 days) - Submissions (IOC + YARA) - ' + escapeHtml(analystChartName) + ' vs team avg</h4>'
                + mispBtnHtml
                + '</div>'
                + '<div class="champs-spotlight-chart-wrap flex-1 min-h-[260px]"><canvas id="champsSpotlightChart"></canvas></div></div>';
        }
        renderChampsTrophyCabinet(a.badges || []);
        content.innerHTML = `
            <div class="champs-spotlight-card rounded-lg border border-white/10 bg-tertiary/80 p-4 champs-spotlight-glow flex-1 min-h-0 flex flex-col overflow-auto">
                <div class="champs-spotlight-grid flex-shrink-0 mb-4">
                    <div class="champs-spotlight-header-cell flex items-center gap-4 min-w-0">
                        <span class="champs-spotlight-avatar w-24 h-24 rounded-full overflow-hidden bg-slate-600/50 flex items-center justify-center ring-4 ring-cyan-500/40 flex-shrink-0${fullSpotlightInactiveClass}">${avatarHtml}</span>
                        <div class="champs-spotlight-name-area flex flex-col justify-center min-w-0">
                            ${nameLineHtml}
                            ${roleDescHtml}
                            <p class="text-secondary text-sm mt-2">Level <strong class="text-white">${a.level || 1}</strong> → <strong class="text-white">${(a.level || 1) + 1}</strong> <span class="opacity-90">(${a.xp_to_next || 0} XP to go)</span></p>
                            <div class="mt-2 h-3 bg-black/40 rounded-full overflow-hidden max-w-xs">
                                <div class="champs-xp-fill h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all duration-500" style="width: 0%" id="champsXpBar"></div>
                            </div>
                        </div>
                    </div>
                    <div class="champs-spotlight-points-hero flex flex-col items-start justify-center">
                        <span class="champs-spotlight-points-label">Points</span>
                        <span class="champs-spotlight-points-value" id="champsScoreFull">0</span>
                    </div>
                    <div class="champs-stat-card rounded-lg p-3 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-0.5">IOCs</span><span class="font-mono text-lg font-bold accent-green truncate block">${a.total_iocs || 0}</span></div>
                    <div class="champs-stat-card rounded-lg p-3 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-0.5">YARA</span><span class="font-mono text-lg font-bold text-amber-400 truncate block">${a.yara_count || 0}</span></div>
                    <div class="champs-stat-card rounded-lg p-3 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-0.5">Deletions</span><span class="font-mono text-lg font-bold truncate block">${a.deletion_count || 0}</span></div>
                    <div class="champs-stat-card rounded-lg p-3 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-0.5">Streak</span><span class="font-mono text-lg font-bold truncate block">${a.streak_days || 0}d</span></div>
                </div>
                ${chartHtml}`;
        
        setTimeout(() => {
            const scoreEl = document.getElementById('champsScoreFull');
            if (scoreEl) animateScore(scoreEl, scoreValue);
            
            const xpBar = document.getElementById('champsXpBar');
            if (xpBar) {
                setTimeout(() => {
                    xpBar.style.width = xpPct + '%';
                    if (xpPct >= 95) {
                        xpBar.classList.add('champs-xp-levelup');
                    }
                }, 200);
            }
            
            // Initialize 3D tilt effect
            init3DCardTilt();
            
            // Animate stat cards
            setTimeout(() => animateStatCards(), 300);
        }, 100);
        
        if (chartHtml && a.activity_per_day && typeof Chart !== 'undefined') {
            setTimeout(() => {
                const ctx = document.getElementById('champsSpotlightChart');
                if (ctx) {
                    if (champsSpotlightChart) { champsSpotlightChart.destroy(); champsSpotlightChart = null; }
                    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
                    const gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
                    const textColor = isDark ? '#ffffff' : '#64748b';
                    const labels = a.activity_per_day.map(d => d.date.slice(5));
                    const data = a.activity_per_day.map(d => d.points);
                    const teamAvg = (a.team_avg_per_day || []).map(d => d.points);
                    const analystLabel = (a && (a.display_name || a.nickname || a.analyst)) ? (a.display_name || a.nickname || a.analyst).trim() : 'You';
                    const datasets = [
                        { label: analystLabel, data, borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.2)', fill: true, tension: 0.3 },
                        { label: 'Team avg', data: teamAvg.length ? teamAvg : labels.map(() => 0), borderColor: 'rgba(128,128,128,0.8)', backgroundColor: 'rgba(128,128,128,0.1)', fill: true, tension: 0.3, borderDash: [4, 2] }
                    ];
                    const chartFont = '"Segoe UI", Arial, Helvetica, system-ui, sans-serif';
                    champsSpotlightChart = new Chart(ctx.getContext('2d'), {
                        type: 'line',
                        data: { labels, datasets },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            font: { family: chartFont },
                            plugins: {
                                legend: {
                                    display: true,
                                    labels: { color: textColor, font: { family: chartFont } }
                                }
                            },
                            scales: {
                                x: {
                                    ticks: { maxRotation: 45, color: textColor, font: { family: chartFont } },
                                    grid: { color: gridColor }
                                },
                                y: {
                                    beginAtZero: true,
                                    ticks: { color: textColor, font: { family: chartFont } },
                                    grid: { color: gridColor }
                                }
                            }
                        }
                    });
                    global.champsSpotlightChart = champsSpotlightChart;

                    const mispBtn = document.getElementById('champsMispToggle');
                    if (mispBtn && champsMispData) {
                        mispBtn.addEventListener('click', function() {
                            if (!champsSpotlightChart) return;
                            champsMispVisible = !champsMispVisible;
                            mispBtn.classList.toggle('champs-misp-active', champsMispVisible);
                            if (champsMispVisible) {
                                const mispCounts = champsMispData.map(d => d.count);
                                champsSpotlightChart.data.datasets.push({
                                    label: 'MISP sync',
                                    data: mispCounts,
                                    borderColor: '#eab308',
                                    backgroundColor: 'rgba(234,179,8,0.08)',
                                    fill: false,
                                    tension: 0.3,
                                    borderDash: [6, 3],
                                    borderWidth: 2,
                                    pointRadius: 2,
                                });
                            } else {
                                const idx = champsSpotlightChart.data.datasets.findIndex(ds => ds.label === 'MISP sync');
                                if (idx !== -1) champsSpotlightChart.data.datasets.splice(idx, 1);
                            }
                            champsSpotlightChart.update();
                        });
                    }
                }
            }, 100);
        }
    }

    global.loadChampsAnalysis = loadChampsAnalysis;
    global.startChampsTickerPolling = startChampsTickerPolling;
    global.stopChampsLeaderboardPolling = stopChampsLeaderboardPolling;
    global.champsSpotlightChart = champsSpotlightChart;
    global.triggerConfetti = triggerConfetti;
    global.showRankUpEffect = showRankUpEffect;
    global.triggerActivityFlash = triggerActivityFlash;
    global.applyGlitchEffect = applyGlitchEffect;
    
    // Real-time life animations
    global.initRealTimeFeatures = initRealTimeFeatures;
    global.showMilestoneCelebration = showMilestoneCelebration;
    global.triggerMexicanWave = triggerMexicanWave;
    global.shakeLeaderboard = shakeLeaderboard;
    global.showTypingIndicator = showTypingIndicator;
    global.createProgressRing = createProgressRing;
    global.showFloatingText = showFloatingText;
    global.showAchievementPopup = showAchievementPopup;
    global.updateStreakMeter = updateStreakMeter;
})(typeof window !== 'undefined' ? window : this);
