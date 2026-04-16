// ============================================================
        // CONSTANTS
        // ============================================================
        const UI_CONSTANTS = {
            KEYBOARD_FOCUS_DURATION: 2000,      // ms - how long keyboard focus highlight stays
            SEARCH_DEBOUNCE_DELAY: 150,         // ms - delay before search filter applies
            TOOLTIP_CLOSE_DELAY: 100,           // ms - delay before tooltip click-to-close activates
            SCROLL_DELAY: 100,                  // ms - delay before scrollIntoView after DOM changes
            VIEWPORT_PADDING: 20,               // px - padding from viewport edges for positioning
            COPY_FEEDBACK_DURATION: 2000,       // ms - how long "Copied!" feedback shows on copy button
            A11Y_ANNOUNCEMENT_DELAY: 100        // ms - delay before screen reader announcements
        };

        // ============================================================
        // ACCESSIBILITY HELPERS
        // ============================================================

        // Announce message to screen readers via live region
        function announceToScreenReader(message, priority = 'polite') {
            const liveRegion = document.getElementById('a11yAnnouncements');
            if (!liveRegion) return;

            // Set priority (polite or assertive)
            liveRegion.setAttribute('aria-live', priority);

            // Clear and set message (timing helps screen readers pick up the change)
            liveRegion.textContent = '';
            setTimeout(() => {
                liveRegion.textContent = message;
            }, UI_CONSTANTS.A11Y_ANNOUNCEMENT_DELAY);
        }

        // Update ARIA pressed state for toggle buttons
        function updateAriaPressed(element, isPressed) {
            if (element) {
                element.setAttribute('aria-pressed', isPressed ? 'true' : 'false');
            }
        }

        // Update ARIA expanded state for collapsible elements
        function updateAriaExpanded(element, isExpanded) {
            if (element) {
                element.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
            }
        }

        // Manage focus for modal-like elements (tooltips, help modal)
        let previouslyFocusedElement = null;

        function trapFocus(element) {
            previouslyFocusedElement = document.activeElement;
            const focusableElements = element.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            const firstFocusable = focusableElements[0];
            const lastFocusable = focusableElements[focusableElements.length - 1];

            if (firstFocusable) {
                firstFocusable.focus();
            }

            element.addEventListener('keydown', function handleTab(e) {
                if (e.key === 'Tab') {
                    if (e.shiftKey && document.activeElement === firstFocusable) {
                        e.preventDefault();
                        lastFocusable.focus();
                    } else if (!e.shiftKey && document.activeElement === lastFocusable) {
                        e.preventDefault();
                        firstFocusable.focus();
                    }
                }
            });
        }

        function restoreFocus() {
            if (previouslyFocusedElement && previouslyFocusedElement.focus) {
                previouslyFocusedElement.focus();
                previouslyFocusedElement = null;
            }
        }

        function toggleTheme() {
            const html = document.documentElement;
            const newTheme = html.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
            html.setAttribute('data-theme', newTheme);
            safeSetItem('adpeas-theme', newTheme);
            updateThemeUI(newTheme);
            announceToScreenReader('Theme changed to ' + newTheme + ' mode');
        }

        function updateThemeUI(theme) {
            document.getElementById('themeIcon').innerHTML = theme === 'dark' ? '&#9788;' : '&#9790;';
            document.getElementById('themeLabel').textContent = theme === 'dark' ? 'Light' : 'Dark';
            // Update ARIA state for theme toggle
            const themeToggle = document.querySelector('.theme-toggle');
            if (themeToggle) {
                updateAriaPressed(themeToggle, theme === 'dark');
            }
        }

        function toggleFinding(header) {
            const card = header.closest('.finding-card');
            card.classList.toggle('expanded');

            // Highlight the category in the sidebar navigation
            highlightCategoryForCard(card);
        }

        function highlightCategoryForCard(card) {
            // Remove previous category highlight
            document.querySelectorAll('.category-filter.category-highlight').forEach(f => f.classList.remove('category-highlight'));

            if (!card.classList.contains('expanded')) return;

            // Get the card's category and highlight the matching nav item
            const category = card.dataset.category;
            if (category) {
                const navItem = document.querySelector('.category-filter[data-category="' + category + '"]');
                if (navItem) navItem.classList.add('category-highlight');
            }
        }

        function toggleExtendedAttrs(objectId) {
            const extSection = document.getElementById('ext-' + objectId);
            const toggleBtn = extSection.previousElementSibling;
            const icon = document.getElementById('icon-' + objectId);

            if (extSection.style.display === 'none') {
                extSection.style.display = 'block';
                toggleBtn.classList.add('expanded');
                toggleBtn.querySelector('span:last-child').textContent =
                    toggleBtn.querySelector('span:last-child').textContent.replace('Show', 'Hide');
            } else {
                extSection.style.display = 'none';
                toggleBtn.classList.remove('expanded');
                toggleBtn.querySelector('span:last-child').textContent =
                    toggleBtn.querySelector('span:last-child').textContent.replace('Hide', 'Show');
            }
        }

        // Toggle individual object card (collapsed/expanded)
        function toggleObjectCard(objectId) {
            const card = document.getElementById('obj-' + objectId);
            if (card) {
                card.classList.toggle('expanded');
            }
        }

        // Expand all object cards in a finding-card
        function expandAllObjects(findingCardId) {
            const findingCard = document.getElementById(findingCardId);
            if (findingCard) {
                findingCard.querySelectorAll('.object-detail').forEach(obj => {
                    obj.classList.add('expanded');
                });
                updateExpandCollapseButton(findingCardId, true);
            }
        }

        // Collapse all object cards in a finding-card
        function collapseAllObjects(findingCardId) {
            const findingCard = document.getElementById(findingCardId);
            if (findingCard) {
                findingCard.querySelectorAll('.object-detail').forEach(obj => {
                    obj.classList.remove('expanded');
                });
                updateExpandCollapseButton(findingCardId, false);
            }
        }

        // Toggle all object cards in a finding-card
        function toggleAllObjects(findingCardId) {
            const findingCard = document.getElementById(findingCardId);
            if (findingCard) {
                const objects = findingCard.querySelectorAll('.object-detail');
                const expandedCount = findingCard.querySelectorAll('.object-detail.expanded').length;
                const shouldExpand = expandedCount < objects.length / 2;

                objects.forEach(obj => {
                    if (shouldExpand) {
                        obj.classList.add('expanded');
                    } else {
                        obj.classList.remove('expanded');
                    }
                });
                updateExpandCollapseButton(findingCardId, shouldExpand);
            }
        }

        // Update the expand/collapse button text
        function updateExpandCollapseButton(findingCardId, isExpanded) {
            const btn = document.querySelector(`#${findingCardId} .expand-collapse-btn`);
            if (btn) {
                btn.innerHTML = isExpanded
                    ? '<span>&#9660;</span> Collapse All'
                    : '<span>&#9654;</span> Expand All';
            }
        }

        let currentSeverityFilter = 'all';
        let currentCategoryFilter = 'all';
        let currentSearchQuery = '';
        let hideCompletedEnabled = false;

        function filterBySeverity(severity) {
            currentSeverityFilter = severity;
            // Reset category filter when severity is clicked
            currentCategoryFilter = 'all';

            // Update active state and ARIA pressed - severity gets highlighted, categories reset
            document.querySelectorAll('.severity-filter').forEach(link => {
                const isActive = link.dataset.severity === severity;
                link.classList.toggle('active', isActive);
                updateAriaPressed(link, isActive);
            });
            // Remove active and card-highlight from ALL categories
            document.querySelectorAll('.category-filter').forEach(link => {
                link.classList.remove('active', 'category-highlight');
                updateAriaPressed(link, false);
            });

            applyFilters();

            // Announce filter change to screen readers
            const count = document.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            const severityLabel = severity === 'all' ? 'all severities' : severity;
            announceToScreenReader('Filtered by ' + severityLabel + '. ' + count + ' findings shown.');
        }

        function filterByCategory(category) {
            currentCategoryFilter = category;
            // Reset severity filter when category is clicked
            currentSeverityFilter = 'all';

            // Update active state and ARIA pressed - category gets highlighted, severities reset
            // Also clear card-highlight since user is now actively filtering
            document.querySelectorAll('.category-filter').forEach(link => {
                const isActive = link.dataset.category === category;
                link.classList.toggle('active', isActive);
                link.classList.remove('category-highlight');
                updateAriaPressed(link, isActive);
            });
            // Remove active from ALL severities (no highlight)
            document.querySelectorAll('.severity-filter').forEach(link => {
                link.classList.remove('active');
                updateAriaPressed(link, false);
            });

            applyFilters();

            // Announce filter change to screen readers
            const count = document.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            announceToScreenReader('Filtered by category ' + category + '. ' + count + ' findings shown.');
        }

        function updateItemCount(card, visible, total) {
            const countEl = card.querySelector('.finding-count');
            if (countEl) {
                if (!countEl.dataset.originalText) {
                    countEl.dataset.originalText = countEl.textContent;
                }
                countEl.textContent = visible + ' of ' + total + ' item(s)';
            }
        }

        function resetItemCount(card) {
            const countEl = card.querySelector('.finding-count');
            if (countEl && countEl.dataset.originalText) {
                countEl.textContent = countEl.dataset.originalText;
            }
        }

        function applyFilters() {
            // Filter finding cards with item-level search filtering
            document.querySelectorAll('.finding-card').forEach(card => {
                const cardSeverity = card.dataset.severity;
                const cardCategory = card.dataset.category;
                const cardId = card.dataset.cardId;

                const matchesSeverity = currentSeverityFilter === 'all' || cardSeverity === currentSeverityFilter;
                const matchesCategory = currentCategoryFilter === 'all' || cardCategory === currentCategoryFilter;
                const isCompleted = completedFindings[cardId] === true;
                const matchesCompleted = !hideCompletedEnabled || !isCompleted;

                // Non-search filters: card-level only
                if (!matchesSeverity || !matchesCategory || !matchesCompleted) {
                    card.style.display = 'none';
                    return;
                }

                // No search query: show card, reset all items to visible
                if (currentSearchQuery === '') {
                    card.style.display = '';
                    card.querySelectorAll('.object-detail, .finding-item').forEach(item => {
                        item.style.display = '';
                    });
                    resetItemCount(card);
                    return;
                }

                // Search active: filter individual items within card
                const items = card.querySelectorAll(':scope > .finding-body > .object-detail, :scope > .finding-body > .finding-item');
                let visibleCount = 0;
                const totalCount = items.length;

                // Check if card header/title matches (show all items if card title matches)
                const header = card.querySelector('.finding-header');
                const headerMatches = header && header.textContent.toLowerCase().includes(currentSearchQuery);

                items.forEach(item => {
                    const itemText = item.textContent.toLowerCase();
                    if (itemText.includes(currentSearchQuery) || headerMatches) {
                        item.style.display = '';
                        visibleCount++;
                    } else {
                        item.style.display = 'none';
                    }
                });

                // Show card only if at least 1 item matches (or header matches)
                if (visibleCount > 0 || headerMatches) {
                    card.style.display = '';
                    if (visibleCount < totalCount && !headerMatches) {
                        updateItemCount(card, visibleCount, totalCount);
                    } else {
                        resetItemCount(card);
                    }
                } else {
                    card.style.display = 'none';
                }
            });
        }

        // Finding definitions (embedded from adPEAS-FindingDefinitions.ps1)
        const findingDefinitions = {{FINDING_DEFINITIONS_JSON}};

        // Check descriptions (embedded from adPEAS-ObjectTypes.ps1)
        const checkDescriptions = {{CHECK_DESCRIPTIONS_JSON}};

        // Scoring context data for context-aware risk calculation
        const scoringContext = {{SCORING_CONTEXT_JSON}};

        document.addEventListener('DOMContentLoaded', function() {
            // Favicon: adPEAS logo as 32x32 PNG via Blob URL (works on file:// protocol)
            (function() {
                try {
                    var b64 = 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAKVSURBVFhH7dHJS9RhHMfxz0xjOjIzbjluiSaCYqBWmkqOhmmUW7hkOU3u5kxu4zb5y1HDMVxGC/diXDLNykuFWZpgZBch6A+I7gXRpVNB8gm9+YOiDtXl9zo+z5fnDd8HkEgkEsmfKwQQKj78l9IBzAA4AsAVQCKASPHQ35aLE4WzWPvyLmZqndp7b4mNLYd4aNuVSZfoi83u8QDcAIqvd6vsdktvGfFZNto0gjDhmTe+oTZahn2rC0xeMeVWz/AHrzIPTSwdS7bdDQyWR8Uvo6qHpwcfMrR3gUjVb7/eb7EnPOqaDV4vNLs/bhnz2hx54UNhPJDnajzfF1s83hha3DZzjMqD4vYO84B2uMqmYYnViVcd3px46cf2yQBmlaqpb1JvOdZieWs1muUdnt+CQkB9kTONgj+zz4PhYaDPfgVN1w7w+nwQLzTso6nLj2Z7APMvuzGzzJnZVXLqcrGq08FZ3N7ROLo3pXNORcuYB+v7fVnb488yQcvMIg/qzd6st/uxrs+PhkZvhkQoGZuiYYZBy4STGgaHuTLfqGVdbwBNNl+WCB4sqFcyq1LGjHLwVDE+pxSgw2qFTNzdpWMB5sHniq+DKwreWFHSvqRi96KKbTOutN5RsW1KTcGhZuOwiqXtziwSXFjW4coau5pNoyo2jijZMOpEYWYPqwdkzK3BpzQDhiLiEC5u/VRWBeIqbLA3jeN126z8Q+s0vjffBrsW5exbUrD/qYKd92W0zoEDzxQcXHFizxM5W6fBtlkZ2+flNPXhY5oeQxoNDgNwEjd+1/ZfBQZF4mhkEjJjUmGIT8elxGzUxqXDEn8aNl0ebiafxcTxAkwm5cChO4OBqCRUAogAIAd2Vv7rtUskEolE8j/9AG6P+zF32FIuAAAAAElFTkSuQmCC';
                    var byteStr = atob(b64);
                    var bytes = new Uint8Array(byteStr.length);
                    for (var i = 0; i < byteStr.length; i++) bytes[i] = byteStr.charCodeAt(i);
                    var blob = new Blob([bytes], { type: 'image/png' });
                    var url = URL.createObjectURL(blob);
                    var link = document.createElement('link');
                    link.rel = 'icon';
                    link.type = 'image/png';
                    link.href = url;
                    document.head.appendChild(link);
                } catch(e) { /* favicon setup failed, non-critical */ }
            })();

            // Theme: Check system preference first, then localStorage, then default
            let savedTheme = safeGetItem('adpeas-theme');
            if (!savedTheme) {
                // Auto-detect system preference
                if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
                    savedTheme = 'light';
                } else {
                    savedTheme = '{{DEFAULT_THEME}}';
                }
            }
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeUI(savedTheme);

            // Listen for system theme changes
            if (window.matchMedia) {
                window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e) {
                    // Only auto-switch if user hasn't manually set a preference
                    if (!safeGetItem('adpeas-theme')) {
                        const newTheme = e.matches ? 'light' : 'dark';
                        document.documentElement.setAttribute('data-theme', newTheme);
                        updateThemeUI(newTheme);
                    }
                });
            }

            // Debounced search input to prevent performance issues on large reports
            let searchDebounceTimer = null;
            document.getElementById('searchInput').addEventListener('input', function(e) {
                clearTimeout(searchDebounceTimer);
                searchDebounceTimer = setTimeout(() => {
                    currentSearchQuery = e.target.value.toLowerCase();
                    applyFilters();
                }, UI_CONSTANTS.SEARCH_DEBOUNCE_DELAY);
            });

            // Initialize finding tooltips
            initFindingTooltips();

            // Initialize check help tooltips
            initCheckTooltips();

            // Initialize score breakdown tooltips
            initScoreTooltips();

            // Initialize draggable tooltips/popups
            initDraggableTooltips();

            // Initialize checkbox system
            initCheckboxSystem();

            // Initialize keyboard shortcuts
            initKeyboardShortcuts();

            // Create shortcut help modal
            createShortcutHelpModal();

            // Generate Top Priority Actions
            generateTopPriorityActions();

            // Populate score badges on finding cards, then sort by score
            populateCardScores();
            sortCardsByScore();

            // Initialize attribute drag & drop reordering
            initAttributeDragAndDrop();
        });

        let activeTooltip = null;

        function initFindingTooltips() {
            // Create tooltip container
            const tooltipDiv = document.createElement('div');
            tooltipDiv.id = 'findingTooltip';
            tooltipDiv.className = 'finding-tooltip';
            tooltipDiv.setAttribute('role', 'dialog');
            tooltipDiv.setAttribute('aria-modal', 'false');
            tooltipDiv.setAttribute('aria-label', 'Finding details');
            document.body.appendChild(tooltipDiv);

            // Add event listeners to all finding triggers
            document.querySelectorAll('[data-finding-id]').forEach(trigger => {
                trigger.classList.add('finding-tooltip-trigger');
                trigger.setAttribute('role', 'button');
                trigger.setAttribute('tabindex', '0');
                trigger.setAttribute('aria-haspopup', 'dialog');
                trigger.setAttribute('aria-expanded', 'false');

                // Click handler
                trigger.addEventListener('click', function(e) {
                    e.stopPropagation();
                    showFindingTooltip(this, this.dataset.findingId);
                });

                // Keyboard handler for accessibility
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        e.stopPropagation();
                        showFindingTooltip(this, this.dataset.findingId);
                    }
                });
            });

            // Close tooltip when clicking outside
            document.addEventListener('click', function(e) {
                if (activeTooltip && !e.target.closest('.finding-tooltip') && !e.target.closest('[data-finding-id]')) {
                    hideTooltip();
                }
            });

            // Close on escape key
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && activeTooltip) {
                    hideTooltip();
                }
            });
        }

        let activeFindingTrigger = null;

        function showFindingTooltip(trigger, findingId) {
            const tooltip = document.getElementById('findingTooltip');
            const finding = findingDefinitions[findingId];

            if (!finding) {
                console.warn('Finding definition not found:', findingId);
                return;
            }

            // Close any previously open tooltip first
            if (activeFindingTrigger && activeFindingTrigger !== trigger) {
                activeFindingTrigger.setAttribute('aria-expanded', 'false');
            }

            // Get actual severity using hybrid approach (Option C):
            // 1. First: Check the trigger element itself for severity class (e.g., <span class="finding" data-finding-id="...">)
            // 2. Then: Check the attr-value div for severity class
            // 3. Fallback: Use parent card's severity
            // 4. Final fallback: Use static definition severity
            let actualSeverity = null;

            // Check severity class directly on the trigger element (most precise - for multi-value attributes)
            // HTML: <span class="finding" data-finding-id="PRIVILEGED_GROUP_MEMBERSHIP">Domain Admins</span>
            if (trigger.classList.contains('finding')) {
                actualSeverity = 'finding';
            } else if (trigger.classList.contains('hint')) {
                actualSeverity = 'hint';
            } else if (trigger.classList.contains('note')) {
                actualSeverity = 'note';
            } else if (trigger.classList.contains('secure')) {
                actualSeverity = 'secure';
            }

            // Check for attribute-level severity on attr-value div (for single-value attributes)
            if (!actualSeverity) {
                const attrValue = trigger.closest('.attr-value');
                if (attrValue) {
                    if (attrValue.classList.contains('finding')) {
                        actualSeverity = 'finding';
                    } else if (attrValue.classList.contains('hint')) {
                        actualSeverity = 'hint';
                    } else if (attrValue.classList.contains('note')) {
                        actualSeverity = 'note';
                    } else if (attrValue.classList.contains('secure')) {
                        actualSeverity = 'secure';
                    }
                }
            }

            // Fallback to card severity if no attribute severity found
            if (!actualSeverity) {
                const parentCard = trigger.closest('.finding-card');
                actualSeverity = parentCard?.dataset?.severity || null;
            }

            // Build tooltip HTML with actual severity override
            tooltip.innerHTML = buildTooltipHtml(finding, findingId, actualSeverity);

            // Make visible first (but off-screen) so we can measure
            tooltip.style.visibility = 'hidden';
            tooltip.classList.add('visible');

            // Position tooltip (now we can measure correctly)
            positionTooltip(tooltip, trigger);

            // Make fully visible
            tooltip.style.visibility = 'visible';
            activeTooltip = tooltip;
            activeFindingTrigger = trigger;

            // Update ARIA state
            trigger.setAttribute('aria-expanded', 'true');

            // Add section toggle listeners
            tooltip.querySelectorAll('.tooltip-section-title').forEach(title => {
                title.addEventListener('click', function() {
                    this.classList.toggle('collapsed');
                    const content = this.nextElementSibling;
                    content.classList.toggle('collapsed');
                });
            });
        }

        function hideTooltip() {
            const tooltip = document.getElementById('findingTooltip');
            tooltip.classList.remove('visible');
            activeTooltip = null;

            // Reset ARIA expanded state on trigger
            if (activeFindingTrigger) {
                activeFindingTrigger.setAttribute('aria-expanded', 'false');
                activeFindingTrigger = null;
            }
        }

        function positionTooltip(tooltip, trigger) {
            const rect = trigger.getBoundingClientRect();
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;

            // Reset position for measurement
            tooltip.style.left = '0';
            tooltip.style.top = '0';

            // Get tooltip dimensions
            const tooltipRect = tooltip.getBoundingClientRect();

            // Calculate position - prefer below and to the right of trigger
            let left = rect.left;
            let top = rect.bottom + 8;

            // Adjust if too far right
            if (left + tooltipRect.width > viewportWidth - UI_CONSTANTS.VIEWPORT_PADDING) {
                left = viewportWidth - tooltipRect.width - 20;
            }

            // Adjust if too far left
            if (left < UI_CONSTANTS.VIEWPORT_PADDING) {
                left = UI_CONSTANTS.VIEWPORT_PADDING;
            }

            // Adjust if too far down - show above instead
            if (top + tooltipRect.height > viewportHeight - UI_CONSTANTS.VIEWPORT_PADDING) {
                top = rect.top - tooltipRect.height - 8;
            }

            // Ensure top is not negative
            if (top < UI_CONSTANTS.VIEWPORT_PADDING) {
                top = UI_CONSTANTS.VIEWPORT_PADDING;
            }

            tooltip.style.left = left + 'px';
            tooltip.style.top = top + 'px';
        }

        function buildTooltipHtml(finding, findingId, actualSeverity) {
            // Map card severity to display label and CSS class
            // actualSeverity comes from parent card's data-severity attribute
            // If provided, it overrides the static finding.risk from definition
            // Maps SeverityClasses (from adPEAS-Types.ps1) to display labels and CSS classes
            // These values are used for tooltip badges and match the central definitions
            const severityMap = {
                'finding': { label: 'FINDING', class: 'finding' },
                'hint': { label: 'HINT', class: 'hint' },
                'note': { label: 'NOTE', class: 'note' },
                'secure': { label: 'SECURE', class: 'secure' }  // Blue in CSS
            };

            let riskLabel, riskClass;
            if (actualSeverity && severityMap[actualSeverity]) {
                // Use actual severity from parent card (dynamic)
                riskLabel = severityMap[actualSeverity].label;
                riskClass = severityMap[actualSeverity].class;
            } else {
                // Fallback to static definition
                riskLabel = finding.risk;
                riskClass = finding.risk.toLowerCase();
            }

            let html = `
                <div class="tooltip-header">
                    <div>
                        <div class="tooltip-title">${escapeHtml(finding.title)}</div>
                        <span class="tooltip-risk ${riskClass}">${escapeHtml(riskLabel)}</span>
                    </div>
                    <button class="tooltip-close" onclick="hideTooltip()">&times;</button>
                </div>
                <div class="tooltip-body">
            `;

            // Description
            html += `
                <div class="tooltip-section">
                    <div class="tooltip-section-title">
                        <span class="toggle-icon">&#9660;</span> Description
                    </div>
                    <div class="tooltip-section-content">
                        ${escapeHtml(finding.description)}
                    </div>
                </div>
            `;

            // Impact (collapsed by default)
            if (finding.impact && finding.impact.length > 0) {
                html += `
                    <div class="tooltip-section">
                        <div class="tooltip-section-title collapsed">
                            <span class="toggle-icon">&#9660;</span> Impact
                        </div>
                        <div class="tooltip-section-content collapsed">
                            <ul>
                                ${finding.impact.map(i => `<li>${escapeHtml(i)}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `;
            }

            // Attack/Protection section (collapsible by default)
            // For "Secure" findings, this section describes what attacks are prevented
            if (finding.attack && finding.attack.length > 0) {
                const isSecure = actualSeverity === 'secure' || (finding.risk && finding.risk.toLowerCase() === 'secure');
                const attackSectionTitle = isSecure ? 'Blocked Attack Vectors' : 'Attack Steps';
                html += `
                    <div class="tooltip-section">
                        <div class="tooltip-section-title collapsed">
                            <span class="toggle-icon">&#9660;</span> ${attackSectionTitle}
                        </div>
                        <div class="tooltip-section-content collapsed">
                            <ul>
                                ${finding.attack.map(a => `<li>${escapeHtml(a)}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `;
            }

            // Remediation / Best Practices section
            // For "Secure" findings, this section describes how to maintain the secure configuration
            if (finding.remediation && finding.remediation.length > 0) {
                const isSecureConfig = actualSeverity === 'secure' || (finding.risk && finding.risk.toLowerCase() === 'secure');
                const remediationTitle = isSecureConfig ? 'Best Practices' : 'Remediation';
                html += `
                    <div class="tooltip-section">
                        <div class="tooltip-section-title collapsed">
                            <span class="toggle-icon">&#9660;</span> ${remediationTitle}
                        </div>
                        <div class="tooltip-section-content collapsed">
                            <ul>
                                ${finding.remediation.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `;
            }

            // Remediation Commands (PowerShell with Copy button)
            if (finding.remediationCommands && finding.remediationCommands.length > 0) {
                html += `
                    <div class="tooltip-section">
                        <div class="tooltip-section-title collapsed">
                            <span class="toggle-icon">&#9660;</span> Quick Fix Commands
                        </div>
                        <div class="tooltip-section-content collapsed">
                            <div class="remediation-disclaimer">&#9888; Example commands for reference only. Always test in a non-production environment first and adapt to your specific situation.</div>
                            ${finding.remediationCommands.map(cmd => `
                                <div class="remediation-command">
                                    <div class="remediation-command-desc">${escapeHtml(cmd.description)}</div>
                                    <div class="remediation-code">
                                        <button class="copy-btn" onclick="copyToClipboard(this, \`${cmd.command.replace(/`/g, '\\`').replace(/\\/g, '\\\\')}\`)">Copy</button>
                                        <pre>${escapeHtml(cmd.command)}</pre>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            // References (collapsible by default)
            if (finding.references && finding.references.length > 0) {
                html += `
                    <div class="tooltip-section">
                        <div class="tooltip-section-title collapsed">
                            <span class="toggle-icon">&#9660;</span> References
                        </div>
                        <div class="tooltip-section-content collapsed tooltip-references">
                            ${finding.references.map(r => `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener">${escapeHtml(r.title)}</a>`).join('')}
                        </div>
                    </div>
                `;
            }

            // Tools (collapsible by default) - supports both string and object format
            if (finding.tools && finding.tools.length > 0) {
                html += `
                    <div class="tooltip-section">
                        <div class="tooltip-section-title collapsed">
                            <span class="toggle-icon">&#9660;</span> Tools
                        </div>
                        <div class="tooltip-section-content collapsed tooltip-tools">
                            ${finding.tools.map(t => {
                                // Support both string (legacy) and object format {name, url}
                                if (typeof t === 'object' && t.name) {
                                    if (t.url) {
                                        return `<a href="${escapeHtml(t.url)}" target="_blank" rel="noopener" class="tooltip-tool tooltip-tool-link">${escapeHtml(t.name)}</a>`;
                                    } else {
                                        return `<span class="tooltip-tool">${escapeHtml(t.name)}</span>`;
                                    }
                                } else {
                                    return `<span class="tooltip-tool">${escapeHtml(t)}</span>`;
                                }
                            }).join('')}
                        </div>
                    </div>
                `;
            }

            // MITRE ATT&CK
            if (finding.mitre) {
                const mitreUrl = `https://attack.mitre.org/techniques/${finding.mitre.replace('.', '/')}/`;
                html += `
                    <div class="tooltip-section">
                        <div class="tooltip-section-content">
                            <span class="tooltip-mitre">
                                <a href="${mitreUrl}" target="_blank" rel="noopener">MITRE ATT&CK: ${escapeHtml(finding.mitre)}</a>
                            </span>
                        </div>
                    </div>
                `;
            }

            html += '</div>';
            return html;
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Escape JSON for use in HTML data attributes
        // Uses single quotes in HTML attribute, escapes single quotes in JSON
        function escapeJsonForAttr(obj) {
            if (!obj) return '';
            const json = JSON.stringify(obj);
            // Replace single quotes with escaped version for safe embedding
            return json.replace(/'/g, '&#39;');
        }

        // Decode HTML entities in a string (for parsing data attributes)
        function decodeHtmlEntities(str) {
            if (!str) return '';
            const txt = document.createElement('textarea');
            txt.innerHTML = str;
            return txt.value;
        }

        // Check description tooltip functionality
        let activeCheckTooltip = null;

        let activeCheckTrigger = null;

        function initCheckTooltips() {
            // Create check tooltip container
            const tooltipDiv = document.createElement('div');
            tooltipDiv.id = 'checkTooltip';
            tooltipDiv.className = 'check-tooltip';
            tooltipDiv.setAttribute('role', 'dialog');
            tooltipDiv.setAttribute('aria-modal', 'false');
            tooltipDiv.setAttribute('aria-label', 'Check description');
            document.body.appendChild(tooltipDiv);

            // Add event listeners to all check help buttons
            document.querySelectorAll('.check-help-btn').forEach(btn => {
                btn.setAttribute('aria-haspopup', 'dialog');
                btn.setAttribute('aria-expanded', 'false');
                btn.setAttribute('aria-label', 'Show information about this check');

                btn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    // Prefer ObjectType over title for tooltip lookup (more reliable)
                    const objectType = btn.dataset.objectType;
                    const checkTitle = btn.dataset.checkTitle;
                    showCheckTooltip(this, objectType, checkTitle);
                });

                // Keyboard support
                btn.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        e.stopPropagation();
                        const objectType = btn.dataset.objectType;
                        const checkTitle = btn.dataset.checkTitle;
                        showCheckTooltip(this, objectType, checkTitle);
                    }
                });
            });

            // Close tooltip when clicking outside
            document.addEventListener('click', function(e) {
                if (activeCheckTooltip && !e.target.closest('.check-tooltip') && !e.target.closest('.check-help-btn')) {
                    hideCheckTooltip();
                }
            });

            // Close on escape key (consistent with finding tooltip)
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && activeCheckTooltip) {
                    hideCheckTooltip();
                }
            });
        }

        function showCheckTooltip(trigger, objectType, checkTitle) {
            const tooltip = document.getElementById('checkTooltip');

            // Look up check description by ObjectType
            if (!objectType || !checkDescriptions[objectType]) {
                console.warn('Check description not found for ObjectType:', objectType);
                return;
            }

            const check = checkDescriptions[objectType];
            const lookupKey = objectType;

            // Get card severity from parent finding-card element
            const findingCard = trigger.closest('.finding-card');
            const cardSeverity = findingCard ? findingCard.dataset.severity : null;

            // Build tooltip HTML (pass severity for secure message display)
            tooltip.innerHTML = buildCheckTooltipHtml(check, checkTitle, cardSeverity);

            // Make visible first (but off-screen) so we can measure
            tooltip.style.visibility = 'hidden';
            tooltip.classList.add('visible');

            // Position tooltip (now we can measure correctly)
            positionCheckTooltip(tooltip, trigger);

            // Make fully visible
            tooltip.style.visibility = 'visible';
            activeCheckTooltip = tooltip;

            // Close any previous trigger and update ARIA
            if (activeCheckTrigger && activeCheckTrigger !== trigger) {
                activeCheckTrigger.setAttribute('aria-expanded', 'false');
            }
            activeCheckTrigger = trigger;
            trigger.setAttribute('aria-expanded', 'true');
        }

        function hideCheckTooltip() {
            const tooltip = document.getElementById('checkTooltip');
            tooltip.classList.remove('visible');

            // Reset ARIA state
            if (activeCheckTrigger) {
                activeCheckTrigger.setAttribute('aria-expanded', 'false');
                activeCheckTrigger = null;
            }
            activeCheckTooltip = null;
        }

        // Reuse the same positioning function for check tooltips
        function positionCheckTooltip(tooltip, trigger) {
            positionTooltip(tooltip, trigger);
        }

        // ============================================================
        // DRAGGABLE TOOLTIPS/POPUPS
        // ============================================================

        let dragState = {
            isDragging: false,
            tooltip: null,
            offsetX: 0,
            offsetY: 0
        };

        function initDraggableTooltips() {
            // Handle mousedown on tooltip headers
            document.addEventListener('mousedown', function(e) {
                const header = e.target.closest('.tooltip-header, .check-tooltip-header');
                if (!header) return;

                // Don't drag if clicking on close button
                if (e.target.closest('.tooltip-close, .check-tooltip-close')) return;

                const tooltip = header.closest('.finding-tooltip, .check-tooltip');
                if (!tooltip || !tooltip.classList.contains('visible')) return;

                e.preventDefault();
                dragState.isDragging = true;
                dragState.tooltip = tooltip;

                // Get current position (could be from CSS or previous drag)
                const rect = tooltip.getBoundingClientRect();
                dragState.offsetX = e.clientX - rect.left;
                dragState.offsetY = e.clientY - rect.top;

                tooltip.classList.add('dragging');
            });

            document.addEventListener('mousemove', function(e) {
                if (!dragState.isDragging || !dragState.tooltip) return;

                e.preventDefault();

                // Calculate new position
                let newX = e.clientX - dragState.offsetX;
                let newY = e.clientY - dragState.offsetY;

                // Keep within viewport bounds
                const tooltipRect = dragState.tooltip.getBoundingClientRect();
                const maxX = window.innerWidth - tooltipRect.width;
                const maxY = window.innerHeight - tooltipRect.height;

                newX = Math.max(0, Math.min(newX, maxX));
                newY = Math.max(0, Math.min(newY, maxY));

                dragState.tooltip.style.left = newX + 'px';
                dragState.tooltip.style.top = newY + 'px';
            });

            document.addEventListener('mouseup', function() {
                if (dragState.isDragging && dragState.tooltip) {
                    dragState.tooltip.classList.remove('dragging');
                }
                dragState.isDragging = false;
                dragState.tooltip = null;
            });

            // Prevent text selection while dragging
            document.addEventListener('selectstart', function(e) {
                if (dragState.isDragging) {
                    e.preventDefault();
                }
            });
        }

        function buildCheckTooltipHtml(check, checkTitle, cardSeverity) {
            let html = `
                <div class="check-tooltip-header">
                    <span class="check-tooltip-title">About this Check</span>
                    <button class="check-tooltip-close" onclick="hideCheckTooltip()">&times;</button>
                </div>
                <div class="check-tooltip-body">
            `;

            // Summary
            html += `<div class="check-tooltip-summary">${escapeHtml(check.summary)}</div>`;

            // Secure Message (shown when card severity is 'secure')
            if (cardSeverity === 'secure' && check.secureMessage) {
                html += `
                    <div class="check-tooltip-section check-tooltip-secure">
                        <div class="check-tooltip-section-title">Secure Configuration</div>
                        <div class="check-tooltip-section-content">
                            ${escapeHtml(check.secureMessage)}
                        </div>
                    </div>
                `;
            }

            // Why It Matters
            if (check.whyItMatters) {
                html += `
                    <div class="check-tooltip-section">
                        <div class="check-tooltip-section-title">Why It Matters</div>
                        <div class="check-tooltip-section-content">
                            ${escapeHtml(check.whyItMatters)}
                        </div>
                    </div>
                `;
            }

            // What We Check
            if (check.whatWeCheck && check.whatWeCheck.length > 0) {
                html += `
                    <div class="check-tooltip-section">
                        <div class="check-tooltip-section-title">What We Check</div>
                        <div class="check-tooltip-section-content">
                            <ul>
                                ${check.whatWeCheck.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `;
            }

            // Filtering Note (documents privilege filtering behavior)
            if (check.filteringNote) {
                html += `
                    <div class="check-tooltip-section check-tooltip-filtering">
                        <div class="check-tooltip-section-title">Output Filtering</div>
                        <div class="check-tooltip-section-content">
                            ${escapeHtml(check.filteringNote)}
                        </div>
                    </div>
                `;
            }

            html += '</div>';
            return html;
        }

        // ============================================================
        // CHECKBOX SYSTEM - Mark findings as completed
        // ============================================================

        let completedFindings = {};
        let reportHash = '';
        let localStorageAvailable = true;
        let localStorageWriteAttempts = 0;
        const MAX_WRITE_FAILURES = 3;

        // Safe localStorage wrapper with differentiated error handling
        // - Security errors (privacy mode): Permanently disable localStorage
        // - Quota errors: Retry up to MAX_WRITE_FAILURES times, then disable writes only
        // - Transient errors: Log and continue
        function safeGetItem(key) {
            if (!localStorageAvailable) return null;
            try {
                return localStorage.getItem(key);
            } catch (e) {
                if (isSecurityError(e)) {
                    console.warn('localStorage blocked (privacy mode):', e.message);
                    localStorageAvailable = false;
                } else {
                    console.warn('localStorage read failed:', e.message);
                }
                return null;
            }
        }

        function safeSetItem(key, value) {
            if (!localStorageAvailable) return false;
            try {
                localStorage.setItem(key, value);
                localStorageWriteAttempts = 0; // Reset on success
                return true;
            } catch (e) {
                if (isSecurityError(e)) {
                    // Privacy mode or security restriction - permanently disable
                    console.warn('localStorage blocked (privacy mode):', e.message);
                    localStorageAvailable = false;
                    return false;
                } else if (isQuotaError(e)) {
                    // Quota exceeded - try to clean up old data
                    localStorageWriteAttempts++;
                    console.warn('localStorage quota exceeded, attempt', localStorageWriteAttempts);
                    if (localStorageWriteAttempts >= MAX_WRITE_FAILURES) {
                        console.warn('localStorage quota exceeded repeatedly, disabling writes');
                        localStorageAvailable = false;
                    }
                    return false;
                } else {
                    // Other transient error - log but don't disable
                    console.warn('localStorage write failed:', e.message);
                    return false;
                }
            }
        }

        function isSecurityError(e) {
            // SecurityError is thrown in privacy mode or when localStorage is blocked
            return e.name === 'SecurityError' ||
                   (e.name === 'Error' && e.message.includes('access'));
        }

        function isQuotaError(e) {
            // QuotaExceededError when storage is full
            return e.name === 'QuotaExceededError' ||
                   e.name === 'NS_ERROR_DOM_QUOTA_REACHED' ||
                   (e.code && e.code === 22);
        }

        function initCheckboxSystem() {
            // Generate a hash from the report content for localStorage key
            reportHash = generateReportHash();

            // Load saved state
            const savedState = safeGetItem('adpeas-completed-' + reportHash);
            if (savedState) {
                try {
                    completedFindings = JSON.parse(savedState);
                } catch (e) {
                    completedFindings = {};
                }
            }

            // Initialize checkboxes on all finding cards (checkbox is already in HTML)
            document.querySelectorAll('.finding-card').forEach((card, index) => {
                // Use existing data-card-id (set by PowerShell) or generate fallback
                const cardId = card.dataset.cardId || ('finding-' + index);
                card.dataset.cardId = cardId;  // Ensure it's set if missing

                // Find existing checkbox and initialize it
                const checkbox = card.querySelector('.finding-checkbox');
                if (checkbox) {
                    checkbox.checked = !!completedFindings[cardId];
                    // Re-bind onclick to ensure proper cardId reference
                    checkbox.onclick = function(e) {
                        e.stopPropagation();
                        toggleCompleted(cardId, this.checked);
                    };
                }

                // Apply initial state
                if (completedFindings[cardId]) {
                    card.classList.add('completed');
                }
            });

            // Update progress bar
            updateProgress();

            // Load hide completed state
            const hideCompleted = safeGetItem('adpeas-hide-completed') === 'true';
            if (hideCompleted) {
                document.getElementById('hideCompletedToggle').checked = true;
                document.body.classList.add('hide-completed');
            }
        }

        function generateReportHash() {
            // Generate hash based on domain, timestamp, and finding titles for uniqueness
            // This ensures different reports don't share completed-state even if same domain/count
            const infoItems = document.querySelectorAll('.info-item');
            let domain = 'unknown';
            let generated = '';

            infoItems.forEach(item => {
                const label = item.querySelector('.label')?.textContent?.trim();
                const value = item.querySelector('.value')?.textContent?.trim();
                if (label === 'Domain') domain = value || 'unknown';
                if (label === 'Generated') generated = value || '';
            });

            // Include first 3 finding titles for additional uniqueness
            const titles = Array.from(document.querySelectorAll('.finding-title'))
                .slice(0, 3)
                .map(t => t.textContent || '')
                .join('');

            const hashInput = domain + generated + titles;
            // Simple hash function
            let hash = 0;
            for (let i = 0; i < hashInput.length; i++) {
                const char = hashInput.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Convert to 32bit integer
            }
            return domain.replace(/[^a-z0-9]/gi, '') + '-' + Math.abs(hash).toString(36);
        }

        function toggleCompleted(cardId, isCompleted) {
            if (isCompleted) {
                completedFindings[cardId] = true;
            } else {
                delete completedFindings[cardId];
            }

            // Update Card View UI
            const card = document.querySelector(`.finding-card[data-card-id="${cardId}"]`);
            if (card) {
                card.classList.toggle('completed', isCompleted);
            }

            // Save state
            safeSetItem('adpeas-completed-' + reportHash, JSON.stringify(completedFindings));

            // Update progress bar
            updateProgress();

            // Re-apply filters (if hide completed is enabled)
            if (hideCompletedEnabled) {
                applyFilters();
            }
        }

        function updateProgress() {
            // Update sidebar counts to show remaining (non-completed) findings
            updateSidebarCounts();
        }

        function updateSidebarCounts() {
            // Count non-completed cards per severity and category
            const severityCounts = { all: 0, finding: 0, hint: 0, note: 0, secure: 0 };
            const categoryCounts = {};

            document.querySelectorAll('.finding-card').forEach(card => {
                const cardId = card.dataset.cardId;
                const isCompleted = completedFindings[cardId];

                if (!isCompleted) {
                    severityCounts.all++;
                    const severity = card.dataset.severity || 'note';
                    if (severityCounts[severity] !== undefined) {
                        severityCounts[severity]++;
                    }

                    // Count by category
                    const category = card.dataset.category || '';
                    if (category) {
                        categoryCounts[category] = (categoryCounts[category] || 0) + 1;
                    }
                }
            });

            // Update sidebar severity filter counts
            document.querySelectorAll('.severity-filter').forEach(filter => {
                const severity = filter.dataset.severity;
                const countSpan = filter.querySelector('.count');
                if (countSpan && severityCounts[severity] !== undefined) {
                    countSpan.textContent = severityCounts[severity];
                }
            });

            // Update sidebar category filter counts
            document.querySelectorAll('.nav-item[data-category]').forEach(navItem => {
                const category = navItem.dataset.category;
                const countSpan = navItem.querySelector('.count');
                if (countSpan) {
                    if (category === 'all') {
                        countSpan.textContent = severityCounts.all;
                    } else if (categoryCounts[category] !== undefined) {
                        countSpan.textContent = categoryCounts[category];
                    } else {
                        countSpan.textContent = '0';
                    }
                }
            });

            // Update summary cards at the top
            const summaryMapping = {
                'finding': '.summary-card.finding .value',
                'hint': '.summary-card.hint .value',
                'note': '.summary-card.note .value',
                'secure': '.summary-card.secure .value'
            };

            Object.keys(summaryMapping).forEach(severity => {
                const el = document.querySelector(summaryMapping[severity]);
                if (el) {
                    el.textContent = severityCounts[severity];
                }
            });
        }

        function toggleHideCompleted() {
            const isChecked = document.getElementById('hideCompletedToggle').checked;
            hideCompletedEnabled = isChecked;
            document.body.classList.toggle('hide-completed', isChecked);
            safeSetItem('adpeas-hide-completed', isChecked);
            // Re-apply filters
            applyFilters();

            // Announce to screen readers
            const visibleCount = document.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            const message = isChecked
                ? 'Completed findings hidden. ' + visibleCount + ' findings visible.'
                : 'Showing all findings including completed. ' + visibleCount + ' findings visible.';
            announceToScreenReader(message);
        }

        // ============================================================
        // KEYBOARD SHORTCUTS
        // ============================================================

        let currentFocusIndex = -1;
        let visibleCards = [];

        function initKeyboardShortcuts() {
            document.addEventListener('keydown', function(e) {
                // Don't trigger shortcuts when typing in search
                if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                    if (e.key === 'Escape') {
                        // Clear search filter if the search input has a value
                        if (e.target.id === 'searchInput' && e.target.value) {
                            e.target.value = '';
                            currentSearchQuery = '';
                            applyFilters();
                        }
                        e.target.blur();
                        clearKeyboardFocus();
                    }
                    return;
                }

                switch(e.key) {
                    // Navigation: Arrow keys (intuitive)
                    case 'ArrowDown':
                        e.preventDefault();
                        navigateFinding(1);
                        break;
                    case 'ArrowUp':
                        e.preventDefault();
                        navigateFinding(-1);
                        break;

                    // Enter: Expand/Collapse
                    case 'Enter':
                        e.preventDefault();
                        if (currentFocusIndex >= 0) {
                            toggleCurrentFinding();
                        }
                        break;

                    // Toggle completed: Space (standard checkbox behavior)
                    case ' ':
                        e.preventDefault();
                        if (currentFocusIndex >= 0 && visibleCards[currentFocusIndex]) {
                            const card = visibleCards[currentFocusIndex];
                            const checkbox = card.querySelector('.finding-checkbox');
                            if (checkbox) {
                                checkbox.checked = !checkbox.checked;
                                toggleCompleted(card.dataset.cardId, checkbox.checked);
                            }
                        }
                        break;

                    // Search: / (vim-like, common in web apps)
                    case '/':
                        e.preventDefault();
                        document.getElementById('searchInput').focus();
                        break;

                    // Hide completed toggle: h
                    case 'h':
                        e.preventDefault();
                        const toggle = document.getElementById('hideCompletedToggle');
                        toggle.checked = !toggle.checked;
                        toggleHideCompleted();
                        break;

                    // Help: ? or F1
                    case '?':
                        e.preventDefault();
                        toggleShortcutHelp();
                        break;
                    case 'F1':
                        e.preventDefault();
                        toggleShortcutHelp();
                        break;

                    // Close/Cancel: Escape (standard)
                    case 'Escape':
                        hideTooltip();
                        hideCheckTooltip();
                        hideShortcutHelp();
                        clearKeyboardFocus();
                        break;
                }
            });
        }

        function getVisibleCards() {
            return Array.from(document.querySelectorAll('.finding-card')).filter(card => {
                return card.style.display !== 'none' && !card.closest('.section[style*="display: none"]');
            });
        }

        function navigateFinding(direction) {
            visibleCards = getVisibleCards();
            if (visibleCards.length === 0) return;

            // Remove visual focus from previous card (don't reset index)
            document.querySelectorAll('.keyboard-focused').forEach(el => {
                el.classList.remove('keyboard-focused');
            });

            // Calculate new index
            currentFocusIndex += direction;
            if (currentFocusIndex < 0) currentFocusIndex = visibleCards.length - 1;
            if (currentFocusIndex >= visibleCards.length) currentFocusIndex = 0;

            // Apply focus
            const card = visibleCards[currentFocusIndex];
            card.classList.add('keyboard-focused');
            card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        function clearKeyboardFocus() {
            document.querySelectorAll('.keyboard-focused').forEach(el => {
                el.classList.remove('keyboard-focused');
            });
            currentFocusIndex = -1;
        }

        function toggleCurrentFinding() {
            if (currentFocusIndex >= 0 && visibleCards[currentFocusIndex]) {
                visibleCards[currentFocusIndex].classList.toggle('expanded');
            }
        }

        let allExpanded = false;
        function toggleAllFindings() {
            allExpanded = !allExpanded;
            document.querySelectorAll('.finding-card').forEach(card => {
                card.classList.toggle('expanded', allExpanded);
            });
        }

        function createShortcutHelpModal() {
            const backdrop = document.createElement('div');
            backdrop.className = 'shortcut-help-backdrop';
            backdrop.id = 'shortcutBackdrop';
            backdrop.onclick = hideShortcutHelp;
            backdrop.setAttribute('aria-hidden', 'true');
            document.body.appendChild(backdrop);

            const modal = document.createElement('div');
            modal.className = 'shortcut-help';
            modal.id = 'shortcutHelp';
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');
            modal.setAttribute('aria-labelledby', 'helpModalTitle');
            modal.innerHTML = `
                <div class="help-header">
                    <h2 id="helpModalTitle">Report Guide</h2>
                    <button class="help-close-btn" onclick="hideShortcutHelp()" aria-label="Close help dialog">&times;</button>
                </div>
                <div class="help-content">
                    <div class="help-section">
                        <h3>Report Structure</h3>
                        <p>The report is organized by security check categories (Domain, Accounts, Delegation, Rights, etc.). Each category contains multiple checks, and each check can have multiple findings.</p>
                        <div class="help-grid">
                            <div class="help-card">
                                <div class="help-card-title">Summary Cards</div>
                                <div class="help-card-desc">Quick overview at the top showing total counts by severity level. Click a card to filter.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title">Top Priority Actions</div>
                                <div class="help-card-desc">AI-scored findings ranked by risk. Start here for the most critical issues.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title">Categories</div>
                                <div class="help-card-desc">Expandable sections grouping related security checks together.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title">Finding Cards</div>
                                <div class="help-card-desc">Individual findings with details. Click to expand and see all attributes.</div>
                            </div>
                        </div>
                    </div>

                    <div class="help-section">
                        <h3>Severity Levels</h3>
                        <div class="help-grid">
                            <div class="help-card">
                                <div class="help-card-title"><span class="severity-sample finding"></span> Finding (Red)</div>
                                <div class="help-card-desc">Security vulnerability or misconfiguration requiring immediate attention.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title"><span class="severity-sample hint"></span> Hint (Yellow)</div>
                                <div class="help-card-desc">Potentially interesting finding that may warrant investigation.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title"><span class="severity-sample note"></span> Note (Blue)</div>
                                <div class="help-card-desc">Informational finding providing context or general information.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title"><span class="severity-sample secure"></span> Secure (Green)</div>
                                <div class="help-card-desc">Security configuration is properly set - no action needed.</div>
                            </div>
                        </div>
                    </div>

                    <div class="help-section">
                        <h3>Interactive Features</h3>
                        <div class="help-grid">
                            <div class="help-card">
                                <div class="help-card-title">? Help Buttons</div>
                                <div class="help-card-desc">Click the blue ? buttons next to check titles or findings for detailed explanations and remediation steps.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title">Checkboxes</div>
                                <div class="help-card-desc">Mark findings as completed. Progress is saved in your browser and persists across sessions.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title">Score Badges</div>
                                <div class="help-card-desc">Each finding shows a calculated risk score badge. Findings are automatically sorted by score, highest first.</div>
                            </div>
                            <div class="help-card">
                                <div class="help-card-title">Filters</div>
                                <div class="help-card-desc">Use severity and category dropdowns to focus on specific finding types.</div>
                            </div>
                        </div>
                    </div>

                    <div class="help-section">
                        <h3>Keyboard Shortcuts</h3>
                        <div class="shortcut-grid">
                            <div class="shortcut-row">
                                <span class="shortcut-key">&uarr; / &darr;</span>
                                <span class="shortcut-desc">Navigate findings</span>
                            </div>
                            <div class="shortcut-row">
                                <span class="shortcut-key">Enter</span>
                                <span class="shortcut-desc">Expand / Collapse</span>
                            </div>
                            <div class="shortcut-row">
                                <span class="shortcut-key">Space</span>
                                <span class="shortcut-desc">Mark completed</span>
                            </div>
                            <div class="shortcut-row">
                                <span class="shortcut-key">h</span>
                                <span class="shortcut-desc">Hide completed</span>
                            </div>
                            <div class="shortcut-row">
                                <span class="shortcut-key">/</span>
                                <span class="shortcut-desc">Search</span>
                            </div>
                            <div class="shortcut-row">
                                <span class="shortcut-key">Esc</span>
                                <span class="shortcut-desc">Close / Clear</span>
                            </div>
                        </div>
                    </div>

                    <div class="help-section">
                        <h3>Tips</h3>
                        <p style="margin-bottom: 8px;"><strong>Start with Top Priority Actions</strong> - These are automatically ranked by exploitability and impact.</p>
                        <p style="margin-bottom: 8px;"><strong>Use the search</strong> - Quickly find specific accounts, computers, or groups by name.</p>
                        <p style="margin-bottom: 0;"><strong>Mark as you go</strong> - Check off findings as you remediate them to track progress.</p>
                    </div>

                    <div class="help-section data-management-section">
                        <h3>Data Management</h3>
                        <p style="margin-bottom: 12px;">This report stores preferences and progress in your browser's local storage:</p>
                        <div class="data-storage-info">
                            <div class="data-item"><span class="data-icon">&#9745;</span> Completed findings (checkboxes)</div>
                            <div class="data-item"><span class="data-icon">&#9788;</span> Theme preference (Dark/Light)</div>
                            <div class="data-item"><span class="data-icon">&#9744;</span> Hide completed toggle state</div>
                        </div>
                        <p style="margin: 12px 0; color: var(--text-muted); font-size: 12px;">Data is stored only in this browser and is not sent anywhere. Each report has its own completion tracking.</p>
                        <button class="clear-data-btn" onclick="clearAdPEASData()" title="Remove all adPEAS data from browser storage">
                            <span class="clear-data-icon">&#128465;</span> Clear All Stored Data
                        </button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        // Clear all adPEAS data from localStorage
        function clearAdPEASData() {
            const keys = Object.keys(localStorage).filter(k => k.startsWith('adpeas-'));
            const count = keys.length;

            if (count === 0) {
                announceToScreenReader('No adPEAS data found in storage.');
                alert('No adPEAS data found in browser storage.');
                return;
            }

            const confirmMsg = 'This will remove all adPEAS data from your browser:\n\n' +
                '• Completed findings (checkboxes) for ALL reports\n' +
                '• Theme preference\n\n' +
                'Found ' + count + ' stored item(s).\n\n' +
                'The page will reload after clearing. Continue?';

            if (confirm(confirmMsg)) {
                keys.forEach(k => localStorage.removeItem(k));
                announceToScreenReader('All adPEAS data cleared. Reloading page.');
                location.reload();
            }
        }

        function toggleShortcutHelp() {
            const backdrop = document.getElementById('shortcutBackdrop');
            const modal = document.getElementById('shortcutHelp');
            const isOpening = !modal.classList.contains('visible');

            backdrop.classList.toggle('visible');
            modal.classList.toggle('visible');

            if (isOpening) {
                // Focus trap and announce
                trapFocus(modal);
                announceToScreenReader('Help dialog opened. Press Escape to close.');
            } else {
                restoreFocus();
            }
        }

        function hideShortcutHelp() {
            document.getElementById('shortcutBackdrop').classList.remove('visible');
            document.getElementById('shortcutHelp').classList.remove('visible');
            restoreFocus();
        }

        // ============================================================
        // TOP PRIORITY ACTIONS with Context-Aware Risk Scoring
        // ============================================================

        // ==========================================================================
        // CONTEXT-AWARE SCORING SYSTEM
        // ==========================================================================
        // Score = BASE_SCORE * IMPACT_MODIFIER * EXPLOITABILITY_MODIFIER * SECURITY_MODIFIER + CORRELATION
        //
        // Definitions are maintained centrally in: src/modules/Core/adPEAS-ScoringDefinitions.ps1
        // Documentation: docs/10-Risk-Scoring-System.md
        // ==========================================================================

        // ---- BEGIN AUTO-GENERATED SCORING DEFINITIONS ----
        // Source: adPEAS-ScoringDefinitions.ps1
{{SCORING_DEFINITIONS}}
        // ---- END AUTO-GENERATED SCORING DEFINITIONS ----

        // Exploitability modifiers for cracking-based attacks
        // Uses values from securityModifiers, passwordAgeModifiers, passwordLengthModifiers, etc.
        function getExploitabilityModifier(accountInfo, findingType) {
            let modifier = 1.0;

            // Only apply these modifiers to attacks that require cracking
            const crackingAttacks = ['kerberoast', 'asrep', 'preauth'];
            const isCrackingAttack = crackingAttacks.some(a => findingType.includes(a));

            if (!isCrackingAttack || !accountInfo) {
                return modifier;
            }

            // Get domain password policy for context-aware age evaluation
            const maxPwdAgeDays = scoringContext?.domainInfo?.maxPwdAgeDays || 0;
            const minPwdLength = scoringContext?.domainInfo?.minPwdLength || 0;

            // Password age factor - relative to policy, not absolute
            if (accountInfo.pwdAgeDays !== null && accountInfo.pwdAgeDays > 0) {
                const pwdAge = accountInfo.pwdAgeDays;

                if (maxPwdAgeDays > 0) {
                    // Policy exists - evaluate relative to policy
                    const policyMultiples = pwdAge / maxPwdAgeDays;

                    if (policyMultiples >= 10) {
                        modifier *= passwordAgeModifiers.multiplier_10x;
                    } else if (policyMultiples >= 5) {
                        modifier *= passwordAgeModifiers.multiplier_5x;
                    } else if (policyMultiples >= 3) {
                        modifier *= passwordAgeModifiers.multiplier_3x;
                    } else if (policyMultiples >= 2) {
                        modifier *= passwordAgeModifiers.multiplier_2x;
                    } else if (policyMultiples >= 1) {
                        modifier *= passwordAgeModifiers.multiplier_1x;
                    } else {
                        modifier *= passwordAgeModifiers.within_policy;
                    }
                } else {
                    // No policy (never expires) - use absolute thresholds
                    if (pwdAge > 365 * 5) {
                        modifier *= passwordAgeModifiers.multiplier_5x;
                    } else if (pwdAge > 365 * 2) {
                        modifier *= passwordAgeModifiers.multiplier_2x;
                    } else if (pwdAge > 365) {
                        modifier *= passwordAgeModifiers.multiplier_1x;
                    }
                }
            }

            // Password policy strength affects cracking difficulty
            const complexityEnabled = scoringContext?.domainInfo?.complexityEnabled || false;

            // Password length impact on cracking time
            if (minPwdLength > 0) {
                if (minPwdLength < 8) {
                    modifier *= passwordLengthModifiers.very_weak;
                } else if (minPwdLength < 12) {
                    modifier *= passwordLengthModifiers.weak;
                } else if (minPwdLength < 16) {
                    modifier *= passwordLengthModifiers.standard;
                } else {
                    modifier *= passwordLengthModifiers.strong;
                }
            }

            // Password complexity
            if (!complexityEnabled) {
                modifier *= passwordComplexityModifiers.disabled;
            } else {
                modifier *= passwordComplexityModifiers.enabled;
            }

            // Combined weak policy scenario (short + no complexity)
            if (minPwdLength > 0 && minPwdLength < 10 && !complexityEnabled) {
                modifier *= 1.15;  // Additional penalty for very weak combination
            }

            // Encryption type factor (RC4 = much easier to crack)
            if (accountInfo.encryptionTypes && accountInfo.encryptionTypes.length > 0) {
                const hasRC4Only = accountInfo.encryptionTypes.includes('RC4-HMAC') &&
                                   !accountInfo.encryptionTypes.includes('AES256') &&
                                   !accountInfo.encryptionTypes.includes('AES128');
                const hasAES = accountInfo.encryptionTypes.includes('AES256') ||
                               accountInfo.encryptionTypes.includes('AES128');

                if (hasRC4Only) {
                    modifier *= encryptionTypeModifiers.rc4_only;
                } else if (hasAES && !accountInfo.encryptionTypes.includes('RC4-HMAC')) {
                    modifier *= encryptionTypeModifiers.aes256;
                }
            }

            return modifier;
        }

        // Security configuration modifiers - REDUCE score for secure settings
        // Uses values from securityModifiers object
        function getSecurityModifier(accountInfo, findingType) {
            if (!accountInfo || !accountInfo.uacFlags) {
                return 1.0;
            }

            let modifier = 1.0;
            const flags = accountInfo.uacFlags;
            const isCrackingAttack = ['kerberoast', 'asrep', 'preauth'].some(a => findingType.includes(a));
            const isCredentialAttack = ['credential', 'password', 'gpp', 'autoadmin'].some(a => findingType.includes(a));

            // ========================================
            // ACCOUNT STATUS FLAGS (affect ALL attacks)
            // ========================================

            if (flags.includes('ACCOUNTDISABLE') || flags.includes('Disabled')) {
                modifier *= securityModifiers.ACCOUNTDISABLE;
            }

            if (flags.includes('LOCKOUT') || flags.includes('Locked')) {
                modifier *= securityModifiers.LOCKOUT;
            }

            // ========================================
            // KERBEROS SECURITY FLAGS (affect cracking attacks)
            // ========================================

            if (isCrackingAttack) {
                if (flags.includes('SMARTCARD_REQUIRED') || flags.includes('SmartcardRequired')) {
                    modifier *= securityModifiers.SMARTCARD_REQUIRED;
                }

                if (accountInfo.isProtectedUser) {
                    modifier *= securityModifiers.PROTECTED_USERS;
                }
            }

            // ========================================
            // DELEGATION FLAGS (affect delegation attacks)
            // ========================================

            const isDelegationAttack = ['delegation', 'rbcd', 'constrained', 'unconstrained'].some(a => findingType.includes(a));

            if (isDelegationAttack) {
                if (flags.includes('NOT_DELEGATED') || flags.includes('NotDelegated') ||
                    flags.includes('AccountNotDelegated') || flags.includes('Sensitive')) {
                    modifier *= securityModifiers.NOT_DELEGATED;
                }
            }

            // ========================================
            // PASSWORD FLAGS (affect credential attacks)
            // ========================================

            if (isCrackingAttack || isCredentialAttack) {
                if (flags.includes('PASSWORD_EXPIRED') || flags.includes('PasswordExpired')) {
                    modifier *= securityModifiers.PASSWORD_EXPIRED;
                }
            }

            // ========================================
            // ENCRYPTION FLAGS (affect Kerberoast specifically)
            // ========================================

            if (flags.includes('USE_DES_KEY_ONLY') || flags.includes('DESKeyOnly')) {
                modifier *= securityModifiers.USE_DES_KEY_ONLY;
            }

            return modifier;
        }

        // Get account info from scoring context
        function getAccountInfoFromCard(card) {
            if (!scoringContext || !scoringContext.accounts) {
                return null;
            }

            // Try to find account by extracting identifiers from card content
            const objectDetails = card.querySelectorAll('.object-detail');
            for (const detail of objectDetails) {
                // Look for sAMAccountName or distinguishedName in the card
                const rows = detail.querySelectorAll('.attr-row');
                for (const row of rows) {
                    const nameEl = row.querySelector('.attr-name');
                    const valueEl = row.querySelector('.attr-value');
                    if (!nameEl || !valueEl) continue;

                    const attrName = nameEl.textContent.trim().toLowerCase();
                    const attrValue = valueEl.textContent.trim();

                    // Match by objectSid first (most reliable)
                    if (attrName === 'objectsid' && scoringContext.accounts[attrValue]) {
                        return scoringContext.accounts[attrValue];
                    }
                    // Match by DN
                    if (attrName === 'distinguishedname' && scoringContext.accounts[attrValue]) {
                        return scoringContext.accounts[attrValue];
                    }
                    // Match by sAMAccountName (iterate through accounts)
                    if (attrName === 'samaccountname') {
                        for (const [key, acct] of Object.entries(scoringContext.accounts)) {
                            if (acct.name && acct.name.toLowerCase() === attrValue.toLowerCase()) {
                                return acct;
                            }
                        }
                    }
                }
            }
            return null;
        }

        // Check if account appears in multiple risky findings (correlation bonus)
        // Uses values from correlationBonus object
        // Non-admin accounts get ENHANCED correlation bonus - they represent potential attack paths
        function getCorrelationBonus(accountInfo) {
            if (!scoringContext || !scoringContext.correlations || !accountInfo) {
                return 0;
            }

            // Find correlations for this account
            const accountId = accountInfo.sid || accountInfo.dn || accountInfo.name;
            const correlation = scoringContext.correlations[accountId];

            if (!correlation) {
                return 0;
            }

            // Determine if this is a non-admin account
            const isNonAdmin = !accountInfo.isAdmin && accountInfo.adminTier === 'none';

            let bonus = 0;

            // Dangerous combinations get max bonus
            if (correlation.hasDCSync && (correlation.hasKerberoast || correlation.hasASREP)) {
                bonus = isNonAdmin ? correlationBonus.nonAdminMaxBonus : correlationBonus.maxBonus;
            } else if (correlation.hasDelegation && correlation.hasKerberoast) {
                const perFinding = isNonAdmin ? correlationBonus.nonAdminPerFinding : correlationBonus.perFinding;
                const maxBonus = isNonAdmin ? correlationBonus.nonAdminMaxBonus : correlationBonus.maxBonus;
                bonus = Math.min(perFinding * 2, maxBonus);
            } else if (correlation.count >= 2) {
                // Non-admin with 3+ findings = enhanced bonus (potential privilege escalation path)
                if (isNonAdmin && correlation.count >= correlationBonus.nonAdminThreshold) {
                    // Enhanced correlation for non-admins appearing in multiple findings
                    bonus = Math.min((correlation.count - 1) * correlationBonus.nonAdminPerFinding, correlationBonus.nonAdminMaxBonus);
                } else {
                    // Standard correlation for admins or non-admins below threshold
                    bonus = Math.min((correlation.count - 1) * correlationBonus.perFinding, correlationBonus.maxBonus);
                }
            }

            return bonus;
        }

        // Calculate score with full breakdown for transparency
        function calculateFindingScoreWithBreakdown(card) {
            const severity = card.dataset.severity || 'note';
            const breakdown = {
                severity: severity,
                baseScore: 0,
                matchedPattern: null,
                impactMod: 1.0,
                impactReason: 'Standard',
                exploitMod: 1.0,
                exploitReasons: [],
                securityMod: 1.0,
                securityReasons: [],
                correlationBonus: 0,
                correlationReason: null,
                finalScore: 0
            };

            // Note and Secure = no security issue
            if (severity === 'note' || severity === 'secure') {
                breakdown.baseScore = 0;
                breakdown.finalScore = 0;
                return breakdown;
            }

            // HINT severity = informational findings
            if (severity === 'hint') {
                breakdown.baseScore = severityBaseScores['hint'] || 15;
                breakdown.finalScore = breakdown.baseScore;
                breakdown.matchedPattern = 'hint (informational)';
                return breakdown;
            }

            // Get finding title
            const title = (card.querySelector('.finding-title')?.textContent || '').toLowerCase();

            // 1. Determine BASE score from finding type
            breakdown.baseScore = severityBaseScores[severity] || 5;

            for (const [pattern, score] of Object.entries(findingBaseScores)) {
                if (title.includes(pattern.toLowerCase())) {
                    if (score > breakdown.baseScore) {
                        breakdown.baseScore = score;
                        breakdown.matchedPattern = pattern;
                    }
                }
            }

            // DCSync/Replication Rights are ALWAYS maximum
            if (breakdown.matchedPattern === 'dcsync' || breakdown.matchedPattern === 'replication rights') {
                breakdown.finalScore = 100;
                breakdown.impactReason = 'Maximum (DCSync)';
                return breakdown;
            }

            // 2. Get account context
            const accountInfo = getAccountInfoFromCard(card);

            // 3. Apply IMPACT modifier
            if (accountInfo && accountInfo.adminTier) {
                breakdown.impactMod = impactMultipliers[accountInfo.adminTier] || impactMultipliers.none;
                const tierNames = { tier0: 'Tier 0 (Domain Admin)', tier1: 'Tier 1 (Server Admin)', tier2: 'Tier 2 (Workstation Admin)', none: 'Non-Admin' };
                breakdown.impactReason = tierNames[accountInfo.adminTier] || 'Standard';
            }

            // 4. Apply EXPLOITABILITY modifier with reasons
            breakdown.exploitMod = getExploitabilityModifier(accountInfo, title);
            if (accountInfo) {
                if (accountInfo.pwdAgeDays > 365) {
                    breakdown.exploitReasons.push('Old password (' + Math.round(accountInfo.pwdAgeDays / 365) + 'y)');
                }
                if (accountInfo.encryptionTypes && accountInfo.encryptionTypes.includes('RC4-HMAC') && !accountInfo.encryptionTypes.includes('AES256')) {
                    breakdown.exploitReasons.push('RC4 encryption');
                }
            }
            if (breakdown.exploitReasons.length === 0 && breakdown.exploitMod !== 1.0) {
                breakdown.exploitReasons.push(breakdown.exploitMod > 1 ? 'Easier to exploit' : 'Harder to exploit');
            }

            // 5. Apply SECURITY modifier with reasons
            breakdown.securityMod = getSecurityModifier(accountInfo, title);
            if (accountInfo && accountInfo.uacFlags) {
                const flags = accountInfo.uacFlags;
                if (flags.includes('ACCOUNTDISABLE') || flags.includes('Disabled')) {
                    breakdown.securityReasons.push('Disabled');
                }
                if (flags.includes('SMARTCARD_REQUIRED') || flags.includes('SmartcardRequired')) {
                    breakdown.securityReasons.push('Smartcard required');
                }
                if (accountInfo.isProtectedUser) {
                    breakdown.securityReasons.push('Protected Users');
                }
            }
            if (breakdown.securityReasons.length === 0 && breakdown.securityMod !== 1.0) {
                breakdown.securityReasons.push(breakdown.securityMod < 1 ? 'Mitigated' : 'Vulnerable');
            }

            // 6. Add correlation bonus
            breakdown.correlationBonus = getCorrelationBonus(accountInfo);
            if (breakdown.correlationBonus > 0) {
                breakdown.correlationReason = 'Appears in multiple findings';
            }

            // Calculate final score
            let rawScore = Math.round(breakdown.baseScore * breakdown.impactMod * breakdown.exploitMod * breakdown.securityMod) + breakdown.correlationBonus;
            breakdown.finalScore = Math.min(Math.max(rawScore, 0), 100);

            return breakdown;
        }

        // Simple wrapper for backwards compatibility
        function calculateFindingScore(card) {
            return calculateFindingScoreWithBreakdown(card).finalScore;
        }

        // Format score breakdown as tooltip text
        function formatScoreBreakdown(breakdown) {
            if (breakdown.finalScore === 0) {
                return 'No risk score (informational)';
            }

            let lines = [];
            lines.push('Score Breakdown:');
            lines.push('─────────────────');
            lines.push('Base: ' + breakdown.baseScore + (breakdown.matchedPattern ? ' (' + breakdown.matchedPattern + ')' : ''));

            if (breakdown.impactMod !== 1.0) {
                lines.push('Impact: ×' + breakdown.impactMod.toFixed(2) + ' (' + breakdown.impactReason + ')');
            }

            if (breakdown.exploitMod !== 1.0) {
                const reasons = breakdown.exploitReasons.length > 0 ? breakdown.exploitReasons.join(', ') : '';
                lines.push('Exploitability: ×' + breakdown.exploitMod.toFixed(2) + (reasons ? ' (' + reasons + ')' : ''));
            }

            if (breakdown.securityMod !== 1.0) {
                const reasons = breakdown.securityReasons.length > 0 ? breakdown.securityReasons.join(', ') : '';
                lines.push('Security: ×' + breakdown.securityMod.toFixed(2) + (reasons ? ' (' + reasons + ')' : ''));
            }

            if (breakdown.correlationBonus > 0) {
                lines.push('Correlation: +' + breakdown.correlationBonus + (breakdown.correlationReason ? ' (' + breakdown.correlationReason + ')' : ''));
            }

            lines.push('─────────────────');
            lines.push('Final: ' + breakdown.finalScore);

            return lines.join('\n');
        }

        // Format score breakdown as styled HTML tooltip content
        function formatScoreBreakdownHtml(breakdown) {
            if (breakdown.finalScore === 0) {
                return `
                    <div class="score-tooltip-header">
                        <span class="score-tooltip-title">Score Breakdown</span>
                        <span class="score-tooltip-final info">0</span>
                    </div>
                    <div class="score-tooltip-body">
                        <div class="score-tooltip-row">
                            <span class="score-tooltip-label">No risk score (informational)</span>
                        </div>
                    </div>
                `;
            }

            const scoreClass = breakdown.finalScore >= scoreThresholds.critical ? 'critical' :
                               breakdown.finalScore >= scoreThresholds.high ? 'high' :
                               breakdown.finalScore >= scoreThresholds.medium ? 'medium' :
                               breakdown.finalScore >= scoreThresholds.low ? 'low' : 'info';

            let rowsHtml = '';

            // Base Score
            rowsHtml += `
                <div class="score-tooltip-row">
                    <span class="score-tooltip-label">Base Score${breakdown.matchedPattern ? `<span class="reason">${escapeHtml(breakdown.matchedPattern)}</span>` : ''}</span>
                    <span class="score-tooltip-value positive">${breakdown.baseScore}</span>
                </div>
            `;

            // Impact Modifier
            if (breakdown.impactMod !== 1.0) {
                rowsHtml += `
                    <div class="score-tooltip-row">
                        <span class="score-tooltip-label">Impact<span class="reason">${escapeHtml(breakdown.impactReason)}</span></span>
                        <span class="score-tooltip-value modifier">×${breakdown.impactMod.toFixed(2)}</span>
                    </div>
                `;
            }

            // Exploitability Modifier
            if (breakdown.exploitMod !== 1.0) {
                const reasons = breakdown.exploitReasons.length > 0 ? breakdown.exploitReasons.join(', ') : '';
                rowsHtml += `
                    <div class="score-tooltip-row">
                        <span class="score-tooltip-label">Exploitability${reasons ? `<span class="reason">${escapeHtml(reasons)}</span>` : ''}</span>
                        <span class="score-tooltip-value modifier">×${breakdown.exploitMod.toFixed(2)}</span>
                    </div>
                `;
            }

            // Security Modifier
            if (breakdown.securityMod !== 1.0) {
                const reasons = breakdown.securityReasons.length > 0 ? breakdown.securityReasons.join(', ') : '';
                rowsHtml += `
                    <div class="score-tooltip-row">
                        <span class="score-tooltip-label">Security${reasons ? `<span class="reason">${escapeHtml(reasons)}</span>` : ''}</span>
                        <span class="score-tooltip-value modifier">×${breakdown.securityMod.toFixed(2)}</span>
                    </div>
                `;
            }

            // Correlation Bonus
            if (breakdown.correlationBonus > 0) {
                rowsHtml += `
                    <div class="score-tooltip-row">
                        <span class="score-tooltip-label">Correlation${breakdown.correlationReason ? `<span class="reason">${escapeHtml(breakdown.correlationReason)}</span>` : ''}</span>
                        <span class="score-tooltip-value positive">+${breakdown.correlationBonus}</span>
                    </div>
                `;
            }

            return `
                <div class="score-tooltip-header">
                    <span class="score-tooltip-title">Score Breakdown</span>
                    <span class="score-tooltip-final ${scoreClass}">${breakdown.finalScore}</span>
                </div>
                <div class="score-tooltip-body">
                    ${rowsHtml}
                </div>
            `;
        }

        // Active score tooltip reference
        let activeScoreTooltip = null;

        // Initialize score tooltips for styled display
        function initScoreTooltips() {
            // Create tooltip container
            const tooltipDiv = document.createElement('div');
            tooltipDiv.id = 'scoreTooltip';
            tooltipDiv.className = 'score-tooltip';
            tooltipDiv.setAttribute('role', 'tooltip');
            document.body.appendChild(tooltipDiv);

            // Close tooltip when clicking outside
            document.addEventListener('click', function(e) {
                if (activeScoreTooltip && !e.target.closest('.score-tooltip') && !e.target.closest('[data-score-breakdown]')) {
                    closeScoreTooltip();
                }
            });

            // Close on Escape key
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && activeScoreTooltip) {
                    closeScoreTooltip();
                }
            });
        }

        function showScoreTooltip(trigger, breakdown) {
            const tooltip = document.getElementById('scoreTooltip');
            if (!tooltip) return;

            // Close any previously open tooltip first
            if (activeScoreTooltip) {
                closeScoreTooltip();
            }

            // Build tooltip HTML
            tooltip.innerHTML = formatScoreBreakdownHtml(breakdown);

            // Make visible for positioning measurement
            tooltip.style.visibility = 'hidden';
            tooltip.classList.add('visible');

            // Position tooltip
            positionScoreTooltip(tooltip, trigger);

            // Show tooltip
            tooltip.style.visibility = 'visible';
            activeScoreTooltip = tooltip;
        }

        function closeScoreTooltip() {
            const tooltip = document.getElementById('scoreTooltip');
            if (tooltip) {
                tooltip.classList.remove('visible');
            }
            activeScoreTooltip = null;
        }

        function positionScoreTooltip(tooltip, trigger) {
            const triggerRect = trigger.getBoundingClientRect();
            const tooltipRect = tooltip.getBoundingClientRect();
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            const padding = UI_CONSTANTS.VIEWPORT_PADDING;

            // Default: position below the trigger, centered
            let left = triggerRect.left + (triggerRect.width / 2) - (tooltipRect.width / 2);
            let top = triggerRect.bottom + 8;

            // Adjust horizontal position if tooltip would overflow
            if (left < padding) {
                left = padding;
            } else if (left + tooltipRect.width > viewportWidth - padding) {
                left = viewportWidth - tooltipRect.width - padding;
            }

            // If tooltip would overflow bottom, position above trigger
            if (top + tooltipRect.height > viewportHeight - padding) {
                top = triggerRect.top - tooltipRect.height - 8;
            }

            // Ensure not above viewport
            if (top < padding) {
                top = padding;
            }

            tooltip.style.left = left + 'px';
            tooltip.style.top = top + 'px';
        }

        // Calculate score from finding metadata (JSON-based, no DOM traversal)
        function calculateScoreFromMetadata(findingMeta) {
            const severity = findingMeta.severity || 'note';
            const breakdown = {
                severity: severity,
                baseScore: 0,
                matchedPattern: null,
                impactMod: 1.0,
                impactReason: 'Standard',
                exploitMod: 1.0,
                exploitReasons: [],
                securityMod: 1.0,
                securityReasons: [],
                correlationBonus: 0,
                correlationReason: null,
                finalScore: 0
            };

            // Note and Secure = no security issue
            if (severity === 'note' || severity === 'secure') {
                return breakdown;
            }

            // HINT severity = informational findings
            if (severity === 'hint') {
                breakdown.baseScore = severityBaseScores['hint'] || 15;
                breakdown.finalScore = breakdown.baseScore;
                breakdown.matchedPattern = 'hint (informational)';
                return breakdown;
            }

            // Get finding title
            const title = (findingMeta.title || '').toLowerCase();

            // 1. Determine BASE score from finding type
            breakdown.baseScore = severityBaseScores[severity] || 5;

            for (const [pattern, score] of Object.entries(findingBaseScores)) {
                if (title.includes(pattern.toLowerCase())) {
                    if (score > breakdown.baseScore) {
                        breakdown.baseScore = score;
                        breakdown.matchedPattern = pattern;
                    }
                }
            }

            // 1b. Check vulnerability tags (e.g., ADCS ESC1, ESC4) against findingBaseScores
            // When the card title (e.g., "Certificate Templates") doesn't match,
            // but objects contain vulnerability tags, use the highest matching score
            if (findingMeta.vulnerabilities && findingMeta.vulnerabilities.length > 0) {
                for (const vulnTag of findingMeta.vulnerabilities) {
                    const vulnLower = vulnTag.toLowerCase();
                    for (const [pattern, score] of Object.entries(findingBaseScores)) {
                        // Match "esc1" against FindingID keys like "esc1_template", "esc1_vulnerable_..."
                        if (pattern.toLowerCase().startsWith(vulnLower + '_') || pattern.toLowerCase() === vulnLower) {
                            if (score > breakdown.baseScore) {
                                breakdown.baseScore = score;
                                breakdown.matchedPattern = pattern + ' (via ' + vulnTag + ')';
                            }
                        }
                    }
                }
            }

            // DCSync/Replication Rights are ALWAYS maximum
            if (breakdown.matchedPattern && (breakdown.matchedPattern.startsWith('dcsync') || breakdown.matchedPattern.startsWith('replication rights'))) {
                breakdown.finalScore = 100;
                breakdown.impactReason = 'Maximum (DCSync)';
                return breakdown;
            }

            // 2. Get account context from scoringContext using accountSID
            const accountInfo = findingMeta.accountSID ? scoringContext?.accounts?.[findingMeta.accountSID] : null;

            // 3. Apply IMPACT modifier
            if (accountInfo && accountInfo.adminTier) {
                breakdown.impactMod = impactMultipliers[accountInfo.adminTier] || impactMultipliers.none;
                const tierNames = { tier0: 'Tier 0 (Domain Admin)', tier1: 'Tier 1 (Server Admin)', tier2: 'Tier 2 (Workstation Admin)', none: 'Non-Admin' };
                breakdown.impactReason = tierNames[accountInfo.adminTier] || 'Standard';
            }

            // 4. Apply EXPLOITABILITY modifier with reasons
            breakdown.exploitMod = getExploitabilityModifier(accountInfo, title);
            if (accountInfo) {
                if (accountInfo.pwdAgeDays > 365) {
                    breakdown.exploitReasons.push('Old password (' + Math.round(accountInfo.pwdAgeDays / 365) + 'y)');
                }
                if (accountInfo.encryptionTypes && accountInfo.encryptionTypes.includes('RC4-HMAC') && !accountInfo.encryptionTypes.includes('AES256')) {
                    breakdown.exploitReasons.push('RC4 encryption');
                }
            }
            if (breakdown.exploitReasons.length === 0 && breakdown.exploitMod !== 1.0) {
                breakdown.exploitReasons.push(breakdown.exploitMod > 1 ? 'Easier to exploit' : 'Harder to exploit');
            }

            // 5. Apply SECURITY modifier with reasons
            breakdown.securityMod = getSecurityModifier(accountInfo, title);
            if (accountInfo && accountInfo.uacFlags) {
                const flags = accountInfo.uacFlags;
                if (flags.includes('ACCOUNTDISABLE') || flags.includes('Disabled')) {
                    breakdown.securityReasons.push('Disabled');
                }
                if (flags.includes('SMARTCARD_REQUIRED') || flags.includes('SmartcardRequired')) {
                    breakdown.securityReasons.push('Smartcard required');
                }
                if (accountInfo.isProtectedUser) {
                    breakdown.securityReasons.push('Protected Users');
                }
            }
            if (breakdown.securityReasons.length === 0 && breakdown.securityMod !== 1.0) {
                breakdown.securityReasons.push(breakdown.securityMod < 1 ? 'Mitigated' : 'Vulnerable');
            }

            // 6. Add correlation bonus
            breakdown.correlationBonus = getCorrelationBonus(accountInfo);
            if (breakdown.correlationBonus > 0) {
                breakdown.correlationReason = 'Appears in multiple findings';
            }

            // Calculate final score
            let rawScore = Math.round(breakdown.baseScore * breakdown.impactMod * breakdown.exploitMod * breakdown.securityMod) + breakdown.correlationBonus;
            breakdown.finalScore = Math.min(Math.max(rawScore, 0), 100);

            return breakdown;
        }

        // Find the best matching findingDefinition for a given finding card metadata
        // Priority: 0) ObjectType primaryFindingId, 1) findingIds from metadata, 2) vulnerability tags, 3) title keyword matching
        function findBestFindingDefinition(meta) {
            if (!findingDefinitions || !meta) return null;
            let bestKey = null;
            let bestScore = 0;

            // 0. ObjectType-level primary finding (highest authority — prevents incidental attribute
            //    triggers from overriding the card's actual topic)
            if (meta.objectType && checkDescriptions) {
                const checkInfo = checkDescriptions[meta.objectType];
                if (checkInfo?.primaryFindingId && findingDefinitions[checkInfo.primaryFindingId]) {
                    return findingDefinitions[checkInfo.primaryFindingId];
                }
            }

            // 1. Direct FindingId lookup (most reliable — from attribute trigger matching)
            if (meta.findingIds && meta.findingIds.length > 0) {
                for (const fid of meta.findingIds) {
                    if (findingDefinitions[fid]) {
                        const score = findingBaseScores[fid] || 0;
                        if (score > bestScore || !bestKey) {
                            bestScore = score;
                            bestKey = fid;
                        }
                    }
                }
            }

            // 2. Vulnerability tags (e.g., "ESC1" → "ESC1_TEMPLATE")
            if (!bestKey && meta.vulnerabilities && meta.vulnerabilities.length > 0) {
                for (const vulnTag of meta.vulnerabilities) {
                    const vulnLower = vulnTag.toLowerCase();
                    for (const [key, score] of Object.entries(findingBaseScores)) {
                        if (key.toLowerCase().startsWith(vulnLower + '_') || key.toLowerCase() === vulnLower) {
                            if (score > bestScore && findingDefinitions[key]) {
                                bestScore = score;
                                bestKey = key;
                            }
                        }
                    }
                }
            }

            // 3. Fallback: title keyword matching
            if (!bestKey) {
                const titleLower = (meta.title || '').toLowerCase();
                for (const [key, score] of Object.entries(findingBaseScores)) {
                    if (titleLower.includes(key.toLowerCase()) && score > bestScore && findingDefinitions[key]) {
                        bestScore = score;
                        bestKey = key;
                    }
                }
            }

            return bestKey ? findingDefinitions[bestKey] : null;
        }

        function generateTopPriorityActions() {
            const container = document.getElementById('topActionsContainer');
            if (!container) return;

            // ========== OPTIMIZED: Use JSON-based scoring if available ==========
            // This avoids DOM traversal for initial score calculation
            let scoredFindings = [];
            let totalCriticalCount = 0;

            if (scoringContext?.findingCards?.length > 0) {
                // NEW: JSON-based scoring (no DOM traversal needed)
                const criticalFindings = scoringContext.findingCards.filter(f => f.severity === 'finding');
                totalCriticalCount = criticalFindings.length;

                if (criticalFindings.length > 0) {
                    scoredFindings = criticalFindings.map((meta, idx) => {
                        const breakdown = calculateScoreFromMetadata(meta);
                        return {
                            meta: meta,
                            index: idx,
                            score: breakdown.finalScore,
                            breakdown: breakdown,
                            title: meta.title || 'Unknown Finding',
                            section: meta.section || meta.category || 'Unknown'
                        };
                    }).sort((a, b) => b.score - a.score);
                }
            } else {
                // FALLBACK: DOM-based scoring (legacy behavior)
                const allCards = Array.from(document.querySelectorAll('.finding-card'));
                const findingCards = allCards.filter(card => card.dataset.severity === 'finding');
                totalCriticalCount = findingCards.length;

                if (findingCards.length > 0) {
                    scoredFindings = findingCards.map((card, idx) => {
                        const breakdown = calculateFindingScoreWithBreakdown(card);
                        return {
                            card: card,
                            index: idx,
                            score: breakdown.finalScore,
                            breakdown: breakdown,
                            title: card.querySelector('.finding-title')?.textContent || 'Unknown Finding',
                            section: card.closest('.section')?.querySelector('.section-title')?.textContent || 'Unknown'
                        };
                    }).sort((a, b) => b.score - a.score);
                }
            }

            if (totalCriticalCount === 0) {
                // No critical findings - show success message
                container.innerHTML = `
                    <div class="top-actions" style="border-color: var(--note); background: linear-gradient(135deg, var(--note-bg) 0%, var(--bg-card) 100%);">
                        <div class="top-actions-header">
                            <div class="top-actions-title" style="color: var(--note);">
                                <span class="icon">&#10003;</span>
                                No Critical Findings
                            </div>
                        </div>
                        <p style="margin: 0; color: var(--text-muted);">No high-priority security issues were detected. Review the hints and notes for potential improvements.</p>
                    </div>
                `;
                return;
            }

            // Take top 3
            const top3 = scoredFindings.slice(0, 3);

            // Generate HTML
            let actionsHTML = `
                <div class="top-actions">
                    <div class="top-actions-header">
                        <div class="top-actions-title">
                            <span class="icon">&#9889;</span>
                            Top Priority Actions
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span style="font-size: 12px; color: var(--text-muted);">${totalCriticalCount} critical findings total</span>
                            <button class="top-actions-toggle" onclick="toggleTopActions()" title="Toggle Top Priority Actions">
                                <span class="toggle-icon">&#9660;</span>
                            </button>
                        </div>
                    </div>
                    <div class="top-actions-list">
            `;

            top3.forEach((item, index) => {
                // Resolve objectType and card ID from JSON metadata or DOM
                let cardId = '';
                let objectType = '';
                let checkTitle = item.title;

                if (item.meta) {
                    // JSON-based path: objectType from metadata
                    objectType = item.meta.objectType || '';
                    checkTitle = item.meta.title || item.title;
                } else if (item.card) {
                    // DOM-based fallback
                    cardId = item.card.dataset.cardId || '';
                    const checkHelpBtn = item.card.querySelector('.check-help-btn');
                    objectType = checkHelpBtn?.dataset.objectType || '';
                    checkTitle = checkHelpBtn?.dataset.checkTitle || item.title;
                }

                // Look up check description for professional title and impact text
                const checkInfo = (objectType && checkDescriptions) ? checkDescriptions[objectType] : null;

                // Professional title: checkDescriptions.title > internal check title
                const displayTitle = checkInfo?.title || item.title;

                // Impact description from checkDescriptions.whyItMatters
                const impactText = checkInfo?.whyItMatters || '';

                // Remediation from findingDefinitions (best match by findingIds/vulnerabilities/title)
                const findingDef = findBestFindingDefinition(item.meta || { title: item.title });
                const remediationText = findingDef?.remediation?.[0] || '';

                // Object count for "N affected" label
                const objectCount = item.meta?.objectCount || 0;

                // Build meta line: "N affected | Section"
                let metaHtml = '';
                if (objectCount > 0) {
                    metaHtml += `<span class="top-action-count">${objectCount} affected</span>`;
                }
                metaHtml += `<span class="top-action-section">${escapeHtml(item.section)}</span>`;

                // Build buttons HTML (info button + score badge)
                let buttonsHtml = '';
                if (checkInfo) {
                    buttonsHtml += `<button class="top-action-info-btn" onclick="event.stopPropagation(); showTopActionInfo(this, '${escapeHtml(objectType)}', '${escapeHtml(checkTitle)}')" data-object-type="${escapeHtml(objectType)}" data-check-title="${escapeHtml(checkTitle)}" title="More Info">?</button>`;
                }
                const scoreClass = item.score >= scoreThresholds.critical ? 'score-critical' : item.score >= scoreThresholds.high ? 'score-high' : item.score >= scoreThresholds.medium ? 'score-medium' : item.score >= scoreThresholds.low ? 'score-low' : 'score-info';
                const breakdownJson = escapeJsonForAttr(item.breakdown);
                buttonsHtml += `<span class="top-action-score ${scoreClass}" data-score-breakdown='${breakdownJson}' onclick="event.stopPropagation(); showScoreTooltip(this, JSON.parse(this.dataset.scoreBreakdown));" style="cursor: pointer;">${item.score}</span>`;

                // Build detail lines (impact + remediation)
                let detailsHtml = '';
                if (impactText) {
                    detailsHtml += `<div class="top-action-details">${escapeHtml(impactText)}</div>`;
                }
                if (remediationText) {
                    detailsHtml += `<div class="top-action-fix">&rarr; ${escapeHtml(remediationText)}</div>`;
                }

                actionsHTML += `
                    <div class="top-action-item" data-target-card="${cardId}" data-target-title="${escapeHtml(checkTitle)}" data-target-index="${item.index}" onclick="scrollToFindingCard(this)" style="cursor: pointer;">
                        <div class="top-action-rank">${index + 1}</div>
                        <div class="top-action-content">
                            <div class="top-action-title">${escapeHtml(displayTitle)}</div>
                            <div class="top-action-meta">${metaHtml}</div>
                            ${detailsHtml}
                        </div>
                        <div class="top-action-buttons" onclick="event.stopPropagation()">${buttonsHtml}</div>
                    </div>
                `;
            });

            actionsHTML += `
                    </div>
                </div>
            `;

            container.innerHTML = actionsHTML;
        }

        function scrollToFindingCard(element) {
            const cardId = element.dataset.targetCard;
            const targetTitle = element.dataset.targetTitle;
            const targetIndex = parseInt(element.dataset.targetIndex);

            let card = cardId ? document.querySelector('.finding-card[data-card-id="' + cardId + '"]') : null;

            // Second try: find by data-check-title
            if (!card && targetTitle) {
                const allCards = Array.from(document.querySelectorAll('.finding-card'));
                card = allCards.find(c => {
                    const helpBtn = c.querySelector('.check-help-btn');
                    return helpBtn && helpBtn.dataset.checkTitle === targetTitle;
                });
            }

            // Fallback: find by index among finding cards
            if (!card && targetIndex >= 0) {
                const findingCards = Array.from(document.querySelectorAll('.finding-card')).filter(c => c.dataset.severity === 'finding');
                card = findingCards[targetIndex];
            }

            if (!card) return;

            // Reset filters to ensure the card is visible
            currentSeverityFilter = 'all';
            currentCategoryFilter = 'all';
            currentSearchQuery = '';

            // Update filter UI
            document.querySelectorAll('.severity-filter').forEach(f => f.classList.remove('active'));
            document.querySelectorAll('.nav-item[data-category]').forEach(f => f.classList.remove('active'));
            const allSeverityFilter = document.querySelector('.severity-filter[data-severity="all"]');
            const allCategoryFilter = document.querySelector('.nav-item[data-category="all"]');
            if (allSeverityFilter) allSeverityFilter.classList.add('active');
            if (allCategoryFilter) allCategoryFilter.classList.add('active');
            const searchInput = document.getElementById('searchInput');
            if (searchInput) searchInput.value = '';

            // Apply filters to show all cards and sections
            applyFilters();

            // Ensure the card is visible
            card.style.display = '';

            // Collapse all other cards first, then expand only the target card
            document.querySelectorAll('.finding-card.expanded').forEach(c => c.classList.remove('expanded'));
            card.classList.add('expanded');

            // Highlight the category in the sidebar
            highlightCategoryForCard(card);

            // Remove any previous highlight
            document.querySelectorAll('.finding-card.keyboard-focused').forEach(c => c.classList.remove('keyboard-focused'));

            // Use setTimeout to ensure the DOM has fully updated after view switch + filter changes
            setTimeout(() => {
                card.scrollIntoView({ behavior: 'auto', block: 'start' });
                card.classList.add('keyboard-focused');
                setTimeout(() => card.classList.remove('keyboard-focused'), UI_CONSTANTS.KEYBOARD_FOCUS_DURATION);
            }, 150);
        }

        function showTopActionInfo(btn, objectType, checkTitle) {
            // Look up check description by ObjectType
            if (!objectType || !checkDescriptions[objectType]) return;
            const checkInfo = checkDescriptions[objectType];

            // Build tooltip content similar to check tooltip
            let content = '<div class="top-action-tooltip-content">';
            content += '<div class="top-action-tooltip-header">' + escapeHtml(checkTitle) + '</div>';

            if (checkInfo.summary) {
                content += '<div class="top-action-tooltip-section">';
                content += '<div class="top-action-tooltip-label">Summary</div>';
                content += '<div class="top-action-tooltip-text">' + escapeHtml(checkInfo.summary) + '</div>';
                content += '</div>';
            }

            if (checkInfo.whyItMatters) {
                content += '<div class="top-action-tooltip-section">';
                content += '<div class="top-action-tooltip-label">Why It Matters</div>';
                content += '<div class="top-action-tooltip-text">' + escapeHtml(checkInfo.whyItMatters) + '</div>';
                content += '</div>';
            }

            if (checkInfo.whatWeCheck && checkInfo.whatWeCheck.length > 0) {
                content += '<div class="top-action-tooltip-section">';
                content += '<div class="top-action-tooltip-label">What We Check</div>';
                content += '<ul class="top-action-tooltip-list">';
                checkInfo.whatWeCheck.forEach(item => {
                    content += '<li>' + escapeHtml(item) + '</li>';
                });
                content += '</ul>';
                content += '</div>';
            }

            if (checkInfo.filteringNote) {
                content += '<div class="top-action-tooltip-section top-action-tooltip-note">';
                content += '<div class="top-action-tooltip-label">Note</div>';
                content += '<div class="top-action-tooltip-text">' + escapeHtml(checkInfo.filteringNote) + '</div>';
                content += '</div>';
            }

            content += '</div>';

            // Show as tooltip near the button
            showTooltipAt(btn, content);
        }

        // Track active floating tooltip and its event listener for cleanup
        let activeFloatingTooltip = null;
        let activeFloatingTooltipListener = null;

        function showTooltipAt(element, content) {
            // Remove any existing tooltip and clean up its event listener
            if (activeFloatingTooltip) {
                activeFloatingTooltip.remove();
                if (activeFloatingTooltipListener) {
                    document.removeEventListener('click', activeFloatingTooltipListener);
                    activeFloatingTooltipListener = null;
                }
                activeFloatingTooltip = null;
            }

            // Create tooltip
            const tooltip = document.createElement('div');
            tooltip.className = 'remediation-floating-tooltip';
            tooltip.innerHTML = content;
            document.body.appendChild(tooltip);
            activeFloatingTooltip = tooltip;

            // Position near element with smart positioning
            const rect = element.getBoundingClientRect();
            const tooltipRect = tooltip.getBoundingClientRect();
            const viewportHeight = window.innerHeight;
            const viewportWidth = window.innerWidth;

            // Calculate vertical position - prefer below, but go above if not enough space
            let top;
            if (rect.bottom + tooltipRect.height + 20 > viewportHeight) {
                // Not enough space below - show above
                top = rect.top + window.scrollY - tooltipRect.height - 8;
            } else {
                // Show below
                top = rect.bottom + window.scrollY + 8;
            }

            // Calculate horizontal position
            let left = rect.left + window.scrollX - 100;
            if (left + tooltipRect.width > viewportWidth - UI_CONSTANTS.VIEWPORT_PADDING) {
                left = viewportWidth - tooltipRect.width - 20;
            }
            if (left < UI_CONSTANTS.VIEWPORT_PADDING) {
                left = UI_CONSTANTS.VIEWPORT_PADDING;
            }

            tooltip.style.top = top + 'px';
            tooltip.style.left = left + 'px';

            // Create named listener for proper cleanup
            activeFloatingTooltipListener = function closeTooltip(e) {
                if (!tooltip.contains(e.target) && e.target !== element) {
                    tooltip.remove();
                    document.removeEventListener('click', closeTooltip);
                    activeFloatingTooltip = null;
                    activeFloatingTooltipListener = null;
                }
            };

            // Close on outside click (with small delay to prevent immediate close)
            setTimeout(() => {
                if (activeFloatingTooltip === tooltip) {
                    document.addEventListener('click', activeFloatingTooltipListener);
                }
            }, UI_CONSTANTS.TOOLTIP_CLOSE_DELAY);
        }

        // ============================================================
        // SCORE SORT STATE
        // ============================================================

        // Populate score badges into finding card headers
        function populateCardScores() {
            const cards = document.querySelectorAll('.finding-card');
            if (!cards.length) return;

            cards.forEach((card, index) => {
                const severity = card.dataset.severity || 'note';

                // Note and Secure cards have no score
                if (severity === 'note' || severity === 'secure') return;

                // Calculate score from JSON metadata (preferred) or DOM fallback
                let breakdown;
                const cardIndex = parseInt(card.dataset.cardIndex);
                if (!isNaN(cardIndex) && scoringContext?.findingCards?.[cardIndex]) {
                    breakdown = calculateScoreFromMetadata(scoringContext.findingCards[cardIndex]);
                } else {
                    breakdown = calculateFindingScoreWithBreakdown(card);
                }

                if (breakdown.finalScore <= 0) return;

                // Determine score class
                const scoreClass = breakdown.finalScore >= scoreThresholds.critical ? 'score-critical' :
                                   breakdown.finalScore >= scoreThresholds.high ? 'score-high' :
                                   breakdown.finalScore >= scoreThresholds.medium ? 'score-medium' :
                                   breakdown.finalScore >= scoreThresholds.low ? 'score-low' : 'score-info';

                // Create score badge element
                const badge = document.createElement('span');
                badge.className = 'score-badge ' + scoreClass;
                badge.textContent = breakdown.finalScore;
                badge.dataset.scoreBreakdown = JSON.stringify(breakdown);
                badge.title = 'Risk Score (click for details)';
                badge.addEventListener('click', function(e) {
                    e.stopPropagation();
                    showScoreTooltip(this, breakdown);
                });

                // Insert badge into finding-meta area (before chevron, after count)
                const meta = card.querySelector('.finding-meta');
                const chevron = meta?.querySelector('.finding-toggle');
                if (meta && chevron) {
                    meta.insertBefore(badge, chevron);
                }

                // Store score on the card element for sorting
                card.dataset.score = breakdown.finalScore;
            });
        }

        // Severity order for sorting (lower = more critical)
        const SEVERITY_ORDER = { 'finding': 0, 'hint': 1, 'note': 2, 'secure': 3 };

        // Sort all finding cards by score (descending), then by severity
        // Called once after populateCardScores() — sections are hidden, cards are flat-sorted
        function sortCardsByScore() {
            const container = document.getElementById('cardViewContainer');
            if (!container) return;

            const allCards = Array.from(container.querySelectorAll('.finding-card'));
            if (allCards.length === 0) return;

            const scoredCards = allCards.map(card => ({
                element: card,
                score: parseInt(card.dataset.score) || 0,
                severity: SEVERITY_ORDER[card.dataset.severity] ?? 99
            }));

            // Sort by score descending, then by severity
            scoredCards.sort((a, b) => {
                if (b.score !== a.score) return b.score - a.score;
                return a.severity - b.severity;
            });

            // Hide all sections (cards are shown flat)
            container.querySelectorAll('.section').forEach(s => s.style.display = 'none');

            // Append sorted cards directly to container
            scoredCards.forEach(item => container.appendChild(item.element));
        }

        function expandAllCards() {
            // Expand all finding cards
            document.querySelectorAll('.finding-card').forEach(card => {
                card.classList.add('expanded');
            });
            // Expand top priority actions
            const topActions = document.querySelector('.top-actions');
            if (topActions) {
                topActions.classList.remove('collapsed');
                updateTopActionsToggleIcon(topActions);
            }
        }

        function collapseAllCards() {
            // Collapse all finding cards
            document.querySelectorAll('.finding-card').forEach(card => {
                card.classList.remove('expanded');
            });
            // Collapse top priority actions
            const topActions = document.querySelector('.top-actions');
            if (topActions) {
                topActions.classList.add('collapsed');
                updateTopActionsToggleIcon(topActions);
            }
        }

        function toggleTopActions() {
            const topActions = document.querySelector('.top-actions');
            if (topActions) {
                topActions.classList.toggle('collapsed');
                updateTopActionsToggleIcon(topActions);
            }
        }

        function updateTopActionsToggleIcon(topActions) {
            const toggleIcon = topActions.querySelector('.toggle-icon');
            if (toggleIcon) {
                toggleIcon.innerHTML = topActions.classList.contains('collapsed') ? '&#9654;' : '&#9660;';
            }
        }

        // ============================================================
        // COPY BUTTON for Remediation
        // ============================================================

        function copyToClipboard(button, text) {
            navigator.clipboard.writeText(text).then(() => {
                button.classList.add('copied');
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                setTimeout(() => {
                    button.classList.remove('copied');
                    button.textContent = originalText;
                }, UI_CONSTANTS.COPY_FEEDBACK_DURATION);
            }).catch(err => {
                console.error('Failed to copy:', err);
                button.textContent = 'Failed';
                setTimeout(() => {
                    button.textContent = 'Copy';
                }, UI_CONSTANTS.COPY_FEEDBACK_DURATION);
            });
        }

        // ============================================================
        // DRAG & DROP Attribute Reordering
        // ============================================================

        function initAttributeDragAndDrop() {
            let draggedElement = null;

            document.addEventListener('dragstart', function(e) {
                if (e.target.classList.contains('attr-row') && e.target.draggable) {
                    draggedElement = e.target;
                    e.target.classList.add('dragging');
                    e.dataTransfer.effectAllowed = 'move';
                    e.dataTransfer.setData('text/html', e.target.innerHTML);
                }
            });

            document.addEventListener('dragend', function(e) {
                if (e.target.classList.contains('attr-row')) {
                    e.target.classList.remove('dragging');
                    // Remove all drag-over indicators
                    document.querySelectorAll('.attr-row.drag-over').forEach(el => {
                        el.classList.remove('drag-over');
                    });
                    draggedElement = null;
                }
            });

            document.addEventListener('dragover', function(e) {
                if (!draggedElement) return;

                const target = e.target.closest('.attr-row');
                if (!target || target === draggedElement) return;

                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';

                // Remove previous drag-over indicators
                document.querySelectorAll('.attr-row.drag-over').forEach(el => {
                    if (el !== target) el.classList.remove('drag-over');
                });

                // Add drag-over indicator to current target
                target.classList.add('drag-over');
            });

            document.addEventListener('drop', function(e) {
                if (!draggedElement) return;

                const target = e.target.closest('.attr-row');
                if (!target || target === draggedElement) return;

                e.preventDefault();
                e.stopPropagation();

                // Get target parent container
                const targetParent = target.parentNode;

                // Determine insertion position based on mouse Y position
                const targetRect = target.getBoundingClientRect();
                const midPoint = targetRect.top + (targetRect.height / 2);

                if (e.clientY < midPoint) {
                    // Insert before target
                    targetParent.insertBefore(draggedElement, target);
                } else {
                    // Insert after target
                    if (target.nextSibling) {
                        targetParent.insertBefore(draggedElement, target.nextSibling);
                    } else {
                        targetParent.appendChild(draggedElement);
                    }
                }

                // Remove drag-over indicator
                target.classList.remove('drag-over');

                // Update extended attributes counter after cross-container moves
                updateExtendedAttrCounters(draggedElement);
            });
        }

        // Update the "Show/Hide N more attribute(s)" counter after drag & drop
        function updateExtendedAttrCounters(movedElement) {
            // Find the closest object-body container
            const objectBody = movedElement.closest('.object-body');
            if (!objectBody) return;

            const extSection = objectBody.querySelector('.extended-attrs');
            const toggleBtn = objectBody.querySelector('.extended-attrs-toggle');
            if (!extSection || !toggleBtn) return;

            // Count remaining attr-rows in extended section
            const extCount = extSection.querySelectorAll(':scope > .attr-row').length;
            const textSpan = toggleBtn.querySelector('span:last-child');
            if (!textSpan) return;

            if (extCount === 0) {
                // No more extended attributes — hide toggle and section
                toggleBtn.style.display = 'none';
                extSection.style.display = 'none';
            } else {
                toggleBtn.style.display = '';
                // Update counter text, preserve Show/Hide prefix
                const currentText = textSpan.textContent;
                const prefix = currentText.startsWith('Hide') ? 'Hide' : 'Show';
                textSpan.textContent = prefix + ' ' + extCount + ' more attribute(s)';
            }
        }

        // ============================================================
        //  PRINT / PDF PREPARATION
        //  Ensures all content is expanded and a Table of Contents
        //  is generated before the browser renders the print layout.
        // ============================================================

        // State snapshot to restore after printing
        var printStateSnapshot = null;

        function preparePrint() {
            // Save current state so we can restore after printing
            printStateSnapshot = {
                expandedCards: [],
                collapsedTopActions: false,
                hiddenCompletedState: false
            };

            // Remember which cards were NOT expanded (so we can collapse them back)
            document.querySelectorAll('.finding-card:not(.expanded)').forEach(function(card) {
                printStateSnapshot.expandedCards.push(card);
            });

            // Remember top-actions state
            var topActions = document.querySelector('.top-actions');
            if (topActions && topActions.classList.contains('collapsed')) {
                printStateSnapshot.collapsedTopActions = true;
            }

            // Remember hide-completed state
            var hideToggle = document.getElementById('hideCompletedToggle');
            if (hideToggle && hideToggle.checked) {
                printStateSnapshot.hiddenCompletedState = true;
                hideToggle.checked = false;
                toggleHideCompleted();
            }

            // Expand ALL finding cards for print
            document.querySelectorAll('.finding-card').forEach(function(card) {
                card.classList.add('expanded');
            });

            // Expand top-actions
            if (topActions) {
                topActions.classList.remove('collapsed');
                updateTopActionsToggleIcon(topActions);
            }

            // Build Table of Contents from section headers
            buildPrintTOC();
        }

        function restoreAfterPrint() {
            if (!printStateSnapshot) return;

            // Collapse cards that were not expanded before print
            printStateSnapshot.expandedCards.forEach(function(card) {
                card.classList.remove('expanded');
            });

            // Restore top-actions collapsed state
            if (printStateSnapshot.collapsedTopActions) {
                var topActions = document.querySelector('.top-actions');
                if (topActions) {
                    topActions.classList.add('collapsed');
                    updateTopActionsToggleIcon(topActions);
                }
            }

            // Restore hide-completed state
            if (printStateSnapshot.hiddenCompletedState) {
                var hideToggle = document.getElementById('hideCompletedToggle');
                if (hideToggle) {
                    hideToggle.checked = true;
                    toggleHideCompleted();
                }
            }

            // Remove TOC
            var toc = document.getElementById('printTOC');
            if (toc) toc.remove();

            printStateSnapshot = null;
        }

        function buildPrintTOC() {
            // Remove existing TOC if any
            var existing = document.getElementById('printTOC');
            if (existing) existing.remove();

            var sections = document.querySelectorAll('.section');
            if (sections.length === 0) return;

            var toc = document.createElement('div');
            toc.id = 'printTOC';
            toc.className = 'print-toc';

            var tocTitle = document.createElement('div');
            tocTitle.className = 'print-toc-title';
            tocTitle.textContent = 'Table of Contents';
            toc.appendChild(tocTitle);

            // Build severity matrix table
            var table = document.createElement('table');
            table.className = 'print-toc-table';

            // Table header
            var thead = document.createElement('thead');
            var headerRow = document.createElement('tr');
            ['Section', 'Findings', 'Hints', 'Notes', 'Secure'].forEach(function(label) {
                var th = document.createElement('th');
                th.textContent = label;
                headerRow.appendChild(th);
            });
            thead.appendChild(headerRow);
            table.appendChild(thead);

            // Pre-build severity counts per section using data-category attribute
            // Note: Cards may be sorted flat outside their sections (sortCardsByScore),
            // so we use the card's data-category to map back to section IDs (cat-<category>)
            var sectionCounts = {};
            document.querySelectorAll('.finding-card[data-severity][data-category]').forEach(function(card) {
                var sid = 'cat-' + card.getAttribute('data-category');
                if (!sectionCounts[sid]) sectionCounts[sid] = { finding: 0, hint: 0, note: 0, secure: 0 };
                var sev = card.getAttribute('data-severity');
                if (sectionCounts[sid][sev] !== undefined) sectionCounts[sid][sev]++;
            });

            // Table body
            var tbody = document.createElement('tbody');
            var totals = { finding: 0, hint: 0, note: 0, secure: 0 };

            sections.forEach(function(section, index) {
                var titleEl = section.querySelector('.section-title');
                if (!titleEl) return;

                var sectionTitle = titleEl.textContent.trim();
                // Strip [N/M] prefix for cleaner display
                sectionTitle = sectionTitle.replace(/^\[\d+\/\d+\]\s*/, '');
                var sectionId = section.id;

                // Get pre-computed counts for this section
                var counts = sectionCounts[sectionId] || { finding: 0, hint: 0, note: 0, secure: 0 };

                // Accumulate totals
                totals.finding += counts.finding;
                totals.hint += counts.hint;
                totals.note += counts.note;
                totals.secure += counts.secure;

                // Determine highest severity for left border color
                var severity = counts.finding > 0 ? 'finding' : counts.hint > 0 ? 'hint' : counts.secure > 0 ? 'secure' : 'note';

                var row = document.createElement('tr');
                row.className = 'toc-severity-' + severity;

                // Section name cell with link
                var nameCell = document.createElement('td');
                nameCell.className = 'toc-section-name';
                var link = document.createElement('a');
                link.href = '#' + sectionId;
                link.textContent = (index + 1) + '. ' + sectionTitle;
                nameCell.appendChild(link);
                row.appendChild(nameCell);

                // Severity count cells
                [
                    { key: 'finding', cls: 'toc-cell-finding' },
                    { key: 'hint', cls: 'toc-cell-hint' },
                    { key: 'note', cls: 'toc-cell-note' },
                    { key: 'secure', cls: 'toc-cell-secure' }
                ].forEach(function(col) {
                    var td = document.createElement('td');
                    td.className = col.cls;
                    if (counts[col.key] > 0) {
                        td.textContent = counts[col.key];
                        td.classList.add('has-value');
                    } else {
                        td.textContent = '\u2013'; // en-dash
                        td.classList.add('no-value');
                    }
                    row.appendChild(td);
                });

                tbody.appendChild(row);
            });
            table.appendChild(tbody);

            // Table footer with totals
            var tfoot = document.createElement('tfoot');
            var footerRow = document.createElement('tr');

            var totalLabel = document.createElement('td');
            totalLabel.className = 'toc-section-name toc-total-label';
            totalLabel.textContent = 'Total';
            footerRow.appendChild(totalLabel);

            [
                { key: 'finding', cls: 'toc-cell-finding' },
                { key: 'hint', cls: 'toc-cell-hint' },
                { key: 'note', cls: 'toc-cell-note' },
                { key: 'secure', cls: 'toc-cell-secure' }
            ].forEach(function(col) {
                var td = document.createElement('td');
                td.className = col.cls;
                if (totals[col.key] > 0) {
                    td.textContent = totals[col.key];
                    td.classList.add('has-value');
                } else {
                    td.textContent = '\u2013';
                    td.classList.add('no-value');
                }
                footerRow.appendChild(td);
            });

            tfoot.appendChild(footerRow);
            table.appendChild(tfoot);

            toc.appendChild(table);

            // Insert TOC after info-bar, before card controls
            var infoBar = document.querySelector('.info-bar');
            if (infoBar && infoBar.parentNode) {
                infoBar.parentNode.insertBefore(toc, infoBar.nextSibling);
            }
        }

        // Register print event handlers
        window.addEventListener('beforeprint', preparePrint);
        window.addEventListener('afterprint', restoreAfterPrint);
