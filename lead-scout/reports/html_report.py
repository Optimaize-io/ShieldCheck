"""
HTML Dashboard Report Generator - Dark Ops Theme
Generates interactive HTML dashboards with modern cybersecurity styling.
"""

from typing import List, Optional
from datetime import datetime
import json
from pathlib import Path

from scoring.scorer import LeadScore, LeadTier


class HTMLReportGenerator:
    """
    Generates interactive HTML dashboards from lead scan results.
    Uses Dark Ops theme with Chart.js for visualizations.
    """
    
    def __init__(self):
        self.generated_at = datetime.now()
    
    def generate(self, leads: List[LeadScore], output_path: Optional[str] = None, json_data_path: Optional[str] = None) -> str:
        """
        Generate a complete HTML dashboard.
        
        Args:
            leads: List of scored leads
            output_path: Optional path to write HTML file
            json_data_path: Path to the JSON data file (for embedded data)
            
        Returns:
            Complete HTML dashboard as string
        """
        # Sort leads by score (lowest/worst first = hottest leads)
        sorted_leads = sorted(leads, key=lambda x: x.total_score)
        
        # Count by tier
        hot_count = sum(1 for l in leads if l.tier == LeadTier.HOT)
        warm_count = sum(1 for l in leads if l.tier == LeadTier.WARM)
        cool_count = sum(1 for l in leads if l.tier == LeadTier.COOL)
        
        # Prepare data for charts
        leads_data = [lead.to_dict() for lead in sorted_leads]
        
        # Generate HTML
        html = self._generate_html(
            leads_data=leads_data,
            total_companies=len(leads),
            hot_count=hot_count,
            warm_count=warm_count,
            cool_count=cool_count,
            generated_at=self.generated_at.strftime("%Y-%m-%d %H:%M")
        )
        
        # Write to file if path provided
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
        
        return html
    
    def generate_from_json(self, json_path: str, output_path: str) -> str:
        """
        Generate HTML dashboard from existing JSON data file.
        
        Args:
            json_path: Path to the report_data.json file
            output_path: Path to write HTML file
            
        Returns:
            Complete HTML dashboard as string
        """
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        html = self._generate_html(
            leads_data=data['leads'],
            total_companies=data['total_companies'],
            hot_count=data['summary']['hot_leads'],
            warm_count=data['summary']['warm_leads'],
            cool_count=data['summary']['cool_leads'],
            generated_at=data['generated_at'][:16].replace('T', ' ')
        )
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return html
    
    def _generate_html(
        self,
        leads_data: list,
        total_companies: int,
        hot_count: int,
        warm_count: int,
        cool_count: int,
        generated_at: str
    ) -> str:
        """Generate the complete HTML document with Dark Ops theme."""
        
        # Serialize leads data for JavaScript.
        # Keep the HTML report lean by not embedding full raw scan results (the PDF is the technical deep-dive).
        sanitized_leads = []
        for lead in leads_data:
            if isinstance(lead, dict):
                d = dict(lead)
                d.pop("raw_results", None)
                sanitized_leads.append(d)
            else:
                sanitized_leads.append(lead)

        leads_json = json.dumps(sanitized_leads, indent=2, ensure_ascii=False)
        
        # Calculate sector distribution
        sector_counts = {}
        for lead in leads_data:
            sector = lead.get('sector', 'Unknown')
            sector_counts[sector] = sector_counts.get(sector, 0) + 1
        
        sectors_json = json.dumps(sector_counts, ensure_ascii=False)
        
        # Calculate findings distribution for lead review
        findings_counts = {"High": 0, "Medium": 0, "Low": 0}
        for lead in leads_data:
            findings = int(lead.get("findings_count") or 0)
            if findings >= 6:
                findings_counts["High"] += 1
            elif findings >= 3:
                findings_counts["Medium"] += 1
            else:
                findings_counts["Low"] += 1

        findings_json = json.dumps(findings_counts, ensure_ascii=False)
        
        # Use string replacement to avoid conflicts with CSS curly braces
        html = self._get_html_template()
        html = html.replace('__GENERATED_AT__', generated_at)
        html = html.replace('__TOTAL_COMPANIES__', str(total_companies))
        html = html.replace('__HOT_COUNT__', str(hot_count))
        html = html.replace('__WARM_COUNT__', str(warm_count))
        html = html.replace('__COOL_COUNT__', str(cool_count))
        html = html.replace('__LEADS_JSON__', leads_json)
        html = html.replace('__SECTORS_JSON__', sectors_json)
        html = html.replace('__PRIORITY_JSON__', findings_json)
        return html
    
    def _get_html_template(self) -> str:
        """Return the Dark Ops HTML template with placeholders."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lead Scout — NIS2 Security Intelligence</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
''' + self._get_css() + '''
</style>
</head>
<body>
    <div class="dashboard">
        <!-- Header -->
        <header class="header">
            <div>
                <h1>Lead Scout Dashboard</h1>
                <p class="header-meta">NIS2 Compliance & Security Posture Analysis</p>
            </div>
            <div class="header-meta">
                <div>Generated: __GENERATED_AT__</div>
                <div>Powered by Nomios Lead Scout</div>
            </div>
        </header>
        
        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-icon">📊</div>
                <div class="stat-value">__TOTAL_COMPANIES__</div>
                <div class="stat-label">Companies Analyzed</div>
            </div>
            <div class="stat-card hot">
                <div class="stat-icon">🔥</div>
                <div class="stat-value">__HOT_COUNT__</div>
                <div class="stat-label">Hot Leads</div>
            </div>
            <div class="stat-card warm">
                <div class="stat-icon">⚡</div>
                <div class="stat-value">__WARM_COUNT__</div>
                <div class="stat-label">Warm Leads</div>
            </div>
            <div class="stat-card cool">
                <div class="stat-icon">✅</div>
                <div class="stat-value">__COOL_COUNT__</div>
                <div class="stat-label">Cool Leads</div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="charts-grid">
            <div class="chart-card">
                <h3>📊 Lead Distribution</h3>
                <div class="chart-container">
                    <canvas id="tierChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>🏢 Sector Distribution</h3>
                <div class="chart-container">
                    <canvas id="sectorChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>⚠️ Findings Severity</h3>
                <div class="chart-container">
                    <canvas id="priorityChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>📈 Score Distribution</h3>
                <div class="chart-container">
                    <canvas id="scoreChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Leads Table -->
        <div class="section">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem;">
                <h2>🏆 Lead Rankings</h2>
                <div class="export-buttons">
                    <button class="btn btn-secondary" onclick="exportCSV()">📥 Export CSV</button>
                </div>
            </div>
            
            <div class="filters">
                <div class="filter-group">
                    <label>Search</label>
                    <input type="text" id="searchInput" placeholder="Company or domain..." oninput="filterTable()">
                </div>
                <div class="filter-group">
                    <label>Tier</label>
                    <select id="tierFilter" onchange="filterTable()">
                        <option value="">All Tiers</option>
                        <option value="HOT">🔴 Hot</option>
                        <option value="WARM">🟠 Warm</option>
                        <option value="COOL">🟢 Cool</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Sector</label>
                    <select id="sectorFilter" onchange="filterTable()">
                        <option value="">All Sectors</option>
                    </select>
                </div>
            </div>
            
            <div style="overflow-x: auto;">
                <table class="leads-table" id="leadsTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable('rank')">Rank <span class="sort-indicator">↕</span></th>
                            <th onclick="sortTable('company')">Company <span class="sort-indicator">↕</span></th>
                            <th onclick="sortTable('domain')">Domain <span class="sort-indicator">↕</span></th>
                            <th onclick="sortTable('sector')">Sector <span class="sort-indicator">↕</span></th>
                            <th onclick="sortTable('employees')">Employees <span class="sort-indicator">↕</span></th>
                            <th onclick="sortTable('score')">Score <span class="sort-indicator">↕</span></th>
                            <th onclick="sortTable('tier')">Tier <span class="sort-indicator">↕</span></th>
                            <th onclick="sortTable('findings')">Findings <span class="sort-indicator">↕</span></th>
                            <th>Key Gap</th>
                        </tr>
                    </thead>
                    <tbody id="leadsTableBody">
                    </tbody>
                </table>
            </div>
            <div id="tableInfo" style="margin-top: 1rem; font-size: 0.875rem; color: var(--color-gray);"></div>
        </div>
    </div>
    
    <!-- Company Detail Modal -->
    <div class="company-modal" id="companyModal" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header">
                <div>
                    <h3 id="modalCompanyName">Company Name</h3>
                    <span id="modalTier" class="tier-badge"></span>
                </div>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="modalBody">
            </div>
        </div>
    </div>
    
    <script>
        // Lead data
        const leadsData = __LEADS_JSON__;
        
        // Sector counts for chart
        const sectorCounts = __SECTORS_JSON__;
        
        // Priority counts for chart
        const priorityCounts = __PRIORITY_JSON__;
        
''' + self._get_javascript() + '''
    </script>
</body>
</html>'''

    def _get_css(self) -> str:
        """Return the Dark Ops CSS styles."""
        return '''
/* ═══════════════════════════════════════════════════════════════
   LEAD SCOUT DASHBOARD — DARK OPS THEME
   Design: Military intelligence meets cybersecurity
   Typography: JetBrains Mono (data) + Outfit (UI)
   Colors: Matte black, electric cyan, ember red, signal green
   ═══════════════════════════════════════════════════════════════ */

@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Outfit:wght@300;400;500;600;700;800;900&display=swap');

:root {
    /* Core palette */
    --bg-void: #08090d;
    --bg-surface: #0e1117;
    --bg-elevated: #151921;
    --bg-card: #1a1f2b;
    --bg-hover: #222837;
    
    /* Borders */
    --border-subtle: rgba(255, 255, 255, 0.06);
    --border-default: rgba(255, 255, 255, 0.1);
    --border-focus: rgba(0, 225, 255, 0.4);
    
    /* Text */
    --text-primary: #e8edf5;
    --text-secondary: #8b95a8;
    --text-muted: #555e70;
    --text-inverse: #08090d;
    
    /* Accent: Cyber Cyan */
    --cyan: #00e1ff;
    --cyan-dim: #0099b3;
    --cyan-glow: rgba(0, 225, 255, 0.15);
    --cyan-glow-strong: rgba(0, 225, 255, 0.3);
    
    /* Status colors */
    --hot: #ff3b4e;
    --hot-dim: #cc2f3e;
    --hot-bg: rgba(255, 59, 78, 0.1);
    --hot-border: rgba(255, 59, 78, 0.25);
    --hot-glow: rgba(255, 59, 78, 0.2);
    
    --warm: #ff8c1a;
    --warm-dim: #cc7015;
    --warm-bg: rgba(255, 140, 26, 0.1);
    --warm-border: rgba(255, 140, 26, 0.25);
    --warm-glow: rgba(255, 140, 26, 0.2);
    
    --cool: #00e676;
    --cool-dim: #00b85c;
    --cool-bg: rgba(0, 230, 118, 0.1);
    --cool-border: rgba(0, 230, 118, 0.25);
    --cool-glow: rgba(0, 230, 118, 0.2);
    
    /* Spacing */
    --space-xs: 0.25rem;
    --space-sm: 0.5rem;
    --space-md: 1rem;
    --space-lg: 1.5rem;
    --space-xl: 2rem;
    --space-2xl: 3rem;
    
    /* Radius */
    --radius-sm: 6px;
    --radius-md: 10px;
    --radius-lg: 14px;
    --radius-xl: 20px;
    
    /* Shadows */
    --shadow-card: 0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px var(--border-subtle);
    --shadow-elevated: 0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px var(--border-subtle);
    --shadow-cyan: 0 0 20px var(--cyan-glow), 0 0 60px rgba(0, 225, 255, 0.05);
    
    /* Legacy variable mapping */
    --color-hot: var(--hot);
    --color-warm: var(--warm);
    --color-cool: var(--cool);
    --color-primary: var(--cyan);
    --color-dark: var(--text-primary);
    --color-gray: var(--text-secondary);
}

/* Reset & Base */
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Outfit', -apple-system, sans-serif;
    background: var(--bg-void);
    color: var(--text-primary);
    min-height: 100vh;
    overflow-x: hidden;
    -webkit-font-smoothing: antialiased;
}

/* Subtle grid texture */
body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image: 
        linear-gradient(rgba(0, 225, 255, 0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 225, 255, 0.02) 1px, transparent 1px);
    background-size: 60px 60px;
    pointer-events: none;
    z-index: 0;
}

/* Top-edge glow */
body::after {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0;
    height: 200px;
    background: radial-gradient(ellipse 80% 100% at 50% 0%, var(--cyan-glow) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
}

/* Animations */
@keyframes slideUp {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Layout */
.dashboard {
    max-width: 1500px;
    margin: 0 auto;
    padding: var(--space-xl);
    position: relative;
    z-index: 1;
}

/* Header */
.header {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-xl);
    padding: var(--space-lg) var(--space-xl);
    margin-bottom: var(--space-xl);
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-md);
    animation: slideUp 0.5s ease-out;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow-card);
}

.header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
}

.header h1 {
    font-family: 'Outfit', sans-serif;
    font-size: 1.75rem;
    font-weight: 800;
    color: var(--text-primary);
    letter-spacing: -0.03em;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}

.header h1::before {
    content: '◆';
    color: var(--cyan);
    font-size: 1.2rem;
}

.header-meta {
    color: var(--text-secondary);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    text-align: right;
}

.header-meta div:first-child {
    color: var(--text-primary);
    font-weight: 500;
}

/* Stat Cards */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: var(--space-md);
    margin-bottom: var(--space-xl);
}

@media (max-width: 900px) {
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 500px) {
    .stats-grid { grid-template-columns: 1fr; }
}

.stat-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
    text-align: center;
    transition: all 0.25s ease;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow-card);
    animation: slideUp 0.5s ease-out backwards;
}

.stat-card:nth-child(1) { animation-delay: 0.05s; }
.stat-card:nth-child(2) { animation-delay: 0.1s; }
.stat-card:nth-child(3) { animation-delay: 0.15s; }
.stat-card:nth-child(4) { animation-delay: 0.2s; }

.stat-card:hover {
    transform: translateY(-4px);
    border-color: var(--border-focus);
    box-shadow: var(--shadow-elevated);
}

.stat-card.total:hover { box-shadow: var(--shadow-cyan); }
.stat-card.hot:hover { box-shadow: 0 8px 32px var(--hot-glow); }
.stat-card.warm:hover { box-shadow: 0 8px 32px var(--warm-glow); }
.stat-card.cool:hover { box-shadow: 0 8px 32px var(--cool-glow); }

.stat-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2.75rem;
    font-weight: 700;
    line-height: 1;
}

.stat-card.total .stat-value { color: var(--cyan); }
.stat-card.hot .stat-value { color: var(--hot); }
.stat-card.warm .stat-value { color: var(--warm); }
.stat-card.cool .stat-value { color: var(--cool); }

.stat-label {
    color: var(--text-secondary);
    font-size: 0.8rem;
    font-weight: 500;
    margin-top: var(--space-sm);
    text-transform: uppercase;
    letter-spacing: 0.06em;
}

.stat-icon { font-size: 1.25rem; margin-bottom: var(--space-xs); }

/* Charts */
.charts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: var(--space-md);
    margin-bottom: var(--space-xl);
}

.chart-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
    box-shadow: var(--shadow-card);
    transition: all 0.25s ease;
}

.chart-card:hover {
    border-color: var(--border-focus);
    box-shadow: var(--shadow-elevated);
    transform: translateY(-2px);
}

.chart-card h3 {
    font-family: 'Outfit', sans-serif;
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: var(--space-md);
}

.chart-container {
    height: 200px;
    position: relative;
}

/* Section */
.section {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-xl);
    padding: var(--space-xl);
    margin-bottom: var(--space-xl);
    box-shadow: var(--shadow-card);
}

.section h2 {
    font-family: 'Outfit', sans-serif;
    font-size: 1.2rem;
    font-weight: 700;
    color: var(--text-primary);
}

/* Filters */
.filters {
    display: flex;
    gap: var(--space-md);
    margin-bottom: var(--space-lg);
    flex-wrap: wrap;
}

.filter-group label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: var(--text-muted);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    display: block;
    margin-bottom: 0.25rem;
}

.filter-group select,
.filter-group input {
    padding: 0.6rem 0.9rem;
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    font-size: 0.8rem;
    font-family: 'Outfit', sans-serif;
    min-width: 160px;
    background: var(--bg-elevated);
    color: var(--text-primary);
    transition: all 0.2s ease;
}

.filter-group select:focus,
.filter-group input:focus {
    outline: none;
    border-color: var(--cyan);
    box-shadow: 0 0 0 3px var(--cyan-glow);
}

.filter-group select option {
    background: var(--bg-card);
    color: var(--text-primary);
}

/* Buttons */
.btn {
    padding: 0.6rem 1rem;
    border-radius: var(--radius-sm);
    font-family: 'Outfit', sans-serif;
    font-size: 0.8rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    border: 1px solid var(--border-default);
}

a.btn {
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}

.btn-primary {
    background: var(--cyan);
    color: var(--text-inverse);
    border-color: rgba(0, 225, 255, 0.35);
}

.btn-primary:hover {
    background: #00c6e1;
    border-color: var(--cyan);
    box-shadow: 0 0 0 3px var(--cyan-glow);
}

.btn-secondary {
    background: var(--bg-elevated);
    color: var(--text-primary);
}

.btn-secondary:hover {
    background: var(--bg-hover);
    border-color: var(--cyan);
}

/* Table */
.leads-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 0.825rem;
}

.leads-table th {
    background: var(--bg-elevated);
    padding: 0.85rem 1rem;
    text-align: left;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border-default);
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    text-transform: uppercase;
    font-size: 0.65rem;
    letter-spacing: 0.08em;
    transition: color 0.2s;
}

.leads-table th:first-child { border-radius: var(--radius-md) 0 0 0; }
.leads-table th:last-child { border-radius: 0 var(--radius-md) 0 0; }

.leads-table th:hover {
    color: var(--cyan);
    background: var(--bg-hover);
}

.leads-table td {
    padding: 0.85rem 1rem;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-primary);
    font-size: 0.825rem;
}

.leads-table tbody tr {
    transition: all 0.15s ease;
    cursor: pointer;
}

.leads-table tbody tr:hover {
    background: var(--bg-hover);
}

/* Tier Badges */
.tier-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
    padding: 0.3rem 0.7rem;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.tier-badge.hot {
    background: var(--hot-bg);
    color: var(--hot);
    border: 1px solid var(--hot-border);
}

.tier-badge.warm {
    background: var(--warm-bg);
    color: var(--warm);
    border: 1px solid var(--warm-border);
}

.tier-badge.cool {
    background: var(--cool-bg);
    color: var(--cool);
    border: 1px solid var(--cool-border);
}

/* Score Bar */
.score-bar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.score-bar span {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    white-space: nowrap;
}

.score-bar-bg {
    flex: 1;
    height: 6px;
    background: var(--bg-elevated);
    border-radius: 3px;
    overflow: hidden;
    min-width: 60px;
}

.score-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.3s ease;
}

.score-bar-fill.low {
    background: var(--hot);
    box-shadow: 0 0 8px var(--hot-glow);
}

.score-bar-fill.medium {
    background: var(--warm);
    box-shadow: 0 0 8px var(--warm-glow);
}

.score-bar-fill.high {
    background: var(--cool);
    box-shadow: 0 0 8px var(--cool-glow);
}

/* Findings Count Badge */
.findings-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 2rem;
    height: 1.75rem;
    padding: 0 0.5rem;
    border-radius: 9999px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    font-weight: 600;
}

.findings-count.high {
    background: var(--hot-bg);
    color: var(--hot);
    border: 1px solid var(--hot-border);
}

.findings-count.medium {
    background: var(--warm-bg);
    color: var(--warm);
    border: 1px solid var(--warm-border);
}

.findings-count.low {
    background: var(--cool-bg);
    color: var(--cool);
    border: 1px solid var(--cool-border);
}

/* Modal */
.company-modal {
    position: fixed;
    inset: 0;
    background: rgba(8, 9, 13, 0.85);
    backdrop-filter: blur(12px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    opacity: 0;
    visibility: hidden;
    transition: all 0.3s ease;
    padding: var(--space-lg);
}

.company-modal.active {
    opacity: 1;
    visibility: visible;
}

.modal-content {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-xl);
    width: 100%;
    max-width: 900px;
    max-height: 90vh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    box-shadow: 0 32px 64px rgba(0, 0, 0, 0.6), var(--shadow-cyan);
}

.modal-header {
    padding: var(--space-lg) var(--space-xl);
    border-bottom: 1px solid var(--border-default);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.modal-header h3 {
    font-family: 'Outfit', sans-serif;
    font-size: 1.35rem;
    font-weight: 800;
    color: var(--text-primary);
}

.modal-close {
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-secondary);
    width: 36px;
    height: 36px;
    border-radius: var(--radius-sm);
    font-size: 1.25rem;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    justify-content: center;
}

.modal-close:hover {
    background: var(--hot);
    color: white;
    border-color: var(--hot);
}

.modal-body {
    padding: var(--space-xl);
    overflow-y: auto;
    flex: 1;
}

/* Modal Company Info */
.company-info {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: var(--space-sm);
    margin-bottom: var(--space-xl);
}

.info-item {
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-md);
}

.info-item label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.6rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    display: block;
    margin-bottom: 0.25rem;
}

.info-item .value {
    color: var(--text-primary);
    font-weight: 500;
    font-size: 0.9rem;
}

/* Score Grid */
.score-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: var(--space-sm);
    margin-bottom: var(--space-xl);
}

.score-item {
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-md);
}

.score-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.25rem;
}

.score-name {
    font-size: 0.8rem;
    font-weight: 500;
}

.score-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: var(--text-secondary);
}

.score-dot {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-left: 0.5rem;
    box-shadow: 0 0 0 2px rgba(255,255,255,0.06);
}
.score-dot.score-risk { background: var(--hot); }
.score-dot.score-warning { background: var(--warm); }
.score-dot.score-ok { background: var(--cool); }
.score-dot.score-unknown { background: var(--text-muted); }

/* Findings Sections */
.findings-section {
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-md);
    margin-bottom: var(--space-md);
}

.findings-section h4 {
    font-size: 0.9rem;
    font-weight: 600;
    margin-bottom: var(--space-sm);
    color: var(--text-primary);
}

.finding-item {
    padding: 0.5rem;
    margin: 0.25rem 0;
    border-radius: var(--radius-sm);
    font-size: 0.825rem;
}

.finding-item.gap {
    background: var(--hot-bg);
    border-left: 3px solid var(--hot);
    color: var(--text-primary);
}

.finding-item.sales {
    background: var(--cyan-glow);
    border-left: 3px solid var(--cyan);
    color: var(--text-primary);
}

/* Dimension Overview (Present vs Missing) */
.dimension-overview .dimension-block {
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-md);
    margin-top: var(--space-sm);
}

.dimension-overview .dimension-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: var(--space-sm);
    font-weight: 600;
}

.dimension-overview .dimension-score {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: var(--text-secondary);
    white-space: nowrap;
}

.dimension-overview .dimension-row {
    margin-bottom: var(--space-sm);
}

.dimension-overview .dimension-row:last-child {
    margin-bottom: 0;
}

.dimension-overview .dimension-row label {
    font-size: 0.7rem;
    color: var(--text-secondary);
    font-weight: 500;
    display: block;
    margin-bottom: var(--space-xs);
}

/* Technical Details */
.technical-details h4 {
    color: var(--text-primary);
}

.tech-section {
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-sm);
    overflow: hidden;
}

.tech-header {
    padding: var(--space-md);
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    font-weight: 500;
    transition: background 0.2s;
}

.tech-header:hover {
    background: var(--bg-hover);
}

.tech-toggle {
    color: var(--text-muted);
    font-size: 0.75rem;
}

.tech-content {
    padding: var(--space-md);
    border-top: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
}

.tech-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: var(--space-sm);
    margin-bottom: var(--space-md);
}

.tech-item {
    background: var(--bg-card);
    border-radius: var(--radius-sm);
    padding: var(--space-sm);
}

.tech-item label {
    font-size: 0.65rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    display: block;
    margin-bottom: 0.2rem;
}

.tech-value {
    font-weight: 500;
    font-size: 0.825rem;
}

.tech-value.urgent { color: var(--hot); font-weight: 700; }
.tech-value.warning { color: var(--warm); }
.tech-value.good { color: var(--cool); }
.tech-value.risky { color: var(--hot); }

.tech-value.grade-A, .tech-value.grade-B { color: var(--cool); font-weight: 700; }
.tech-value.grade-C, .tech-value.grade-D { color: var(--warm); font-weight: 700; }
.tech-value.grade-E, .tech-value.grade-F { color: var(--hot); font-weight: 700; }

.tech-subsection {
    margin-bottom: var(--space-md);
}

.tech-subsection label {
    font-size: 0.7rem;
    color: var(--text-secondary);
    font-weight: 500;
    display: block;
    margin-bottom: var(--space-xs);
}

.tech-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
}

.tech-tag {
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
}

.tech-tag.risky {
    background: var(--hot-bg);
    border-color: var(--hot-border);
    color: var(--hot);
}

.tech-tag.good {
    background: var(--cool-bg);
    border-color: var(--cool-border);
    color: var(--cool);
}

.tech-list {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.tech-list-item {
    padding: 0.4rem 0.6rem;
    background: var(--bg-card);
    border-radius: var(--radius-sm);
    font-size: 0.8rem;
    border-left: 3px solid var(--border-default);
}

.tech-list-item.risky {
    border-left-color: var(--hot);
    background: var(--hot-bg);
}

.tech-list-item.good {
    border-left-color: var(--cool);
    background: var(--cool-bg);
}

.tech-list-item.cve {
    border-left-color: var(--hot);
    color: var(--hot);
    text-decoration: none;
}

.tech-list-item a {
    color: var(--cyan);
    text-decoration: none;
}

.tech-none {
    color: var(--text-secondary);
    font-size: 0.8rem;
    padding: var(--space-sm);
}

/* NIS2 Badge */
.nis2-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.3rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.nis2-badge.covered {
    background: var(--hot-bg);
    color: var(--hot);
    border: 1px solid var(--hot-border);
}

.nis2-badge.not-covered {
    background: var(--cool-bg);
    color: var(--cool);
    border: 1px solid var(--cool-border);
}

/* Table info */
#tableInfo {
    color: var(--text-muted) !important;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem !important;
}
'''

    def _get_javascript(self) -> str:
        """Return the JavaScript for interactivity."""
        return '''
        // State
        let filteredLeads = [...leadsData];
        let currentSort = { column: 'rank', direction: 'asc' };
        
        // Populate sector filter
        const sectorSelect = document.getElementById('sectorFilter');
        Object.keys(sectorCounts).sort().forEach(sector => {
            const opt = document.createElement('option');
            opt.value = sector;
            opt.textContent = sector;
            sectorSelect.appendChild(opt);
        });
        
        // Render table
        function renderTable() {
            const tbody = document.getElementById('leadsTableBody');
            tbody.innerHTML = '';
            
            filteredLeads.forEach((lead, index) => {
                const row = document.createElement('tr');
                const tierClass = lead.tier.includes('HOT') ? 'hot' : lead.tier.includes('WARM') ? 'warm' : 'cool';
                const tierText = lead.tier.includes('HOT') ? 'HOT' : lead.tier.includes('WARM') ? 'WARM' : 'COOL';
                const scorePercent = (lead.total_score / lead.max_score) * 100;
                const scoreClass = scorePercent <= 33 ? 'low' : scorePercent <= 66 ? 'medium' : 'high';
                
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td><strong>${lead.company_name}</strong></td>
                    <td>${lead.domain}</td>
                    <td>${lead.sector.substring(0, 20)}${lead.sector.length > 20 ? '...' : ''}</td>
                    <td>${lead.employees.toLocaleString()}</td>
                    <td>
                        <div class="score-bar">
                            <span>${lead.total_score}/${Math.round(lead.max_score)}</span>
                            <div class="score-bar-bg">
                                <div class="score-bar-fill ${scoreClass}" style="width: ${scorePercent}%"></div>
                            </div>
                        </div>
                    </td>
                    <td><span class="tier-badge ${tierClass}">${tierText}</span></td>
                    <td><span class="findings-count ${(lead.findings_count || 0) > 5 ? 'high' : (lead.findings_count || 0) > 2 ? 'medium' : 'low'}">${lead.findings_count || 0}</span></td>
                    <td>${lead.key_gaps[0] || '-'}</td>
                `;
                row.onclick = () => openModal(lead);
                tbody.appendChild(row);
            });
            
            document.getElementById('tableInfo').textContent = 
                `Showing ${filteredLeads.length} of ${leadsData.length} companies`;
        }
        
        // Filter table
        function filterTable() {
            const search = document.getElementById('searchInput').value.toLowerCase();
            const tier = document.getElementById('tierFilter').value;
            const sector = document.getElementById('sectorFilter').value;
            
            filteredLeads = leadsData.filter(lead => {
                const matchesSearch = !search || 
                    lead.company_name.toLowerCase().includes(search) ||
                    lead.domain.toLowerCase().includes(search);
                const matchesTier = !tier || lead.tier.includes(tier);
                const matchesSector = !sector || lead.sector === sector;
                
                return matchesSearch && matchesTier && matchesSector;
            });
            
            sortLeads();
            renderTable();
        }
        
        // Sort table
        function sortTable(column) {
            if (currentSort.column === column) {
                currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort.column = column;
                currentSort.direction = 'asc';
            }
            sortLeads();
            renderTable();
        }
        
        function sortLeads() {
            filteredLeads.sort((a, b) => {
                let aVal, bVal;
                switch (currentSort.column) {
                    case 'rank':
                    case 'score':
                        aVal = a.total_score;
                        bVal = b.total_score;
                        break;
                    case 'company':
                        aVal = a.company_name.toLowerCase();
                        bVal = b.company_name.toLowerCase();
                        break;
                    case 'domain':
                        aVal = a.domain.toLowerCase();
                        bVal = b.domain.toLowerCase();
                        break;
                    case 'sector':
                        aVal = a.sector.toLowerCase();
                        bVal = b.sector.toLowerCase();
                        break;
                    case 'employees':
                        aVal = a.employees;
                        bVal = b.employees;
                        break;
                    case 'tier':
                        aVal = a.tier.includes('HOT') ? 0 : a.tier.includes('WARM') ? 1 : 2;
                        bVal = b.tier.includes('HOT') ? 0 : b.tier.includes('WARM') ? 1 : 2;
                        break;
                    case 'findings':
                        aVal = a.findings_count || 0;
                        bVal = b.findings_count || 0;
                        break;
                    default:
                        aVal = a.total_score;
                        bVal = b.total_score;
                }
                
                if (currentSort.direction === 'asc') {
                    return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
                } else {
                    return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
                }
            });
        }
        
        // Modal functions
        function openModal(lead) {
          try {
            const modal = document.getElementById('companyModal');
            const tierClass = lead.tier.includes('HOT') ? 'hot' : lead.tier.includes('WARM') ? 'warm' : 'cool';
            const tierText = lead.tier.includes('HOT') ? '🔴 HOT' : lead.tier.includes('WARM') ? '🟠 WARM' : '🟢 COOL';
            
            document.getElementById('modalCompanyName').textContent = lead.company_name;
            const tierBadge = document.getElementById('modalTier');
            tierBadge.textContent = tierText;
            tierBadge.className = 'tier-badge ' + tierClass;
            
            const body = document.getElementById('modalBody');
            const raw = lead.raw_results || {};
            const pdfFilename = 'security_report_' + String(lead.domain || '').replace(/\\./g, '_') + '.pdf';
            const pdfHref = 'pdfs/' + pdfFilename;

            const dimensionOverviewHtml = (() => {
                const scores = lead.scores || {};
                const blocks = Object.entries(scores).map(([key, dim]) => {
                    if (!dim || dim.analyzed === false) return '';
                    const present = (dim.present || []).filter(Boolean);
                    const missing = (dim.missing || []).filter(Boolean);
                    if (present.length === 0 && missing.length === 0) return '';

                    const name = key.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
                    const scoreText = (typeof dim.score === 'number' && typeof dim.max_score === 'number')
                        ? `${dim.score}/${dim.max_score}`
                        : 'N/A';

                    const presentMax = 6;
                    const missingMax = 10;

                    const presentHtml = present.length > 0
                        ? present.slice(0, presentMax).map(item => `<span class="tech-tag good">${item}</span>`).join('') +
                          (present.length > presentMax ? `<span class="tech-tag">+${present.length - presentMax} more</span>` : '')
                        : `<span class="tech-tag">—</span>`;

                    const missingHtml = missing.length > 0
                        ? missing.slice(0, missingMax).map(item => `<span class="tech-tag risky">${item}</span>`).join('') +
                          (missing.length > missingMax ? `<span class="tech-tag risky">+${missing.length - missingMax} more</span>` : '')
                        : `<span class="tech-tag good">None found</span>`;

                    return `
                        <div class="dimension-block">
                            <div class="dimension-header">
                                <span>${name}</span>
                                <span class="dimension-score">${scoreText}</span>
                            </div>
                            <div class="dimension-row">
                                <label>Already in place</label>
                                <div class="tech-tags">${presentHtml}</div>
                            </div>
                            <div class="dimension-row">
                                <label>What needs attention</label>
                                <div class="tech-tags">${missingHtml}</div>
                            </div>
                        </div>
                    `;
                }).filter(Boolean).join('');

                if (!blocks) return '';
                return `
                    <div class="findings-section dimension-overview">
                        <h4>✅ Present vs Missing</h4>
                        ${blocks}
                    </div>
                `;
            })();
            
            body.innerHTML = `
                <div class="company-info">
                    <div class="info-item">
                        <label>Domain</label>
                        <div class="value"><a href="https://${lead.domain}" target="_blank">${lead.domain}</a></div>
                    </div>
                    <div class="info-item">
                        <label>Sector</label>
                        <div class="value">${lead.sector}</div>
                    </div>
                    <div class="info-item">
                        <label>Employees</label>
                        <div class="value">~${lead.employees.toLocaleString()}</div>
                    </div>
                    <div class="info-item">
                        <label>Overall Score</label>
                        <div class="value">${lead.total_score}/${Math.round(lead.max_score)}</div>
                    </div>
                </div>
                
                ${lead.key_gaps.length > 0 ? `
                    <div class="findings-section">
                        <h4>ðŸš¨ Key Gaps</h4>
                        ${lead.key_gaps.map(gap => `<div class="finding-item gap">${gap}</div>`).join('')}
                    </div>
                ` : ''}
                
                ${''}
                
                <div class="score-grid">
                    <h4 style="grid-column: 1 / -1; margin-bottom: 0.5rem;">📊 Score Breakdown</h4>
                    ${Object.entries(lead.scores).map(([key, val]) => {
                        const emoji = val.score === 0 ? '🔴' : val.score === 1 ? '🟡' : '🟢';
                        const name = key.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
                        const analyzed = val.analyzed !== false;
                        const scoreText = analyzed && typeof val.score === 'number' && typeof val.max_score === 'number' ? `${val.score}/${val.max_score}` : 'N/A';
                        const status = (() => {
                            if (!analyzed) return 'unknown';
                            const s = val.score;
                            const m = val.max_score;
                            if (typeof s === 'number' && typeof m === 'number' && m > 0) {
                                if (s >= m) return 'ok';
                                if (s > 0) return 'warning';
                                return 'risk';
                            }
                            if (typeof s === 'number') {
                                if (s <= 0) return 'risk';
                                if (s === 1) return 'warning';
                                return 'ok';
                            }
                            return 'unknown';
                        })();
                        return `
                            <div class="score-item">
                                <div class="score-header">
                                    <span class="score-name">${name}</span>
                                    <span class="score-value">${scoreText}</span>
                                    <span class="score-dot score-${status}"></span>
                                </div>
                                <div style="font-size: 0.75rem; color: var(--text-secondary);">${val.description}</div>
                            </div>
                        `;
                    }).join('')}
                </div>
                
                ${dimensionOverviewHtml}
                
                ${false ? `
                    <div class="findings-section">
                        <h4>🚨 Key Gaps</h4>
                        ${lead.key_gaps.map(gap => `<div class="finding-item gap">${gap}</div>`).join('')}
                    </div>
                ` : ''}
                
                ${lead.sales_angles.length > 0 ? `
                    <div class="findings-section">
                        <h4>💼 Recommended Sales Approach</h4>
                        ${lead.sales_angles.map((angle, i) => `<div class="finding-item sales">${i + 1}. ${angle}</div>`).join('')}
                    </div>
                ` : ''}
                
                <!-- Technical Details -->
                <div class="technical-details">
                    <h4 style="margin-top: 1.5rem; margin-bottom: 1rem;">🔬 Detailed Technical Analysis</h4>
                    
                    <!-- DNS/Email Security -->
                    ${raw.dns ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>📧 Email Security (DNS)</span>
                            <span class="tech-toggle">▼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>SPF Policy</label>
                                    <span class="tech-value ${raw.dns.spf?.score === 2 ? 'good' : raw.dns.spf?.score === 1 ? 'warning' : 'urgent'}">${raw.dns.spf?.policy || 'Not configured'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>DMARC Policy</label>
                                    <span class="tech-value ${raw.dns.dmarc?.score === 2 ? 'good' : raw.dns.dmarc?.score === 1 ? 'warning' : 'urgent'}">${raw.dns.dmarc?.policy || 'Not configured'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>DKIM</label>
                                    <span class="tech-value ${raw.dns.dkim?.found ? 'good' : 'urgent'}">${raw.dns.dkim?.found ? '✅ Configured' : '❌ Not found'}</span>
                                </div>
                            </div>
                            ${raw.dns.findings?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Findings</label>
                                <div class="tech-list">
                                    ${raw.dns.findings.map(f => `<div class="tech-list-item">${f}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Shodan -->
                    ${raw.shodan ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>🌐 Internet Exposure (Shodan)</span>
                            <span class="tech-toggle">▼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>IP Address</label>
                                    <span class="tech-value">${raw.shodan.ip_address || 'Unknown'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Indexed in Shodan</label>
                                    <span class="tech-value">${raw.shodan.not_indexed ? '✅ No' : '❌ Yes'}</span>
                                </div>
                            </div>
                            <div class="tech-subsection">
                                <label>Open Ports (${raw.shodan.ports?.length || 0})</label>
                                <div class="tech-tags">
                                    ${raw.shodan.ports?.length > 0 
                                        ? raw.shodan.ports.map(p => `<span class="tech-tag ${raw.shodan.risky_ports?.includes(p) ? 'risky' : ''}">${p}</span>`).join('')
                                        : '<span class="tech-none">No open ports detected</span>'
                                    }
                                </div>
                            </div>
                            ${raw.shodan.vulns?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>🔓 Vulnerabilities (CVEs)</label>
                                <div class="tech-list">
                                    ${raw.shodan.vulns.map(cve => 
                                        `<a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" class="tech-list-item cve">${cve}</a>`
                                    ).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- SSL -->
                    ${raw.ssl ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>🔒 SSL/TLS Certificate</span>
                            <span class="tech-toggle">▼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>Has SSL</label>
                                    <span class="tech-value">${raw.ssl.has_ssl ? '✅ Yes' : '❌ No'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Certificate Valid</label>
                                    <span class="tech-value">${raw.ssl.certificate_valid ? '✅ Yes' : '❌ No'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Issuer</label>
                                    <span class="tech-value">${raw.ssl.issuer || 'Unknown'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Days Until Expiry</label>
                                    <span class="tech-value ${raw.ssl.days_until_expiry <= 30 ? 'urgent' : raw.ssl.days_until_expiry <= 90 ? 'warning' : ''}">${raw.ssl.days_until_expiry} days</span>
                                </div>
                                <div class="tech-item">
                                    <label>Protocol</label>
                                    <span class="tech-value">${raw.ssl.protocol_version || 'Unknown'}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- HTTP Headers -->
                    ${raw.headers ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>🛡️ HTTP Security Headers</span>
                            <span class="tech-toggle">▼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>Overall Grade</label>
                                    <span class="tech-value grade-${raw.headers.grade || 'F'}">${raw.headers.grade || 'N/A'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Headers Present</label>
                                    <span class="tech-value">${Object.values(raw.headers.headers_present || {}).filter(v => v).length}/6</span>
                                </div>
                            </div>
                            ${raw.headers.headers_missing?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Missing Headers</label>
                                <div class="tech-tags">
                                    ${raw.headers.headers_missing.map(h => `<span class="tech-tag risky">${h}</span>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.headers.info_leakage && Object.keys(raw.headers.info_leakage).length > 0 ? `
                            <div class="tech-subsection">
                                <label>⚠️ Information Leakage</label>
                                <div class="tech-list">
                                    ${Object.entries(raw.headers.info_leakage).map(([k, v]) => `<div class="tech-list-item risky">${k}: ${v}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Cookies -->
                    ${raw.cookies ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>🍪 Cookie & GDPR Compliance</span>
                            <span class="tech-toggle">▼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>Compliance Status</label>
                                    <span class="tech-value ${raw.cookies.compliance_status === 'COMPLIANT' ? 'good' : 'risky'}">${raw.cookies.compliance_status || 'Unknown'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Consent Banner</label>
                                    <span class="tech-value">${raw.cookies.consent_banner_detected ? '✅ Detected' : '❌ Not Found'}</span>
                                </div>
                            </div>
                            ${raw.cookies.tracking_cookies?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>⚠️ Tracking Cookies (${raw.cookies.tracking_cookies.length})</label>
                                <div class="tech-tags">
                                    ${raw.cookies.tracking_cookies.map(c => `<span class="tech-tag risky">${c}</span>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Subdomains -->
                    ${raw.subdomains ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>🔍 Attack Surface (Subdomains)</span>
                            <span class="tech-toggle">▼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>Total Subdomains</label>
                                    <span class="tech-value">${raw.subdomains.total_count || 0}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Risky Subdomains</label>
                                    <span class="tech-value ${(raw.subdomains.risky_count || 0) > 0 ? 'risky' : 'good'}">${raw.subdomains.risky_count || 0}</span>
                                </div>
                            </div>
                            ${raw.subdomains.risky_subdomains?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>⚠️ Risky Subdomains</label>
                                <div class="tech-list">
                                    ${raw.subdomains.risky_subdomains.map(s => 
                                        `<div class="tech-list-item risky">${s.subdomain || s} ${s.reasons ? `<span style="color: var(--text-secondary);">(${s.reasons.join(', ')})</span>` : ''}</div>`
                                    ).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Tech Stack -->
                    ${raw.techstack ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>⚙️ Technology Stack</span>
                            <span class="tech-toggle">▼</span>
                        </div>
                        <div class="tech-content">
                            ${raw.techstack.cms_detected ? `
                            <div class="tech-subsection">
                                <label>CMS Detected</label>
                                <span class="tech-value">${raw.techstack.cms_detected}</span>
                            </div>
                            ` : ''}
                            ${raw.techstack.version_leaks?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>⚠️ Version Leaks</label>
                                <div class="tech-list">
                                    ${raw.techstack.version_leaks.map(v => `<div class="tech-list-item risky">${typeof v === 'object' ? v.header + ': ' + v.value : v}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.techstack.outdated_software?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>🚨 Outdated Software</label>
                                <div class="tech-list">
                                    ${raw.techstack.outdated_software.map(sw => 
                                        `<div class="tech-list-item cve">${sw.software} ${sw.version} - ${sw.issue || sw.risk || 'Unknown'}</div>`
                                    ).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Admin -->
                    ${raw.admin ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>🔐 Admin Panel Security</span>
                            <span class="tech-toggle">▼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>Admin Pages Found</label>
                                    <span class="tech-value">${(raw.admin.admin_pages_found?.length || 0) + (raw.admin.login_pages_found?.length || 0)}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Without MFA</label>
                                    <span class="tech-value ${raw.admin.exposed_without_mfa > 0 ? 'urgent' : ''}">${raw.admin.exposed_without_mfa || 0}</span>
                                </div>
                            </div>
                            ${raw.admin.sso_providers_detected?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>✅ SSO Providers</label>
                                <div class="tech-tags">
                                    ${raw.admin.sso_providers_detected.map(p => `<span class="tech-tag good">${p}</span>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Jobs -->
                    ${false && raw.jobs ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>Security Hiring Signals</span>
                            <span class="tech-toggle">â–¼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>Jobs Page Found</label>
                                    <span class="tech-value ${raw.jobs.jobs_page_found ? 'good' : 'urgent'}">${raw.jobs.jobs_page_found ? 'Yes' : 'No'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Security Keywords Found</label>
                                    <span class="tech-value ${raw.jobs.security_jobs_found > 0 ? 'good' : raw.jobs.jobs_page_found ? 'warning' : 'urgent'}">${raw.jobs.security_jobs_found || 0}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Total Listings (approx.)</label>
                                    <span class="tech-value">${raw.jobs.total_jobs_found || 0}</span>
                                </div>
                            </div>
                            ${raw.jobs.jobs_page_url ? `
                            <div class="tech-subsection">
                                <label>Jobs Page</label>
                                <div class="tech-list">
                                    <a href="${raw.jobs.jobs_page_url}" target="_blank" class="tech-list-item">${raw.jobs.jobs_page_url}</a>
                                </div>
                            </div>
                            ` : ''}
                            ${raw.jobs.security_job_titles?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Security Role Matches</label>
                                <div class="tech-list">
                                    ${raw.jobs.security_job_titles.map(t => `<div class="tech-list-item">${t}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.jobs.findings?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Findings</label>
                                <div class="tech-list">
                                    ${raw.jobs.findings.map(f => `<div class="tech-list-item">${f}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Website -->
                    ${false && raw.website ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>Website Signals (Security & NIS2)</span>
                            <span class="tech-toggle">â–¼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>Security Page</label>
                                    <span class="tech-value ${raw.website.has_security_page ? 'good' : 'warning'}">${raw.website.has_security_page ? 'Yes' : 'No'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Privacy Page</label>
                                    <span class="tech-value ${raw.website.has_privacy_page ? 'good' : 'warning'}">${raw.website.has_privacy_page ? 'Yes' : 'No'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>NIS2 Keywords</label>
                                    <span class="tech-value ${raw.website.nis2_keywords_found?.length > 0 ? 'good' : ''}">${raw.website.nis2_keywords_found?.length || 0}</span>
                                </div>
                            </div>
                            ${raw.website.security_keywords_found?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Security Keywords</label>
                                <div class="tech-tags">
                                    ${raw.website.security_keywords_found.slice(0, 20).map(k => `<span class="tech-tag">${k}</span>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.website.nis2_keywords_found?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>NIS2 Keywords</label>
                                <div class="tech-tags">
                                    ${raw.website.nis2_keywords_found.slice(0, 20).map(k => `<span class="tech-tag good">${k}</span>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.website.sector_indicators && Object.keys(raw.website.sector_indicators).length > 0 ? `
                            <div class="tech-subsection">
                                <label>Sector Indicators</label>
                                <div class="tech-list">
                                    ${Object.entries(raw.website.sector_indicators).map(([sector, kws]) => `<div class="tech-list-item">${sector}: ${(kws || []).slice(0, 6).join(', ')}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.website.findings?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Findings</label>
                                <div class="tech-list">
                                    ${raw.website.findings.map(f => `<div class="tech-list-item">${f}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Governance -->
                    ${false && raw.governance ? `
                    <div class="tech-section">
                        <div class="tech-header" onclick="toggleSection(this)">
                            <span>Governance Signals</span>
                            <span class="tech-toggle">â–¼</span>
                        </div>
                        <div class="tech-content">
                            <div class="tech-grid">
                                <div class="tech-item">
                                    <label>Leadership Page</label>
                                    <span class="tech-value ${raw.governance.leadership_page_found ? 'good' : 'warning'}">${raw.governance.leadership_page_found ? 'Yes' : 'No'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Visible CISO</label>
                                    <span class="tech-value ${raw.governance.has_visible_ciso ? 'good' : 'warning'}">${raw.governance.has_visible_ciso ? 'Yes' : 'No'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Annual Report Found</label>
                                    <span class="tech-value ${raw.governance.annual_report_found ? 'good' : 'warning'}">${raw.governance.annual_report_found ? 'Yes' : 'No'}</span>
                                </div>
                                <div class="tech-item">
                                    <label>Cyber Mentions</label>
                                    <span class="tech-value">${raw.governance.cyber_mentions_in_report || 0}</span>
                                </div>
                            </div>
                            ${raw.governance.leadership_page_url ? `
                            <div class="tech-subsection">
                                <label>Leadership Page</label>
                                <div class="tech-list">
                                    <a href="${raw.governance.leadership_page_url}" target="_blank" class="tech-list-item">${raw.governance.leadership_page_url}</a>
                                </div>
                            </div>
                            ` : ''}
                            ${raw.governance.security_titles_found?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Security Titles Found</label>
                                <div class="tech-tags">
                                    ${raw.governance.security_titles_found.map(t => `<span class="tech-tag good">${t}</span>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.governance.security_leaders_found?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Named Leaders Found</label>
                                <div class="tech-list">
                                    ${raw.governance.security_leaders_found.map(n => `<div class="tech-list-item">${n}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.governance.annual_report_url ? `
                            <div class="tech-subsection">
                                <label>Annual Report</label>
                                <div class="tech-list">
                                    <a href="${raw.governance.annual_report_url}" target="_blank" class="tech-list-item">${raw.governance.annual_report_year || ''} ${raw.governance.annual_report_url}</a>
                                </div>
                            </div>
                            ` : ''}
                            ${raw.governance.risk_keywords_found?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Risk Keywords</label>
                                <div class="tech-tags">
                                    ${raw.governance.risk_keywords_found.slice(0, 25).map(k => `<span class="tech-tag">${k}</span>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                            ${raw.governance.findings?.length > 0 ? `
                            <div class="tech-subsection">
                                <label>Findings</label>
                                <div class="tech-list">
                                    ${raw.governance.findings.map(f => `<div class="tech-list-item">${f}</div>`).join('')}
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                </div>
            `;

            // The PDF report contains the full deep-dive technical details; keep the HTML modal lean.
            const tech = body.querySelector('.technical-details');
            if (tech) {
                tech.innerHTML = `
                    <h4 style="margin-top: 1.5rem; margin-bottom: 1rem;">🔬 Technical Overview</h4>
                    <div class="tech-subsection" style="margin-top: 0;">
                        <label>Download PDF</label>
                        <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
                            <a class="btn btn-primary" href="${pdfHref}" target="_blank" rel="noopener">Download PDF</a>
                        </div>
                    </div>
                `;
            }
            
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
          } catch(err) {
            console.error('openModal error:', err);
            alert('Error opening lead details: ' + err.message);
          }
        }
        
        function toggleSection(header) {
            const content = header.nextElementSibling;
            const toggle = header.querySelector('.tech-toggle');
            if (content.style.display === 'none') {
                content.style.display = 'block';
                toggle.textContent = '▼';
            } else {
                content.style.display = 'none';
                toggle.textContent = '▶';
            }
        }
        
        function closeModal(event) {
            if (event && event.target !== event.currentTarget) return;
            document.getElementById('companyModal').classList.remove('active');
            document.body.style.overflow = '';
        }
        
        // Export CSV
        function exportCSV() {
            const headers = ['Rank', 'Company', 'Domain', 'Sector', 'Employees', 'Score', 'Max Score', 'Tier', 'Findings', 'Key Gaps'];
            const rows = filteredLeads.map((lead, i) => [
                i + 1,
                lead.company_name,
                lead.domain,
                lead.sector,
                lead.employees,
                lead.total_score,
                lead.max_score,
                lead.tier.replace('🔴 ', '').replace('🟠 ', '').replace('🟢 ', ''),
                lead.findings_count || 0,
                lead.key_gaps.join('; ')
            ]);
            
            const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))].join('\\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'lead-scout-report.csv';
            a.click();
            URL.revokeObjectURL(url);
        }
        
        // Dark theme for Chart.js
        if (typeof Chart !== 'undefined') {
            Chart.defaults.color = '#8b95a8';
            Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
            Chart.defaults.plugins.legend.labels.color = '#8b95a8';
            Chart.defaults.plugins.legend.labels.font = { family: 'JetBrains Mono, monospace', size: 11 };
        }

        // Initialize charts
        function initCharts() {
            // Tier distribution chart
            new Chart(document.getElementById('tierChart'), {
                type: 'doughnut',
                data: {
                    labels: ['🔴 Hot', '🟠 Warm', '🟢 Cool'],
                    datasets: [{
                        data: [
                            leadsData.filter(l => l.tier.includes('HOT')).length,
                            leadsData.filter(l => l.tier.includes('WARM')).length,
                            leadsData.filter(l => l.tier.includes('COOL')).length
                        ],
                        backgroundColor: ['#ff3b4e', '#ff8c1a', '#00e676'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom' } }
                }
            });
            
            // Sector distribution chart
            const sectorLabels = Object.keys(sectorCounts).map(s => s.length > 15 ? s.substring(0, 15) + '...' : s);
            const sectorValues = Object.values(sectorCounts);
            
            new Chart(document.getElementById('sectorChart'), {
                type: 'bar',
                data: {
                    labels: sectorLabels,
                    datasets: [{
                        label: 'Companies',
                        data: sectorValues,
                        backgroundColor: '#00e1ff',
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { beginAtZero: true, ticks: { stepSize: 1 } }
                    }
                }
            });
            
            // Priority chart
            new Chart(document.getElementById('priorityChart'), {
                type: 'pie',
                data: {
                    labels: Object.keys(priorityCounts),
                    datasets: [{
                        data: Object.values(priorityCounts),
                        backgroundColor: ['#ff3b4e', '#ff8c1a', '#00e676', '#555e70', '#ff3b4e'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom' } }
                }
            });
            
            // Score distribution histogram
            const scoreBuckets = Array(19).fill(0);
            leadsData.forEach(lead => {
                const bucket = Math.min(Math.floor(lead.total_score), 18);
                scoreBuckets[bucket]++;
            });
            
            new Chart(document.getElementById('scoreChart'), {
                type: 'bar',
                data: {
                    labels: Array.from({length: 19}, (_, i) => i.toString()),
                    datasets: [{
                        label: 'Companies',
                        data: scoreBuckets,
                        backgroundColor: scoreBuckets.map((_, i) => i <= 6 ? '#ff3b4e' : i <= 12 ? '#ff8c1a' : '#00e676'),
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, ticks: { stepSize: 1 } },
                        x: { title: { display: true, text: 'Security Score (lower = more gaps)' } }
                    }
                }
            });
        }
        
        // Keyboard shortcuts
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') closeModal();
        });
        
        // Initialize on load
        try {
            renderTable();
        } catch(err) {
            console.error('renderTable error:', err);
            document.getElementById('leadsTableBody').innerHTML = '<tr><td colspan="9">Error rendering table: ' + err.message + '</td></tr>';
        }
        try {
            initCharts();
        } catch(err) {
            console.error('initCharts error:', err);
        }
'''
