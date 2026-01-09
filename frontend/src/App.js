import React, { useState } from 'react';
import axios from 'axios';
import { generatePDFReport } from './utils/pdfExport';
import './App.css';

const API_BASE = 'https://hackathon-backend-ojfb.onrender.com';
function App() {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('theme') || 'light';
  });

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    localStorage.setItem('theme', newTheme);
  };

  const [packageJson, setPackageJson] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [projectId, setProjectId] = useState(''); // now holds project name
  const [scanHistory, setScanHistory] = useState([]);
  const [activeTab, setActiveTab] = useState('summary');

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    try {
      const text = await file.text();
      const json = JSON.parse(text);
      setPackageJson(json);
      setError('');
    } catch (err) {
      setError(`Invalid JSON file: ${err.message}`);
      setPackageJson(null);
    }
  };

  const handleScan = async () => {
    if (!packageJson) {
      setError('Please upload a package.json file first');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const projKey = projectName || packageJson.name || 'My Project';

      const response = await axios.post(`${API_BASE}/scan`, {
        packageJson,
        projectName: projKey
      });

      setResult(response.data);
      setProjectId(projKey);        // use project name as history key
      setScanHistory([]);
      setActiveTab('summary');
      setLoading(false);
    } catch (err) {
      setError(`Scan failed: ${err.response?.data?.error || err.message}`);
      setLoading(false);
    }
  };

  const handleFetchHistory = async () => {
    if (!projectId) {
      setError('No project scanned yet');
      return;
    }

    try {
      const response = await axios.get(
        `${API_BASE}/scans/${encodeURIComponent(projectId)}`
      );
      setScanHistory(response.data.scans || []);
      setActiveTab('history');
    } catch (err) {
      setError(`Failed to fetch history: ${err.message}`);
    }
  };

  const handleDownloadPDF = async () => {
    if (!result) {
      setError('No scan results to download');
      return;
    }

    try {
      await generatePDFReport(result, projectName || 'SBOM-Report');
    } catch (err) {
      setError(`PDF generation failed: ${err.message}`);
    }
  };

  const getTrend = () => {
    if (scanHistory.length < 2) return null;
    const latest = scanHistory[0].summary.riskScore;
    const previous = scanHistory[1].summary.riskScore;
    const diff = latest - previous;
    return {
      trend: diff > 0 ? '📈 Worsening' : diff < 0 ? '📉 Improving' : '➡️ Stable',
      color: diff > 0 ? '#ef4444' : diff < 0 ? '#10b981' : '#94a3b8',
      diff: Math.abs(diff)
    };
  };

  return (
    <div className="app" data-theme={theme}>
      {/* Theme Toggle Button */}
      <button 
        className="theme-toggle" 
        onClick={toggleTheme}
        title={theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
      >
        {theme === 'light' ? '🌙' : '☀️'}
      </button>

      <header className="header">
        <h1>🔒 Advanced SBOM Auditor</h1>
        <p>
          ✅ Dependency Scanner • ✅ Vulnerability Detection • ✅ Sigstore Verification • ✅ Continuous Monitoring • ✨ Multi-Language
        </p>
      </header>

      <main className="container">
        {/* Upload Section */}
        <section className="card upload-section">
          <h2>📦 Step 1: Upload package.json</h2>
          <input
            type="text"
            placeholder="Project name (optional)"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            className="input"
          />
          
          <label htmlFor="package-upload" className="file-upload-label">
            <input
              id="package-upload"
              type="file"
              accept=".json"
              onChange={handleFileChange}
              className="file-input-hidden"
              style={{ display: 'none' }}
            />
            <span className="file-upload-btn">
              📁 Choose package.json File
            </span>
          </label>

          {packageJson && (
            <p className="file-selected">
              ✓ {packageJson.name || 'Unnamed'} v{packageJson.version || '?'} selected
            </p>
          )}

          <button
            onClick={handleScan}
            disabled={!packageJson || loading}
            className="btn btn-primary"
          >
            {loading ? '⏳ Advanced Scan Running...' : '🔍 Start Advanced SBOM Audit'}
          </button>
        </section>

        {error && <div className="error-box">{error}</div>}

        {result && (
          <>
            {/* Tabs */}
            <div className="tabs">
              <button 
                className={`tab ${activeTab === 'summary' ? 'active' : ''}`}
                onClick={() => setActiveTab('summary')}
              >
                📊 Summary Report
              </button>
              <button 
                className={`tab ${activeTab === 'vulns' ? 'active' : ''}`}
                onClick={() => setActiveTab('vulns')}
              >
                🚨 Vulnerabilities
              </button>
              <button 
                className={`tab ${activeTab === 'signatures' ? 'active' : ''}`}
                onClick={() => setActiveTab('signatures')}
              >
                🔐 Signature Verification
              </button>
              <button 
                className={`tab ${activeTab === 'deps' ? 'active' : ''}`}
                onClick={() => setActiveTab('deps')}
              >
                📦 All Dependencies
              </button>
              <button 
                className={`tab ${activeTab === 'history' ? 'active' : ''}`}
                onClick={() => setActiveTab('history')}
              >
                📜 Risk Trends
              </button>
            </div>

            {/* SUMMARY TAB */}
            {activeTab === 'summary' && (
              <section className="card summary-section">
                <h2>📊 Advanced Risk Assessment</h2>
                <div className="summary-grid">
                  <div className="summary-item">
                    <span className="label">Total Vulns</span>
                    <span className="value">
                      {result.summary.totalVulnerabilities}
                    </span>
                  </div>
                  <div className="summary-item critical">
                    <span className="label">🔴 Critical</span>
                    <span className="value">{result.summary.critical}</span>
                  </div>
                  <div className="summary-item high">
                    <span className="label">🟠 High</span>
                    <span className="value">{result.summary.high}</span>
                  </div>
                  <div className="summary-item moderate">
                    <span className="label">🟡 Moderate</span>
                    <span className="value">{result.summary.moderate}</span>
                  </div>
                  <div className="summary-item low">
                    <span className="label">🟢 Low</span>
                    <span className="value">{result.summary.low}</span>
                  </div>
                  <div className="summary-item">
                    <span className="label">Risk Score</span>
                    <span className="value">{result.summary.riskScore}/100</span>
                  </div>
                </div>

                <div className="risk-bar-container">
                  <div
                    className="risk-bar"
                    style={{
                      width: `${result.summary.riskScore}%`
                    }}
                  ></div>
                </div>

                {scanHistory.length > 0 && getTrend() && (
                  <div
                    className="trend-box"
                    style={{ borderLeftColor: getTrend().color }}
                  >
                    <strong>Risk Trend:</strong> {getTrend().trend} (
                    {getTrend().diff} points change)
                  </div>
                )}

                <h3>📋 Supported Languages</h3>
                <div className="languages-list">
                  <span className="lang-badge">✅ Node.js (npm audit)</span>
                  <span className="lang-badge">🐍 Python (pip-audit)</span>
                  <span className="lang-badge">☕ Java (OWASP DC)</span>
                  <span className="lang-badge">🐳 Docker (Syft)</span>
                </div>

                <p
                  style={{
                    marginTop: '20px',
                    fontSize: '13px',
                    color: 'var(--text-tertiary)'
                  }}
                >
                  💡 Risk Score = Combined severity weight / total vulnerabilities
                  (0-100 scale)
                </p>
              </section>
            )}

            {/* VULNERABILITIES TAB */}
            {activeTab === 'vulns' && (
              <section className="card vulns-section">
                <h2>🚨 Vulnerabilities ({result.vulnerabilities.length})</h2>
                {result.vulnerabilities.length === 0 ? (
                  <p className="success">✓ No vulnerabilities found! ✓</p>
                ) : (
                  <table className="vulns-table">
                    <thead>
                      <tr>
                        <th>Package</th>
                        <th>Severity</th>
                        <th>Issue Description</th>
                        <th>Fix Available</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.vulnerabilities.map((v, i) => (
                        <tr key={i}>
                          <td className="name">{v.name}</td>
                          <td>
                            <span className={`badge badge-${v.severity}`}>
                              {v.severity.toUpperCase()}
                            </span>
                          </td>
                          <td>{v.description}</td>
                          <td>
                            {v.fixAvailable === 'yes' ? '✓ Yes' : '✗ No'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </section>
            )}

            {/* SIGSTORE SIGNATURES TAB */}
            {activeTab === 'signatures' && (
              <section className="card signatures-section">
                <h2>🔐 Sigstore Package Verification</h2>
                <div className="sig-status">
                  <p>
                    <strong>Verification Status:</strong>{' '}
                    <span
                      style={{
                        color:
                          result.signatures.status === 'full'
                            ? '#10b981'
                            : '#f97316',
                        fontWeight: 'bold'
                      }}
                    >
                      {result.signatures.status.toUpperCase()}
                    </span>
                  </p>
                  <p>
                    <strong>Method:</strong> {result.signatures.message}
                  </p>
                </div>

                <div className="sig-stats">
                  <div className="sig-stat">
                    <span className="label">Total Packages</span>
                    <span className="value">
                      {result.signatures.totalPackages}
                    </span>
                  </div>
                  <div className="sig-stat verified">
                    <span className="label">✓ Verified</span>
                    <span className="value">
                      {result.signatures.verifiedCount}
                    </span>
                  </div>
                  <div className="sig-stat unverified">
                    <span className="label">⚠️ Unverified</span>
                    <span className="value">
                      {result.signatures.unverifiedCount}
                    </span>
                  </div>
                </div>

                {result.signatures.verified.length > 0 && (
                  <>
                    <h3>✓ Verified Packages (npm registry)</h3>
                    <div className="package-list">
                      {result.signatures.verified.map((pkg, i) => (
                        <span key={i} className="pkg-badge verified">
                          {pkg}
                        </span>
                      ))}
                    </div>
                  </>
                )}

                {result.signatures.unverified.length > 0 && (
                  <>
                    <h3>⚠️ Unverified Packages</h3>
                    <div className="package-list">
                      {result.signatures.unverified.map((pkg, i) => (
                        <span key={i} className="pkg-badge unverified">
                          {pkg}
                        </span>
                      ))}
                    </div>
                    <p
                      style={{
                        marginTop: '15px',
                        fontSize: '12px',
                        color: 'var(--text-tertiary)'
                      }}
                    >
                      💡 Future: @sigstore/verify will provide cryptographic
                      signature validation
                    </p>
                  </>
                )}
              </section>
            )}

            {/* DEPENDENCIES TAB */}
            {activeTab === 'deps' && (
              <section className="card deps-section">
                <h2>📚 Dependencies ({result.dependencies.length})</h2>
                <div className="deps-grid">
                  {result.dependencies.slice(0, 20).map((d, i) => (
                    <div key={i} className="dep-item">
                      <strong>{d.name}</strong>
                      <small>v{d.version}</small>
                      <small className="type">{d.type}</small>
                      {d.vulnerabilities > 0 && (
                        <span className="vul-count">
                          ⚠️ {d.vulnerabilities}
                        </span>
                      )}
                    </div>
                  ))}
                  {result.dependencies.length > 20 && (
                    <div className="dep-item placeholder">
                      +{result.dependencies.length - 20} more
                    </div>
                  )}
                </div>
              </section>
            )}

            {/* HISTORY & TRENDS TAB */}
            {activeTab === 'history' && (
              <section className="card history-section">
                <h2>📊 Continuous Monitoring & Risk Trends</h2>
                <button
                  onClick={handleFetchHistory}
                  className="btn btn-primary"
                >
                  📜 Load Scan History
                </button>

                {scanHistory.length > 0 ? (
                  <>
                    <h3>📈 Risk Score Trend Over Time</h3>
                    <table className="history-table">
                      <thead>
                        <tr>
                          <th>Scan Time</th>
                          <th>Total Vulns</th>
                          <th>Critical</th>
                          <th>High</th>
                          <th>Risk Score</th>
                          <th>Trend</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanHistory.map((scan, i) => {
                          const prevRisk =
                            i < scanHistory.length - 1
                              ? scanHistory[i + 1].summary.riskScore
                              : null;
                          const trend =
                            prevRisk === null
                              ? '→'
                              : scan.summary.riskScore > prevRisk
                              ? '📈'
                              : scan.summary.riskScore < prevRisk
                              ? '📉'
                              : '→';
                          return (
                            <tr key={i}>
                              <td>
                                {new Date(scan.scannedAt).toLocaleString()}
                              </td>
                              <td>{scan.summary.totalVulnerabilities}</td>
                              <td>{scan.summary.critical}</td>
                              <td>{scan.summary.high}</td>
                              <td>
                                <span
                                  style={{
                                    color:
                                      scan.summary.riskScore > 70
                                        ? '#ef4444'
                                        : scan.summary.riskScore > 40
                                        ? '#f97316'
                                        : '#10b981',
                                    fontWeight: 'bold'
                                  }}
                                >
                                  {scan.summary.riskScore}
                                </span>
                              </td>
                              <td>{trend}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </>
                ) : (
                  <p>
                    No history found. Click "Load Scan History" to fetch previous
                    scans.
                  </p>
                )}
              </section>
            )}

            {/* Actions */}
            <section className="card actions-section">
              <button onClick={handleScan} className="btn btn-secondary">
                🔄 Re-scan
              </button>
              <button
                onClick={handleFetchHistory}
                className="btn btn-secondary"
              >
                📊 Load Trends
              </button>
              <button
                onClick={handleDownloadPDF}
                className="btn btn-secondary"
                style={{
                  background: 'var(--accent-success)',
                  color: 'white'
                }}
              >
                📥 Download PDF Report
              </button>
            </section>
          </>
        )}

        {!result && (
          <section className="card welcome-section">
            <h2>🚀 Advanced SBOM Auditor - 6 Features</h2>
            <div className="features-grid">
              <div className="feature-card">
                <h3>📦 Dependency Scanner</h3>
                <p>Extracts all direct + transitive dependencies from package.json</p>
              </div>
              <div className="feature-card">
                <h3>🚨 Vulnerability Detection</h3>
                <p>Real-time CVE detection via npm audit with severity classification</p>
              </div>
              <div className="feature-card">
                <h3>🔐 Sigstore Verification</h3>
                <p>Verifies package signatures via npm registry & Sigstore</p>
              </div>
              <div className="feature-card">
                <h3>📊 Continuous Monitoring</h3>
                <p>Tracks vulnerability trends over time with historical data</p>
              </div>
              <div className="feature-card">
                <h3>🌐 Multi-Language Ready</h3>
                <p>Supports Node.js, Python, Java, Docker (Syft/Grype)</p>
              </div>
              <div className="feature-card">
                <h3>📈 Risk Trends</h3>
                <p>Visual dashboard with risk score trends and comparisons</p>
              </div>
            </div>

            <div className="quick-start-box">
              <h3>🎯 Quick Start Guide</h3>
              <ul className="quick-start-list">
                <li>Upload your <code>package.json</code> file</li>
                <li>
                  Click <strong>"🔍 Start Advanced SBOM Audit"</strong> button
                </li>
                <li>
                  Review all 5 tabs: Summary Report, Vulnerabilities, Signature
                  Verification, All Dependencies, Risk Trends
                </li>
                <li>
                  Click <strong>"📥 Download PDF Report"</strong> to export
                  professional results
                </li>
              </ul>
            </div>
          </section>
        )}
      </main>

      <footer className="footer">
        <p>
          🔐 Advanced SBOM Auditor • Enterprise Supply Chain Security | 6
          Features: Scanner • Detection • Sigstore • Monitoring • Multi-Lang •
          Trends • PDF Export
        </p>
      </footer>
    </div>
  );
}

export default App;
