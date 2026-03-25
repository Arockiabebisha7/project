import { useState, useEffect, useRef } from "react";

// ─── Utilities ───────────────────────────────────────────────────────────────

const COMMON_PASSWORDS = ["password","123456","password123","qwerty","letmein","admin","welcome","monkey","dragon","master","sunshine","princess","abc123","iloveyou","trustno1","football","shadow","superman","michael","jessica","sam"];

function analyzePassword(pwd) {
  const score = { length: 0, upper: 0, lower: 0, numbers: 0, symbols: 0, common: 0, repeat: 0, sequential: 0 };
  if (!pwd) return { score: 0, label: "Empty", color: "#333", entropy: 0, checks: score };
  const lower = pwd.toLowerCase();
  score.length = pwd.length >= 16 ? 2 : pwd.length >= 12 ? 1.5 : pwd.length >= 8 ? 1 : 0;
  score.upper = /[A-Z]/.test(pwd) ? 1 : 0;
  score.lower = /[a-z]/.test(pwd) ? 1 : 0;
  score.numbers = /[0-9]/.test(pwd) ? 1 : 0;
  score.symbols = /[^A-Za-z0-9]/.test(pwd) ? 1.5 : 0;
  score.common = COMMON_PASSWORDS.some(c => lower.includes(c)) ? -2 : 0;
  score.repeat = /(.)\1{2,}/.test(pwd) ? -0.5 : 0;
  score.sequential = /(abc|bcd|cde|def|efg|123|234|345|456|qwerty|asdf)/i.test(pwd) ? -0.5 : 0;
  const total = Math.max(0, Math.min(10, Object.values(score).reduce((a, b) => a + b, 0)));
  const charSet = (/[a-z]/.test(pwd) ? 26 : 0) + (/[A-Z]/.test(pwd) ? 26 : 0) + (/[0-9]/.test(pwd) ? 10 : 0) + (/[^A-Za-z0-9]/.test(pwd) ? 32 : 0);
  const entropy = Math.round(pwd.length * Math.log2(Math.max(charSet, 1)));
  const labels = ["Critical", "Critical", "Weak", "Weak", "Fair", "Fair", "Good", "Good", "Strong", "Strong", "Fort Knox"];
  const colors = ["#ff1744","#ff1744","#ff5252","#ff6d00","#ffab00","#ffd600","#c6ff00","#76ff03","#00e676","#00e5ff","#00b0ff"];
  return { score: total, label: labels[Math.round(total)], color: colors[Math.round(total)], entropy, checks: score };
}

const PHISHING_PATTERNS = [
  { pattern: /urgent|immediately|act now|limited time|expires|deadline/i, weight: 2, label: "Urgency trigger" },
  { pattern: /verify your account|confirm your (password|identity|account|details)/i, weight: 3, label: "Credential phishing" },
  { pattern: /click here|click the link|follow this link/i, weight: 1.5, label: "Suspicious CTA" },
  { pattern: /won|winner|prize|lottery|reward|claim your/i, weight: 2.5, label: "Too-good-to-be-true" },
  { pattern: /suspended|locked|disabled|unauthorized access|security alert/i, weight: 2, label: "Fear tactic" },
  { pattern: /bank|paypal|amazon|netflix|apple|microsoft|google|irs|fbi/i, weight: 1, label: "Brand impersonation" },
  { pattern: /password|username|ssn|social security|credit card|bank account/i, weight: 2.5, label: "Sensitive data request" },
  { pattern: /http:\/\/|bit\.ly|tinyurl|goo\.gl|t\.co\/|ow\.ly/i, weight: 2, label: "Suspicious URL" },
  { pattern: /dear (customer|user|member|account holder|valued)/i, weight: 1.5, label: "Generic salutation" },
  { pattern: /\$\d+|\d+ dollars|free money|send money|wire transfer/i, weight: 2, label: "Financial lure" },
  { pattern: /update your (information|payment|billing|account)/i, weight: 2, label: "Info update demand" },
  { pattern: /do not (ignore|delete|discard) this/i, weight: 1.5, label: "Imperative warning" },
];

function analyzePhishing(text) {
  if (!text.trim()) return { score: 0, label: "Clean", color: "#00e676", risk: 0, matches: [] };
  let totalWeight = 0;
  const matches = [];
  for (const { pattern, weight, label } of PHISHING_PATTERNS) {
    if (pattern.test(text)) { totalWeight += weight; matches.push({ label, weight }); }
  }
  const risk = Math.min(100, Math.round((totalWeight / 18) * 100));
  const label = risk >= 75 ? "High Risk" : risk >= 45 ? "Suspicious" : risk >= 20 ? "Caution" : "Likely Safe";
  const color = risk >= 75 ? "#ff1744" : risk >= 45 ? "#ff6d00" : risk >= 20 ? "#ffab00" : "#00e676";
  return { score: totalWeight, label, color, risk, matches };
}

// ─── URL Analysis ─────────────────────────────────────────────────────────────

const URL_DEMAND_PATTERNS = [
  // Payment / Money
  { pattern: /pay|payment|checkout|billing|invoice|purchase|order|cart|buy|subscribe|subscription|donate|donation|fund|wallet|crypto|bitcoin|paypal|stripe|venmo/i, category: "💳 Payment / Money", severity: "critical", description: "This URL likely leads to a payment page. Never pay through links in unsolicited emails." },
  // Login / Credentials
  { pattern: /login|log-in|signin|sign-in|auth|authenticate|account|password|credential|session|oauth|sso|token/i, category: "🔑 Login / Credentials", severity: "high", description: "This URL may ask for your username and password. Always verify the domain before logging in." },
  // Personal Identity
  { pattern: /verify|verification|identity|confirm|kyc|passport|license|id|dob|birth|ssn|social.?security|national.?id|aadhaar|pan.?card/i, category: "🪪 Identity Verification", severity: "critical", description: "This URL may request government IDs or identity documents. Legitimate services rarely ask via email links." },
  // Financial Data
  { pattern: /card|credit|debit|cvv|expiry|iban|routing|bank|account.?number|swift|ifsc/i, category: "🏦 Financial Data", severity: "critical", description: "This URL may collect bank account or credit card numbers. Extremely high risk." },
  // Personal Info
  { pattern: /profile|update|personal|address|phone|mobile|contact|dob|birthday|name|email/i, category: "👤 Personal Information", severity: "medium", description: "This URL may request personal details such as name, address, or phone number." },
  // Survey / Form
  { pattern: /survey|form|questionnaire|feedback|response|quiz|register|registration|enroll/i, category: "📋 Form / Survey", severity: "low", description: "This URL leads to a form or survey that may collect your information." },
  // File Download
  { pattern: /download|file|attachment|install|setup|exe|zip|pdf|doc|dmg|apk/i, category: "📥 File Download", severity: "high", description: "This URL may trigger a file download. Malware is often distributed this way." },
  // OTP / 2FA
  { pattern: /otp|2fa|two.factor|multi.factor|mfa|code|pin|passcode/i, category: "🔒 OTP / 2FA Code", severity: "high", description: "This URL may ask for a one-time code or 2FA token. Never share these — legitimate sites don't ask via external links." },
  // Prize / Reward
  { pattern: /prize|reward|gift|win|winner|bonus|cashback|offer|deal|discount|coupon|promo/i, category: "🎁 Prize / Reward Claim", severity: "high", description: "This URL promises prizes or rewards. This is a common social engineering tactic." },
  // Subscription Cancel
  { pattern: /cancel|unsubscribe|opt.out|refund|chargeback|dispute/i, category: "⚠️ Cancel / Refund", severity: "medium", description: "This URL claims to let you cancel or get a refund. May be used to extract banking details." },
];

const SUSPICIOUS_DOMAIN_SIGNALS = [
  { test: url => /^http:\/\//i.test(url), label: "No HTTPS encryption", severity: "critical" },
  { test: url => /bit\.ly|tinyurl|goo\.gl|ow\.ly|t\.co|short\.|tiny\.|rb\.gy|is\.gd|cutt\.ly/i.test(url), label: "URL shortener used", severity: "high" },
  { test: url => /@/.test(url.replace(/^https?:\/\//, "")), label: "Contains @ symbol (redirect trick)", severity: "critical" },
  { test: url => /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url), label: "IP address instead of domain", severity: "critical" },
  { test: url => { try { const d = new URL(url).hostname; return (d.match(/-/g) || []).length >= 3; } catch { return false; } }, label: "Excessive hyphens in domain", severity: "medium" },
  { test: url => { try { const d = new URL(url).hostname; return d.split(".").length > 5; } catch { return false; } }, label: "Deeply nested subdomain", severity: "high" },
  { test: url => /paypal|apple|amazon|microsoft|google|netflix|bank|chase|wellsfargo|citibank|facebook|instagram/i.test(url) && !/\.(paypal|apple|amazon|microsoft|google|netflix|com)$/i.test(new URL(url).hostname), label: "Brand name in non-official domain", severity: "critical" },
  { test: url => { try { return new URL(url).hostname.length > 40; } catch { return false; } }, label: "Unusually long domain name", severity: "medium" },
  { test: url => /[а-яёА-ЯЁ]|[α-ωΑ-Ω]/.test(url), label: "Non-Latin characters (IDN homograph attack)", severity: "critical" },
];

function extractUrls(text) {
  const urlRegex = /https?:\/\/[^\s"'<>)\]]+|www\.[^\s"'<>)\]]+\.[a-z]{2,}[^\s"'<>)\]]*/gi;
  const found = text.match(urlRegex) || [];
  return [...new Set(found)].map(u => u.startsWith("www.") ? "https://" + u : u);
}

function analyzeUrl(rawUrl) {
  let url = rawUrl;
  try { new URL(url); } catch { return null; }

  const demands = [];
  for (const p of URL_DEMAND_PATTERNS) {
    if (p.pattern.test(url)) demands.push(p);
  }

  const domainFlags = SUSPICIOUS_DOMAIN_SIGNALS.filter(s => {
    try { return s.test(url); } catch { return false; }
  });

  let hostname = "";
  let pathname = "";
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    pathname = parsed.pathname;
  } catch {}

  const criticalCount = demands.filter(d => d.severity === "critical").length + domainFlags.filter(d => d.severity === "critical").length;
  const highCount = demands.filter(d => d.severity === "high").length + domainFlags.filter(d => d.severity === "high").length;
  const medCount = demands.filter(d => d.severity === "medium").length + domainFlags.filter(d => d.severity === "medium").length;

  const riskScore = Math.min(100, criticalCount * 35 + highCount * 20 + medCount * 10 + demands.length * 5);
  const overallSeverity = riskScore >= 70 ? "critical" : riskScore >= 40 ? "high" : riskScore >= 15 ? "medium" : "safe";

  return { url: rawUrl, hostname, pathname, demands, domainFlags, riskScore, overallSeverity };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function GlowBar({ value, max = 10, color }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div style={{ background: "#0a0a0f", borderRadius: 99, height: 8, overflow: "hidden" }}>
      <div style={{
        height: "100%", width: `${pct}%`, background: `linear-gradient(90deg, ${color}88, ${color})`,
        borderRadius: 99, transition: "width 0.6s cubic-bezier(.4,0,.2,1), background 0.4s",
        boxShadow: `0 0 12px ${color}99`
      }} />
    </div>
  );
}

function CheckItem({ label, passed }) {
  const icon = passed > 0 ? "✓" : passed < 0 ? "✗" : "○";
  const clr = passed > 0 ? "#00e676" : passed < 0 ? "#ff5252" : "#444";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0" }}>
      <span style={{ color: clr, fontFamily: "monospace", fontSize: 13, width: 16 }}>{icon}</span>
      <span style={{ color: passed !== 0 ? "#ccc" : "#555", fontSize: 13 }}>{label}</span>
    </div>
  );
}

function Tag({ label, weight }) {
  const bg = weight >= 2.5 ? "#ff174420" : weight >= 2 ? "#ff6d0020" : "#ffab0020";
  const border = weight >= 2.5 ? "#ff174488" : weight >= 2 ? "#ff6d0088" : "#ffab0088";
  const txt = weight >= 2.5 ? "#ff5252" : weight >= 2 ? "#ff9800" : "#ffc107";
  return (
    <span style={{ background: bg, border: `1px solid ${border}`, color: txt, borderRadius: 6, padding: "3px 10px", fontSize: 12, display: "inline-flex", gap: 5, alignItems: "center" }}>
      <span style={{ opacity: 0.7 }}>⚠</span> {label}
    </span>
  );
}

const SEVERITY_META = {
  critical: { color: "#ff1744", label: "CRITICAL", bg: "#ff174412", border: "#ff174440", icon: "🚨" },
  high:     { color: "#ff6d00", label: "HIGH RISK", bg: "#ff6d0012", border: "#ff6d0040", icon: "⛔" },
  medium:   { color: "#ffab00", label: "CAUTION",   bg: "#ffab0012", border: "#ffab0040", icon: "⚠️" },
  safe:     { color: "#00e676", label: "LOOKS SAFE", bg: "#00e67612", border: "#00e67640", icon: "✅" },
};

function SeverityPill({ severity }) {
  const m = SEVERITY_META[severity] || SEVERITY_META.safe;
  return (
    <span style={{ background: m.bg, border: `1px solid ${m.border}`, color: m.color, borderRadius: 99, padding: "2px 10px", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
      {m.label}
    </span>
  );
}

function UrlCard({ result, index }) {
  const [expanded, setExpanded] = useState(false);
  const m = SEVERITY_META[result.overallSeverity];

  return (
    <div style={{
      background: "#09090f", border: `1px solid ${m.color}33`,
      borderRadius: 14, overflow: "hidden", marginBottom: 14,
      boxShadow: `0 4px 20px ${m.color}12`,
      transition: "box-shadow 0.3s"
    }}>
      {/* Header */}
      <div
        onClick={() => setExpanded(e => !e)}
        style={{ padding: "14px 16px", cursor: "pointer", display: "flex", alignItems: "flex-start", gap: 12 }}
      >
        <span style={{ fontSize: 22, lineHeight: 1, marginTop: 2 }}>{m.icon}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
            <SeverityPill severity={result.overallSeverity} />
            <span style={{ color: "#444", fontSize: 12 }}>URL #{index + 1}</span>
          </div>
          <div style={{
            color: m.color, fontSize: 13, fontFamily: "monospace",
            wordBreak: "break-all", lineHeight: 1.5,
            textShadow: `0 0 10px ${m.color}55`
          }}>
            {result.hostname}
            <span style={{ color: "#555" }}>{result.pathname.length > 30 ? result.pathname.slice(0, 30) + "…" : result.pathname}</span>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4, flexShrink: 0 }}>
          <span style={{ color: m.color, fontSize: 18, fontWeight: 800, fontFamily: "monospace" }}>{result.riskScore}%</span>
          <span style={{ color: "#333", fontSize: 11 }}>risk</span>
          <span style={{ color: "#444", fontSize: 18, marginTop: 4 }}>{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      {/* Risk bar */}
      <div style={{ padding: "0 16px 12px" }}>
        <GlowBar value={result.riskScore} max={100} color={m.color} />
      </div>

      {/* Expanded details */}
      {expanded && (
        <div style={{ borderTop: `1px solid #1a1a2e`, padding: 16 }}>

          {/* Domain flags */}
          {result.domainFlags.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ color: "#888", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>🔍 Domain Red Flags</div>
              {result.domainFlags.map((f, i) => {
                const fc = f.severity === "critical" ? "#ff1744" : f.severity === "high" ? "#ff6d00" : "#ffab00";
                return (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 10px", background: `${fc}10`, border: `1px solid ${fc}30`, borderRadius: 8, marginBottom: 6 }}>
                    <span style={{ color: fc, fontSize: 13 }}>⛳</span>
                    <span style={{ color: "#ccc", fontSize: 13 }}>{f.label}</span>
                    <span style={{ marginLeft: "auto", color: fc, fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>{f.severity}</span>
                  </div>
                );
              })}
            </div>
          )}

          {/* What it's demanding */}
          {result.demands.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ color: "#888", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>📌 What This URL May Demand</div>
              {result.demands.map((d, i) => {
                const dc = d.severity === "critical" ? "#ff1744" : d.severity === "high" ? "#ff6d00" : d.severity === "medium" ? "#ffab00" : "#00b4d8";
                return (
                  <div key={i} style={{ background: `${dc}10`, border: `1px solid ${dc}33`, borderRadius: 10, padding: "10px 14px", marginBottom: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
                      <span style={{ color: dc, fontWeight: 700, fontSize: 13 }}>{d.category}</span>
                      <span style={{ color: dc, fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, background: `${dc}20`, padding: "2px 8px", borderRadius: 99 }}>{d.severity}</span>
                    </div>
                    <p style={{ color: "#888", fontSize: 12, margin: 0, lineHeight: 1.6 }}>{d.description}</p>
                  </div>
                );
              })}
            </div>
          )}

          {/* Safe if no issues */}
          {result.demands.length === 0 && result.domainFlags.length === 0 && (
            <div style={{ background: "#00e67610", border: "1px solid #00e67633", borderRadius: 10, padding: "12px 14px", color: "#00e676", fontSize: 13 }}>
              ✅ No suspicious demands or domain flags detected for this URL.
            </div>
          )}

          {/* Warning footer */}
          {result.overallSeverity !== "safe" && (
            <div style={{ background: "#1a0a0a", border: "1px solid #ff174422", borderRadius: 10, padding: "10px 14px", marginTop: 8 }}>
              <div style={{ color: "#ff5252", fontSize: 12, lineHeight: 1.7 }}>
                ⚠️ <strong>Do not visit this URL</strong> unless you are 100% sure of its source. Copy the domain and manually verify it on the official website instead.
              </div>
            </div>
          )}

          {/* Full URL */}
          <div style={{ marginTop: 12, background: "#0a0a0a", borderRadius: 8, padding: "8px 12px" }}>
            <div style={{ color: "#333", fontSize: 10, textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>Full URL</div>
            <div style={{ color: "#555", fontSize: 11, fontFamily: "monospace", wordBreak: "break-all" }}>{result.url}</div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Password Tab ─────────────────────────────────────────────────────────────

function PasswordTab() {
  const [pwd, setPwd] = useState("");
  const [show, setShow] = useState(false);
  const [copied, setCopied] = useState(false);
  const result = analyzePassword(pwd);

  const generate = () => {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let p = "";
    for (let i = 0; i < 20; i++) p += chars[Math.floor(Math.random() * chars.length)];
    setPwd(p); setShow(true);
  };

  const copy = () => {
    navigator.clipboard?.writeText(pwd);
    setCopied(true); setTimeout(() => setCopied(false), 1500);
  };

  const checks = [
    { label: "Length ≥ 16 chars", val: result.checks.length >= 2 ? 1 : result.checks.length >= 1.5 ? 0.5 : 0 },
    { label: "Uppercase letters", val: result.checks.upper },
    { label: "Lowercase letters", val: result.checks.lower },
    { label: "Numbers", val: result.checks.numbers },
    { label: "Special symbols", val: result.checks.symbols > 0 ? 1 : 0 },
    { label: "No common patterns", val: result.checks.common === 0 ? 0.5 : -1 },
    { label: "No repeated chars", val: result.checks.repeat === 0 ? 0.5 : -1 },
    { label: "No sequential chars", val: result.checks.sequential === 0 ? 0.5 : -1 },
  ];

  return (
    <div>
      <p style={{ color: "#666", fontSize: 14, marginBottom: 24, lineHeight: 1.6 }}>
        Analyze your password's strength in real time — entropy, patterns, and vulnerability checks.
      </p>
      <div style={{ position: "relative", marginBottom: 24 }}>
        <input
          type={show ? "text" : "password"}
          value={pwd}
          onChange={e => setPwd(e.target.value)}
          placeholder="Enter or paste your password…"
          style={{
            width: "100%", background: "#0d0d16", border: `1px solid ${pwd ? result.color + "55" : "#1e1e2e"}`,
            borderRadius: 12, padding: "14px 100px 14px 16px", color: "#eee", fontSize: 15,
            fontFamily: "'Courier New', monospace", outline: "none", boxSizing: "border-box",
            transition: "border-color 0.3s", boxShadow: pwd ? `0 0 20px ${result.color}22` : "none"
          }}
        />
        <div style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", display: "flex", gap: 8 }}>
          <button onClick={() => setShow(s => !s)} style={{ background: "#1a1a2e", border: "1px solid #2a2a3e", color: "#888", borderRadius: 8, padding: "4px 10px", cursor: "pointer", fontSize: 13 }}>
            {show ? "🙈" : "👁"}
          </button>
          {pwd && <button onClick={copy} style={{ background: "#1a1a2e", border: "1px solid #2a2a3e", color: copied ? "#00e676" : "#888", borderRadius: 8, padding: "4px 10px", cursor: "pointer", fontSize: 12 }}>
            {copied ? "✓" : "Copy"}
          </button>}
        </div>
      </div>
      {pwd && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ color: result.color, fontWeight: 700, fontSize: 18, letterSpacing: 1, textShadow: `0 0 20px ${result.color}` }}>{result.label}</span>
            <span style={{ color: "#555", fontSize: 13 }}>Score: <span style={{ color: result.color }}>{result.score.toFixed(1)}/10</span></span>
          </div>
          <GlowBar value={result.score} max={10} color={result.color} />
        </div>
      )}
      {pwd && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 24 }}>
          {[{ label: "Characters", value: pwd.length }, { label: "Entropy", value: `${result.entropy} bits` }, { label: "Unique", value: new Set(pwd).size }].map(s => (
            <div key={s.label} style={{ background: "#0d0d16", border: "1px solid #1e1e2e", borderRadius: 10, padding: "12px 14px", textAlign: "center" }}>
              <div style={{ color: result.color, fontSize: 20, fontWeight: 700, fontFamily: "monospace" }}>{s.value}</div>
              <div style={{ color: "#555", fontSize: 12, marginTop: 2 }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}
      {pwd && (
        <div style={{ background: "#0d0d16", border: "1px solid #1e1e2e", borderRadius: 12, padding: 16, marginBottom: 20 }}>
          <div style={{ color: "#888", fontSize: 12, letterSpacing: 1, marginBottom: 10, textTransform: "uppercase" }}>Security Checks</div>
          {checks.map(c => <CheckItem key={c.label} label={c.label} passed={c.val} />)}
        </div>
      )}
      <button onClick={generate} style={{
        width: "100%", background: "linear-gradient(135deg, #00b4d8, #0077b6)", border: "none",
        color: "#fff", borderRadius: 12, padding: "13px 0", fontSize: 15, fontWeight: 600,
        cursor: "pointer", letterSpacing: 0.5, transition: "opacity 0.2s",
      }}
        onMouseEnter={e => e.target.style.opacity = "0.85"}
        onMouseLeave={e => e.target.style.opacity = "1"}
      >
        ⚡ Generate Strong Password
      </button>
    </div>
  );
}

// ─── Phishing Tab ────────────────────────────────────────────────────────────

function PhishingTab() {
  const [text, setText] = useState("");
  const result = analyzePhishing(text);
  const circumference = 2 * Math.PI * 42;
  const strokeDash = circumference - (result.risk / 100) * circumference;

  return (
    <div>
      <p style={{ color: "#666", fontSize: 14, marginBottom: 24, lineHeight: 1.6 }}>
        Paste any email, SMS, or message to detect phishing signals, social engineering, and suspicious patterns.
      </p>
      <textarea
        value={text}
        onChange={e => setText(e.target.value)}
        placeholder="Paste the suspicious message here…"
        rows={6}
        style={{
          width: "100%", background: "#0d0d16", border: `1px solid ${text ? result.color + "44" : "#1e1e2e"}`,
          borderRadius: 12, padding: "14px 16px", color: "#ddd", fontSize: 14, resize: "vertical",
          fontFamily: "inherit", outline: "none", boxSizing: "border-box", lineHeight: 1.7,
          transition: "border-color 0.3s", boxShadow: text ? `0 0 20px ${result.color}18` : "none"
        }}
      />
      {text && (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 24, margin: "24px 0" }}>
            <svg width={110} height={110} viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="42" fill="none" stroke="#1a1a2e" strokeWidth="10" />
              <circle cx="50" cy="50" r="42" fill="none" stroke={result.color} strokeWidth="10"
                strokeDasharray={circumference} strokeDashoffset={strokeDash}
                strokeLinecap="round" transform="rotate(-90 50 50)"
                style={{ transition: "stroke-dashoffset 0.7s cubic-bezier(.4,0,.2,1), stroke 0.4s", filter: `drop-shadow(0 0 8px ${result.color})` }}
              />
              <text x="50" y="46" textAnchor="middle" fill={result.color} fontSize="18" fontWeight="bold" fontFamily="monospace">{result.risk}%</text>
              <text x="50" y="62" textAnchor="middle" fill="#555" fontSize="9" fontFamily="sans-serif">RISK</text>
            </svg>
            <div>
              <div style={{ color: result.color, fontSize: 22, fontWeight: 800, letterSpacing: 0.5, textShadow: `0 0 20px ${result.color}` }}>{result.label}</div>
              <div style={{ color: "#555", fontSize: 13, marginTop: 4 }}>{result.matches.length} indicator{result.matches.length !== 1 ? "s" : ""} found</div>
              <div style={{ color: "#444", fontSize: 12, marginTop: 2 }}>{text.split(/\s+/).length} words · {text.length} chars</div>
            </div>
          </div>
          {result.matches.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <div style={{ color: "#888", fontSize: 12, letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>Detected Signals</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {result.matches.map((m, i) => <Tag key={i} label={m.label} weight={m.weight} />)}
              </div>
            </div>
          )}
          <div style={{
            background: result.risk >= 75 ? "#ff174410" : result.risk >= 45 ? "#ff6d0010" : result.risk >= 20 ? "#ffab0010" : "#00e67610",
            border: `1px solid ${result.color}33`, borderRadius: 12, padding: "14px 16px"
          }}>
            <div style={{ color: result.color, fontWeight: 600, marginBottom: 6, fontSize: 14 }}>
              {result.risk >= 75 ? "🚨 Do Not Engage" : result.risk >= 45 ? "⚠️ Treat With Caution" : result.risk >= 20 ? "🔍 Review Carefully" : "✅ Appears Safe"}
            </div>
            <div style={{ color: "#888", fontSize: 13, lineHeight: 1.6 }}>
              {result.risk >= 75 ? "This message shows strong phishing indicators. Do not click any links, provide personal information, or respond to the sender."
                : result.risk >= 45 ? "Several suspicious patterns detected. Verify the sender's identity through official channels before taking any action."
                : result.risk >= 20 ? "Minor warning signs present. Cross-check the sender and avoid clicking unknown links."
                : "No significant phishing patterns detected. Always stay vigilant with unsolicited messages."}
            </div>
          </div>
        </>
      )}
      {!text && (
        <div style={{ textAlign: "center", padding: "40px 0", color: "#2a2a3e" }}>
          <div style={{ fontSize: 48, marginBottom: 10 }}>🎣</div>
          <div style={{ fontSize: 14 }}>Waiting for message input…</div>
        </div>
      )}
    </div>
  );
}

// ─── URL Scanner Tab ──────────────────────────────────────────────────────────

function UrlScannerTab() {
  const [text, setText] = useState("");
  const [scanned, setScanned] = useState(false);
  const [results, setResults] = useState([]);

  const scan = () => {
    const urls = extractUrls(text);
    const analyzed = urls.map(analyzeUrl).filter(Boolean);
    setResults(analyzed);
    setScanned(true);
  };

  const reset = () => { setText(""); setResults([]); setScanned(false); };

  const criticalCount = results.filter(r => r.overallSeverity === "critical").length;
  const highCount = results.filter(r => r.overallSeverity === "high").length;

  return (
    <div>
      <p style={{ color: "#666", fontSize: 14, marginBottom: 20, lineHeight: 1.6 }}>
        Paste any email or message containing URLs. We'll extract every link and warn you what each one might demand — before you click.
      </p>

      {!scanned ? (
        <>
          <textarea
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder={`Paste your full email or message here…\n\nExample:\n  Dear customer, your account is suspended.\n  Verify now: https://secure-paypal-login.xyz/verify\n  Claim your prize: http://bit.ly/win2024`}
            rows={8}
            style={{
              width: "100%", background: "#0d0d16", border: "1px solid #1e1e2e",
              borderRadius: 12, padding: "14px 16px", color: "#ddd", fontSize: 13, resize: "vertical",
              fontFamily: "inherit", outline: "none", boxSizing: "border-box", lineHeight: 1.8,
              transition: "border-color 0.3s"
            }}
            onFocus={e => e.target.style.borderColor = "#00b4d855"}
            onBlur={e => e.target.style.borderColor = "#1e1e2e"}
          />
          <button
            onClick={scan}
            disabled={!text.trim()}
            style={{
              width: "100%", marginTop: 14,
              background: text.trim() ? "linear-gradient(135deg, #ff6d00, #ff1744)" : "#111",
              border: "none", color: text.trim() ? "#fff" : "#333",
              borderRadius: 12, padding: "13px 0", fontSize: 15, fontWeight: 600,
              cursor: text.trim() ? "pointer" : "not-allowed", letterSpacing: 0.5, transition: "all 0.2s",
            }}
          >
            🔍 Scan URLs in Message
          </button>
        </>
      ) : (
        <>
          {/* Summary banner */}
          <div style={{
            background: criticalCount > 0 ? "#ff174412" : highCount > 0 ? "#ff6d0012" : "#00e67612",
            border: `1px solid ${criticalCount > 0 ? "#ff174440" : highCount > 0 ? "#ff6d0040" : "#00e67640"}`,
            borderRadius: 14, padding: "14px 18px", marginBottom: 20,
            display: "flex", alignItems: "center", gap: 14
          }}>
            <span style={{ fontSize: 28 }}>{criticalCount > 0 ? "🚨" : highCount > 0 ? "⛔" : results.length === 0 ? "🔎" : "✅"}</span>
            <div>
              <div style={{ color: criticalCount > 0 ? "#ff5252" : highCount > 0 ? "#ff9800" : "#00e676", fontWeight: 700, fontSize: 15 }}>
                {results.length === 0
                  ? "No URLs found in this message"
                  : criticalCount > 0
                  ? `${criticalCount} critical URL${criticalCount > 1 ? "s" : ""} detected — Do NOT click!`
                  : highCount > 0
                  ? `${highCount} high-risk URL${highCount > 1 ? "s" : ""} detected — Proceed with extreme caution`
                  : `${results.length} URL${results.length > 1 ? "s" : ""} scanned — No critical threats found`}
              </div>
              <div style={{ color: "#555", fontSize: 12, marginTop: 3 }}>
                {results.length} URL{results.length !== 1 ? "s" : ""} extracted · Click any card to expand details
              </div>
            </div>
          </div>

          {/* URL cards */}
          {results.map((r, i) => <UrlCard key={i} result={r} index={i} />)}

          {results.length === 0 && (
            <div style={{ textAlign: "center", padding: "30px 0", color: "#2a2a3e" }}>
              <div style={{ fontSize: 40, marginBottom: 10 }}>🔗</div>
              <div style={{ fontSize: 14 }}>No URLs (http/https/www) were found in the pasted text.</div>
            </div>
          )}

          {/* Scan another */}
          <button onClick={reset} style={{
            width: "100%", marginTop: 8, background: "#0d0d16", border: "1px solid #1e1e2e",
            color: "#888", borderRadius: 12, padding: "12px 0", fontSize: 14,
            cursor: "pointer", transition: "border-color 0.2s",
          }}
            onMouseEnter={e => e.target.style.borderColor = "#00b4d855"}
            onMouseLeave={e => e.target.style.borderColor = "#1e1e2e"}
          >
            ↩ Scan Another Message
          </button>
        </>
      )}
    </div>
  );
}

// ─── App ──────────────────────────────────────────────────────────────────────

export default function App() {
  const [tab, setTab] = useState(0);
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setTimeout(() => setMounted(true), 50); }, []);

  const tabs = [
    { label: "🔐 Password", short: "Password" },
    { label: "🎣 Phishing", short: "Phishing" },
    { label: "🔗 URL Scanner", short: "URL" },
  ];

  return (
    <div style={{
      minHeight: "100vh", background: "#07070f",
      fontFamily: "'Segoe UI', 'Helvetica Neue', sans-serif",
      display: "block",
      padding: "20px 16px",
      backgroundImage: "radial-gradient(ellipse 80% 50% at 50% -20%, #0a0a2a, transparent), radial-gradient(ellipse 60% 40% at 80% 80%, #0a1a0a, transparent)"
    }}>
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        backgroundImage: "linear-gradient(#ffffff08 1px, transparent 1px), linear-gradient(90deg, #ffffff08 1px, transparent 1px)",
        backgroundSize: "40px 40px"
      }} />

      <div style={{
        position: "relative", zIndex: 1, width: "100%",
        opacity: mounted ? 1 : 0, transform: mounted ? "translateY(0)" : "translateY(20px)",
        transition: "opacity 0.6s ease, transform 0.6s ease"
      }}>
        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 10, background: "#0d0d1a", border: "1px solid #1e1e35", borderRadius: 99, padding: "6px 16px", marginBottom: 16 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#00e676", display: "inline-block", boxShadow: "0 0 8px #00e676" }} />
            <span style={{ color: "#555", fontSize: 12, letterSpacing: 1.5, textTransform: "uppercase" }}>Security Toolkit</span>
          </div>
          <h1 style={{ color: "#eee", fontSize: 30, fontWeight: 800, margin: "0 0 8px", letterSpacing: -0.5 }}>
            Cyber<span style={{ color: "#00b4d8", textShadow: "0 0 20px #00b4d8" }}>Guard</span>
          </h1>
          <p style={{ color: "#444", fontSize: 14, margin: 0 }}>Real-time security analysis at your fingertips</p>
        </div>

        {/* Card */}
        <div style={{
          background: "linear-gradient(145deg, #0e0e1c, #0a0a14)",
          border: "1px solid #1a1a2e", borderRadius: 20, overflow: "hidden",
          boxShadow: "0 40px 80px #00000088, 0 0 0 1px #ffffff05"
        }}>
          {/* Tabs */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", background: "#08080f", borderBottom: "1px solid #1a1a2e" }}>
            {tabs.map((t, i) => (
              <button key={i} onClick={() => setTab(i)} style={{
                background: "none", border: "none", padding: "16px 0", cursor: "pointer",
                color: tab === i ? "#00b4d8" : "#444", fontSize: 13, fontWeight: tab === i ? 700 : 400,
                borderBottom: tab === i ? "2px solid #00b4d8" : "2px solid transparent",
                transition: "all 0.25s", letterSpacing: 0.3,
                textShadow: tab === i ? "0 0 20px #00b4d8" : "none"
              }}>
                {t.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div style={{ padding: 24 }}>
            {tab === 0 ? <PasswordTab /> : tab === 1 ? <PhishingTab /> : <UrlScannerTab />}
          </div>
        </div>

        <p style={{ textAlign: "center", color: "#2a2a3a", fontSize: 12, marginTop: 20 }}>
          Analysis runs entirely in your browser — nothing is stored or transmitted.
        </p>
      </div>
    </div>
  );
}