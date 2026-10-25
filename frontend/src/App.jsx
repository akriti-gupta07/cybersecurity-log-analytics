import { useEffect, useMemo, useState } from 'react'
import { ShieldCheck, LayoutDashboard, ChartNoAxesCombined, Search, ScanSearch, BrainCircuit, Upload, Menu, Bell, ChevronLeft, ChevronRight, Database, RefreshCw } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts'
import { api } from './api'

const nav = [
  ['Overview', LayoutDashboard], ['Attack Analytics', ChartNoAxesCombined],
  ['Network Logs', Search], ['Threat Detection', ScanSearch],
  ['Model Performance', BrainCircuit]
]
const COLORS = ['#2563eb', '#93c5fd', '#1d4ed8', '#60a5fa', '#bfdbfe', '#3b82f6']
const fmt = n => Number(n || 0).toLocaleString('en-US')
function Card({ label, value, note, icon: Icon }) {
  return <div className="kpi"><div className="kpi-top"><span>{label}</span><span className="kpi-icon"><Icon size={18}/></span></div><div className="kpi-value">{value}</div><div className="kpi-note">{note}</div></div>
}
function Panel({ title, subtitle, children }) {
  return <section className="panel"><div className="panel-head"><div><h3>{title}</h3>{subtitle && <p>{subtitle}</p>}</div></div>{children}</section>
}
export default function App() {
  const [page, setPage] = useState('Overview')
  const [menuOpen, setMenuOpen] = useState(false)
  const [summary, setSummary] = useState(null)
  const [attacks, setAttacks] = useState([])
  const [rates, setRates] = useState([])
  const [features, setFeatures] = useState([])
  const [health, setHealth] = useState(null)
  const [error, setError] = useState('')
  const [logs, setLogs] = useState([])
  const [logTotal, setLogTotal] = useState(0)
  const [logPage, setLogPage] = useState(1)
  const [label, setLabel] = useState('')
  const [search, setSearch] = useState('')
  const [port, setPort] = useState('')
  const [uploadFile, setUploadFile] = useState(null)
  const [prediction, setPrediction] = useState(null)
  const [uploadError, setUploadError] = useState('')
  const [uploading, setUploading] = useState(false)

  async function loadBase() {
    setError('')
    try {
      const [s, a, r, f, h] = await Promise.all([
        api('/dashboard/summary'), api('/analytics/attack-types'),
        api('/analytics/detection-rates'), api('/analytics/feature-importance'),
        api('/health').catch(e => ({status:'degraded', database:'disconnected', error:e.message}))
      ])
      setSummary(s); setAttacks(a.data || []); setRates(r.data || []); setFeatures(f.data || []); setHealth(h)
    } catch (e) { setError(e.message) }
  }
  
async function loadLogs(pageNum = logPage, selectedLabel) {
  try {
    const p = new URLSearchParams({
      page: String(pageNum),
      page_size: '15'
    });

    const currentLabel =
      selectedLabel !== undefined ? selectedLabel : label;

    if (currentLabel) {
      p.set('label', currentLabel);
    }

    // Threat Detection should never include BENIGN records.
    if (page === 'Threat Detection') {
      p.set('attacks_only', 'true');
    }

    const d = await api(`/logs?${p}`);

    setLogs(d.data || []);
    setLogTotal(d.total || 0);
    setLogPage(pageNum);
  } catch (e) {
    setError(e.message);
  }
}

  useEffect(() => { loadBase() }, [])
  useEffect(() => { if (page === 'Network Logs' || page === 'Threat Detection') loadLogs(1) }, [page])
  const traffic = useMemo(() => summary ? [{name:'Normal', value:summary.normal},{name:'Attack',value:summary.attack}] : [], [summary])
  const maxPage = Math.max(1, Math.ceil(logTotal / 15))
  async function submitUpload(e) {
    e.preventDefault(); setUploadError(''); setPrediction(null)
    if (!uploadFile) { setUploadError('Choose a CSV file first.'); return }
    const form = new FormData(); form.append('file', uploadFile)
    setUploading(true)
    try { setPrediction(await api('/predict/upload', {method:'POST', body:form})) }
    catch (err) { setUploadError(err.message) }
    finally { setUploading(false) }
  }

  return <div className="app-shell">
    <aside className={`sidebar ${menuOpen ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={23}/></div><div><strong>CyberGuard</strong><small>SECURITY ANALYTICS</small></div></div>
      <div className="nav-label">WORKSPACE</div>
      <nav>{nav.map(([name, Icon]) => <button key={name} className={`nav-item ${page===name?'active':''}`} onClick={()=>{setPage(name);setMenuOpen(false);setError('')}}><Icon size={18}/><span>{name}</span></button>)}</nav>
      <div className="sidebar-bottom"><div className="db-status"><span className={`status-dot ${health?.database==='connected'?'online':''}`}/><div><b>Database</b><small>{health?.database || 'Checking connection…'}</small></div><Database size={17}/></div><p>CyberGuard v1.0 · CIC-IDS2017</p></div>
    </aside>
    <main className="main">
      <header className="topbar"><button className="mobile-menu icon-button" onClick={()=>setMenuOpen(!menuOpen)}><Menu/></button><div className="breadcrumb">Workspace <span>/</span> <b>{page}</b></div><div className="top-actions"><button className="icon-button" title="Refresh data" onClick={loadBase}><RefreshCw size={17}/></button><span className="user-avatar">CG</span></div></header>
      <div className="content">
        {error && <div className="notice error">{error}</div>}
        {page==='Overview' && <><div className="page-title"><div><div className="eyebrow">SECURITY OVERVIEW</div><h1>Cybersecurity dashboard</h1><p>Network traffic insights and machine-learning detection results.</p></div><button className="primary-button" onClick={loadBase}><RefreshCw size={16}/> Refresh data</button></div>
          <div className="kpi-grid">
            <Card label="Total network flows" value={fmt(summary?.total)} note="Records in the dataset" icon={Database}/>
            <Card label="Normal traffic" value={fmt(summary?.normal)} note="Labelled BENIGN" icon={ShieldCheck}/>
            <Card label="Attack traffic" value={fmt(summary?.attack)} note="Non-BENIGN labels" icon={ScanSearch}/>
            <Card label="Model accuracy" value={`${summary?.accuracy_percent ?? '—'}%`} note="Existing held-out test split" icon={BrainCircuit}/>
          </div>
          {summary?.warning && <div className="notice">{summary.warning}</div>}
          <div className="chart-grid"><Panel title="Normal vs attack traffic" subtitle="Overall record distribution"><div className="chart chart-donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={traffic} dataKey="value" nameKey="name" innerRadius={66} outerRadius={96} paddingAngle={4}>{traffic.map((d,i)=><Cell key={d.name} fill={i===0?'#2563eb':'#93c5fd'}/>)}</Pie><Tooltip formatter={v=>fmt(v)}/><Legend/></PieChart></ResponsiveContainer></div></Panel>
          <Panel title="Traffic by attack type" subtitle="Most frequent labels in the dataset"><div className="chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={attacks.slice(0,8)} layout="vertical" margin={{left:15,right:16}}><CartesianGrid strokeDasharray="3 3" horizontal={false}/><XAxis type="number" tickFormatter={v=>fmt(v)} fontSize={11}/><YAxis type="category" dataKey="attack_type" width={125} fontSize={10} tickFormatter={v=>String(v).slice(0,19)}/><Tooltip formatter={v=>fmt(v)}/><Bar dataKey="count" fill="#2563eb" radius={[0,5,5,0]}/></BarChart></ResponsiveContainer></div></Panel></div>
          <Panel title="Top 15 model features" subtitle="Features with the highest overall importance"><div className="chart chart-tall"><ResponsiveContainer width="100%" height="100%"><BarChart data={features} layout="vertical" margin={{left:20,right:20}}><CartesianGrid strokeDasharray="3 3" horizontal={false}/><XAxis type="number" fontSize={11}/><YAxis type="category" dataKey="feature" width={180} fontSize={10} tickFormatter={v=>String(v).slice(0,26)}/><Tooltip/><Bar dataKey="importance" fill="#60a5fa" radius={[0,5,5,0]}/></BarChart></ResponsiveContainer></div></Panel>
        </>}
        {page==='Attack Analytics' && <><div className="page-title"><div><div className="eyebrow">TRAFFIC INTELLIGENCE</div><h1>Attack analytics</h1><p>Explore the distribution and detection rates of attack categories.</p></div></div><div className="chart-grid"><Panel title="Attack distribution" subtitle="Record count by original label"><div className="chart chart-tall"><ResponsiveContainer width="100%" height="100%"><BarChart data={attacks} layout="vertical" margin={{left:15,right:18}}><CartesianGrid strokeDasharray="3 3" horizontal={false}/><XAxis type="number" fontSize={11}/><YAxis type="category" dataKey="attack_type" width={150} fontSize={10}/><Tooltip/><Bar dataKey="count" fill="#2563eb" radius={[0,4,4,0]}/></BarChart></ResponsiveContainer></div></Panel><Panel title="Detection rate by attack type" subtitle="Saved model analysis results"><div className="chart chart-tall"><ResponsiveContainer width="100%" height="100%"><BarChart data={rates} layout="vertical" margin={{left:15,right:18}}><CartesianGrid strokeDasharray="3 3" horizontal={false}/><XAxis type="number" domain={[0,100]} unit="%" fontSize={11}/><YAxis type="category" dataKey="attack_type" width={150} fontSize={10}/><Tooltip formatter={v=>`${v}%`}/><Bar dataKey="detection_rate" fill="#60a5fa" radius={[0,4,4,0]}/></BarChart></ResponsiveContainer></div></Panel></div></>}
        {(page==='Network Logs' || page==='Threat Detection') && <><div className="page-title"><div><div className="eyebrow">INVESTIGATION</div><h1>{page}</h1><p>{page==='Threat Detection'?'Review records whose original dataset label indicates an attack. These are historical records, not live alerts.':'Search and filter historical CIC-IDS2017 network records.'}</p></div></div><Panel title="Network records" subtitle={`${fmt(logTotal)} matching records`}>
          {/* <div className="filters"><input placeholder="Search label or IP…" value={search} onChange={e=>setSearch(e.target.value)}/><select value={label} onChange={e=>setLabel(e.target.value)}><option value="">All labels</option><option>BENIGN</option><option>DDoS</option><option>DoS Hulk</option><option>PortScan</option><option>Bot</option></select><input placeholder="Destination port" value={port} onChange={e=>setPort(e.target.value)}/><button className="primary-button" onClick={()=>loadLogs(1)}><Search size={15}/> Apply filters</button></div> */}
          
<div className="filters">
  <select
    value={label}
    onChange={(e) => {
      const selected = e.target.value;
      setLabel(selected);
      loadLogs(1, selected);
    }}
  >
    {page === 'Network Logs' ? (
      <>
        <option value="">All Labels</option>
        <option value="BENIGN">BENIGN</option>
        <option value="DDoS">DDoS</option>
        <option value="DoS Hulk">DoS Hulk</option>
        <option value="DoS GoldenEye">DoS GoldenEye</option>
        <option value="DoS slowloris">DoS slowloris</option>
        <option value="DoS Slowhttptest">DoS Slowhttptest</option>
        <option value="PortScan">PortScan</option>
        <option value="Bot">Bot</option>
        <option value="FTP-Patator">FTP-Patator</option>
        <option value="SSH-Patator">SSH-Patator</option>
        <option value="Infiltration">Infiltration</option>
        <option value="Heartbleed">Heartbleed</option>
        <option value="Web Attack – Brute Force">Web Attack – Brute Force</option>
        <option value="Web Attack – XSS">Web Attack – XSS</option>
        <option value="Web Attack – Sql Injection">Web Attack – Sql Injection</option>
      </>
    ) : (
      <>
        <option value="">All Attacks</option>
        <option value="DDoS">DDoS</option>
        <option value="DoS Hulk">DoS Hulk</option>
        <option value="DoS GoldenEye">DoS GoldenEye</option>
        <option value="DoS slowloris">DoS slowloris</option>
        <option value="DoS Slowhttptest">DoS Slowhttptest</option>
        <option value="PortScan">PortScan</option>
        <option value="Bot">Bot</option>
        <option value="FTP-Patator">FTP-Patator</option>
        <option value="SSH-Patator">SSH-Patator</option>
        <option value="Infiltration">Infiltration</option>
        <option value="Heartbleed">Heartbleed</option>
        <option value="Web Attack – Brute Force">Web Attack – Brute Force</option>
        <option value="Web Attack – XSS">Web Attack – XSS</option>
        <option value="Web Attack – Sql Injection">Web Attack – Sql Injection</option>
      </>
    )}
  </select>
</div>
          
<div className="table-wrap">
  <table>
    <thead>
      <tr>
        {[
          'Label',
          'Destination Port',
          'Flow Duration',
          'Fwd Packets',
          'Bwd Packets'
        ].map(c => (
          <th key={c}>{c}</th>
        ))}
      </tr>
    </thead>

    <tbody>
      {logs.map((r, i) => (
        <tr key={r._id || i}>
          <td>
            <span className={`pill ${r.Label === 'BENIGN' ? 'normal' : 'attack'}`}>
              {r.Label || 'Unknown'}
            </span>
          </td>
          <td>{r['Destination Port'] ?? '—'}</td>
          <td>{fmt(r['Flow Duration'])}</td>
          <td>{fmt(r['Total Fwd Packets'])}</td>
          <td>{fmt(r['Total Backward Packets'])}</td>
        </tr>
      ))}
    </tbody>
  </table>

  {logs.length === 0 && (
    <div className="empty">
      No records found, or the backend is unavailable.
    </div>
  )}
</div>

          <div className="pagination"><span>Page {logPage} of {maxPage} · {fmt(logTotal)} records</span><div><button className="secondary-button" disabled={logPage<=1} onClick={()=>loadLogs(logPage-1)}><ChevronLeft size={16}/> Previous</button><button className="secondary-button" disabled={logPage>=maxPage} onClick={()=>loadLogs(logPage+1)}>Next <ChevronRight size={16}/></button></div></div>
        </Panel></>}
        {page==='Model Performance' && <><div className="page-title"><div><div className="eyebrow">MODEL EVALUATION</div><h1>Model performance</h1><p>Existing Random Forest evaluation on the held-out test split.</p></div></div><div className="kpi-grid"><Card label="Accuracy" value="99.8894%" note="Held-out test split" icon={BrainCircuit}/><Card label="Test records" value="566,149" note="20% test partition" icon={Database}/><Card label="Correct predictions" value="565,523" note="From confusion matrix" icon={ShieldCheck}/><Card label="Incorrect predictions" value="626" note="False positives + false negatives" icon={ScanSearch}/></div><Panel title="Confusion matrix" subtitle="Rows are actual labels; columns are predicted labels"><div className="table-wrap"><table><thead><tr><th>Actual</th><th>Predicted Normal</th><th>Predicted Attack</th></tr></thead><tbody><tr><td>Normal</td><td>454,317</td><td>303</td></tr><tr><td>Attack</td><td>323</td><td>111,206</td></tr></tbody></table></div></Panel><Panel title="Feature importance" subtitle="Top features from the existing model"><div className="chart chart-tall"><ResponsiveContainer width="100%" height="100%"><BarChart data={features} layout="vertical" margin={{left:20,right:20}}><CartesianGrid strokeDasharray="3 3" horizontal={false}/><XAxis type="number"/><YAxis type="category" dataKey="feature" width={190} fontSize={10}/><Tooltip/><Bar dataKey="importance" fill="#2563eb" radius={[0,5,5,0]}/></BarChart></ResponsiveContainer></div></Panel><div className="notice">The overall accuracy is not a guarantee of performance on new or real-world network traffic. Per-class precision, recall, and F1-score should be calculated from the exact saved predictions before being displayed.</div></>}
        
        <footer>CyberGuard · Big Data Cybersecurity Log Analytics · CIC-IDS2017</footer>
      </div>
    </main>
  </div>
}
