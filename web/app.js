const state = { data: null, activeStep: 3 };
const $ = (id) => document.getElementById(id);

const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
}[char]));

async function fetchOverview() {
  const start = performance.now();
  const response = await fetch('/api/overview');
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Analysis failed');
  payload.elapsed = performance.now() - start;
  return payload;
}

function renderSummary(data) {
  const summary = data.summary;
  $('advisoryId').textContent = data.advisory.id;
  $('advisorySummary').textContent = data.advisory.summary;
  $('queryTime').textContent = `${Math.max(1, Math.round(data.elapsed))} ms`;
  $('exposedCount').textContent = summary.applications_exposed;
  $('productionCount').textContent = summary.production_exposed;
  $('transitiveCount').textContent = summary.transitive_exposure;
  $('directCount').textContent = summary.direct_exposure;
  $('pathCount').textContent = summary.evidence_paths;
  $('upgradeCount').textContent = summary.recommended_upgrades;
}

function renderExposures(data) {
  const container = $('exposureList');
  if (!data.exposures.length) {
    container.innerHTML = '<div class="empty">No verified exposure paths.</div>';
    return;
  }
  container.innerHTML = data.exposures.map((exposure, index) => {
    const path = exposure.paths[0].packages;
    return `<article class="exposure" data-index="${index}" tabindex="0">
      <div class="exposure-top">
        <div class="exposure-name"><span class="risk-icon">!</span>${escapeHtml(exposure.application.name)}</div>
        <span class="environment">${escapeHtml(exposure.application.environment)}</span>
      </div>
      <p class="exposure-path">${path.map((node) => escapeHtml(node.name)).join(' → ')}</p>
      <div class="exposure-meta"><span>${exposure.path_count} verified path${exposure.path_count === 1 ? '' : 's'}</span><span>${exposure.direct ? 'direct' : `${exposure.shortest_depth} hops`}</span></div>
    </article>`;
  }).join('');
  container.querySelectorAll('.exposure').forEach((element) => {
    const open = () => openEvidence(data.exposures[Number(element.dataset.index)]);
    element.addEventListener('click', open);
    element.addEventListener('keydown', (event) => { if (event.key === 'Enter') open(); });
  });
}

function openEvidence(exposure) {
  const path = exposure.paths[0];
  $('dialogTitle').textContent = exposure.application.name;
  $('dialogSubtitle').textContent = `${exposure.application.repository} · ${exposure.application.environment} · ${path.depth} dependency hops`;
  const nodes = [{ name: exposure.application.name, bad: false }, ...path.packages.map((node, index) => ({ name: `${node.name}@${node.version}`, bad: index === path.packages.length - 1 }))];
  $('dialogPath').innerHTML = nodes.map((node, index) => `${index ? '<span class="path-arrow">→</span>' : ''}<span class="path-node ${node.bad ? 'bad' : ''}">${escapeHtml(node.name)}</span>`).join('');
  $('evidenceDialog').showModal();
}

function renderRemediations(data) {
  const container = $('remediationList');
  container.innerHTML = data.remediations.map((item) => `<article class="remediation">
    <span class="priority">${item.priority}</span>
    <div><h3>${escapeHtml(item.action)}</h3><p>${item.applications.map(escapeHtml).join(', ')}</p><small>Breaks ${item.paths_removed} verified attack path${item.paths_removed === 1 ? '' : 's'}</small></div>
  </article>`).join('') || '<div class="empty">No remediation required.</div>';
}

function buildGraphData(data) {
  const nodes = new Map();
  const edges = new Map();
  data.exposures.forEach((exposure) => exposure.paths.forEach((path) => {
    const appId = `app:${exposure.application.id}`;
    nodes.set(appId, { id: appId, label: exposure.application.name, sub: exposure.application.environment, type: 'app' });
    let previous = appId;
    path.packages.forEach((pkg, index) => {
      nodes.set(pkg.id, { id: pkg.id, label: pkg.name, sub: pkg.version, type: index === path.packages.length - 1 ? 'bad' : 'package' });
      edges.set(`${previous}|${pkg.id}`, { source: previous, target: pkg.id, hot: index === path.packages.length - 1 });
      previous = pkg.id;
    });
  }));
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

function renderGraph(data) {
  const graph = buildGraphData(data);
  const width = 900, height = 390;
  const layers = { app: [], package: [], bad: [] };
  graph.nodes.forEach((node) => layers[node.type].push(node));
  const positions = new Map();
  const place = (items, x, span = 300) => items.forEach((node, index) => {
    const y = height / 2 + (index - (items.length - 1) / 2) * Math.min(72, span / Math.max(1, items.length - 1));
    positions.set(node.id, { x, y });
  });
  place(layers.app, 115, 300);
  const packageNodes = layers.package.sort((a,b) => a.label.localeCompare(b.label));
  packageNodes.forEach((node, index) => {
    const column = index % 2;
    const row = Math.floor(index / 2);
    positions.set(node.id, { x: 360 + column * 205, y: 72 + row * 78 });
  });
  place(layers.bad, 795, 120);

  const edgeSvg = graph.edges.map((edge) => {
    const from = positions.get(edge.source), to = positions.get(edge.target);
    if (!from || !to) return '';
    const curve = Math.max(45, (to.x - from.x) * .45);
    return `<path class="graph-edge ${edge.hot ? 'hot' : ''}" d="M${from.x},${from.y} C${from.x + curve},${from.y} ${to.x - curve},${to.y} ${to.x},${to.y}"/>`;
  }).join('');
  const nodeSvg = graph.nodes.map((node) => {
    const pos = positions.get(node.id); const radius = node.type === 'app' ? 24 : node.type === 'bad' ? 31 : 21;
    return `<g class="node ${node.type}" transform="translate(${pos.x} ${pos.y})"><circle r="${radius}"/><text y="${radius + 18}">${escapeHtml(node.label)}</text><text class="sub" y="${radius + 30}">${escapeHtml(node.sub)}</text>${node.type === 'bad' ? '<text y="4" style="fill:#ff6b6b;font-size:17px">!</text>' : ''}</g>`;
  }).join('');
  $('graphCanvas').innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet"><g>${edgeSvg}${nodeSvg}</g></svg>`;
}

function setTimeline(step) {
  state.activeStep = step;
  document.querySelectorAll('.time-point').forEach((button, index) => button.classList.toggle('active', index <= step));
  $('timelineProgress').style.width = `${step * 33.333}%`;
  const svg = $('graphCanvas').querySelector('svg');
  if (svg) { svg.style.opacity = step === 0 ? '.24' : '1'; svg.style.filter = step === 1 ? 'saturate(.7)' : 'none'; }
}

async function load() {
  try {
    const [data, health] = await Promise.all([fetchOverview(), fetch('/api/health').then((r) => r.json())]);
    state.data = data;
    $('backendLabel').textContent = `${health.backend.replace('Graph', '').toUpperCase()} GRAPH ONLINE`;
    renderSummary(data); renderExposures(data); renderRemediations(data); renderGraph(data); setTimeline(3);
  } catch (error) {
    $('graphCanvas').innerHTML = `<div class="error">${escapeHtml(error.message)}<br><small>Start the demo with: make demo</small></div>`;
    $('backendLabel').textContent = 'GRAPH CONNECTION ERROR';
  }
}

$('resetButton').addEventListener('click', async () => {
  $('resetButton').disabled = true;
  try {
    await fetch('/api/demo/reset', { method: 'POST' });
    setTimeline(0);
    for (let step = 1; step <= 3; step++) await new Promise((resolve) => setTimeout(() => { setTimeline(step); resolve(); }, 550));
    await load();
    $('toast').classList.add('show'); setTimeout(() => $('toast').classList.remove('show'), 2200);
  } finally { $('resetButton').disabled = false; }
});
document.querySelectorAll('.time-point').forEach((button) => button.addEventListener('click', () => setTimeline(Number(button.dataset.step))));
$('dialogClose').addEventListener('click', () => $('evidenceDialog').close());
$('evidenceDialog').addEventListener('click', (event) => { if (event.target === $('evidenceDialog')) $('evidenceDialog').close(); });
load();

