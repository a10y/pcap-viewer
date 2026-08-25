import init, { WebGpuRenderer } from "./pkg/pcap_analyze.js";

const ROW_HEIGHT = 34;
const MAX_SCROLL_HEIGHT = 16_000_000;
const protocolColors = new Map([
  ["HTTP/1", 0x61d0b2], ["HTTP/2", 0x61d0b2], ["TLS", 0xb18ddd],
  ["TCP", 0x6da7d9], ["UDP", 0xd9b36c], ["DNS", 0x72c5d9],
  ["DNS/TCP", 0x72c5d9], ["ARP", 0xe58b7b], ["ICMP", 0xc0c972],
  ["QUIC", 0xb18ddd], ["DHCP", 0xd9b36c], ["mDNS", 0x72c5d9],
]);

const elements = Object.fromEntries([
  "app-shell", "open-file", "file-input", "empty-open", "empty-state", "log-view",
  "capture-name", "capture-meta", "stat-packets", "stat-flows", "stat-entities",
  "stat-bytes", "render-badge", "flow-scroll", "log-spacer", "viewport-stack",
  "flow-canvas", "row-labels", "detail-panel", "detail-content", "close-detail",
  "status-light", "status-text", "status-right", "progress-wrap", "progress-bar",
  "drop-overlay", "host-popover",
].map((id) => [id, document.getElementById(id)]));

const state = {
  packetCount: 0,
  totalBytes: 0,
  selectedPacket: null,
  rows: [],
  visibleStart: 0,
  firstTimestamp: null,
  renderGeneration: 0,
  requestId: 0,
  pending: new Map(),
  workerReady: false,
  renderer: null,
  resizeObserver: null,
  renderQueued: false,
  rowQueryInFlight: false,
  rowRenderPending: false,
  hoverToken: 0,
  detailToken: 0,
};

const worker = new Worker(new URL("./parser.worker.js", import.meta.url), { type: "module" });
worker.onmessage = ({ data }) => {
  if (data.type === "response") {
    const pending = state.pending.get(data.requestId);
    if (!pending) return;
    state.pending.delete(data.requestId);
    data.error ? pending.reject(new Error(data.error)) : pending.resolve(data.value);
    return;
  }
  if (data.type === "ready") {
    state.workerReady = true;
    return;
  }
  if (data.type === "load-start") {
    beginLoad(data.name, data.size);
    return;
  }
  if (data.type === "progress" || data.type === "complete") {
    applyProgress(data.progress, data.type === "complete");
    return;
  }
  if (data.type === "error") failWorker(data.message);
};
worker.onerror = (event) => failWorker(event.message || "Parser worker failed");

boot();

async function boot() {
  bindEvents();
  try {
    await init();
    state.renderer = await WebGpuRenderer.create("flow-canvas");
    elements["render-badge"].textContent = "WebGPU active";
    elements["render-badge"].classList.add("ok");
  } catch (error) {
    console.warn("WebGPU unavailable; using Canvas2D", error);
    const oldCanvas = elements["flow-canvas"];
    const fallbackCanvas = oldCanvas.cloneNode(false);
    oldCanvas.replaceWith(fallbackCanvas);
    elements["flow-canvas"] = fallbackCanvas;
    state.renderer = new CanvasFallback(fallbackCanvas);
    elements["render-badge"].textContent = "Canvas2D fallback";
    elements["render-badge"].classList.add("warn");
  }
  state.resizeObserver = new ResizeObserver(resizeRenderer);
  state.resizeObserver.observe(elements["viewport-stack"]);
  resizeRenderer();
}

function bindEvents() {
  const openPicker = () => elements["file-input"].click();
  elements["open-file"].addEventListener("click", openPicker);
  elements["empty-open"].addEventListener("click", openPicker);
  elements["file-input"].addEventListener("change", (event) => {
    const [file] = event.target.files;
    if (file) loadFile(file);
    event.target.value = "";
  });
  window.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "o") {
      event.preventDefault();
      openPicker();
    }
    if (event.key === "Escape") closeDetail();
  });

  let dragDepth = 0;
  window.addEventListener("dragenter", (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth += 1;
    elements["drop-overlay"].hidden = false;
  });
  window.addEventListener("dragover", (event) => {
    if (isFileDrag(event)) event.preventDefault();
  });
  window.addEventListener("dragleave", (event) => {
    event.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) elements["drop-overlay"].hidden = true;
  });
  window.addEventListener("drop", (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth = 0;
    elements["drop-overlay"].hidden = true;
    const [file] = event.dataTransfer.files;
    if (file) loadFile(file);
  });

  elements["flow-scroll"].addEventListener("scroll", scheduleVisibleRender, { passive: true });
  elements["close-detail"].addEventListener("click", closeDetail);
  elements["row-labels"].addEventListener("click", handleRowClick);
  elements["row-labels"].addEventListener("keydown", handleRowKeydown);
  elements["row-labels"].addEventListener("pointerover", handleAddressHover);
  elements["row-labels"].addEventListener("focusin", handleAddressHover);
  elements["row-labels"].addEventListener("pointerout", hideHostPopover);
  elements["row-labels"].addEventListener("focusout", hideHostPopover);
  elements["detail-content"].addEventListener("click", (event) => {
    const flowMore = event.target.closest("[data-flow-more]");
    if (flowMore) {
      loadMoreFlowRows(flowMore);
      return;
    }
    const entityMore = event.target.closest("[data-entity-more]");
    if (entityMore) {
      loadMoreEntityFlows(entityMore);
      return;
    }
    const button = event.target.closest("[data-flow-id]");
    if (button) showFlow(button.dataset.flowId);
  });
}

function isFileDrag(event) {
  return event.dataTransfer?.types?.includes("Files") ?? false;
}

function loadFile(file) {
  const name = file.name.toLowerCase();
  if (!name.endsWith(".pcap") && !name.endsWith(".pcapng")) {
    showError("Choose a .pcap or .pcapng file");
    return;
  }
  worker.postMessage({ type: "load", file });
}

function beginLoad(name, size) {
  state.packetCount = 0;
  state.totalBytes = size;
  state.selectedPacket = null;
  state.firstTimestamp = null;
  elements["capture-name"].textContent = name;
  elements["capture-meta"].textContent = `${formatBytes(size)} · detecting format`;
  elements["empty-state"].hidden = true;
  elements["log-view"].hidden = false;
  elements["progress-wrap"].hidden = false;
  elements["progress-bar"].style.width = "0%";
  elements["status-light"].className = "status-light active";
  elements["status-text"].textContent = "Indexing capture…";
  elements["status-right"].textContent = "Worker parser active";
  closeDetail();
  updateStats({ packets: 0, flows: 0, entities: 0, capturedBytes: 0 });
  updateScrollExtent();
  scheduleVisibleRender();
}

function applyProgress(progress, complete) {
  state.packetCount = Number(progress.stats.packets);
  const consumed = Number(progress.consumedBytes);
  const total = Number(progress.totalBytes) || state.totalBytes;
  const percent = total ? Math.min(100, consumed / total * 100) : 0;
  elements["progress-bar"].style.width = `${percent}%`;
  elements["progress-wrap"].setAttribute("aria-valuenow", percent.toFixed(1));
  elements["capture-meta"].textContent = `${formatBytes(total)} · ${progress.format.toUpperCase()}`;
  elements["status-text"].textContent = complete
    ? `Indexed ${formatNumber(state.packetCount)} packets`
    : `Indexing ${formatNumber(state.packetCount)} packets · ${percent.toFixed(1)}%`;
  elements["status-right"].textContent = complete ? "Index complete" : `${formatBytes(consumed)} / ${formatBytes(total)}`;
  elements["status-light"].className = complete ? "status-light active" : "status-light active";
  elements["progress-wrap"].hidden = complete;
  updateStats(progress.stats);
  updateScrollExtent();
  scheduleVisibleRender();
}

function updateStats(stats) {
  elements["stat-packets"].textContent = formatNumber(Number(stats.packets));
  elements["stat-flows"].textContent = formatNumber(Number(stats.flows));
  elements["stat-entities"].textContent = formatNumber(Number(stats.entities));
  elements["stat-bytes"].textContent = formatBytes(Number(stats.capturedBytes));
}

function updateScrollExtent() {
  const logicalHeight = Math.max(elements["flow-scroll"].clientHeight, state.packetCount * ROW_HEIGHT);
  elements["log-spacer"].style.height = `${Math.min(MAX_SCROLL_HEIGHT, logicalHeight)}px`;
}

function scheduleVisibleRender() {
  if (state.renderQueued) return;
  state.renderQueued = true;
  requestAnimationFrame(() => {
    state.renderQueued = false;
    renderVisibleRows();
  });
}

async function renderVisibleRows() {
  if (!state.renderer || !state.packetCount) {
    if (state.renderer) state.renderer.render_rows([], -1, ROW_HEIGHT, 0);
    elements["row-labels"].replaceChildren();
    return;
  }
  const scroll = elements["flow-scroll"];
  if (state.rowQueryInFlight) {
    state.rowRenderPending = true;
    return;
  }
  const physicalHeight = Math.max(scroll.clientHeight, state.packetCount * ROW_HEIGHT);
  const spacerHeight = Math.min(MAX_SCROLL_HEIGHT, physicalHeight);
  const logicalRange = Math.max(0, physicalHeight - scroll.clientHeight);
  const spacerRange = Math.max(0, spacerHeight - scroll.clientHeight);
  const logicalTop = spacerRange > 0 ? scroll.scrollTop * logicalRange / spacerRange : 0;
  const visibleCount = Math.ceil(scroll.clientHeight / ROW_HEIGHT) + 2;
  const maxStart = Math.max(0, state.packetCount - visibleCount);
  const start = Math.min(maxStart, Math.floor(logicalTop / ROW_HEIGHT));
  const count = Math.min(state.packetCount - start, visibleCount);
  const offset = logicalTop - start * ROW_HEIGHT;
  const generation = ++state.renderGeneration;
  state.rowQueryInFlight = true;
  try {
    const rows = await query("rows", { start, count });
    if (generation !== state.renderGeneration) return;
    state.rows = rows;
    state.visibleStart = start;
    if (state.firstTimestamp === null && rows.length && Number.isFinite(rows[0].timestampMicros)) {
      state.firstTimestamp = Number(rows[0].timestampMicros);
    }
    const colors = rows.map((row) => protocolColors.get(row.protocol) ?? 0x6f8792);
    const selected = rows.findIndex((row) => String(row.id) === String(state.selectedPacket));
    state.renderer.render_rows(new Uint32Array(colors), selected, ROW_HEIGHT, offset);
    renderLabels(rows, offset);
  } catch (error) {
    showError(error.message);
  } finally {
    state.rowQueryInFlight = false;
    if (state.rowRenderPending) {
      state.rowRenderPending = false;
      scheduleVisibleRender();
    }
  }
}

function renderLabels(rows, offset) {
  const fragment = document.createDocumentFragment();
  rows.forEach((row, index) => {
    const item = document.createElement("div");
    item.className = "flow-row";
    item.role = "listitem";
    item.tabIndex = row.flowId !== undefined && row.flowId !== null ? 0 : -1;
    if (row.flowId !== undefined && row.flowId !== null) item.setAttribute("aria-haspopup", "dialog");
    item.dataset.packetId = String(row.id);
    item.setAttribute("aria-label", `${row.protocol} packet from ${row.source} to ${row.destination}`);
    if (row.flowId !== undefined && row.flowId !== null) item.dataset.flowId = String(row.flowId);
    item.style.top = `${index * ROW_HEIGHT - offset}px`;
    item.innerHTML = `
      <span>${formatTimestamp(row.timestampMicros)}</span>
      <span class="protocol" style="color:#${(protocolColors.get(row.protocol) ?? 0x8299a3).toString(16).padStart(6, "0")}">${escapeHtml(row.protocol)}</span>
      ${addressButton(row.source, row.sourceEntity)}
      ${addressButton(row.destination, row.destinationEntity)}
      <span class="summary">${escapeHtml(row.summary)}</span>
      <span class="bytes">${formatNumber(Number(row.wireLen))}</span>`;
    fragment.append(item);
  });
  elements["row-labels"].replaceChildren(fragment);
}

function addressButton(address, entityId) {
  if (entityId === undefined || entityId === null) {
    return `<span class="address address-static">${escapeHtml(address)}</span>`;
  }
  return `<button class="address" type="button" data-entity-id="${escapeHtml(String(entityId))}">${escapeHtml(address)}</button>`;
}

function handleRowKeydown(event) {
  if (event.target !== event.target.closest(".flow-row")) return;
  if (event.key !== "Enter" && event.key !== " ") return;
  event.preventDefault();
  handleRowClick(event);
}

function handleRowClick(event) {
  const address = event.target.closest(".address[data-entity-id]");
  if (address) {
    event.stopPropagation();
    showEntity(address.dataset.entityId);
    return;
  }
  const row = event.target.closest(".flow-row");
  if (!row) return;
  state.selectedPacket = row.dataset.packetId;
  scheduleVisibleRender();
  if (row.dataset.flowId !== undefined) showFlow(row.dataset.flowId);
}

async function handleAddressHover(event) {
  const address = event.target.closest(".address[data-entity-id]");
  if (!address) return;
  const token = ++state.hoverToken;
  try {
    const entity = await query("entity", { id: BigInt(address.dataset.entityId) });
    if (!entity || state.hoverToken !== token) return;
    const rect = address.getBoundingClientRect();
    elements["host-popover"].innerHTML = `<strong>${escapeHtml(entity.label)}</strong>
      <p>${entity.addresses.length} addresses · ${formatNumber(Number(entity.flowCount))} flows</p>
      <p>↑ ${formatNumber(Number(entity.packetsOut))} packets · ↓ ${formatNumber(Number(entity.packetsIn))} packets</p>`;
    elements["host-popover"].style.left = `${Math.max(8, Math.min(innerWidth - 235, rect.left))}px`;
    elements["host-popover"].style.top = `${Math.max(8, Math.min(innerHeight - 90, rect.bottom + 7))}px`;
    elements["host-popover"].hidden = false;
  } catch (_) { /* A later hover can supersede this query. */ }
}

function hideHostPopover(event) {
  if (!event.target.closest(".address")) return;
  state.hoverToken += 1;
  elements["host-popover"].hidden = true;
}

async function showFlow(id) {
  const token = ++state.detailToken;
  openDetail("Loading flow…");
  try {
    const { flow, packets } = await query("flow", { id: BigInt(id) });
    if (token !== state.detailToken) return;
    if (!flow) throw new Error("Flow was not found");
    const total = Number(flow.packetCount);
    elements["detail-content"].innerHTML = `
      <div class="detail-head"><p>FLOW ${escapeHtml(String(flow.id))} · ${escapeHtml(flow.transport)}</p><h2>${escapeHtml(flow.application)}</h2><p>${escapeHtml(flow.endpointA)} ↔ ${escapeHtml(flow.endpointB)}</p></div>
      <div class="detail-body">
        <section class="detail-section"><h3>Traffic</h3><div class="metric-row">
          ${metric("Packets", flow.packetCount)}${metric("Duration", formatDuration(Number(flow.endedMicros) - Number(flow.startedMicros)))}
          ${metric("A → B", formatBytes(Number(flow.bytesAToB)))}${metric("B → A", formatBytes(Number(flow.bytesBToA)))}
        </div></section>
        <section class="detail-section"><h3>Packets in this flow</h3>
          <ul id="flow-packet-list" class="packet-list">${packets.map(packetListItem).join("")}</ul>
          ${total > packets.length ? `<button class="load-more" type="button" data-flow-more="${flow.id}" data-start="${packets.length}" data-total="${total}">Load 500 more packets</button>` : ""}
        </section>
      </div>`;
  } catch (error) { if (token === state.detailToken) showDetailError(error.message); }
}

async function showEntity(id) {
  const token = ++state.detailToken;
  openDetail("Loading entity…");
  try {
    const entityId = BigInt(id);
    const [entity, flows] = await Promise.all([
      query("entity", { id: entityId }),
      query("entityFlows", { id: entityId, start: 0, count: 500 }),
    ]);
    if (token !== state.detailToken) return;
    if (!entity) throw new Error("Entity was not found");
    const total = Number(entity.flowCount);
    elements["detail-content"].innerHTML = `
      <div class="detail-head"><p>HOST ENTITY ${escapeHtml(String(entity.id))}</p><h2>${escapeHtml(entity.label)}</h2><p>${formatNumber(entity.addresses.length)} observed addresses</p></div>
      <div class="detail-body">
        <section class="detail-section"><h3>Packet counters</h3><div class="metric-row">
          ${metric("Packets out", entity.packetsOut)}${metric("Packets in", entity.packetsIn)}
          ${metric("Bytes out", formatBytes(Number(entity.bytesOut)))}${metric("Bytes in", formatBytes(Number(entity.bytesIn)))}
        </div></section>
        <section class="detail-section"><h3>Observed addresses</h3><ul class="address-list">${entity.addresses.map((address) => `<li>${escapeHtml(address)}</li>`).join("")}</ul></section>
        <section class="detail-section"><h3>Associated flows</h3><ul id="entity-flow-list" class="flow-list">${flows.map(flowListItem).join("") || "<li>No transport flows observed</li>"}</ul>
          ${total > flows.length ? `<button class="load-more" type="button" data-entity-more="${entity.id}" data-start="${flows.length}" data-total="${total}">Load 500 more flows</button>` : ""}
        </section>
      </div>`;
  } catch (error) { if (token === state.detailToken) showDetailError(error.message); }
}

async function loadMoreFlowRows(button) {
  button.disabled = true;
  const token = state.detailToken;
  const start = Number(button.dataset.start);
  try {
    const packets = await query("flowRows", { id: BigInt(button.dataset.flowMore), start, count: 500 });
    if (token !== state.detailToken || !button.isConnected) return;
    document.getElementById("flow-packet-list").insertAdjacentHTML("beforeend", packets.map(packetListItem).join(""));
    const loaded = start + packets.length;
    if (!packets.length || loaded >= Number(button.dataset.total)) button.remove();
    else {
      button.dataset.start = String(loaded);
      button.disabled = false;
    }
  } catch (error) {
    if (button.isConnected) {
      button.disabled = false;
      showError(error.message);
    }
  }
}

async function loadMoreEntityFlows(button) {
  button.disabled = true;
  const token = state.detailToken;
  const start = Number(button.dataset.start);
  try {
    const flows = await query("entityFlows", { id: BigInt(button.dataset.entityMore), start, count: 500 });
    if (token !== state.detailToken || !button.isConnected) return;
    document.getElementById("entity-flow-list").insertAdjacentHTML("beforeend", flows.map(flowListItem).join(""));
    const loaded = start + flows.length;
    if (!flows.length || loaded >= Number(button.dataset.total)) button.remove();
    else {
      button.dataset.start = String(loaded);
      button.disabled = false;
    }
  } catch (error) {
    if (button.isConnected) {
      button.disabled = false;
      showError(error.message);
    }
  }
}

function packetListItem(packet) {
  return `<li><span>#${packet.id}</span><span>${escapeHtml(packet.protocol)}</span><span>${escapeHtml(packet.summary)}</span><span>${formatBytes(Number(packet.wireLen))}</span></li>`;
}

function flowListItem(flow) {
  return `<li><button type="button" data-flow-id="${flow.id}">${escapeHtml(flow.application)} · ${escapeHtml(flow.endpointA)} ↔ ${escapeHtml(flow.endpointB)} · ${formatNumber(Number(flow.packetCount))} packets</button></li>`;
}

function openDetail(message) {
  elements["detail-panel"].hidden = false;
  elements["close-detail"].hidden = false;
  elements["app-shell"].classList.add("has-detail");
  elements["detail-content"].innerHTML = `<div class="detail-head"><p>${escapeHtml(message)}</p></div>`;
  elements["detail-panel"].focus({ preventScroll: true });
  requestAnimationFrame(resizeRenderer);
}

function closeDetail() {
  state.detailToken += 1;
  elements["detail-panel"].hidden = true;
  elements["close-detail"].hidden = true;
  elements["app-shell"].classList.remove("has-detail");
  requestAnimationFrame(resizeRenderer);
}

function showDetailError(message) {
  elements["detail-content"].innerHTML = `<div class="detail-head"><p>DETAIL ERROR</p><h2>${escapeHtml(message)}</h2></div>`;
}

function failWorker(message) {
  const error = new Error(message);
  for (const pending of state.pending.values()) pending.reject(error);
  state.pending.clear();
  state.rowQueryInFlight = false;
  showError(message);
}

function query(type, payload) {
  const requestId = ++state.requestId;
  return new Promise((resolve, reject) => {
    state.pending.set(requestId, { resolve, reject });
    worker.postMessage({ type, requestId, ...payload });
  });
}

function resizeRenderer() {
  if (!state.renderer) return;
  elements["viewport-stack"].style.height = `${Math.max(1, elements["flow-scroll"].clientHeight)}px`;
  const rect = elements["viewport-stack"].getBoundingClientRect();
  state.renderer.resize(rect.width, rect.height, window.devicePixelRatio || 1);
  scheduleVisibleRender();
}

function showError(message) {
  elements["status-light"].className = "status-light error";
  elements["status-text"].textContent = message;
  elements["progress-wrap"].hidden = true;
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(formatNumberLike(value))}</strong></div>`;
}
function formatNumberLike(value) { return typeof value === "bigint" || typeof value === "number" ? formatNumber(Number(value)) : String(value); }
function formatNumber(value) { return new Intl.NumberFormat("en-US", { notation: value >= 1_000_000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(value || 0); }
function formatBytes(value) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const unit = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** unit).toFixed(unit ? 1 : 0)} ${units[unit]}`;
}
function formatDuration(micros) {
  if (!Number.isFinite(micros)) return "—";
  if (micros < 1000) return `${Math.max(0, micros).toFixed(0)} µs`;
  if (micros < 1_000_000) return `${(micros / 1000).toFixed(1)} ms`;
  return `${(micros / 1_000_000).toFixed(2)} s`;
}
function formatTimestamp(value) {
  const micros = Number(value);
  if (!Number.isFinite(micros)) return "—";
  if (state.firstTimestamp === null) state.firstTimestamp = micros;
  return `+${((micros - state.firstTimestamp) / 1_000_000).toFixed(6)}`;
}
function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
}

class CanvasFallback {
  constructor(canvas) {
    this.canvas = canvas;
    this.context = canvas.getContext("2d");
    if (!this.context) throw new Error("Canvas2D is unavailable");
    this.cssWidth = 1;
  }
  resize(width, height, ratio) {
    const scale = Math.min(3, Math.max(1, ratio));
    this.cssWidth = width;
    this.canvas.width = Math.max(1, Math.round(width * scale));
    this.canvas.height = Math.max(1, Math.round(height * scale));
  }
  render_rows(colors, selected, rowHeightCss, offsetCss) {
    const context = this.context;
    const scale = this.canvas.width / Math.max(1, this.cssWidth);
    context.clearRect(0, 0, this.canvas.width, this.canvas.height);
    context.fillStyle = "#071016";
    context.fillRect(0, 0, this.canvas.width, this.canvas.height);
    colors.forEach((color, index) => {
      const y = (index * rowHeightCss - offsetCss) * scale;
      context.fillStyle = selected === index ? "#1f303b" : index % 2 ? "#0b171e" : "#09141a";
      context.fillRect(0, y, this.canvas.width, rowHeightCss * scale - 1);
      context.fillStyle = `#${Number(color).toString(16).padStart(6, "0")}`;
      context.fillRect(0, y, (selected === index ? 5 : 3) * scale, rowHeightCss * scale - 1);
    });
  }
}
