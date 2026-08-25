import init, { Analyzer } from "./pkg/pcap_analyze.js";

let analyzer;
let activeLoad = 0;
let wasmFailure;
const wasmReady = init()
  .then(() => {
    analyzer = new Analyzer();
    postMessage({ type: "ready" });
  })
  .catch((error) => {
    wasmFailure = error instanceof Error ? error.message : String(error);
    postMessage({ type: "error", fatal: true, message: `WASM initialization failed: ${wasmFailure}` });
  });

self.onmessage = async ({ data }) => {
  try {
    await wasmReady;
    if (!analyzer) throw new Error(wasmFailure || "WASM analyzer is unavailable");
    switch (data.type) {
      case "load":
        await loadCapture(data.file);
        break;
      case "rows":
        respond(data.requestId, analyzer.rows(data.start, data.count));
        break;
      case "flow": {
        const flow = analyzer.flow(data.id);
        const packets = flow ? analyzer.flow_rows(data.id, 0, Math.min(Number(flow.packetCount), 500)) : [];
        respond(data.requestId, { flow, packets });
        break;
      }
      case "flowRows":
        respond(data.requestId, analyzer.flow_rows(data.id, data.start, data.count));
        break;
      case "entity":
        respond(data.requestId, analyzer.entity(data.id));
        break;
      case "entityFlows":
        respond(data.requestId, analyzer.entity_flows(data.id, data.start, data.count));
        break;
      default:
        throw new Error(`Unknown parser command: ${data.type}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (data.requestId !== undefined) {
      postMessage({ type: "response", requestId: data.requestId, error: message });
    } else {
      postMessage({ type: "error", message });
    }
  }
};

async function loadCapture(file) {
  const loadId = ++activeLoad;
  const chunkSize = 2 * 1024 * 1024;
  let lastProgressAt = 0;
  analyzer.reset(BigInt(file.size));
  postMessage({ type: "load-start", name: file.name, size: file.size });

  for (let offset = 0; offset < file.size; offset += chunkSize) {
    if (loadId !== activeLoad) return;
    const end = Math.min(file.size, offset + chunkSize);
    const bytes = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    if (loadId !== activeLoad) return;
    const progress = analyzer.push_chunk(bytes);
    const now = performance.now();
    if (lastProgressAt === 0 || now - lastProgressAt >= 100) {
      postMessage({ type: "progress", progress });
      lastProgressAt = now;
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (loadId !== activeLoad) return;
  const progress = analyzer.finish();
  postMessage({ type: "complete", progress });
}

function respond(requestId, value) {
  postMessage({ type: "response", requestId, value });
}
