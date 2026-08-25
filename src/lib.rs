mod capture;
mod decode;
mod model;

#[cfg(target_arch = "wasm32")]
mod render;

use capture::CaptureParser;
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
pub use render::WebGpuRenderer;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
#[derive(Default)]
pub struct Analyzer {
    parser: CaptureParser,
}

#[wasm_bindgen]
impl Analyzer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self, total_bytes: u64) {
        self.parser.reset(total_bytes);
    }

    pub fn push_chunk(&mut self, bytes: &[u8]) -> Result<JsValue, JsValue> {
        let progress = self.parser.push(bytes).map_err(js_error)?;
        to_js(&progress)
    }

    pub fn finish(&mut self) -> Result<JsValue, JsValue> {
        let progress = self.parser.finish().map_err(js_error)?;
        to_js(&progress)
    }

    pub fn progress(&self) -> Result<JsValue, JsValue> {
        to_js(&self.parser.progress())
    }

    pub fn rows(&self, start: usize, count: usize) -> Result<JsValue, JsValue> {
        to_js(&self.parser.index().rows(start, count))
    }

    pub fn flow(&self, id: u64) -> Result<JsValue, JsValue> {
        to_js(&self.parser.index().flow(id))
    }

    pub fn flow_rows(&self, id: u64, start: usize, count: usize) -> Result<JsValue, JsValue> {
        to_js(&self.parser.index().flow_rows(id, start, count))
    }

    pub fn entity(&self, id: u64) -> Result<JsValue, JsValue> {
        to_js(&self.parser.index().entity(id))
    }

    pub fn entity_flows(&self, id: u64, start: usize, count: usize) -> Result<JsValue, JsValue> {
        to_js(&self.parser.index().entity_flows(id, start, count))
    }
}

fn to_js<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|error| js_error(error.to_string()))
}

fn js_error(error: impl ToString) -> JsValue {
    js_sys::Error::new(&error.to_string()).into()
}
