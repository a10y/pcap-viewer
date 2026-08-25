use bytemuck::{Pod, Zeroable};
use wasm_bindgen::{prelude::*, JsCast};
use wgpu::util::DeviceExt;

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Vertex {
    position: [f32; 2],
    color: [f32; 4],
}

#[wasm_bindgen]
pub struct WebGpuRenderer {
    _instance: wgpu::Instance,
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::RenderPipeline,
    config: wgpu::SurfaceConfiguration,
    canvas: web_sys::HtmlCanvasElement,
    css_width: f32,
    max_texture_dimension: u32,
}

#[wasm_bindgen]
impl WebGpuRenderer {
    #[wasm_bindgen(js_name = create)]
    pub async fn create(canvas_id: String) -> Result<WebGpuRenderer, JsValue> {
        let window = web_sys::window().ok_or_else(|| error("window is unavailable"))?;
        let document = window
            .document()
            .ok_or_else(|| error("document is unavailable"))?;
        let canvas = document
            .get_element_by_id(&canvas_id)
            .ok_or_else(|| error(format!("canvas #{canvas_id} was not found")))?
            .dyn_into::<web_sys::HtmlCanvasElement>()?;

        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::BROWSER_WEBGPU,
            ..Default::default()
        });
        let surface = instance
            .create_surface(wgpu::SurfaceTarget::Canvas(canvas.clone()))
            .map_err(|value| error(format!("could not create WebGPU surface: {value}")))?;
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: Some(&surface),
                force_fallback_adapter: false,
            })
            .await
            .map_err(|value| error(format!("WebGPU adapter is unavailable: {value}")))?;
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("pcap-analyze device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_webgl2_defaults(),
                memory_hints: wgpu::MemoryHints::Performance,
                trace: wgpu::Trace::Off,
            })
            .await
            .map_err(|value| error(format!("could not open WebGPU device: {value}")))?;

        let capabilities = surface.get_capabilities(&adapter);
        let format = capabilities
            .formats
            .iter()
            .copied()
            .find(wgpu::TextureFormat::is_srgb)
            .or_else(|| capabilities.formats.first().copied())
            .ok_or_else(|| error("WebGPU surface has no supported texture format"))?;
        let alpha_mode = capabilities
            .alpha_modes
            .first()
            .copied()
            .unwrap_or(wgpu::CompositeAlphaMode::Opaque);
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width: 1,
            height: 1,
            present_mode: wgpu::PresentMode::Fifo,
            desired_maximum_frame_latency: 2,
            alpha_mode,
            view_formats: vec![],
        };
        surface.configure(&device, &config);

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("flow row shader"),
            source: wgpu::ShaderSource::Wgsl(include_str!("row.wgsl").into()),
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("flow row pipeline layout"),
            bind_group_layouts: &[],
            push_constant_ranges: &[],
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("flow row pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_main"),
                compilation_options: Default::default(),
                buffers: &[wgpu::VertexBufferLayout {
                    array_stride: std::mem::size_of::<Vertex>() as u64,
                    step_mode: wgpu::VertexStepMode::Vertex,
                    attributes: &[
                        wgpu::VertexAttribute {
                            format: wgpu::VertexFormat::Float32x2,
                            offset: 0,
                            shader_location: 0,
                        },
                        wgpu::VertexAttribute {
                            format: wgpu::VertexFormat::Float32x4,
                            offset: 8,
                            shader_location: 1,
                        },
                    ],
                }],
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_main"),
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
            cache: None,
        });

        let max_texture_dimension = device.limits().max_texture_dimension_2d;
        Ok(Self {
            _instance: instance,
            surface,
            device,
            queue,
            pipeline,
            config,
            canvas,
            css_width: 1.0,
            max_texture_dimension,
        })
    }

    pub fn resize(&mut self, css_width: f32, css_height: f32, device_pixel_ratio: f32) {
        let ratio = device_pixel_ratio.clamp(1.0, 3.0);
        self.css_width = css_width.max(1.0);
        let requested_width = self.css_width * ratio;
        let requested_height = css_height.max(1.0) * ratio;
        let limit = self.max_texture_dimension as f32;
        let limit_scale = (limit / requested_width.max(requested_height)).min(1.0);
        self.config.width = (requested_width * limit_scale).round().max(1.0) as u32;
        self.config.height = (requested_height * limit_scale).round().max(1.0) as u32;
        self.canvas.set_width(self.config.width);
        self.canvas.set_height(self.config.height);
        self.surface.configure(&self.device, &self.config);
    }

    pub fn render_rows(
        &self,
        colors: &[u32],
        selected_index: i32,
        row_height_css: f32,
        scroll_offset_css: f32,
    ) -> Result<(), JsValue> {
        let frame = match self.surface.get_current_texture() {
            Ok(frame) => frame,
            Err(wgpu::SurfaceError::Outdated | wgpu::SurfaceError::Lost) => {
                self.surface.configure(&self.device, &self.config);
                match self.surface.get_current_texture() {
                    Ok(frame) => frame,
                    Err(wgpu::SurfaceError::Timeout) => return Ok(()),
                    Err(value) => {
                        return Err(error(format!("WebGPU surface recovery failed: {value}")))
                    }
                }
            }
            Err(wgpu::SurfaceError::Timeout) => return Ok(()),
            Err(value) => return Err(error(format!("WebGPU surface error: {value}"))),
        };
        let view = frame.texture.create_view(&Default::default());
        let scale = self.config.width as f32 / self.css_width.max(1.0);
        let row_height = row_height_css * scale;
        let scroll_offset = scroll_offset_css * scale;
        let width = self.config.width as f32;
        let height = self.config.height as f32;
        let mut vertices = Vec::with_capacity(colors.len() * 12);
        for (index, packed) in colors.iter().copied().enumerate() {
            let y0 = index as f32 * row_height - scroll_offset;
            let y1 = y0 + row_height - scale;
            let accent = unpack_color(packed, 0.95);
            let selected = selected_index == index as i32;
            let base = if selected {
                [0.12, 0.19, 0.25, 1.0]
            } else if index % 2 == 0 {
                [0.035, 0.052, 0.064, 1.0]
            } else {
                [0.042, 0.061, 0.074, 1.0]
            };
            push_rect(&mut vertices, 0.0, y0, width, y1, width, height, base);
            push_rect(
                &mut vertices,
                0.0,
                y0,
                if selected { 5.0 * scale } else { 3.0 * scale },
                y1,
                width,
                height,
                accent,
            );
        }
        let vertex_buffer = (!vertices.is_empty()).then(|| {
            self.device
                .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                    label: Some("visible flow rows"),
                    contents: bytemuck::cast_slice(&vertices),
                    usage: wgpu::BufferUsages::VERTEX,
                })
        });
        let mut encoder = self.device.create_command_encoder(&Default::default());
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("flow row pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color {
                            r: 0.027,
                            g: 0.039,
                            b: 0.047,
                            a: 1.0,
                        }),
                        store: wgpu::StoreOp::Store,
                    },
                    depth_slice: None,
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
            if let Some(vertex_buffer) = &vertex_buffer {
                pass.set_pipeline(&self.pipeline);
                pass.set_vertex_buffer(0, vertex_buffer.slice(..));
                pass.draw(0..vertices.len() as u32, 0..1);
            }
        }
        self.queue.submit(Some(encoder.finish()));
        frame.present();
        Ok(())
    }
}

fn push_rect(
    output: &mut Vec<Vertex>,
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
    width: f32,
    height: f32,
    color: [f32; 4],
) {
    let point = |x: f32, y: f32| [x / width * 2.0 - 1.0, 1.0 - y / height * 2.0];
    let top_left = point(x0, y0);
    let top_right = point(x1, y0);
    let bottom_left = point(x0, y1);
    let bottom_right = point(x1, y1);
    for position in [
        top_left,
        bottom_left,
        top_right,
        top_right,
        bottom_left,
        bottom_right,
    ] {
        output.push(Vertex { position, color });
    }
}

fn unpack_color(packed: u32, alpha: f32) -> [f32; 4] {
    [
        ((packed >> 16) & 0xff) as f32 / 255.0,
        ((packed >> 8) & 0xff) as f32 / 255.0,
        (packed & 0xff) as f32 / 255.0,
        alpha,
    ]
}

fn error(message: impl ToString) -> JsValue {
    js_sys::Error::new(&message.to_string()).into()
}
