
// pub use wasm_bindgen_rayon::init_thread_pool;
// #[wasm_bindgen]
// extern "C" {
//     // Use `js_namespace` here to bind `console.log(..)` instead of just
//     // `log(..)`
//     #[wasm_bindgen(js_namespace = console)]
//     pub fn log(s: &str);

//     // The `console.log` is quite polymorphic, so we can bind it with multiple
//     // signatures. Note that we need to use `js_name` to ensure we always call
//     // `log` in JS.
//     #[wasm_bindgen(js_namespace = console, js_name = log)]
//     pub fn log_u32(a: u32);

//     // Multiple arguments too!
//     #[wasm_bindgen(js_namespace = console, js_name = log)]
//     pub fn log_many(a: &str, b: &str);

//     pub type Performance;

//     pub static performance: Performance;

//     #[wasm_bindgen(method)]
//     pub fn now(this: &Performance) -> f64;
// }
