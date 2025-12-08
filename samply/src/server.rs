use std::collections::HashMap;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::io::BufWriter;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use futures_util::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Either, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rand::RngCore;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;
use wholesym::SymbolManager;

use crate::profile_analysis::ProfileAnalyzer;
use crate::shared::ctrl_c;

#[derive(Clone, Debug)]
pub struct ServerProps {
    pub address: IpAddr,
    pub port_selection: PortSelection,
    pub verbose: bool,
    pub open_in_browser: bool,
}

const BAD_CHARS: &AsciiSet = &CONTROLS.add(b':').add(b'/');

#[derive(Clone, Debug)]
pub enum PortSelection {
    OnePort(u16),
    TryMultiple(Range<u16>),
}

impl PortSelection {
    pub fn try_from_str(s: &str) -> std::result::Result<Self, <u16 as FromStr>::Err> {
        if s.ends_with('+') {
            let start = s.trim_end_matches('+').parse()?;
            let end = start + 100;
            Ok(PortSelection::TryMultiple(start..end))
        } else {
            Ok(PortSelection::OnePort(s.parse()?))
        }
    }
}

pub struct RunningServerInfo {
    pub server_join_handle:
        tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    pub server_origin: String,
    pub token_url: String,
    pub profiler_url: Option<String>,
    /// Whether the profile appears to be unsymbolicated (function names are hex addresses)
    pub is_likely_unsymbolicated: bool,
}

pub async fn start_server(
    profile_filename: Option<&Path>,
    server_props: ServerProps,
    symbol_manager: SymbolManager,
    stop_signal: ctrl_c::Receiver,
) -> RunningServerInfo {
    let (listener, addr) = make_listener(server_props.address, server_props.port_selection).await;

    let token = generate_token();
    let path_prefix = format!("/{token}");
    let env_server_override = std::env::var("SAMPLY_SERVER_URL").ok();
    let server_origin = match &env_server_override {
        Some(s) => s.trim_end_matches('/').to_string(),
        None => format!("http://{addr}"),
    };
    let symbol_server_url = format!("{server_origin}{path_prefix}");
    let mut template_values: HashMap<&'static str, String> = HashMap::new();
    template_values.insert("SAMPLY_SERVER_URL", server_origin.clone());
    template_values.insert("PATH_PREFIX", path_prefix.clone());

    let profiler_url = if profile_filename.is_some() {
        let profile_url = format!("{symbol_server_url}/profile.json");

        let env_profiler_override = std::env::var("PROFILER_URL").ok();
        let profiler_origin = match &env_profiler_override {
            Some(s) => s.trim_end_matches('/'),
            None => "https://profiler.firefox.com",
        };

        let encoded_profile_url = utf8_percent_encode(&profile_url, BAD_CHARS).to_string();
        let encoded_symbol_server_url =
            utf8_percent_encode(&symbol_server_url, BAD_CHARS).to_string();
        let profiler_url = format!(
            "{profiler_origin}/from-url/{encoded_profile_url}/?symbolServer={encoded_symbol_server_url}"
        );
        template_values.insert("PROFILER_URL", profiler_url.clone());
        template_values.insert("PROFILE_URL", profile_url);
        Some(profiler_url)
    } else {
        None
    };

    let template_values = Arc::new(template_values);

    let server_join_handle = tokio::task::spawn(run_server(
        listener,
        symbol_manager,
        None, // No profile analyzer for regular server
        profile_filename.map(PathBuf::from),
        template_values,
        path_prefix.clone(),
        stop_signal,
    ));

    RunningServerInfo {
        server_join_handle,
        server_origin,
        token_url: symbol_server_url,
        profiler_url,
        is_likely_unsymbolicated: false, // Not applicable for regular server
    }
}

/// Start an analysis server with profile loaded for querying
pub async fn start_analysis_server(
    profile_path: &Path,
    server_props: ServerProps,
    symbol_manager: SymbolManager,
    stop_signal: ctrl_c::Receiver,
) -> Result<RunningServerInfo, crate::profile_analysis::AnalysisError> {
    // Load the profile for analysis
    let analyzer = ProfileAnalyzer::from_file(profile_path)?;
    let is_likely_unsymbolicated = analyzer.is_likely_unsymbolicated();

    let (listener, addr) = make_listener(server_props.address, server_props.port_selection.clone()).await;

    let token = generate_token();
    let path_prefix = format!("/{token}");
    let env_server_override = std::env::var("SAMPLY_SERVER_URL").ok();
    let server_origin = match &env_server_override {
        Some(s) => s.trim_end_matches('/').to_string(),
        None => format!("http://{addr}"),
    };
    let symbol_server_url = format!("{server_origin}{path_prefix}");

    let mut template_values: HashMap<&'static str, String> = HashMap::new();
    template_values.insert("SAMPLY_SERVER_URL", server_origin.clone());
    template_values.insert("PATH_PREFIX", path_prefix.clone());

    let profile_url = format!("{symbol_server_url}/profile.json");
    let env_profiler_override = std::env::var("PROFILER_URL").ok();
    let profiler_origin = match &env_profiler_override {
        Some(s) => s.trim_end_matches('/'),
        None => "https://profiler.firefox.com",
    };

    let encoded_profile_url = utf8_percent_encode(&profile_url, BAD_CHARS).to_string();
    let encoded_symbol_server_url =
        utf8_percent_encode(&symbol_server_url, BAD_CHARS).to_string();
    let profiler_url = format!(
        "{profiler_origin}/from-url/{encoded_profile_url}/?symbolServer={encoded_symbol_server_url}"
    );
    template_values.insert("PROFILER_URL", profiler_url.clone());
    template_values.insert("PROFILE_URL", profile_url);

    let template_values = Arc::new(template_values);

    let server_join_handle = tokio::task::spawn(run_server(
        listener,
        symbol_manager,
        Some(Arc::new(analyzer)),
        Some(profile_path.to_path_buf()),
        template_values,
        path_prefix.clone(),
        stop_signal,
    ));

    Ok(RunningServerInfo {
        server_join_handle,
        server_origin,
        token_url: symbol_server_url,
        profiler_url: Some(profiler_url),
        is_likely_unsymbolicated,
    })
}

// Returns a base32 string for 24 random bytes.
fn generate_token() -> String {
    let mut bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    nix_base32::to_nix_base32(&bytes)
}

async fn make_listener(addr: IpAddr, port_selection: PortSelection) -> (TcpListener, SocketAddr) {
    match port_selection {
        PortSelection::OnePort(port) => {
            let addr = SocketAddr::from((addr, port));
            match TcpListener::bind(&addr).await {
                Ok(listener) => (listener, addr),
                Err(e) => {
                    eprintln!("Could not bind to port {port}: {e}");
                    std::process::exit(1)
                }
            }
        }
        PortSelection::TryMultiple(range) => {
            let mut error = None;
            for port in range.clone() {
                let addr = SocketAddr::from((addr, port));
                match TcpListener::bind(&addr).await {
                    Ok(listener) => return (listener, addr),
                    Err(e) => {
                        error.get_or_insert(e);
                    }
                }
            }
            match error {
                Some(error) => {
                    eprintln!("Could not bind to any port in the range {range:?}: {error}",);
                }
                None => {
                    eprintln!("Binding failed, port range empty? {range:?}");
                }
            }
            std::process::exit(1)
        }
    }
}

const TEMPLATE_WITH_PROFILE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<meta charset="utf-8">
<title>Profiler Symbol Server</title>
<body>

<p>This is the profiler symbol server, running at <code>SAMPLY_SERVER_URL</code>. You can:</p>
<ul>
    <li><a href="PROFILER_URL">Open the profile in the profiler UI</a></li>
    <li><a download href="PROFILE_URL">Download the raw profile JSON</a></li>
    <li>Obtain symbols by POSTing to <code>PATH_PREFIX/symbolicate/v5</code>, with the format specified by the <a href="https://tecken.readthedocs.io/en/latest/symbolication.html">Mozilla symbolication API documentation</a>.</li>
    <li>Obtain source code by POSTing to <code>PATH_PREFIX/source/v1</code>, with the format specified in this <a href="https://github.com/mstange/profiler-get-symbols/issues/24#issuecomment-989985588">github comment</a>.</li>
</ul>
"#;

const TEMPLATE_WITHOUT_PROFILE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<meta charset="utf-8">
<title>Profiler Symbol Server</title>
<body>

<p>This is the profiler symbol server, running at <code>SAMPLY_SERVER_URL</code>. You can:</p>
<ul>
    <li>Obtain symbols by POSTing to <code>PATH_PREFIX/symbolicate/v5</code>, with the format specified by the <a href="https://tecken.readthedocs.io/en/latest/symbolication.html">Mozilla symbolication API documentation</a>.</li>
    <li>Obtain source code by POSTing to <code>PATH_PREFIX/source/v1</code>, with the format specified in this <a href="https://github.com/mstange/profiler-get-symbols/issues/24#issuecomment-989985588">github comment</a>.</li>
</ul>
"#;

async fn run_server(
    listener: TcpListener,
    symbol_manager: SymbolManager,
    analyzer: Option<Arc<ProfileAnalyzer>>,
    profile_filename: Option<PathBuf>,
    template_values: Arc<HashMap<&'static str, String>>,
    path_prefix: String,
    mut stop_signal: ctrl_c::Receiver,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let symbol_manager = Arc::new(symbol_manager);

    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = tokio::select! {
            stream_and_addr_res = listener.accept() => stream_and_addr_res?,
            ctrl_c_result = &mut stop_signal => {
                return Ok(ctrl_c_result?);
            }
        };

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        let symbol_manager = symbol_manager.clone();
        let analyzer = analyzer.clone();
        let profile_filename = profile_filename.clone();
        let template_values = template_values.clone();
        let path_prefix = path_prefix.clone();

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        symbolication_service(
                            req,
                            template_values.clone(),
                            symbol_manager.clone(),
                            analyzer.clone(),
                            profile_filename.clone(),
                            path_prefix.clone(),
                        )
                    }),
                )
                .await
            {
                println!("Error serving connection: {err:?}");
            }
        });
    }
}

type MyBody = Either<String, Either<BoxBody<Bytes, std::io::Error>, BoxBody<Bytes, Infallible>>>;

async fn symbolication_service(
    req: Request<hyper::body::Incoming>,
    template_values: Arc<HashMap<&'static str, String>>,
    symbol_manager: Arc<SymbolManager>,
    analyzer: Option<Arc<ProfileAnalyzer>>,
    profile_filename: Option<PathBuf>,
    path_prefix: String,
) -> Result<Response<MyBody>, hyper::Error> {
    let has_profile = profile_filename.is_some();
    let method = req.method();
    let path = req.uri().path();
    let mut response = Response::new(Either::Left(String::new()));

    let Some(path_without_prefix) = path.strip_prefix(&path_prefix) else {
        // The secret prefix was not part of the URL. Do not send CORS headers.
        match (method, path) {
            (&Method::GET, "/") => {
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_static("text/html"),
                );
                let template = match has_profile {
                    true => TEMPLATE_WITH_PROFILE,
                    false => TEMPLATE_WITHOUT_PROFILE,
                };
                *response.body_mut() =
                    Either::Left(substitute_template(template, &template_values));
            }
            _ => {
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
        }
        return Ok(response);
    };

    // If we get here, then the secret prefix was part of the URL.
    // This part is open to the public: we allow requests across origins.
    // For background on CORS, see this document:
    // https://w3c.github.io/webappsec-cors-for-developers/#cors
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );

    match (method, path_without_prefix, profile_filename) {
        (&Method::OPTIONS, _, _) => {
            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
            *response.status_mut() = StatusCode::NO_CONTENT;
            if req
                .headers()
                .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
            {
                // This is a CORS preflight request.
                // Reassure the client that we are CORS-aware and that it's free to request whatever.
                response.headers_mut().insert(
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    header::HeaderValue::from_static("POST, GET, OPTIONS"),
                );
                response.headers_mut().insert(
                    header::ACCESS_CONTROL_MAX_AGE,
                    header::HeaderValue::from(86400),
                );
                if let Some(req_headers) = req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS)
                {
                    // All headers are fine.
                    response
                        .headers_mut()
                        .insert(header::ACCESS_CONTROL_ALLOW_HEADERS, req_headers.clone());
                }
            } else {
                // This is a regular OPTIONS request. Just send an Allow header with the allowed methods.
                response.headers_mut().insert(
                    header::ALLOW,
                    header::HeaderValue::from_static("POST, GET, OPTIONS"),
                );
            }
        }
        (&Method::GET, "/profile.json", Some(profile_filename)) => {
            if profile_filename.extension() == Some(OsStr::new("gz")) {
                response.headers_mut().insert(
                    header::CONTENT_ENCODING,
                    header::HeaderValue::from_static("gzip"),
                );
            }
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json; charset=UTF-8"),
            );

            // Stream the file. This follows the send_file example from the hyper repo.
            // https://github.com/hyperium/hyper/blob/7206fe30302937075c51c16a69d1eb3bbce6a671/examples/send_file.rs
            let file = tokio::fs::File::open(&profile_filename)
                .await
                .expect("couldn't open profile file");

            // Wrap in a buffered tokio_util::io::ReaderStream
            let reader = BufReader::with_capacity(64 * 1024, file);
            let reader_stream = ReaderStream::new(reader);

            let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
            *response.body_mut() = Either::Right(Either::Left(stream_body.boxed()));
        }
        (&Method::POST, path, _) => {
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );
            let path = path.to_string();
            // Await the full body to be concatenated into a `Collected<Bytes>`.
            let request_body = req.into_body().collect().await?;
            // Convert the `Collected<Bytes>` into a `String`.
            let request_body =
                String::from_utf8(request_body.to_bytes().to_vec()).expect("invalid utf-8");
            let response_json = symbol_manager.query_json_api(&path, &request_body).await;
            let mut response_bytes = Vec::new();
            let response_writer = BufWriter::new(&mut response_bytes);
            serde_json::to_writer(response_writer, &response_json).expect("json writing error");
            let response_body = Full::new(Bytes::from(response_bytes));

            *response.body_mut() = Either::Right(Either::Right(response_body.boxed()));
        }
        // Query endpoints for AI-assisted analysis
        (&Method::GET, path, _) if path.starts_with("/query/") => {
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );

            let query_string = req.uri().query().unwrap_or("");
            let query_params: HashMap<String, String> = url::form_urlencoded::parse(query_string.as_bytes())
                .into_owned()
                .collect();

            let response_json = handle_query_request(path, &query_params, analyzer.as_deref());
            let response_body = Full::new(Bytes::from(response_json));
            *response.body_mut() = Either::Right(Either::Right(response_body.boxed()));
        }
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };

    Ok(response)
}

/// Handle query requests for AI-assisted analysis
fn handle_query_request(
    path: &str,
    params: &HashMap<String, String>,
    analyzer: Option<&ProfileAnalyzer>,
) -> String {
    let Some(analyzer) = analyzer else {
        return serde_json::json!({
            "success": false,
            "error": "Analysis not available. Start server with 'samply analyze serve' to enable queries."
        }).to_string();
    };

    match path {
        "/query/hotspots" => {
            let limit = params.get("limit")
                .and_then(|s| s.parse().ok())
                .unwrap_or(20);
            let thread = params.get("thread").map(|s| s.as_str());
            // By default, don't include hot_lines and hot_addresses (compact output)
            let include_lines = params.get("include_lines")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false);
            let include_addresses = params.get("include_addresses")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false);
            let hotspots = analyzer.compute_hotspots(limit, thread, include_lines, include_addresses);
            serde_json::json!({
                "success": true,
                "query": "hotspots",
                "data": hotspots
            }).to_string()
        }
        "/query/callers" => {
            let function = params.get("function").map(|s| s.as_str()).unwrap_or("");
            let depth = params.get("depth")
                .and_then(|s| s.parse().ok())
                .unwrap_or(5);
            let limit = params.get("limit")
                .and_then(|s| s.parse().ok())
                .unwrap_or(20);
            if function.is_empty() {
                return serde_json::json!({
                    "success": false,
                    "error": "Missing 'function' parameter"
                }).to_string();
            }
            let callers = analyzer.find_callers(function, depth, limit);
            serde_json::json!({
                "success": true,
                "query": "callers",
                "data": callers
            }).to_string()
        }
        "/query/callees" => {
            let function = params.get("function").map(|s| s.as_str()).unwrap_or("");
            let depth = params.get("depth")
                .and_then(|s| s.parse().ok())
                .unwrap_or(5);
            let limit = params.get("limit")
                .and_then(|s| s.parse().ok())
                .unwrap_or(20);
            if function.is_empty() {
                return serde_json::json!({
                    "success": false,
                    "error": "Missing 'function' parameter"
                }).to_string();
            }
            let callees = analyzer.find_callees(function, depth, limit);
            serde_json::json!({
                "success": true,
                "query": "callees",
                "data": callees
            }).to_string()
        }
        "/query/summary" => {
            let summary = analyzer.get_summary();
            serde_json::json!({
                "success": true,
                "query": "summary",
                "data": summary
            }).to_string()
        }
        "/query/asm" => {
            let function = params.get("function").map(|s| s.as_str()).unwrap_or("");
            if function.is_empty() {
                return serde_json::json!({
                    "success": false,
                    "error": "Missing 'function' parameter"
                }).to_string();
            }
            let asm = analyzer.get_asm(function);
            serde_json::json!({
                "success": true,
                "query": "asm",
                "data": asm
            }).to_string()
        }
        "/query/drilldown" => {
            let function = params.get("function").map(|s| s.as_str()).unwrap_or("");
            if function.is_empty() {
                return serde_json::json!({
                    "success": false,
                    "error": "Missing 'function' parameter"
                }).to_string();
            }
            let depth: usize = params.get("depth")
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);
            let threshold: f64 = params.get("threshold")
                .and_then(|s| s.parse().ok())
                .unwrap_or(5.0);
            let drilldown = analyzer.drilldown(function, depth, threshold);
            serde_json::json!({
                "success": true,
                "query": "drilldown",
                "data": drilldown
            }).to_string()
        }
        _ => {
            serde_json::json!({
                "success": false,
                "error": format!("Unknown query endpoint: {}", path)
            }).to_string()
        }
    }
}

fn substitute_template(template: &str, template_values: &HashMap<&'static str, String>) -> String {
    let mut s = template.to_string();
    for (key, value) in template_values {
        s = s.replace(key, value);
    }
    s
}
