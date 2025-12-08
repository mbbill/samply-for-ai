//! HTTP client for querying the analysis server.
//!
//! This module provides a simple blocking HTTP client for making queries
//! to a running samply analysis server.

use std::io::{self, Read};
use std::net::TcpStream;
use std::time::Duration;

use crate::session::Session;

/// Error type for query client operations
#[derive(Debug)]
pub enum QueryError {
    /// No active session found
    NoSession(io::Error),
    /// Server not running or not reachable
    ConnectionFailed(io::Error),
    /// HTTP request failed
    RequestFailed(String),
    /// Invalid response
    InvalidResponse(String),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::NoSession(e) => write!(f, "No active session: {}", e),
            QueryError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            QueryError::RequestFailed(msg) => write!(f, "Request failed: {}", msg),
            QueryError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
        }
    }
}

impl std::error::Error for QueryError {}

/// Client for querying a running analysis server
pub struct QueryClient {
    /// Full URL including token (e.g., "http://127.0.0.1:3000/abc123")
    server_url: String,
}

impl QueryClient {
    /// Create a client by reading the session file
    pub fn from_session() -> Result<Self, QueryError> {
        let session = Session::load().map_err(QueryError::NoSession)?;

        // Check if server is still alive
        if !session.is_server_alive() {
            return Err(QueryError::ConnectionFailed(io::Error::new(
                io::ErrorKind::NotConnected,
                "Server process is not running",
            )));
        }

        Ok(Self {
            server_url: session.server_url,
        })
    }

    /// Query hotspots
    pub fn query_hotspots(
        &self,
        limit: usize,
        thread: Option<&str>,
    ) -> Result<String, QueryError> {
        let mut url = format!("{}/query/hotspots?limit={}", self.server_url, limit);
        if let Some(t) = thread {
            url.push_str(&format!("&thread={}", urlencoding::encode(t)));
        }
        self.get(&url)
    }

    /// Query callers of a function
    pub fn query_callers(&self, function: &str, depth: usize) -> Result<String, QueryError> {
        let url = format!(
            "{}/query/callers?function={}&depth={}",
            self.server_url,
            urlencoding::encode(function),
            depth
        );
        self.get(&url)
    }

    /// Query callees of a function
    pub fn query_callees(&self, function: &str, depth: usize) -> Result<String, QueryError> {
        let url = format!(
            "{}/query/callees?function={}&depth={}",
            self.server_url,
            urlencoding::encode(function),
            depth
        );
        self.get(&url)
    }

    /// Query profile summary
    pub fn query_summary(&self) -> Result<String, QueryError> {
        let url = format!("{}/query/summary", self.server_url);
        self.get(&url)
    }

    /// Make a simple HTTP GET request and return the response body
    fn get(&self, url: &str) -> Result<String, QueryError> {
        // Parse the URL to extract host, port, and path
        let url_parsed = url::Url::parse(url)
            .map_err(|e| QueryError::InvalidResponse(format!("Invalid URL: {}", e)))?;

        let host = url_parsed
            .host_str()
            .ok_or_else(|| QueryError::InvalidResponse("No host in URL".to_string()))?;
        let port = url_parsed.port().unwrap_or(80);
        let path = url_parsed.path();
        let query = url_parsed.query().unwrap_or("");
        let full_path = if query.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, query)
        };

        // Connect to the server
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect(&addr).map_err(QueryError::ConnectionFailed)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .ok();

        // Send HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
            full_path, host, port
        );

        use std::io::Write;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| QueryError::ConnectionFailed(e))?;

        // Read response
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| QueryError::ConnectionFailed(e))?;

        // Parse HTTP response - extract body after headers
        let body_start = response
            .find("\r\n\r\n")
            .ok_or_else(|| QueryError::InvalidResponse("No body delimiter found".to_string()))?;
        let body = &response[body_start + 4..];

        // Check for HTTP error status
        let first_line = response.lines().next().unwrap_or("");
        if !first_line.contains("200") {
            return Err(QueryError::RequestFailed(format!(
                "HTTP error: {}",
                first_line
            )));
        }

        Ok(body.to_string())
    }
}

/// Simple URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
                _ => {
                    for byte in c.to_string().as_bytes() {
                        result.push_str(&format!("%{:02X}", byte));
                    }
                }
            }
        }
        result
    }
}
