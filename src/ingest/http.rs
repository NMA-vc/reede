//! A deliberately small HTTP/1.1 server for `POST /v1/traces`: one request per connection
//! (`Connection: close`), Content-Length or chunked bodies, no compression, no TLS. It is for
//! loopback use; `--allow-remote` exists but adds no authentication.
//!
//! Bounds: 32 concurrent connections, a 60 s deadline for reading one request (the seal that
//! follows is never cancelled), 16 KiB and 64 headers, 1 KiB chunk-size lines, 8 MiB body.

use super::otlp::ExportTraceServiceRequest;
use super::Ingest;
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

pub const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_CHUNK_LINE: usize = 1024;
const MAX_CONNS: usize = 32;
const READ_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Server {
    listener: TcpListener,
    ingest: Arc<Mutex<Ingest>>,
}

impl Server {
    /// Bind `addr`. A non-loopback address is refused unless `allow_remote`.
    pub async fn bind(
        addr: SocketAddr,
        allow_remote: bool,
        ingest: Ingest,
    ) -> Result<Server, String> {
        if !addr.ip().is_loopback() && !allow_remote {
            return Err(format!(
                "refusing to listen on non-loopback address {addr}: the ingest has no authentication; pass --allow-remote to override"
            ));
        }
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        Ok(Server {
            listener,
            ingest: Arc::new(Mutex::new(ingest)),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("bound listener has an address")
    }

    pub async fn run(self) {
        let slots = Arc::new(Semaphore::new(MAX_CONNS));
        loop {
            let permit = slots.clone().acquire_owned().await.expect("never closed");
            let stream = match self.listener.accept().await {
                Ok((stream, _)) => stream,
                Err(_) => {
                    // e.g. out of file descriptors: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let ingest = self.ingest.clone();
            tokio::spawn(async move {
                handle(stream, ingest).await;
                drop(permit);
            });
        }
    }
}

struct Reply(u16, &'static str, &'static str, Vec<u8>);

fn text(code: u16, reason: &'static str, msg: &str) -> Reply {
    Reply(code, reason, "text/plain", format!("{msg}\n").into_bytes())
}

fn bad(msg: &str) -> Reply {
    text(400, "Bad Request", msg)
}

async fn handle(mut s: TcpStream, ingest: Arc<Mutex<Ingest>>) {
    // Only reading is timed. Once a full request is in, sealing runs to completion.
    let read = tokio::time::timeout(READ_TIMEOUT, read_request(&mut s)).await;
    let reply = match read {
        Err(_) => text(408, "Request Timeout", "request not received in time"),
        Ok(Err(reply)) => reply,
        Ok(Ok(request)) => process(request, &ingest).await.unwrap_or_else(|r| r),
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.0,
        reply.1,
        reply.2,
        reply.3.len()
    );
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        let _ = s.write_all(head.as_bytes()).await;
        let _ = s.write_all(&reply.3).await;
        let _ = s.shutdown().await;
    })
    .await;
}

struct Request {
    json: bool,
    body: Vec<u8>,
}

fn find(buf: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

async fn read_request(s: &mut TcpStream) -> Result<Request, Reply> {
    let mut buf: Vec<u8> = Vec::new();
    let mut scanned = 0;
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n", scanned) {
            break i;
        }
        scanned = buf.len().saturating_sub(3);
        if buf.len() > MAX_HEAD {
            return Err(text(
                431,
                "Request Header Fields Too Large",
                "headers too large",
            ));
        }
        fill(s, &mut buf).await?;
    };
    if head_end > MAX_HEAD {
        return Err(text(
            431,
            "Request Header Fields Too Large",
            "headers too large",
        ));
    }
    let head =
        String::from_utf8(buf[..head_end].to_vec()).map_err(|_| bad("headers are not UTF-8"))?;
    buf.drain(..head_end + 4);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(text(
                431,
                "Request Header Fields Too Large",
                "too many headers",
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| bad("malformed header"))?;
        if name.is_empty() || name.ends_with([' ', '\t']) || name.starts_with([' ', '\t']) {
            return Err(bad("malformed header name"));
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    let header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if headers
        .iter()
        .filter(|(k, _)| k == "content-length")
        .count()
        > 1
    {
        return Err(bad("duplicate content-length"));
    }

    if path.split('?').next() != Some("/v1/traces") {
        return Err(text(404, "Not Found", "only POST /v1/traces is served"));
    }
    if method != "POST" {
        return Err(text(
            405,
            "Method Not Allowed",
            "only POST /v1/traces is served",
        ));
    }
    let media = header("content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media != "application/x-protobuf" && media != "application/json" {
        return Err(text(
            415,
            "Unsupported Media Type",
            "use application/x-protobuf or application/json",
        ));
    }
    if let Some(enc) = header("content-encoding") {
        if !enc.eq_ignore_ascii_case("identity") {
            return Err(text(
                415,
                "Unsupported Media Type",
                "content-encoding is not supported; disable exporter compression",
            ));
        }
    }
    let chunked = match header("transfer-encoding") {
        None => false,
        Some(t) if t.eq_ignore_ascii_case("chunked") => true,
        Some(_) => return Err(bad("unsupported transfer-encoding")),
    };
    let length = match header("content-length") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| bad("invalid content-length"))?,
        ),
        None => None,
    };
    if chunked && length.is_some() {
        return Err(bad("both content-length and transfer-encoding"));
    }
    if length.is_some_and(|n| n > MAX_BODY) {
        return Err(text(413, "Payload Too Large", "body exceeds 8 MiB"));
    }
    if !chunked && length.is_none() {
        return Err(text(411, "Length Required", "content-length required"));
    }
    if header("expect").is_some_and(|e| e.eq_ignore_ascii_case("100-continue")) {
        let _ = s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
    }

    let body = if chunked {
        read_chunked(s, buf).await?
    } else {
        let n = length.unwrap_or(0);
        while buf.len() < n {
            fill(s, &mut buf).await?;
        }
        buf.truncate(n);
        buf
    };
    Ok(Request {
        json: media == "application/json",
        body,
    })
}

async fn process(request: Request, ingest: &Mutex<Ingest>) -> Result<Reply, Reply> {
    let Request { json, body } = request;
    let request: ExportTraceServiceRequest = if json {
        serde_json::from_slice(&body).map_err(|e| bad(&format!("malformed OTLP JSON: {e}")))?
    } else {
        ExportTraceServiceRequest::decode(&body[..])
            .map_err(|e| bad(&format!("malformed OTLP protobuf: {e}")))?
    };
    let spans = request.into_spans();
    for sealed in &spans {
        sealed.span.validate().map_err(|e| bad(&e))?;
    }
    match ingest.lock().await.seal(spans).await {
        Ok(range) => {
            if let Some((a, b)) = range {
                println!("sealed receipts seq {a}..{b}");
            }
        }
        Err(e) => {
            eprintln!("seal failed: {e}");
            return Err(text(
                500,
                "Internal Server Error",
                "could not seal all spans; earlier spans of this request may already be sealed, so do not blindly retry",
            ));
        }
    }
    // An empty ExportTraceServiceResponse (no partial_success) is zero protobuf bytes.
    Ok(if json {
        Reply(200, "OK", "application/json", b"{}".to_vec())
    } else {
        Reply(200, "OK", "application/x-protobuf", Vec::new())
    })
}

/// Decode a chunked body (trailers ignored), capped at `MAX_BODY`.
async fn read_chunked(s: &mut TcpStream, mut buf: Vec<u8>) -> Result<Vec<u8>, Reply> {
    let mut body = Vec::new();
    loop {
        // One chunk-size line, scanned incrementally and capped.
        let mut scanned = 0;
        let line_end = loop {
            if let Some(i) = find(&buf, b"\r\n", scanned) {
                break i;
            }
            if buf.len() > MAX_CHUNK_LINE {
                return Err(bad("chunk-size line too long"));
            }
            scanned = buf.len().saturating_sub(1);
            fill(s, &mut buf).await?;
        };
        if line_end > MAX_CHUNK_LINE {
            return Err(bad("chunk-size line too long"));
        }
        let size_text = String::from_utf8_lossy(&buf[..line_end]).to_string();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| bad("invalid chunk size"))?;
        buf.drain(..line_end + 2);
        if size == 0 {
            return Ok(body);
        }
        if size > MAX_BODY - body.len() {
            return Err(text(413, "Payload Too Large", "body exceeds 8 MiB"));
        }
        let need = size + 2; // cannot overflow: size <= MAX_BODY
        while buf.len() < need {
            fill(s, &mut buf).await?;
        }
        if &buf[size..need] != b"\r\n" {
            return Err(bad("chunk is not followed by CRLF"));
        }
        body.extend_from_slice(&buf[..size]);
        buf.drain(..need);
    }
}

async fn fill(s: &mut TcpStream, buf: &mut Vec<u8>) -> Result<(), Reply> {
    let mut chunk = [0u8; 16384];
    let n = s.read(&mut chunk).await.map_err(|_| bad("read error"))?;
    if n == 0 {
        return Err(bad("connection closed before the request ended"));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}
