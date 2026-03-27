//! Raw TCP socket for TLS communication
//!
//! Provides a thin wrapper around tokio's TcpStream for sending/receiving
//! raw TLS records without any TLS handshaking (we do that manually).

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, trace};

/// A raw TCP socket for sending/receiving TLS records
pub struct TlsSocket {
    stream: TcpStream,
    timeout: Duration,
    /// Internal receive buffer for incomplete reads
    recv_buf: Vec<u8>,
}

impl TlsSocket {
    /// Connect to a host:port with timeout
    pub async fn connect(host: &str, port: u16, timeout_secs: u64) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        debug!("Connecting to {}", addr);
        let dur = Duration::from_secs(timeout_secs);
        let stream = timeout(dur, TcpStream::connect(&addr))
            .await
            .context("Connection timed out")?
            .with_context(|| format!("TCP connection to {} failed", addr))?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            timeout: dur,
            recv_buf: Vec::new(),
        })
    }

    /// Connect to an IP:port with timeout
    pub async fn connect_ip(ip: std::net::IpAddr, port: u16, timeout_secs: u64) -> Result<Self> {
        let addr = std::net::SocketAddr::new(ip, port);
        debug!("Connecting to {}", addr);
        let dur = Duration::from_secs(timeout_secs);
        let stream = timeout(dur, TcpStream::connect(addr))
            .await
            .context("Connection timed out")?
            .with_context(|| format!("TCP connection to {} failed", addr))?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            timeout: dur,
            recv_buf: Vec::new(),
        })
    }

    /// Connect with a custom timeout duration
    pub async fn connect_with_timeout(
        host: &str,
        port: u16,
        connect_timeout: Duration,
    ) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        debug!("Connecting to {} with {:?} timeout", addr, connect_timeout);
        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .context("Connection timed out")?
            .with_context(|| format!("TCP connection to {} failed", addr))?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            timeout: connect_timeout,
            recv_buf: Vec::new(),
        })
    }

    /// Send raw bytes to the server
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        trace!("Sending {} bytes", data.len());
        timeout(self.timeout, self.stream.write_all(data))
            .await
            .context("Send timed out")?
            .context("Send failed")?;
        Ok(())
    }

    /// Send a raw TLS record
    pub async fn send_record(&mut self, record: &crate::tls::TlsRecord) -> Result<()> {
        let bytes = record.to_bytes();
        self.send(&bytes).await
    }

    /// Receive up to max_bytes, returning whatever is available
    pub async fn recv(&mut self, max_bytes: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; max_bytes];
        let n = timeout(self.timeout, self.stream.read(&mut buf))
            .await
            .context("Receive timed out")?
            .context("Receive failed")?;
        if n == 0 {
            return Err(anyhow::anyhow!("Connection closed by remote"));
        }
        trace!("Received {} bytes", n);
        buf.truncate(n);
        Ok(buf)
    }

    /// Receive exactly n bytes, blocking until all are received
    pub async fn recv_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        timeout(self.timeout, self.stream.read_exact(&mut buf))
            .await
            .context("Receive exact timed out")?
            .context("Receive exact failed")?;
        trace!("Received exactly {} bytes", n);
        Ok(buf)
    }

    /// Read exactly one complete TLS record (header + payload).
    ///
    /// Returns the raw TLS record including the 5-byte header.
    ///
    /// Wire format of TLS record:
    /// ```text
    /// content_type:   1 byte
    /// version_major:  1 byte
    /// version_minor:  1 byte
    /// length:         2 bytes (big-endian, length of payload only)
    /// payload:        N bytes
    /// ```
    pub async fn recv_tls_record_raw(&mut self) -> Result<Vec<u8>> {
        // Read 5-byte header
        let header = self.recv_exact(5).await?;
        let payload_len = ((header[3] as usize) << 8) | header[4] as usize;

        // Sanity check
        if payload_len > 18432 {
            return Err(anyhow::anyhow!(
                "TLS record payload length {} exceeds maximum allowed",
                payload_len
            ));
        }

        let payload = self.recv_exact(payload_len).await?;

        let mut record = Vec::with_capacity(5 + payload_len);
        record.extend_from_slice(&header);
        record.extend_from_slice(&payload);
        Ok(record)
    }

    /// Read exactly one TLS record, returning it as a TlsRecord struct
    pub async fn recv_tls_record(&mut self) -> Result<crate::tls::TlsRecord> {
        let header = self.recv_exact(5).await?;
        let len = ((header[3] as usize) << 8) | header[4] as usize;
        let payload = self.recv_exact(len).await?;
        Ok(crate::tls::TlsRecord {
            content_type: header[0],
            version_major: header[1],
            version_minor: header[2],
            payload,
        })
    }

    /// Receive all available TLS records within a timeout window.
    ///
    /// This reads data until:
    /// 1. The timeout expires (no more data)
    /// 2. The connection is closed
    /// 3. An error occurs
    ///
    /// Returns all received bytes concatenated together.
    pub async fn recv_multiple_records(&mut self, max_wait_ms: u64) -> Result<Vec<u8>> {
        let wait = Duration::from_millis(max_wait_ms);
        let mut all_data = Vec::new();
        let mut tmp_buf = vec![0u8; 65536];

        loop {
            match tokio::time::timeout(wait, self.stream.read(&mut tmp_buf)).await {
                Ok(Ok(0)) => {
                    debug!("Connection closed by peer");
                    break;
                }
                Ok(Ok(n)) => {
                    trace!("Read {} bytes", n);
                    all_data.extend_from_slice(&tmp_buf[..n]);
                    // If we got less than the buffer, there's probably no more data right now
                    if n < tmp_buf.len() {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    if all_data.is_empty() {
                        return Err(e.into());
                    }
                    // We got some data before the error, return what we have
                    debug!("Read error after receiving {} bytes: {}", all_data.len(), e);
                    break;
                }
                Err(_) => {
                    // Timeout - no more data available within wait period
                    trace!("Receive timeout after {} ms", max_wait_ms);
                    break;
                }
            }
        }

        Ok(all_data)
    }

    /// Receive all available TLS records until server stops sending.
    ///
    /// Similar to recv_multiple_records but tries to read complete TLS records
    /// and stops when we receive a ServerHelloDone or similar terminal message.
    pub async fn recv_server_hello(&mut self) -> Result<Vec<u8>> {
        // Use 5 second timeout for initial response
        let initial_timeout = Duration::from_secs(5);
        let mut all_data = Vec::new();
        let mut tmp_buf = vec![0u8; 65536];

        // Wait for initial response
        match tokio::time::timeout(initial_timeout, self.stream.read(&mut tmp_buf)).await {
            Ok(Ok(0)) => {
                return Err(anyhow::anyhow!(
                    "Connection closed by server before response"
                ));
            }
            Ok(Ok(n)) => {
                all_data.extend_from_slice(&tmp_buf[..n]);
            }
            Ok(Err(e)) => {
                return Err(e.into());
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Timeout waiting for server response"));
            }
        }

        // Continue reading with shorter timeout until no more data arrives
        let continuation_timeout = Duration::from_millis(500);
        loop {
            match tokio::time::timeout(continuation_timeout, self.stream.read(&mut tmp_buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    all_data.extend_from_slice(&tmp_buf[..n]);
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }

        Ok(all_data)
    }

    /// Peek at available data without consuming it from the stream buffer
    pub async fn peek(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.stream.peek(buf).await?;
        Ok(n)
    }

    /// Get a reference to the inner TCP stream
    pub fn inner(&self) -> &TcpStream {
        &self.stream
    }

    /// Set a new default timeout for operations
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout = Duration::from_secs(secs);
    }

    /// Set a new default timeout as Duration
    pub fn set_timeout_duration(&mut self, dur: Duration) {
        self.timeout = dur;
    }

    /// Get the current timeout
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Get the remote peer address
    pub fn peer_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.stream.peer_addr()?)
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.stream.local_addr()?)
    }

    /// Flush the internal receive buffer
    pub fn flush_recv_buf(&mut self) {
        self.recv_buf.clear();
    }

    /// Read a line of text (for STARTTLS protocols like SMTP, IMAP, etc.)
    pub async fn read_line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            let n = timeout(self.timeout, self.stream.read(&mut buf))
                .await
                .context("Read line timed out")?
                .context("Read line failed")?;
            if n == 0 {
                break;
            }
            line.push(buf[0]);
            if buf[0] == b'\n' {
                break;
            }
            // Safety: prevent infinite loop on very long lines
            if line.len() > 8192 {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&line).trim_end().to_string())
    }

    /// Write a line of text followed by CRLF (for STARTTLS protocols)
    pub async fn write_line(&mut self, line: &str) -> Result<()> {
        let data = format!("{}\r\n", line);
        self.send(data.as_bytes()).await
    }

    /// Try to read a complete TLS record using the internal buffer.
    /// Returns Ok(Some(bytes)) when a complete record is available,
    /// Ok(None) when more data is needed, Err when there's a fatal error.
    pub async fn try_recv_record(&mut self, timeout_ms: u64) -> Result<Option<Vec<u8>>> {
        let wait = Duration::from_millis(timeout_ms);
        let mut tmp = vec![0u8; 65536];

        // Try to read more data into internal buffer
        match tokio::time::timeout(wait, self.stream.read(&mut tmp)).await {
            Ok(Ok(0)) => {
                // Connection closed
                if self.recv_buf.is_empty() {
                    return Ok(None);
                }
            }
            Ok(Ok(n)) => {
                self.recv_buf.extend_from_slice(&tmp[..n]);
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Timeout
                if self.recv_buf.is_empty() {
                    return Ok(None);
                }
            }
        }

        // Check if we have a complete TLS record in the buffer
        if self.recv_buf.len() < 5 {
            return Ok(None);
        }

        let payload_len = ((self.recv_buf[3] as usize) << 8) | self.recv_buf[4] as usize;
        let total_len = 5 + payload_len;

        if self.recv_buf.len() < total_len {
            return Ok(None);
        }

        let record = self.recv_buf[..total_len].to_vec();
        self.recv_buf.drain(..total_len);
        Ok(Some(record))
    }
}
