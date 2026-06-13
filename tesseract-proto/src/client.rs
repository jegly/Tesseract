//! Blocking client for the agent socket (feature "client").
//!
//! Used by the CLI and the GUI. Secrets are passed as `Zeroizing` buffers
//! and wiped after sending; neither client ever derives keys.

use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::{
    decode_frame_header, encode_frame_header, Event, Op, RequestEnvelope, ResponseEnvelope,
    FRAME_CONTROL, FRAME_HEADER_LEN, FRAME_SECRET, MAX_CONTROL_LEN,
};

pub const FD_MARKER: u8 = 0xFD;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach the Tesseract agent at {path} ({source}); is tesseract-agent running?")]
    Connect {
        path: String,
        source: std::io::Error,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("agent error: {0}")]
    Agent(String),
}

pub fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("TESSERACT_SOCKET") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(crate::SOCKET_NAME)
}

pub struct Client {
    stream: UnixStream,
    next_id: u64,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tesseract Client")
    }
}

impl Client {
    pub fn connect() -> Result<Self, ClientError> {
        let path = socket_path();
        let stream = UnixStream::connect(&path).map_err(|source| ClientError::Connect {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self { stream, next_id: 1 })
    }

    /// Send a request with optional fds and secrets; wait for the response.
    pub fn call(
        &mut self,
        op: Op,
        fds: &[BorrowedFd<'_>],
        secrets: Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<ResponseEnvelope, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let envelope = RequestEnvelope {
            id,
            secrets: secrets.len() as u8,
            fds: fds.len() as u8,
            op,
        };
        let json = serde_json::to_vec(&envelope)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        self.stream
            .write_all(&encode_frame_header(FRAME_CONTROL, json.len() as u32))?;
        self.stream.write_all(&json)?;

        if !fds.is_empty() {
            self.send_fds(fds)?;
        }
        for secret in secrets {
            self.stream
                .write_all(&encode_frame_header(FRAME_SECRET, secret.len() as u32))?;
            self.stream.write_all(&secret)?;
            // Zeroizing drop wipes our copy
        }
        self.stream.flush()?;

        // responses interleave with event frames on subscribed connections;
        // skip events until our reply arrives
        loop {
            let frame = self.read_control()?;
            if let Ok(resp) = serde_json::from_slice::<ResponseEnvelope>(&frame) {
                if resp.id == id {
                    return Ok(resp);
                }
                continue;
            }
            // event frame: ignore here (poll_event exposes them)
        }
    }

    /// Convenience: call and turn `ok=false` into an error.
    pub fn call_ok(
        &mut self,
        op: Op,
        fds: &[BorrowedFd<'_>],
        secrets: Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<ResponseEnvelope, ClientError> {
        let resp = self.call(op, fds, secrets)?;
        if resp.ok {
            Ok(resp)
        } else {
            Err(ClientError::Agent(
                resp.error.unwrap_or_else(|| "unknown agent error".into()),
            ))
        }
    }

    /// Blocking read of the next event frame (for subscribed connections).
    pub fn next_event(&mut self) -> Result<Event, ClientError> {
        loop {
            let frame = self.read_control()?;
            if let Ok(ev) = serde_json::from_slice::<Event>(&frame) {
                return Ok(ev);
            }
            // a stray response (shouldn't happen on a dedicated event
            // connection) is skipped
        }
    }

    fn read_control(&mut self) -> Result<Vec<u8>, ClientError> {
        let mut h = [0u8; FRAME_HEADER_LEN];
        self.stream.read_exact(&mut h)?;
        let header =
            decode_frame_header(&h).map_err(|e| ClientError::Protocol(e.to_string()))?;
        if header.kind != FRAME_CONTROL || header.len > MAX_CONTROL_LEN {
            return Err(ClientError::Protocol("unexpected frame".into()));
        }
        let mut payload = vec![0u8; header.len as usize];
        self.stream.read_exact(&mut payload)?;
        Ok(payload)
    }

    fn send_fds(&mut self, fds: &[BorrowedFd<'_>]) -> Result<(), ClientError> {
        use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
        let mut space =
            vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(crate::MAX_FDS))];
        let mut cmsg = SendAncillaryBuffer::new(&mut space);
        if !cmsg.push(SendAncillaryMessage::ScmRights(fds)) {
            return Err(ClientError::Protocol("too many fds".into()));
        }
        let byte = [FD_MARKER];
        let iov = [std::io::IoSlice::new(&byte)];
        sendmsg(self.stream.as_fd(), &iov, &mut cmsg, SendFlags::empty())
            .map_err(|e| ClientError::Io(e.into()))?;
        Ok(())
    }
}
