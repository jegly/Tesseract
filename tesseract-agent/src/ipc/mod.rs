//! IPC server: Unix socket, SO_PEERCRED gate, frame IO, fd reception.
//!
//! Wire protocol per `tesseract-proto`. Control frames are plain reads;
//! after a control frame announcing `fds > 0`, the client sends ONE 1-byte
//! message (0xFD) carrying all fds as SCM_RIGHTS ancillary data; then any
//! secret frames follow, each read straight into a `LockedSecret` (locked,
//! non-dumpable, zeroize-on-drop) without touching serde or the heap.

use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{bail, Context, Result};
use tesseract_proto::{
    decode_frame_header, encode_frame_header, FrameHeader, RequestEnvelope, ResponseEnvelope,
    FRAME_CONTROL, FRAME_HEADER_LEN, FRAME_SECRET, MAX_FDS,
};

use crate::os::secmem::LockedSecret;

pub const FD_MARKER: u8 = 0xFD;

pub fn bind(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path).ok();
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(listener)
}

/// Reject any peer whose UID differs from ours (SO_PEERCRED).
pub fn check_peer(stream: &UnixStream) -> Result<()> {
    let cred = rustix::net::sockopt::socket_peercred(stream.as_fd())
        .context("SO_PEERCRED")?;
    let my_uid = rustix::process::getuid();
    if cred.uid != my_uid {
        bail!(
            "rejecting peer uid {} (agent uid {})",
            cred.uid.as_raw(),
            my_uid.as_raw()
        );
    }
    Ok(())
}

pub struct Connection {
    pub stream: UnixStream,
}

impl Connection {
    pub fn new(stream: UnixStream) -> Result<Self> {
        check_peer(&stream)?;
        Ok(Self { stream })
    }

    fn read_header(&mut self) -> Result<Option<FrameHeader>> {
        let mut h = [0u8; FRAME_HEADER_LEN];
        match self.stream.read_exact(&mut h) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        Ok(Some(decode_frame_header(&h).map_err(|e| anyhow::anyhow!("{e}"))?))
    }

    /// Read one full request: control frame + optional fd batch + secrets.
    /// Returns None on clean EOF before a new request.
    pub fn read_request(
        &mut self,
    ) -> Result<Option<(RequestEnvelope, Vec<OwnedFd>, Vec<LockedSecret>)>> {
        let Some(header) = self.read_header()? else {
            return Ok(None);
        };
        if header.kind != FRAME_CONTROL {
            bail!("expected control frame, got kind {}", header.kind);
        }
        let mut payload = vec![0u8; header.len as usize];
        self.stream.read_exact(&mut payload)?;
        let req: RequestEnvelope =
            serde_json::from_slice(&payload).context("malformed control frame")?;

        if req.fds as usize > MAX_FDS || req.secrets > 8 {
            bail!("fd/secret count exceeds protocol limits");
        }

        // fd batch
        let mut fds = Vec::new();
        if req.fds > 0 {
            fds = self.recv_fds(req.fds as usize)?;
        }

        // secrets straight into locked memory
        let mut secrets = Vec::with_capacity(req.secrets as usize);
        for _ in 0..req.secrets {
            let Some(h) = self.read_header()? else {
                bail!("eof inside secret frames");
            };
            if h.kind != FRAME_SECRET {
                bail!("expected secret frame");
            }
            let mut secret = LockedSecret::with_len(h.len as usize)?;
            if h.len > 0 {
                self.stream.read_exact(secret.as_mut_slice())?;
            }
            secrets.push(secret);
        }

        Ok(Some((req, fds, secrets)))
    }

    fn recv_fds(&mut self, expect: usize) -> Result<Vec<OwnedFd>> {
        use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
        let mut byte = [0u8; 1];
        let mut space =
            vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
        let mut cmsg_buf = RecvAncillaryBuffer::new(&mut space);
        let iov = &mut [std::io::IoSliceMut::new(&mut byte)];
        let r = recvmsg(
            self.stream.as_fd(),
            iov,
            &mut cmsg_buf,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        if r.bytes != 1 || byte[0] != FD_MARKER {
            bail!("bad fd marker");
        }
        let mut fds = Vec::with_capacity(expect);
        for msg in cmsg_buf.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = msg {
                fds.extend(received);
            }
        }
        if fds.len() != expect {
            bail!("expected {expect} fds, got {}", fds.len());
        }
        Ok(fds)
    }

    pub fn write_response(&mut self, resp: &ResponseEnvelope) -> Result<()> {
        let json = serde_json::to_vec(resp)?;
        let header = encode_frame_header(FRAME_CONTROL, json.len() as u32);
        self.stream.write_all(&header)?;
        self.stream.write_all(&json)?;
        self.stream.flush()?;
        Ok(())
    }
}

/// Push an event frame to a subscriber stream (best effort).
pub fn push_event(stream: &mut UnixStream, event: &tesseract_proto::Event) -> bool {
    let Ok(json) = serde_json::to_vec(event) else {
        return false;
    };
    let header = encode_frame_header(FRAME_CONTROL, json.len() as u32);
    stream.write_all(&header).and_then(|_| stream.write_all(&json)).is_ok()
}
