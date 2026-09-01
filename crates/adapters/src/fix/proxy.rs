use super::framing::find_complete_message;
use blackswan_core::{Direction, HarnessError, InterceptAction, ProtocolAdapter, RawMessage};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

// TCP man-in-the-middle for FIX sessions. Listens on `listen_addr`, accepts
// one connection (the OMS under test connects here instead of the real
// exchange), dials `upstream_addr` (the real exchange, or a test double
// standing in for one), and relays both directions, framing each side's
// byte stream into complete FIX messages and asking the adapter what to do
// with each one.
//
// Single connection only for now: accept() blocks on run_session() for the
// whole lifetime of that session, so a second connection attempt sits in
// the OS backlog queue and only gets accepted once the first session ends,
// it isn't actively refused. This is a proxy for one target connection at
// a time, not built to serve concurrent clients, see Known limitations.
pub struct FixProxy {
    listen_addr: String,
    upstream_addr: String,
    adapter: Arc<dyn ProtocolAdapter>,
    enabled: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl FixProxy {
    pub fn new(listen_addr: impl Into<String>, upstream_addr: impl Into<String>, adapter: Arc<dyn ProtocolAdapter>) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            upstream_addr: upstream_addr.into(),
            adapter,
            enabled: Arc::new(AtomicBool::new(false)),
            handle: None,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    // Shared flag the fault injector wrapping this proxy toggles: when
    // false, every message is forwarded regardless of what the adapter
    // would decide, matching the "hook stays attached, only the config
    // toggles" pattern the XDP injectors use.
    pub fn enabled_flag(&self) -> Arc<AtomicBool> {
        self.enabled.clone()
    }

    pub fn start(&mut self) -> Result<(), HarnessError> {
        if self.handle.is_some() {
            return Ok(());
        }

        let listener = TcpListener::bind(&self.listen_addr)
            .map_err(|e| HarnessError::ArmFailed("fix-proxy".into(), format!("binding {}: {e}", self.listen_addr)))?;

        let upstream_addr = self.upstream_addr.clone();
        let adapter = self.adapter.clone();
        let enabled = self.enabled.clone();
        let shutdown = self.shutdown.clone();

        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                match listener.accept() {
                    Ok((client, _)) => {
                        if let Ok(upstream) = TcpStream::connect(&upstream_addr) {
                            run_session(client, upstream, adapter.clone(), enabled.clone(), shutdown.clone());
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });

        self.handle = Some(handle);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// One accepted client paired with its upstream connection. Two threads,
// one per direction, each doing read-frame-decide-forward in a loop until
// either side closes or the proxy is told to shut down.
fn run_session(
    client: TcpStream,
    upstream: TcpStream,
    adapter: Arc<dyn ProtocolAdapter>,
    enabled: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
) {
    let client_read = client.try_clone().expect("clone client stream");
    let upstream_read = upstream.try_clone().expect("clone upstream stream");

    let outbound = {
        let adapter = adapter.clone();
        let enabled = enabled.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || {
            relay(client_read, upstream, Direction::Outbound, adapter, enabled, shutdown);
        })
    };
    let inbound = std::thread::spawn(move || {
        relay(upstream_read, client, Direction::Inbound, adapter, enabled, shutdown);
    });

    let _ = outbound.join();
    let _ = inbound.join();
}

fn relay(
    mut src: TcpStream,
    mut dst: TcpStream,
    direction: Direction,
    adapter: Arc<dyn ProtocolAdapter>,
    enabled: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
) {
    src.set_read_timeout(Some(std::time::Duration::from_millis(200))).ok();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }

        match src.read(&mut chunk) {
            Ok(0) => return, // peer closed
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(_) => return,
        }

        loop {
            let Ok(Some(len)) = find_complete_message(&buf) else { break };
            let message_bytes: Vec<u8> = buf.drain(..len).collect();

            let action = if enabled.load(Ordering::SeqCst) {
                let msg = RawMessage { bytes: message_bytes.clone(), direction };
                adapter.intercept(&msg).unwrap_or(InterceptAction::Forward)
            } else {
                InterceptAction::Forward
            };

            match action {
                InterceptAction::Forward => {
                    if dst.write_all(&message_bytes).is_err() {
                        return;
                    }
                }
                InterceptAction::Drop => {} // silently swallowed, that's the fault
                InterceptAction::Mutate(bytes) => {
                    if dst.write_all(&bytes).is_err() {
                        return;
                    }
                }
                InterceptAction::Delay(ns) => {
                    std::thread::sleep(std::time::Duration::from_nanos(ns));
                    if dst.write_all(&message_bytes).is_err() {
                        return;
                    }
                }
            }
        }
    }
}
