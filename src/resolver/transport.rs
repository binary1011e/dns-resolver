use async_trait::async_trait;
use hickory_proto::op::Message;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, Semaphore};
use tokio::time::timeout;

#[async_trait]
pub(crate) trait DnsTransport: Send + Sync {
    async fn exchange(&self, request: &[u8], server: SocketAddr) -> Result<Vec<u8>, Error>;
}

type PendingKey = (u16, SocketAddr);
type PendingMap = Arc<Mutex<HashMap<PendingKey, oneshot::Sender<Vec<u8>>>>>;

pub struct UdpTransportAdapter {
    socket: Arc<UdpSocket>,
    pending: PendingMap,
    recv_task: tokio::task::JoinHandle<()>,
    timeout: Duration,
    pending_limiter: Arc<Semaphore>,
}

impl UdpTransportAdapter {
    pub async fn new(
        socket: UdpSocket,
        timeout: Duration,
        max_pending: usize,
    ) -> Result<Self, Error> {
        let socket = Arc::new(socket);
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let recv_task = spawn_recv_loop(Arc::clone(&socket), Arc::clone(&pending));

        Ok(Self {
            socket,
            pending,
            recv_task,
            timeout,
            pending_limiter: Arc::new(Semaphore::new(max_pending)),
        })
    }
}

fn spawn_recv_loop(socket: Arc<UdpSocket>, pending: PendingMap) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("transport recv loop error: {e}");
                    continue;
                }
            };

            let bytes = buf[..len].to_vec();
            let id = match Message::from_vec(&bytes) {
                Ok(msg) => msg.metadata.id,
                Err(_) => continue,
            };

            let key = (id, src);
            let mut guard = pending.lock().await;
            if let Some(tx) = guard.remove(&key) {
                let _ = tx.send(bytes);
            } else {
                eprintln!("dropping late/unmatched upstream response from {src} with id={id}");
            }
        }
    })
}

#[async_trait]
impl DnsTransport for UdpTransportAdapter {
    async fn exchange(&self, request: &[u8], server: SocketAddr) -> Result<Vec<u8>, Error> {
        let req = Message::from_vec(request).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        let key = (req.metadata.id, server);

        let _permit = self
            .pending_limiter
            .acquire()
            .await
            .map_err(|_| Error::new(ErrorKind::Other, "transport limiter closed"))?;

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock().await;
            if guard.contains_key(&key) {
                return Err(Error::new(
                    ErrorKind::AlreadyExists,
                    "duplicate upstream request id/server in flight",
                ));
            }
            guard.insert(key, tx);
        }

        if let Err(e) = self.socket.send_to(request, server).await {
            let mut guard = self.pending.lock().await;
            guard.remove(&key);
            return Err(e);
        }

        match timeout(self.timeout, rx).await {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(_)) => {
                let mut guard = self.pending.lock().await;
                guard.remove(&key);
                Err(Error::new(ErrorKind::BrokenPipe, "response routing channel closed"))
            }
            Err(_) => {
                let mut guard = self.pending.lock().await;
                guard.remove(&key);
                Err(Error::new(ErrorKind::TimedOut, "upstream timeout"))
            }
        }
    }
}

impl Drop for UdpTransportAdapter {
    fn drop(&mut self) {
        self.recv_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use tokio::task::JoinHandle;

    fn make_query(id: u16, host: &str) -> Vec<u8> {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_ascii(host).unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    fn make_response_from_query(query: &[u8]) -> Vec<u8> {
        let req = Message::from_vec(query).unwrap();
        let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.response_code = hickory_proto::op::ResponseCode::NoError;
        resp.to_vec().unwrap()
    }

    fn spawn_responder(sock: Arc<UdpSocket>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, src) = sock.recv_from(&mut buf).await.unwrap();
            let response = make_response_from_query(&buf[..len]);
            let _ = sock.send_to(&response, src).await;
        })
    }

    #[tokio::test]
    async fn exchange_times_out_without_response() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let adapter = UdpTransportAdapter::new(client, Duration::from_millis(30), 8)
            .await
            .unwrap();

        let req = make_query(7, "example.com.");
        let err = adapter.exchange(&req, server.local_addr().unwrap()).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn exchange_demuxes_same_id_across_servers() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let adapter = Arc::new(
            UdpTransportAdapter::new(client, Duration::from_millis(150), 8)
                .await
                .unwrap(),
        );

        let resp_a = spawn_responder(Arc::clone(&server_a));
        let resp_b = spawn_responder(Arc::clone(&server_b));

        let req_a = make_query(42, "a.example.com.");
        let req_b = make_query(42, "b.example.com.");

        let a_addr = server_a.local_addr().unwrap();
        let b_addr = server_b.local_addr().unwrap();
        let adapter_a = Arc::clone(&adapter);
        let adapter_b = Arc::clone(&adapter);

        let fut_a = tokio::spawn(async move { adapter_a.exchange(&req_a, a_addr).await });
        let fut_b = tokio::spawn(async move { adapter_b.exchange(&req_b, b_addr).await });

        assert!(fut_a.await.unwrap().is_ok());
        assert!(fut_b.await.unwrap().is_ok());
        let _ = resp_a.await;
        let _ = resp_b.await;
    }
}
