use crate::preview2::{
    FlushResult, HostOutputStream, StreamRuntimeError, StreamState, Table, TableError,
    WriteReadiness,
};
use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use std::sync::Arc;

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct FilePerms: usize {
        const READ = 0b1;
        const WRITE = 0b10;
    }
}

pub(crate) struct File {
    /// Wrapped in an Arc because the same underlying file is used for
    /// implementing the stream types. Also needed for [`block`].
    pub file: Arc<cap_std::fs::File>,
    pub perms: FilePerms,
}

impl File {
    pub fn new(file: cap_std::fs::File, perms: FilePerms) -> Self {
        Self {
            file: Arc::new(file),
            perms,
        }
    }

    /// Spawn a task on tokio's blocking thread for performing blocking
    /// syscalls on the underlying [`cap_std::fs::File`].
    pub(crate) async fn spawn_blocking<F, R>(&self, body: F) -> R
    where
        F: FnOnce(&cap_std::fs::File) -> R + Send + 'static,
        R: Send + 'static,
    {
        let f = self.file.clone();
        tokio::task::spawn_blocking(move || body(&f)).await.unwrap()
    }
}
pub(crate) trait TableFsExt {
    fn push_file(&mut self, file: File) -> Result<u32, TableError>;
    fn delete_file(&mut self, fd: u32) -> Result<File, TableError>;
    fn is_file(&self, fd: u32) -> bool;
    fn get_file(&self, fd: u32) -> Result<&File, TableError>;

    fn push_dir(&mut self, dir: Dir) -> Result<u32, TableError>;
    fn delete_dir(&mut self, fd: u32) -> Result<Dir, TableError>;
    fn is_dir(&self, fd: u32) -> bool;
    fn get_dir(&self, fd: u32) -> Result<&Dir, TableError>;
}

impl TableFsExt for Table {
    fn push_file(&mut self, file: File) -> Result<u32, TableError> {
        self.push(Box::new(file))
    }
    fn delete_file(&mut self, fd: u32) -> Result<File, TableError> {
        self.delete(fd)
    }
    fn is_file(&self, fd: u32) -> bool {
        self.is::<File>(fd)
    }
    fn get_file(&self, fd: u32) -> Result<&File, TableError> {
        self.get(fd)
    }

    fn push_dir(&mut self, dir: Dir) -> Result<u32, TableError> {
        self.push(Box::new(dir))
    }
    fn delete_dir(&mut self, fd: u32) -> Result<Dir, TableError> {
        self.delete(fd)
    }
    fn is_dir(&self, fd: u32) -> bool {
        self.is::<Dir>(fd)
    }
    fn get_dir(&self, fd: u32) -> Result<&Dir, TableError> {
        self.get(fd)
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct DirPerms: usize {
        const READ = 0b1;
        const MUTATE = 0b10;
    }
}

pub(crate) struct Dir {
    pub dir: Arc<cap_std::fs::Dir>,
    pub perms: DirPerms,
    pub file_perms: FilePerms,
}

impl Dir {
    pub fn new(dir: cap_std::fs::Dir, perms: DirPerms, file_perms: FilePerms) -> Self {
        Dir {
            dir: Arc::new(dir),
            perms,
            file_perms,
        }
    }

    /// Spawn a task on tokio's blocking thread for performing blocking
    /// syscalls on the underlying [`cap_std::fs::Dir`].
    pub(crate) async fn spawn_blocking<F, R>(&self, body: F) -> R
    where
        F: FnOnce(&cap_std::fs::Dir) -> R + Send + 'static,
        R: Send + 'static,
    {
        let d = self.dir.clone();
        tokio::task::spawn_blocking(move || body(&d)).await.unwrap()
    }
}

pub(crate) struct FileInputStream {
    file: Arc<cap_std::fs::File>,
    position: u64,
}
impl FileInputStream {
    pub fn new(file: Arc<cap_std::fs::File>, position: u64) -> Self {
        Self { file, position }
    }

    pub async fn read(&mut self, size: usize) -> anyhow::Result<(Bytes, StreamState)> {
        use system_interface::fs::FileIoExt;
        let f = Arc::clone(&self.file);
        let p = self.position;
        let (r, mut buf) = tokio::task::spawn_blocking(move || {
            let mut buf = BytesMut::zeroed(size);
            let r = f.read_at(&mut buf, p);
            (r, buf)
        })
        .await
        .unwrap();
        let (n, state) = read_result(r)?;
        buf.truncate(n);
        self.position += n as u64;
        Ok((buf.freeze(), state))
    }

    pub async fn skip(&mut self, nelem: usize) -> anyhow::Result<(usize, StreamState)> {
        let mut nread = 0;
        let mut state = StreamState::Open;

        let (bs, read_state) = self.read(nelem).await?;
        // TODO: handle the case where `bs.len()` is less than `nelem`
        nread += bs.len();
        if read_state.is_closed() {
            state = read_state;
        }

        Ok((nread, state))
    }
}

fn read_result(r: Result<usize, std::io::Error>) -> Result<(usize, StreamState), anyhow::Error> {
    match r {
        Ok(0) => Ok((0, StreamState::Closed)),
        Ok(n) => Ok((n, StreamState::Open)),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok((0, StreamState::Open)),
        Err(e) => Err(StreamRuntimeError::from(anyhow::anyhow!(e)).into()),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FileOutputMode {
    Position(u64),
    Append,
}

pub(crate) struct FileOutputStream {
    file: Arc<cap_std::fs::File>,
    mode: FileOutputMode,
    task: Option<tokio::task::JoinHandle<Result<(), std::io::Error>>>,
    closed: bool,
}
impl FileOutputStream {
    pub fn write_at(file: Arc<cap_std::fs::File>, position: u64) -> Self {
        Self {
            file,
            mode: FileOutputMode::Position(position),
            task: None,
            closed: false,
        }
    }
    pub fn append(file: Arc<cap_std::fs::File>) -> Self {
        Self {
            file,
            mode: FileOutputMode::Append,
            task: None,
            closed: false,
        }
    }
}

#[async_trait::async_trait]
impl HostOutputStream for FileOutputStream {
    fn write(&mut self, buf: Bytes) -> anyhow::Result<Option<WriteReadiness>> {
        use system_interface::fs::FileIoExt;

        if self.closed {
            return Ok(Some(WriteReadiness::Closed));
        }
        if self.task.is_some() {
            // a write is pending - this call was not permitted
            return Err(anyhow!(
                "write not permitted: FileOutputStream write pending"
            ));
        }
        let f = Arc::clone(&self.file);
        let m = self.mode;
        self.task = Some(tokio::task::spawn_blocking(move || match m {
            FileOutputMode::Position(p) => {
                let _ = f.write_at(buf.as_ref(), p)?; // FIXME: make sure writes all
                Ok(())
            }
            FileOutputMode::Append => {
                let _ = f.append(buf.as_ref())?; // FIXME: make sure writes all
                Ok(())
            }
        }));
        Ok(None)
    }
    fn flush(&mut self) -> anyhow::Result<Option<FlushResult>> {
        if self.closed {
            return Ok(Some(FlushResult::Closed));
        }
        if self.task.is_none() {
            return Ok(Some(FlushResult::Done));
        }
        Ok(None)
    }
    async fn write_ready(&mut self) -> anyhow::Result<WriteReadiness> {
        if self.closed {
            return Ok(WriteReadiness::Closed);
        }
        if let Some(t) = self.task.take() {
            match t.await.context("join of FileOutputStream worker task")? {
                Ok(()) => Ok(WriteReadiness::Ready(64 * 1024)),
                Err(e) => {
                    tracing::debug!("FileOutputStream closed with {e:?}");
                    self.closed = true;
                    Ok(WriteReadiness::Closed)
                }
            }
        } else {
            Ok(WriteReadiness::Ready(64 * 1024))
        }
    }
    async fn flush_ready(&mut self) -> anyhow::Result<FlushResult> {
        if self.closed {
            return Ok(FlushResult::Closed);
        }
        if let Some(t) = self.task.take() {
            match t.await.context("join of FileOutputStream worker task")? {
                Ok(()) => Ok(FlushResult::Done),
                Err(e) => {
                    tracing::debug!("FileOutputStream closed with {e:?}");
                    self.closed = true;
                    Ok(FlushResult::Closed)
                }
            }
        } else {
            Ok(FlushResult::Done)
        }
    }
}
