use crate::preview2::{
    bindings::io::streams::{self, InputStream, OutputStream},
    bindings::poll::poll::Pollable,
    filesystem::FileInputStream,
    poll::PollableFuture,
    stream::{
        FlushResult, HostInputStream, HostOutputStream, InternalInputStream,
        InternalTableStreamExt, StreamRuntimeError, StreamState, TableStreamExt, WriteReadiness,
    },
    HostPollable, TablePollableExt, WasiView,
};
use std::any::Any;

impl From<StreamState> for streams::StreamStatus {
    fn from(state: StreamState) -> Self {
        match state {
            StreamState::Open => Self::Open,
            StreamState::Closed => Self::Ended,
        }
    }
}

impl From<WriteReadiness> for streams::WriteReadiness {
    fn from(w: WriteReadiness) -> Self {
        match w {
            WriteReadiness::Ready(n) => Self::Ready(n as u64),
            WriteReadiness::Closed => Self::Closed,
        }
    }
}

impl From<FlushResult> for streams::FlushResult {
    fn from(r: FlushResult) -> Self {
        match r {
            FlushResult::Done => Self::Done,
            FlushResult::Closed => Self::Closed,
        }
    }
}

#[async_trait::async_trait]
impl<T: WasiView> streams::Host for T {
    async fn drop_input_stream(&mut self, stream: InputStream) -> anyhow::Result<()> {
        self.table_mut().delete_internal_input_stream(stream)?;
        Ok(())
    }

    async fn drop_output_stream(&mut self, stream: OutputStream) -> anyhow::Result<()> {
        self.table_mut().delete_output_stream(stream)?;
        Ok(())
    }

    async fn read(
        &mut self,
        stream: InputStream,
        len: u64,
    ) -> anyhow::Result<Result<(Vec<u8>, streams::StreamStatus), ()>> {
        match self.table_mut().get_internal_input_stream_mut(stream)? {
            InternalInputStream::Host(s) => {
                let (bytes, state) = match HostInputStream::read(s.as_mut(), len as usize) {
                    Ok(a) => a,
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                            tracing::debug!("stream runtime error: {e:?}");
                            return Ok(Err(()));
                        } else {
                            return Err(e);
                        }
                    }
                };
                debug_assert!(bytes.len() <= len as usize);

                Ok(Ok((bytes.into(), state.into())))
            }
            InternalInputStream::File(s) => {
                let (bytes, state) = match FileInputStream::read(s, len as usize).await {
                    Ok(a) => a,
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                            tracing::debug!("stream runtime error: {e:?}");
                            return Ok(Err(()));
                        } else {
                            return Err(e);
                        }
                    }
                };
                Ok(Ok((bytes.into(), state.into())))
            }
        }
    }

    async fn blocking_read(
        &mut self,
        stream: InputStream,
        len: u64,
    ) -> anyhow::Result<Result<(Vec<u8>, streams::StreamStatus), ()>> {
        match self.table_mut().get_internal_input_stream_mut(stream)? {
            InternalInputStream::Host(s) => {
                s.ready().await?;
                let (bytes, state) = match HostInputStream::read(s.as_mut(), len as usize) {
                    Ok(a) => a,
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                            tracing::debug!("stream runtime error: {e:?}");
                            return Ok(Err(()));
                        } else {
                            return Err(e);
                        }
                    }
                };
                debug_assert!(bytes.len() <= len as usize);
                Ok(Ok((bytes.into(), state.into())))
            }
            InternalInputStream::File(s) => {
                let (bytes, state) = match FileInputStream::read(s, len as usize).await {
                    Ok(a) => a,
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                            tracing::debug!("stream runtime error: {e:?}");
                            return Ok(Err(()));
                        } else {
                            return Err(e);
                        }
                    }
                };
                Ok(Ok((bytes.into(), state.into())))
            }
        }
    }

    async fn skip(
        &mut self,
        stream: InputStream,
        len: u64,
    ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
        match self.table_mut().get_internal_input_stream_mut(stream)? {
            InternalInputStream::Host(s) => {
                // TODO: the cast to usize should be fallible, use `.try_into()?`
                let (bytes_skipped, state) = match HostInputStream::skip(s.as_mut(), len as usize) {
                    Ok(a) => a,
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                            tracing::debug!("stream runtime error: {e:?}");
                            return Ok(Err(()));
                        } else {
                            return Err(e);
                        }
                    }
                };

                Ok(Ok((bytes_skipped as u64, state.into())))
            }
            InternalInputStream::File(s) => {
                let (bytes_skipped, state) = match FileInputStream::skip(s, len as usize).await {
                    Ok(a) => a,
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                            tracing::debug!("stream runtime error: {e:?}");
                            return Ok(Err(()));
                        } else {
                            return Err(e);
                        }
                    }
                };
                Ok(Ok((bytes_skipped as u64, state.into())))
            }
        }
    }

    async fn blocking_skip(
        &mut self,
        stream: InputStream,
        len: u64,
    ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
        match self.table_mut().get_internal_input_stream_mut(stream)? {
            InternalInputStream::Host(s) => {
                s.ready().await?;
                // TODO: the cast to usize should be fallible, use `.try_into()?`
                let (bytes_skipped, state) = match HostInputStream::skip(s.as_mut(), len as usize) {
                    Ok(a) => a,
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                            tracing::debug!("stream runtime error: {e:?}");
                            return Ok(Err(()));
                        } else {
                            return Err(e);
                        }
                    }
                };

                Ok(Ok((bytes_skipped as u64, state.into())))
            }
            InternalInputStream::File(s) => {
                let (bytes_skipped, state) = match FileInputStream::skip(s, len as usize).await {
                    Ok(a) => a,
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                            tracing::debug!("stream runtime error: {e:?}");
                            return Ok(Err(()));
                        } else {
                            return Err(e);
                        }
                    }
                };
                Ok(Ok((bytes_skipped as u64, state.into())))
            }
        }
    }

    async fn subscribe_to_input_stream(&mut self, stream: InputStream) -> anyhow::Result<Pollable> {
        // Ensure that table element is an input-stream:
        let pollable = match self.table_mut().get_internal_input_stream_mut(stream)? {
            InternalInputStream::Host(_) => {
                fn input_stream_ready<'a>(stream: &'a mut dyn Any) -> PollableFuture<'a> {
                    let stream = stream
                        .downcast_mut::<InternalInputStream>()
                        .expect("downcast to InternalInputStream failed");
                    match *stream {
                        InternalInputStream::Host(ref mut hs) => hs.ready(),
                        _ => unreachable!(),
                    }
                }

                HostPollable::TableEntry {
                    index: stream,
                    make_future: input_stream_ready,
                }
            }
            // Files are always "ready" immediately (because we have no way to actually wait on
            // readiness in epoll)
            InternalInputStream::File(_) => {
                HostPollable::Closure(Box::new(|| Box::pin(futures::future::ready(Ok(())))))
            }
        };
        Ok(self.table_mut().push_host_pollable(pollable)?)
    }

    /* --------------------------------------------------------------
     *
     * OutputStream methods
     *
     * -------------------------------------------------------------- */

    async fn check_write(
        &mut self,
        stream: OutputStream,
    ) -> anyhow::Result<Option<streams::WriteReadiness>> {
        let s = self.table_mut().get_output_stream_mut(stream)?;
        // FIXME StreamRuntimeError to close stream
        match futures::future::poll_immediate(s.write_ready()).await {
            Some(Ok(readiness)) => Ok(Some(readiness.into())),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }
    async fn write(
        &mut self,
        stream: OutputStream,
        bytes: Vec<u8>,
    ) -> anyhow::Result<Option<streams::WriteReadiness>> {
        let s = self.table_mut().get_output_stream_mut(stream)?;
        match HostOutputStream::write(s, bytes.into()) {
            Ok(Some(readiness)) => Ok(Some(readiness.into())),
            Ok(None) => Ok(None),
            Err(e) => {
                if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                    tracing::debug!("stream runtime error: {e:?}");
                    return Ok(Some(streams::WriteReadiness::Closed));
                } else {
                    return Err(e);
                }
            }
        }
    }

    async fn subscribe_to_write_ready(&mut self, stream: OutputStream) -> anyhow::Result<Pollable> {
        // Ensure that table element is an output-stream:
        let _ = self.table_mut().get_output_stream_mut(stream)?;

        fn output_stream_ready<'a>(stream: &'a mut dyn Any) -> PollableFuture<'a> {
            let stream = stream
                .downcast_mut::<Box<dyn HostOutputStream>>()
                .expect("downcast to HostOutputStream failed");
            Box::pin(async move {
                let _ = stream.write_ready().await?;
                Ok(())
            })
        }

        Ok(self
            .table_mut()
            .push_host_pollable(HostPollable::TableEntry {
                index: stream,
                make_future: output_stream_ready,
            })?)
    }

    async fn blocking_check_write(
        &mut self,
        stream: OutputStream,
    ) -> anyhow::Result<streams::WriteReadiness> {
        let s = self.table_mut().get_output_stream_mut(stream)?;
        // await until actually ready for writing:
        // FIXME StreamRuntimeError to close stream
        Ok(s.write_ready().await?.into())
    }

    async fn write_zeroes(
        &mut self,
        stream: OutputStream,
        len: u64,
    ) -> anyhow::Result<Option<streams::WriteReadiness>> {
        let s = self.table_mut().get_output_stream_mut(stream)?;
        match HostOutputStream::write_zeroes(s, len as usize) {
            Ok(Some(readiness)) => Ok(Some(readiness.into())),
            Ok(None) => Ok(None),
            Err(e) => {
                if let Some(e) = e.downcast_ref::<StreamRuntimeError>() {
                    tracing::debug!("stream runtime error: {e:?}");
                    return Ok(Some(streams::WriteReadiness::Closed));
                } else {
                    return Err(e);
                }
            }
        }
    }

    async fn flush(
        &mut self,
        stream: OutputStream,
    ) -> anyhow::Result<Option<streams::FlushResult>> {
        let s = self.table_mut().get_output_stream_mut(stream)?;
        // FIXME StreamRuntimeError to close stream
        match HostOutputStream::flush(s)? {
            Some(result) => Ok(Some(result.into())),
            None => Ok(None),
        }
    }
    async fn check_flush(
        &mut self,
        stream: OutputStream,
    ) -> anyhow::Result<Option<streams::FlushResult>> {
        let s = self.table_mut().get_output_stream_mut(stream)?;
        // FIXME StreamRuntimeError to close stream
        match futures::future::poll_immediate(s.flush_ready()).await {
            Some(Ok(result)) => Ok(Some(result.into())),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }
    async fn blocking_flush(
        &mut self,
        stream: OutputStream,
    ) -> anyhow::Result<streams::FlushResult> {
        let s = self.table_mut().get_output_stream_mut(stream)?;
        // FIXME StreamRuntimeError to close stream
        HostOutputStream::flush(s)?;
        Ok(HostOutputStream::flush_ready(s).await?.into())
    }

    async fn subscribe_to_flush(&mut self, stream: OutputStream) -> anyhow::Result<Pollable> {
        // Ensure that table element is an output-stream:
        let _ = self.table_mut().get_output_stream_mut(stream)?;

        fn output_stream_ready<'a>(stream: &'a mut dyn Any) -> PollableFuture<'a> {
            let stream = stream
                .downcast_mut::<Box<dyn HostOutputStream>>()
                .expect("downcast to HostOutputStream failed");
            Box::pin(async move {
                let _ = stream.flush_ready().await?;
                Ok(())
            })
        }

        Ok(self
            .table_mut()
            .push_host_pollable(HostPollable::TableEntry {
                index: stream,
                make_future: output_stream_ready,
            })?)
    }
    /* --------------------------------------------------------------
     *
     * Aspirational methods
     *
     * -------------------------------------------------------------- */
    async fn splice(
        &mut self,
        _src: InputStream,
        _dst: OutputStream,
        _len: u64,
    ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
        // TODO: We can't get two streams at the same time because they both
        // carry the exclusive lifetime of `ctx`. When [`get_many_mut`] is
        // stabilized, that could allow us to add a `get_many_stream_mut` or
        // so which lets us do this.
        //
        // [`get_many_mut`]: https://doc.rust-lang.org/stable/std/collections/hash_map/struct.HashMap.html#method.get_many_mut
        /*
        let s: &mut Box<dyn crate::InputStream> = ctx
            .table_mut()
            .get_input_stream_mut(src)
            ?;
        let d: &mut Box<dyn crate::OutputStream> = ctx
            .table_mut()
            .get_output_stream_mut(dst)
            ?;

        let bytes_spliced: u64 = s.splice(&mut **d, len).await?;

        Ok(bytes_spliced)
        */
        todo!("stream splice is not implemented")
    }

    async fn blocking_splice(
        &mut self,
        _src: InputStream,
        _dst: OutputStream,
        _len: u64,
    ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
        // TODO: once splice is implemented, figure out what the blocking semantics are for waiting
        // on src and dest here.
        todo!("stream splice is not implemented")
    }

    async fn forward(
        &mut self,
        _src: InputStream,
        _dst: OutputStream,
    ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
        // TODO: We can't get two streams at the same time because they both
        // carry the exclusive lifetime of `ctx`. When [`get_many_mut`] is
        // stabilized, that could allow us to add a `get_many_stream_mut` or
        // so which lets us do this.
        //
        // [`get_many_mut`]: https://doc.rust-lang.org/stable/std/collections/hash_map/struct.HashMap.html#method.get_many_mut
        /*
        let s: &mut Box<dyn crate::InputStream> = ctx
            .table_mut()
            .get_input_stream_mut(src)
            ?;
        let d: &mut Box<dyn crate::OutputStream> = ctx
            .table_mut()
            .get_output_stream_mut(dst)
            ?;

        let bytes_spliced: u64 = s.splice(&mut **d, len).await?;

        Ok(bytes_spliced)
        */

        todo!("stream forward is not implemented")
    }
}

pub mod sync {
    use crate::preview2::{
        bindings::io::streams::{self as async_streams, Host as AsyncHost},
        bindings::sync_io::io::streams::{self, InputStream, OutputStream},
        bindings::sync_io::poll::poll::Pollable,
        in_tokio, WasiView,
    };

    // same boilerplate everywhere, converting between two identical types with different
    // definition sites. one day wasmtime-wit-bindgen will make all this unnecessary
    fn xform<A>(
        r: Result<(A, async_streams::StreamStatus), ()>,
    ) -> Result<(A, streams::StreamStatus), ()> {
        r.map(|(a, b)| (a, b.into()))
    }

    impl From<async_streams::StreamStatus> for streams::StreamStatus {
        fn from(other: async_streams::StreamStatus) -> Self {
            match other {
                async_streams::StreamStatus::Open => Self::Open,
                async_streams::StreamStatus::Ended => Self::Ended,
            }
        }
    }

    impl From<async_streams::WriteReadiness> for streams::WriteReadiness {
        fn from(other: async_streams::WriteReadiness) -> Self {
            match other {
                async_streams::WriteReadiness::Ready(a) => Self::Ready(a),
                async_streams::WriteReadiness::Closed => Self::Closed,
            }
        }
    }

    impl From<async_streams::FlushResult> for streams::FlushResult {
        fn from(other: async_streams::FlushResult) -> Self {
            match other {
                async_streams::FlushResult::Done => Self::Done,
                async_streams::FlushResult::Closed => Self::Closed,
            }
        }
    }

    impl<T: WasiView> streams::Host for T {
        fn drop_input_stream(&mut self, stream: InputStream) -> anyhow::Result<()> {
            in_tokio(async { AsyncHost::drop_input_stream(self, stream).await })
        }

        fn drop_output_stream(&mut self, stream: OutputStream) -> anyhow::Result<()> {
            in_tokio(async { AsyncHost::drop_output_stream(self, stream).await })
        }

        fn read(
            &mut self,
            stream: InputStream,
            len: u64,
        ) -> anyhow::Result<Result<(Vec<u8>, streams::StreamStatus), ()>> {
            in_tokio(async { AsyncHost::read(self, stream, len).await }).map(xform)
        }

        fn blocking_read(
            &mut self,
            stream: InputStream,
            len: u64,
        ) -> anyhow::Result<Result<(Vec<u8>, streams::StreamStatus), ()>> {
            in_tokio(async { AsyncHost::blocking_read(self, stream, len).await }).map(xform)
        }

        fn check_write(
            &mut self,
            stream: OutputStream,
        ) -> anyhow::Result<Option<streams::WriteReadiness>> {
            in_tokio(async { AsyncHost::check_write(self, stream).await })
                .map(|r| r.map(|opt| opt.into()))
        }
        fn write(
            &mut self,
            stream: OutputStream,
            bytes: Vec<u8>,
        ) -> anyhow::Result<Option<streams::WriteReadiness>> {
            in_tokio(async { AsyncHost::write(self, stream, bytes).await })
                .map(|opt| opt.map(|r| r.into()))
        }
        fn subscribe_to_write_ready(&mut self, stream: OutputStream) -> anyhow::Result<Pollable> {
            in_tokio(async { AsyncHost::subscribe_to_write_ready(self, stream).await })
        }
        fn write_zeroes(
            &mut self,
            stream: OutputStream,
            len: u64,
        ) -> anyhow::Result<Option<streams::WriteReadiness>> {
            in_tokio(async { AsyncHost::write_zeroes(self, stream, len).await })
                .map(|opt| opt.map(|r| r.into()))
        }
        fn blocking_check_write(
            &mut self,
            stream: OutputStream,
        ) -> anyhow::Result<streams::WriteReadiness> {
            in_tokio(async { AsyncHost::blocking_check_write(self, stream).await })
                .map(|opt| opt.into())
        }

        fn flush(&mut self, stream: OutputStream) -> anyhow::Result<Option<streams::FlushResult>> {
            in_tokio(async { AsyncHost::flush(self, stream).await })
                .map(|res| res.map(|opt| opt.into()))
        }
        fn check_flush(
            &mut self,
            stream: OutputStream,
        ) -> anyhow::Result<Option<streams::FlushResult>> {
            in_tokio(async { AsyncHost::check_flush(self, stream).await })
                .map(|res| res.map(|opt| opt.into()))
        }
        fn blocking_flush(&mut self, stream: OutputStream) -> anyhow::Result<streams::FlushResult> {
            in_tokio(async { AsyncHost::blocking_flush(self, stream).await }).map(|res| res.into())
        }

        fn subscribe_to_flush(&mut self, stream: OutputStream) -> anyhow::Result<Pollable> {
            in_tokio(async { AsyncHost::subscribe_to_flush(self, stream).await })
        }
        fn skip(
            &mut self,
            stream: InputStream,
            len: u64,
        ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
            in_tokio(async { AsyncHost::skip(self, stream, len).await }).map(xform)
        }

        fn blocking_skip(
            &mut self,
            stream: InputStream,
            len: u64,
        ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
            in_tokio(async { AsyncHost::blocking_skip(self, stream, len).await }).map(xform)
        }

        fn splice(
            &mut self,
            src: InputStream,
            dst: OutputStream,
            len: u64,
        ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
            in_tokio(async { AsyncHost::splice(self, src, dst, len).await }).map(xform)
        }

        fn blocking_splice(
            &mut self,
            src: InputStream,
            dst: OutputStream,
            len: u64,
        ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
            in_tokio(async { AsyncHost::blocking_splice(self, src, dst, len).await }).map(xform)
        }

        fn forward(
            &mut self,
            src: InputStream,
            dst: OutputStream,
        ) -> anyhow::Result<Result<(u64, streams::StreamStatus), ()>> {
            in_tokio(async { AsyncHost::forward(self, src, dst).await }).map(xform)
        }

        fn subscribe_to_input_stream(&mut self, stream: InputStream) -> anyhow::Result<Pollable> {
            in_tokio(async { AsyncHost::subscribe_to_input_stream(self, stream).await })
        }
    }
}
