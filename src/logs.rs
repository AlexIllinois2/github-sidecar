//! 日志环形缓冲：tracing 输出同时写到 stderr 和内存环形缓冲，供管理界面轮询。

use serde::Serialize;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const MAX_ENTRIES: usize = 1000;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub seq: u64,
    pub line: String,
}

#[derive(Default)]
pub struct LogBuffer {
    entries: Mutex<VecDeque<LogEntry>>,
    next_seq: AtomicU64,
}

impl LogBuffer {
    pub fn push(&self, line: &str) {
        let line = line.trim_end();
        if line.is_empty() {
            return;
        }
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= MAX_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(LogEntry { seq, line: line.to_string() });
    }

    /// 返回 seq 大于 after 的日志（最多 limit 条）
    pub fn after(&self, after: u64, limit: usize) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| e.seq > after)
            .take(limit)
            .cloned()
            .collect()
    }
}

/// tracing_subscriber 的 MakeWriter 工厂：每个 fmt 调用生成一个 writer 实例，
/// writer 内部自己缓冲半行，遇到换行才推进环形缓冲。
#[derive(Clone)]
pub struct DualLogWriter {
    buf: Arc<LogBuffer>,
}

impl DualLogWriter {
    pub fn new(buf: Arc<LogBuffer>) -> Self {
        Self { buf }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DualLogWriter {
    type Writer = LineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter {
            buf: self.buf.clone(),
            partial: Vec::new(),
        }
    }
}

pub struct LineWriter {
    buf: Arc<LogBuffer>,
    partial: Vec<u8>,
}

impl Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // 原样透传到 stderr
        let _ = std::io::stderr().write_all(data);
        self.partial.extend_from_slice(data);
        while let Some(pos) = self.partial.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=pos).collect();
            let s = String::from_utf8_lossy(&line[..pos]);
            self.buf.push(&s);
        }
        // 防御：没有换行的超长输出直接截断
        if self.partial.len() > 64 * 1024 {
            let s = String::from_utf8_lossy(&self.partial);
            self.buf.push(&s);
            self.partial.clear();
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.partial.is_empty() {
            let s = String::from_utf8_lossy(&self.partial);
            self.buf.push(&s);
            self.partial.clear();
        }
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}
