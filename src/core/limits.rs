use anyhow::{bail, Result};

pub const DEFAULT_MAX_INPUT: u64 = 4 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_CHUNK: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    pub max_input_size: u64,
    pub max_chunk_size: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self { max_input_size: DEFAULT_MAX_INPUT, max_chunk_size: DEFAULT_MAX_CHUNK }
    }
}

impl ResourceLimits {
    pub fn validate(&self, input_size: u64) -> Result<()> {
        if self.max_input_size == 0 || self.max_chunk_size == 0 {
            bail!("resource limits must be non-zero");
        }
        if input_size > self.max_input_size {
            bail!("input exceeds configured size limit");
        }
        Ok(())
    }
}
