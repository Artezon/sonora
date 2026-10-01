//! The CDM host process: the Sonora executable started with [`crate::HOST_ARG`]. It loads the
//! module, answers [`crate::wire`] requests from stdin on stdout, and exits when stdin closes.
//!
//! Keeping the module out of the app is what lets its memory go. Widevine maps about 80 MiB the
//! moment it initializes and none of it can be handed back, so the app starts this process
//! while a protected track is loaded and lets it exit once none is.

use std::io::{self, BufWriter, Read, Write};
use std::path::Path;

use anyhow::{Context as _, Result, bail};

use crate::shim::Shim;
use crate::wire;

/// Room for a whole answer, so each one leaves in a single write.
const ANSWER_BUFFER: usize = 64 * 1024;

/// Opens the module at `module` and serves requests until the parent closes stdin. Fails only
/// when the pipe itself breaks or the module does not open, which the parent hears about first.
pub fn serve(module: &Path) -> Result<()> {
    let mut input = io::stdin().lock();
    let mut output = BufWriter::with_capacity(ANSWER_BUFFER, answers()?);

    let shim = match Shim::open(module) {
        Ok(shim) => {
            reply(&mut output, wire::OK, &[])?;
            shim
        }
        Err(error) => {
            reply(&mut output, wire::FAILED, format!("{error:#}").as_bytes())?;
            return Err(error);
        }
    };
    log::info!("widevine: host opened {}", module.display());

    let mut payload = Vec::new();
    let mut subs = Vec::new();
    loop {
        let (op, len) = match wire::take_header(&mut input) {
            Ok(header) => header,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error).context("cannot read a request"),
        };
        payload.resize(len, 0);
        input
            .read_exact(&mut payload)
            .context("cannot read a request")?;
        match answer(&shim, op, &payload, &mut subs) {
            Ok(body) => reply(&mut output, wire::OK, &body)?,
            Err(error) => reply(&mut output, wire::FAILED, format!("{error:#}").as_bytes())?,
        }
    }
}

/// Runs one request against the module.
fn answer(shim: &Shim, op: u8, payload: &[u8], subs: &mut Vec<u32>) -> Result<Vec<u8>> {
    match op {
        wire::CHALLENGE => shim.challenge(payload),
        wire::UPDATE => shim.update(payload).map(|()| Vec::new()),
        wire::DECRYPT => {
            let Some(request) = wire::split_decrypt(payload, subs) else {
                bail!("the decrypt request is malformed");
            };
            let clear = shim.decrypt(request.sample, request.key_id, request.iv, subs)?;
            if clear.len() != request.sample.len() {
                bail!(
                    "the cdm returned {} bytes for a {} byte sample",
                    clear.len(),
                    request.sample.len()
                );
            }
            Ok(clear)
        }
        op => bail!("no such request ({op})"),
    }
}

/// Sends one answer and flushes it, so the parent is never left waiting on a buffer.
fn reply(output: &mut impl Write, status: u8, body: &[u8]) -> Result<()> {
    wire::put_header(output, status, body.len())
        .and_then(|()| output.write_all(body))
        .and_then(|()| output.flush())
        .context("cannot answer the app")
}

/// Where answers go. The module and whatever it links may print, and a stray byte on the
/// answer pipe would put the parent out of step, so on Unix answers leave on a private copy of
/// stdout and fd 1 is pointed at stderr.
#[cfg(unix)]
fn answers() -> Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;

    let private = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
    if private < 0 {
        return Err(io::Error::last_os_error()).context("cannot copy stdout");
    }
    if unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error()).context("cannot point stdout at stderr");
    }
    Ok(unsafe { std::fs::File::from_raw_fd(private) })
}

/// Where answers go. Off Unix they go straight to stdout.
#[cfg(not(unix))]
fn answers() -> Result<io::Stdout> {
    Ok(io::stdout())
}
