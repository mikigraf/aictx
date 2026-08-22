use std::{
    io::IoSliceMut,
    os::fd::{AsFd, AsRawFd},
};

use nix::sys::socket::{ControlMessageOwned, MsgFlags, UnixCredentials, recvmsg};
use rustix::{
    io::{FdFlags, fcntl_getfd},
    net::{AddressFamily, SocketType, sockopt},
};

use crate::automation::{
    attestation::{AttestationError, AuthenticatedCaller, AuthenticatedMessage},
    authority::{AuthenticationAssurance, PreparedAuthority},
};

use super::{LinuxAttestor, PeerCredentials};

const MAX_HARD_FRAME_BYTES: usize = 1_048_576;
// Linux caps one SCM_RIGHTS transfer at SCM_MAX_FD (253). Reserving the full
// kernel maximum keeps `RecvMsg::cmsgs` iterable, so every installed descriptor
// can be closed before a rights-bearing record is rejected.
const LINUX_SCM_MAX_FD: usize = 253;

/// A connected Linux record channel whose opener remains pidfd-attested.
///
/// Construction enables and reads back `SO_PASSCRED`. Each receive consumes
/// exactly one `SOCK_SEQPACKET` record and requires exactly one matching
/// `SCM_CREDENTIALS` item. The returned message borrows this channel, so a
/// second record cannot be received while the first record's proof is live.
pub(crate) struct LinuxAuthenticatedChannel<Fd: AsFd> {
    socket: Fd,
    caller: AuthenticatedCaller,
}

impl<Fd: AsFd> LinuxAuthenticatedChannel<Fd> {
    pub(crate) fn new(socket: Fd, authority: &PreparedAuthority) -> Result<Self, AttestationError> {
        validate_socket(&socket)?;
        sockopt::set_socket_passcred(&socket, true)
            .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
        if !sockopt::socket_passcred(&socket)
            .map_err(|_| AttestationError::CallerAuthenticationFailed)?
        {
            return Err(AttestationError::CallerAuthenticationFailed);
        }
        let caller = LinuxAttestor::attest(&socket, authority)?;
        Ok(Self { socket, caller })
    }

    pub(crate) fn receive_message<'channel>(
        &'channel mut self,
        authority: &PreparedAuthority,
    ) -> Result<AuthenticatedMessage<'channel>, AttestationError> {
        self.caller.revalidate(authority)?;
        let maximum = usize::try_from(authority.service_limits().max_frame_bytes)
            .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
        let payload = receive_record(&self.socket, self.caller.process_guard.credentials, maximum)?;
        self.caller.revalidate(authority)?;
        AuthenticatedMessage::new(
            &self.caller,
            payload,
            AuthenticationAssurance::LinuxMessageAuthenticated,
            authority,
        )
    }
}

fn validate_socket<Fd: AsFd>(socket: &Fd) -> Result<(), AttestationError> {
    let descriptor_flags =
        fcntl_getfd(socket).map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if !descriptor_flags.contains(FdFlags::CLOEXEC)
        || sockopt::socket_domain(socket)
            .map_err(|_| AttestationError::CallerAuthenticationFailed)?
            != AddressFamily::UNIX
        || sockopt::socket_type(socket).map_err(|_| AttestationError::CallerAuthenticationFailed)?
            != SocketType::SEQPACKET
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(())
}

fn receive_record<Fd: AsFd>(
    socket: &Fd,
    expected: PeerCredentials,
    maximum: usize,
) -> Result<Box<[u8]>, AttestationError> {
    if maximum == 0 || maximum > MAX_HARD_FRAME_BYTES {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let capacity = maximum
        .checked_add(1)
        .ok_or(AttestationError::CallerAuthenticationFailed)?;
    let mut payload = vec![0_u8; capacity];
    let mut ancillary = nix::cmsg_space!(UnixCredentials, [std::os::fd::RawFd; LINUX_SCM_MAX_FD]);
    let mut slices = [IoSliceMut::new(&mut payload)];
    let message = recvmsg::<()>(
        socket.as_fd().as_raw_fd(),
        &mut slices,
        Some(&mut ancillary),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    let bytes = message.bytes;
    let flags = message.flags;
    let mut credentials = None;
    let mut invalid_ancillary = false;
    let messages = message
        .cmsgs()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    for item in messages {
        match item {
            ControlMessageOwned::ScmCredentials(value) => {
                if credentials.replace(value).is_some() {
                    invalid_ancillary = true;
                }
            }
            ControlMessageOwned::ScmRights(descriptors) => {
                invalid_ancillary = true;
                for descriptor in descriptors {
                    let _ = nix::unistd::close(descriptor);
                }
            }
            _ => invalid_ancillary = true,
        }
    }
    let truncated = flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
    if bytes == 0
        || bytes > maximum
        || truncated
        || invalid_ancillary
        || !credentials.is_some_and(|value| credentials_match(expected, value))
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    payload.truncate(bytes);
    Ok(payload.into_boxed_slice())
}

fn credentials_match(expected: PeerCredentials, observed: UnixCredentials) -> bool {
    observed.pid() == expected.pid.as_raw_pid()
        && observed.uid() == expected.uid
        && observed.gid() == expected.gid
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{ControlMessage, MsgFlags, UnixCredentials, sendmsg};
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    use super::*;

    fn credentials() -> PeerCredentials {
        PeerCredentials {
            pid: rustix::process::getpid(),
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        }
    }

    fn pair() -> (rustix::fd::OwnedFd, rustix::fd::OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap_or_else(|error| panic!("seqpacket pair: {error:?}"))
    }

    fn send_payload<Fd: AsFd>(socket: &Fd, payload: &[u8]) {
        let slices = [std::io::IoSlice::new(payload)];
        sendmsg::<()>(
            socket.as_fd().as_raw_fd(),
            &slices,
            &[],
            MsgFlags::empty(),
            None,
        )
        .unwrap_or_else(|error| panic!("send record: {error}"));
    }

    #[test]
    fn native_record_has_one_matching_kernel_credential() {
        let (receiver, sender) = pair();
        sockopt::set_socket_passcred(&receiver, true)
            .unwrap_or_else(|error| panic!("passcred: {error:?}"));
        send_payload(&sender, b"bounded-message");
        assert_eq!(
            receive_record(&receiver, credentials(), 64)
                .unwrap_or_else(|error| panic!("receive: {error:?}"))
                .as_ref(),
            b"bounded-message"
        );
    }

    #[test]
    fn missing_credentials_and_oversized_records_are_rejected() {
        let (receiver, sender) = pair();
        send_payload(&sender, b"no-credentials");
        assert!(receive_record(&receiver, credentials(), 64).is_err());

        let (receiver, sender) = pair();
        sockopt::set_socket_passcred(&receiver, true)
            .unwrap_or_else(|error| panic!("passcred: {error:?}"));
        send_payload(&sender, b"too-long");
        assert!(receive_record(&receiver, credentials(), 3).is_err());
    }

    #[test]
    fn rights_are_closed_and_rejected_even_with_matching_credentials() {
        let (receiver, sender) = pair();
        let (sent, _other) = pair();
        sockopt::set_socket_passcred(&receiver, true)
            .unwrap_or_else(|error| panic!("passcred: {error:?}"));
        let payload = [std::io::IoSlice::new(b"with-right")];
        let descriptors = [sent.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&descriptors)];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &payload,
            &control,
            MsgFlags::empty(),
            None,
        )
        .unwrap_or_else(|error| panic!("send rights: {error}"));
        assert!(receive_record(&receiver, credentials(), 64).is_err());
    }

    #[test]
    fn rights_at_the_linux_kernel_limit_are_all_closed_before_rejection() {
        let (receiver, sender) = pair();
        let (sent, _other) = pair();
        sockopt::set_socket_passcred(&receiver, true)
            .unwrap_or_else(|error| panic!("passcred: {error:?}"));
        let descriptors = [sent.as_raw_fd(); LINUX_SCM_MAX_FD];
        let sent_target = descriptor_target(sent.as_raw_fd());
        let before = descriptor_target_count(&sent_target);
        let payload = [std::io::IoSlice::new(b"many-rights")];
        let control = [ControlMessage::ScmRights(&descriptors)];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &payload,
            &control,
            MsgFlags::empty(),
            None,
        )
        .unwrap_or_else(|error| panic!("send rights: {error}"));
        assert!(receive_record(&receiver, credentials(), 64).is_err());
        assert_eq!(descriptor_target_count(&sent_target), before);
    }

    fn descriptor_target(descriptor: std::os::fd::RawFd) -> std::path::PathBuf {
        std::fs::read_link(format!("/proc/self/fd/{descriptor}"))
            .unwrap_or_else(|error| panic!("read fd target: {error}"))
    }

    fn descriptor_target_count(target: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap_or_else(|error| panic!("open fd directory: {error}"))
            .filter_map(Result::ok)
            .filter(|entry| {
                std::fs::read_link(entry.path()).is_ok_and(|candidate| candidate == target)
            })
            .count()
    }

    #[test]
    fn wrong_kernel_identity_is_rejected() {
        let (receiver, sender) = pair();
        sockopt::set_socket_passcred(&receiver, true)
            .unwrap_or_else(|error| panic!("passcred: {error:?}"));
        send_payload(&sender, b"identity");
        let mut wrong = credentials();
        wrong.uid = wrong.uid.saturating_add(1);
        assert!(receive_record(&receiver, wrong, 64).is_err());
    }

    #[test]
    fn socket_shape_and_cloexec_are_required() {
        let (seqpacket, _peer) = pair();
        assert!(validate_socket(&seqpacket).is_ok());
        let (stream, _peer) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap_or_else(|error| panic!("stream pair: {error:?}"));
        assert!(validate_socket(&stream).is_err());
    }

    #[test]
    fn explicit_current_credentials_are_accepted_once() {
        let (receiver, sender) = pair();
        sockopt::set_socket_passcred(&receiver, true)
            .unwrap_or_else(|error| panic!("passcred: {error:?}"));
        let payload = [std::io::IoSlice::new(b"credential")];
        let current = UnixCredentials::new();
        let control = [ControlMessage::ScmCredentials(&current)];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &payload,
            &control,
            MsgFlags::empty(),
            None,
        )
        .unwrap_or_else(|error| panic!("send credential: {error}"));
        assert!(receive_record(&receiver, credentials(), 64).is_ok());
    }
}
