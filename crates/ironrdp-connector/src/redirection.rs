use ironrdp_pdu::rdp::headers::{ShareControlPdu, decode_share_control};
use ironrdp_pdu::rdp::server_redirection::ServerRedirectionFlags;
use tracing::{debug, info};

use crate::{ConnectorError, ConnectorErrorKind, ConnectorResult};

/// Servers may send a Server Redirection PDU on the I/O channel at any point after the MCS
/// connection is established, for example in place of a licensing or Demand Active PDU
/// (MS-RDPBCGR 1.3.1.5).
///
/// Returns `Ok(true)` for a redirection carrying `LB_NOREDIRECT`, which the caller should skip,
/// an error for any other redirection, and `Ok(false)` when `input` is not a redirection.
pub(crate) fn check_server_redirection(input: &[u8], io_channel_id: u16) -> ConnectorResult<bool> {
    let Ok(ctx) = ironrdp_pdu::mcs::decode_send_data_indication(input) else {
        return Ok(false);
    };
    if ctx.channel_id != io_channel_id {
        return Ok(false);
    }
    let is_redirection = ctx
        .user_data
        .get(2..4)
        .is_some_and(|pdu_type| pdu_type[0] & 0x0F == 0x0A && pdu_type[1] == 0);
    if !is_redirection {
        return Ok(false);
    }

    let ShareControlPdu::ServerRedirect(redirection) = decode_share_control(ctx)
        .map_err(<ConnectorError as crate::ConnectorErrorExt>::decode)?
        .pdu
    else {
        return Ok(false);
    };

    if redirection.flags.contains(ServerRedirectionFlags::NO_REDIRECT) {
        debug!("Ignoring Server Redirection PDU with LB_NOREDIRECT");
        return Ok(true);
    }

    info!(flags = ?redirection.flags, "Server requested redirection");
    Err(ConnectorError::new(
        "server redirection",
        ConnectorErrorKind::ServerRedirection(redirection),
    ))
}
