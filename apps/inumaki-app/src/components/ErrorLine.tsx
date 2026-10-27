import type { CmdError } from "../types";
import { CopyButton } from "./CopyButton";
import { NoticeIcon } from "./Notice";

/** The fixed explanation shown whenever a Revert left the client header in a harness file. */
export const CLIENT_HEADER_LEFT_TEXT =
  "Reverted, but the harness configuration still carries the inumaki client header (X-Inumaki-Client), which now goes to the model provider. Remove that line by hand.";

// Fixed sentences per error kind (kinds come from src-tauri/src/error.rs and the
// harness and command modules). Nothing here is a daemon message.
const TEXT: Record<string, string> = {
  service_unreachable: "The inumaki service is not running.",
  config_error: "Configuration error: the config file that names the service socket cannot be used. See Overview.",
  timeout: "The inumaki service did not answer in time.",
  not_available: "Not available yet in this version of the service.",
  cannot_edit_safely: "inumaki cannot edit this file safely. Add the lines below by hand.",
  privacy_block: "Blocked: the result still contained identifying information.",
  managed_elsewhere:
    "This service is managed outside the app (Homebrew, the Debian package, or by hand). The app leaves it alone.",
  service_did_not_start: "The service was registered but did not answer within 20 seconds. Check its log in the data folder.",
  service_install_failed: "The system refused to register the login service.",
  service_restart_failed: "The system refused to restart the service.",
  service_remove_failed: "The service file could not be removed.",
  service_not_installed_by_app:
    "The running service says the app manages it, but the app's service file is missing, so the app cannot stop it. Stop it from the command line, or install it again here first.",
  service_file_unwritable: "inumaki could not write the service file or its log.",
  helper_missing: "The app bundle lacks a helper program. Reinstall the app.",
  bin_dir_unwritable: "inumaki could not copy its helper programs into the data folder.",
  sign_failed: "inumaki could not prepare its helper programs to run (signature).",
  launchctl_failed: "launchctl could not be run.",
  systemctl_failed: "systemctl could not be run.",
  home_unreadable: "Your home folder could not be read.",
  reconnect_failed_disconnected:
    "Harness disconnected; its protected servers talk to the originals again. Reconnect it from Overview.",
  client_header_left: CLIENT_HEADER_LEFT_TEXT,
  client_header_left_pending: CLIENT_HEADER_LEFT_TEXT,
  revocation_store: "inumaki could not record which gateway token to revoke, so nothing was changed.",
  file_unwritable: "inumaki could not write the harness's configuration file.",
  changed_meanwhile: "The harness changed its configuration while inumaki edited it. Try again.",
  not_our_gateway: "The configuration points at another gateway; nothing was changed.",
  command_not_found: "The server's program was not found on your PATH.",
  cannot_protect_yet: "This server needs a sign-in flow inumaki does not support yet.",
  outside_mirror_root: "That folder is outside the inumaki mirror.",
  mail_auth_failed: "The mailbox refused the username or app password.",
  mail_unreachable: "The mail server could not be reached.",
  mail_tls_failed: "The secure connection to the mail server failed.",
  mail_protocol: "The mail server answered in a way inumaki does not understand.",
  not_supported: "This harness does not support that.",
  state_unwritable: "inumaki could not save its own state file. Nothing else was changed.",
  backup_in_use: "That backup may be in use or is being cleaned up. Refresh the list; to restore a connected harness, use Revert on Overview.",
  backup_unreadable: "The harness's backup cannot be read, so inumaki cannot tell what to restore.",
  not_a_mailbox: "That is not a mailbox.",
  not_a_folder: "That is not a folder.",
  not_a_wrapped_server: "That is not a protected server.",
  server_not_found: "The server is no longer in the harness's configuration. Refresh the list.",
  not_protected: "That server is not protected.",
  already_protected: "That server is already protected.",
  not_routed: "That harness's chat does not go through inumaki.",
  not_acknowledgeable: "Only a path that cannot be protected can be acknowledged.",
  still_in_use: "A harness still uses it.",
  harness_not_found: "That harness is not known.",
  harness_not_installed: "That harness is not installed.",
  bad_request: "inumaki could not use that input.",
  bad_response: "The inumaki service answered in a way the app does not understand.",
  open_failed: "inumaki could not open that.",
  conflict: "That conflicts with the current state. Refresh and try again.",
  folder_busy: "The folder is busy (macOS may be asking for access). Try again in a moment; the folder stays until it is removed.",
  check_running:
    "Another end-to-end check is still live in the service (possibly one the app lost track of). It expires within 10 minutes; run the check again after that.",
  check_start_lost:
    "The service did not confirm the check in time. If it started one anyway, new checks are refused for up to 10 minutes.",
  check_in_progress: "An end-to-end check is already running.",
  check_expired: "The check expired or was removed. Run it again.",
  check_no_report: "The check has no result yet. Run it again.",
  check_tmp_unwritable: "inumaki could not prepare the temporary folders for the check.",
  not_found: "Not found.",
  unavailable: "The inumaki service is busy. Try again.",
  internal: "Something failed inside the app.",
};

/**
 * A compact red notice. The outer element holds the sentence as ONE text node (kinds appended) and
 * carries `role="alert"`: tests find the sentence and read the role off the same element.
 */
export function ErrorLine({ error }: { error: CmdError }) {
  const kinds = error.kinds?.length ? ` (${error.kinds.join(", ")})` : "";
  const warning = error.kind === "client_header_left" || error.kind === "client_header_left_pending";
  return (
    <div className="notice red error-line" role="alert">
      <NoticeIcon kind="red" />
      {warning && <strong>Warning: </strong>}
      {(TEXT[error.kind] ?? `Something went wrong (${error.kind}).`) + kinds}
      {error.reason && !warning && <div>{error.reason.text}</div>}
      {error.snippet && (
        <>
          <pre className="card">{error.snippet}</pre>
          <CopyButton text={error.snippet} label="Copy the lines" />
        </>
      )}
    </div>
  );
}
