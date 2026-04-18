const logContent = document.getElementById('log-content');

export function log(message, type = 'info') {
  const timestamp = new Date().toLocaleTimeString();
  const typeClass = `log-${type}`;
  let icon = '';

  switch (type) {
    case 'kerberos': icon = '<i class="fas fa-key fa-fw me-1"></i>'; break;
    case 'ldap':     icon = '<i class="fas fa-book fa-fw me-1"></i>'; break;
    case 'attack':   icon = '<i class="fas fa-biohazard fa-fw me-1"></i>'; break;
    case 'success':  icon = '<i class="fas fa-check-circle fa-fw me-1"></i>'; break;
    case 'fail':     icon = '<i class="fas fa-times-circle fa-fw me-1"></i>'; break;
    case 'info':     icon = '<i class="fas fa-info-circle fa-fw me-1"></i>'; break;
    case 'rpc':      icon = '<i class="fas fa-network-wired fa-fw me-1"></i>'; break;
    case 'smb':      icon = '<i class="fas fa-folder-open fa-fw me-1"></i>'; break;
    case 'dns':      icon = '<i class="fas fa-search-location fa-fw me-1"></i>'; break;
    case 'http':     icon = '<i class="fas fa-globe fa-fw me-1"></i>'; break;
    case 'drsuapi':  icon = '<i class="fas fa-database fa-fw me-1"></i>'; break;
    case 'ntlm':     icon = '<i class="fas fa-fingerprint fa-fw me-1"></i>'; break;
    default:
      icon = '<i class="fas fa-angle-right fa-fw me-1"></i>';
  }

  const safe = message.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  logContent.innerHTML += `<span class="${typeClass}">[${timestamp}] ${icon}${safe}\n</span>`;
  logContent.scrollTop = logContent.scrollHeight;
}
