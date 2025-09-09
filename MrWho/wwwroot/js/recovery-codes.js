(function(){
  'use strict';

  function byId(id){ return document.getElementById(id); }
  function getRoot(){ return document.getElementById('rc-root'); }

  function getCodes(){
    var el = byId('recoveryCodes');
    if(!el) return [];
    try{ return JSON.parse(el.getAttribute('data-codes') || '[]'); }
    catch{ return []; }
  }

  function showCopied(btn){
    if(!btn) return;
    var orig = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check me-2"></i><span class="btn-text">Copied!</span>';
    btn.classList.remove('btn-outline-primary');
    btn.classList.add('btn-success');
    setTimeout(function(){
      btn.innerHTML = orig;
      btn.classList.remove('btn-success');
      btn.classList.add('btn-outline-primary');
    }, 1600);
  }

  function copyAll(btn){
    var codes = getCodes();
    var payload = codes.join('\n');
    if (navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(payload).then(function(){ showCopied(btn); })
        .catch(function(){ fallbackCopy(payload, btn); });
      return;
    }
    fallbackCopy(payload, btn);
  }

  function fallbackCopy(text, btn){
    try{
      var ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly','');
      ta.style.position='fixed'; ta.style.left='-9999px';
      document.body.appendChild(ta); ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if(ok) showCopied(btn); else alert('Copy failed. Please copy manually.');
    }catch(e){ alert('Copy failed: ' + e); }
  }

  function printCodes(){
    var codes = getCodes();
    var w = window.open('', '_blank');
    if(!w){ alert('Popup blocked. Please allow popups to print.'); return; }
    var currentDate = new Date().toLocaleDateString();
    var html = '';
    html += '<!doctype html><html><head><title>MrWho Recovery Codes</title>';
    html += '<style>body{font-family:Arial,sans-serif;margin:40px}.header{text-align:center;margin-bottom:30px}.codes{background:#f8f9fa;padding:20px;border-radius:8px}.code-item{margin:10px 0;font-size:16px;font-family:monospace}.warning{background:#fff3cd;padding:15px;border-radius:5px;margin:20px 0}.footer{margin-top:30px;font-size:12px;color:#666}</style>';
    html += '</head><body>';
    html += '<div class="header"><h1>MrWho Recovery Codes</h1><p>Generated on: ' + currentDate + '</p></div>';
    html += '<div class="warning"><strong>SECURITY WARNING:</strong><ul>' +
            '<li>Each code can only be used once</li>' +
            '<li>Store this document in a secure location</li>' +
            '<li>Do not share these codes with anyone</li>' +
            '<li>Use only if you lose access to your authenticator app</li>' +
            '</ul></div>';
    html += '<div class="codes">';
    for (var i=0;i<codes.length;i++){
      html += '<div class="code-item">' + (i+1) + '. ' + codes[i] + '</div>';
    }
    html += '</div><div class="footer"><p>MrWho Identity Server - Two-Factor Authentication Recovery Codes</p></div>';
    html += '</body></html>';
    w.document.write(html); w.document.close(); w.print();
  }

  function continueNav(){
    var root = getRoot();
    var url = root ? root.getAttribute('data-return-url') : '/';
    var confirmSaved = byId('confirmSaved');
    if (confirmSaved && !confirmSaved.checked){
      if (!window.confirm('Proceed without confirming you saved the codes?')) return;
    }
    if (!url) url = '/';
    window.location.href = url;
  }

  function wire(){
    var btnCopy = byId('btnCopyAll');
    var btnPrint = byId('btnPrint');
    var btnContinue = byId('continueBtn');
    if (btnCopy) btnCopy.addEventListener('click', function(){ copyAll(btnCopy); });
    if (btnPrint) btnPrint.addEventListener('click', printCodes);
    if (btnContinue) btnContinue.addEventListener('click', continueNav);
  }

  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
