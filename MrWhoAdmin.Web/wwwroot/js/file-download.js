(function(){
  window.mrwho = window.mrwho || {};
  window.mrwho.downloadFile = function(fileName, contentType, base64Data){
    try {
      const binaryString = atob(base64Data);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: contentType || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName || 'download';
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
      setTimeout(function(){
        URL.revokeObjectURL(url);
        document.body.removeChild(link);
      }, 0);
    } catch (e) {
      console.error('downloadFile failed', e);
    }
  };
})();
