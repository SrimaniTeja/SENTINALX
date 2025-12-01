// script.js

function internal() {
    // Primary behaviour: go to internal page (keeps your old onclick behavior)
    try {
      // If the environment is a typical browser, navigate
      window.location.href = 'internal.html';
    } catch (e) {
      console.warn('Navigation failed:', e);
    }
  }
  
  function openLogs() {
    console.log('Opening logs...');
    
    // invoke('open_logs');
  }
  
  function deviceScan() {
    console.log('Starting device scan...');
    
    // invoke('device_scan');
  }
  
  function portScan() {
    console.log('Starting port scan...');
    
    // invoke('port_scan');
  }
  
  function serviceVersionDetection() {
    console.log('Starting service & version detection...');
   
    // invoke('service_version_detection');
  }
  
  /* Background logs toggle: observe the checkbox and handle changes */
  const bgCheckbox = document.getElementById('sx-background-logs');
  if (bgCheckbox) {
    bgCheckbox.addEventListener('change', (e) => {
        const enabled = e.target.checked;
        console.log('Background logs:', enabled ? 'Enabled' : 'Disabled');
      // invoke('toggle_background_logs', { enabled });
    });
  }
  