document.getElementById('start-scan').addEventListener('click', () => {
  const statusElement = document.getElementById('scan-status');
  statusElement.textContent = 'Status: Scanning...';
  statusElement.style.color = 'orange';

  // Send POST request to backend to start the scan
  fetch('http://localhost:5000/start-scan', {
    method: 'POST',
  })
  .then(response => response.json())
  .then(data => {
    if (data.message === 'Scan started') {
      // Simulate scan completion after a few seconds
      setTimeout(() => {
        statusElement.textContent = 'Status: Scan Complete';
        statusElement.style.color = 'green';
      }, 3000); // Adjust to your scan time
    } else {
      statusElement.textContent = 'Status: Error';
      statusElement.style.color = 'red';
    }
  })
  .catch(error => {
    console.error('Error starting scan:', error);
    statusElement.textContent = 'Status: Error';
    statusElement.style.color = 'red';
  });
});

document.getElementById('start-monitor').addEventListener('click', () => {
  const statusElement = document.getElementById('monitor-status');
  statusElement.textContent = 'Status: Monitoring...';
  statusElement.style.color = 'orange';

  // Send POST request to backend to start the monitor
  fetch('http://localhost:5000/start-monitor', {
    method: 'POST',
  })
  .then(response => response.json())
  .then(data => {
    if (data.message === 'Monitor started') {
      // Simulate monitor completion after a few seconds
      setTimeout(() => {
        statusElement.textContent = 'Status: Monitoring Complete';
        statusElement.style.color = 'green';
      }, 3000); // Adjust to your monitor time
    } else {
      statusElement.textContent = 'Status: Error';
      statusElement.style.color = 'red';
    }
  })
  .catch(error => {
    console.error('Error starting monitor:', error);
    statusElement.textContent = 'Status: Error';
    statusElement.style.color = 'red';
  });
});