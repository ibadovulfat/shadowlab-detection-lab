$env:SHADOWLAB_REQUIRE_AUTH = "true"
$env:SHADOWLAB_POLICY_PROFILE = "lab"
$env:SHADOWLAB_ENABLE_DANGEROUS_ACTIONS = "true"
$env:SHADOWLAB_API_KEYS_SHA256 = "viewer:464f8b8bd93e5c6441114ec9b69eb309ed583500ac1ee3f1e63e46d2ee9dfada,analyst:c5853663c2321613ad1b166e9f30bd5204d2fea87acba2b0fd750e54909915f3,admin:3b79d32f5098ac32d07b191cd9dc4a32fdf143e531c5db303981d31b9c118e91"

Start-Process python -ArgumentList '-m','uvicorn','api.main:app','--host','127.0.0.1','--port','8000' -WorkingDirectory 'C:\Users\ulfat\Documents\shadowlab-detection-lab'
Start-Sleep -Seconds 3
Start-Process python -ArgumentList 'desktop/main.py' -WorkingDirectory 'C:\Users\ulfat\Documents\shadowlab-detection-lab'
