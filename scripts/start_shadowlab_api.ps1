param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8000
)

$env:SHADOWLAB_HOST = $HostAddress
$env:SHADOWLAB_PORT = [string]$Port

python app.py
