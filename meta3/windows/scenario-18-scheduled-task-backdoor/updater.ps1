# Operator beacon - writes a heartbeat file every run so incident response has
# something to pivot on. A real implant would call out to C2 here.
$stamp = Get-Date -Format o
Add-Content -Path C:\Users\Public\Updater\heartbeat.log -Value "$stamp beacon"
