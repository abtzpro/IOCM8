# Define the list of known IOCs
$knownIOCs = @(
    "1.2.3.4",
    "example.com",
    "somefile.exe",
    "malware.dll"
)

# Iterate through each known IOC
foreach ($ioc in $knownIOCs) {
    # Check if the IOC is present on the system
    if (Test-Path $ioc) {
        # If the IOC is a file, print its properties
        if (Get-Item $ioc -ErrorAction SilentlyContinue -ErrorVariable err) {
            Write-Host "File Found: $($err.TargetObject.FullName)"
            Write-Host "Size: $($err.TargetObject.Length) bytes"
            Write-Host "Last Modified: $($err.TargetObject.LastWriteTime)"
        }
        # If the IOC is a network connection, print the connection details
        elseif (Get-NetTCPConnection -RemoteAddress $ioc -ErrorAction SilentlyContinue -ErrorVariable err) {
            foreach ($conn in $err.TargetObject) {
                Write-Host "Network Connection Found: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
                Write-Host "State: $($conn.State)"
                Write-Host "Process ID: $($conn.OwningProcess)"
            }
        }
        # If the IOC is a DNS query, print the query details
        elseif (Get-DnsClientCache | where { $_.EntryName -eq $ioc -or $_.HostName -eq $ioc -or $_.RecordData -eq $ioc } -ErrorAction SilentlyContinue -ErrorVariable err) {
            foreach ($query in $err.TargetObject) {
                Write-Host "DNS Query Found: $($query.EntryName)"
                Write-Host "Type: $($query.Type)"
                Write-Host "Data: $($query.RecordData)"
            }
        }
    }
}
