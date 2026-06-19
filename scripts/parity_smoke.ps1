param(
    [string]$BaseUrl = "http://127.0.0.1",
    [int[]]$Ports = @(8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8011, 8012, 8013, 8014)
)

$ErrorActionPreference = "Stop"
$results = @()

foreach ($port in $Ports) {
    $url = "${BaseUrl}:$port/health"
    try {
        $response = Invoke-RestMethod -Method Get -Uri $url -TimeoutSec 5
        $results += [pscustomobject]@{
            Port = $port
            Url = $url
            Status = $response.status
            Service = $response.service
        }
    } catch {
        $results += [pscustomobject]@{
            Port = $port
            Url = $url
            Status = "error"
            Service = $_.Exception.Message
        }
    }
}

$results | Format-Table -AutoSize

if ($results.Status -contains "error") {
    exit 1
}
