Param (
    [string]$evtx,
    [switch]$local
)

if ($local) {
    $evtx = 'C:\Windows\System32\winevt\Logs\Security.evtx'
}
elseif (!$evtx) {
    $evtx = (Get-ChildItem -Path $pwd.Path -Filter "*_Security.evtx" -File | Select-Object -First 1).FullName
}

if (!$evtx) {
    Write-Host "[!] No event log file specified. Please use the -evtx parameter to specify a file or use the -local parameter to load the local Security event log." -ForegroundColor Yellow
    return
}

$time=Get-Date -Format h:mm:ss
$evtx=(Get-Item $evtx).fullname
$outfile=(Get-Item $evtx).BaseName+"_login"+".csv"

$logsize=[int]((Get-Item $evtx).length/1MB)

write-host [+] $time Load $evtx "("Size: $logsize MB")" ... -ForegroundColor Green

$LogonType = @{
    [uint32]2 = 'Interactive'
    [uint32]3 = 'ipc'
    [uint32]4 = 'Batch'
    [uint32]5 = 'Service'
    [uint32]7 = 'Unlock'
    [uint32]8 = 'NetworkCleartext'
    [uint32]9 = 'NewCredentials'
    [uint32]10 = 'RDP'
    [uint32]11 = 'CachedInteractive'
}

$EventID = @{
    [uint32]4624 = 'successfully'
    [uint32]4625 = 'failed'
}

function OneEventToDict {
    Param (
        $event
    )
    $ret = @{
        "SystemTime" = $event.System.TimeCreated.SystemTime | Convert-DateTimeFormat -OutputFormat 'yyyy"/"MM"/"dd HH:mm:ss';
        "EventID" = $EventID[[uint32]$event.System.EventID]
    }
    $data=$event.EventData.Data
    for ($i=0; $i -lt $data.Count; $i++){
        if ($data[$i].name -eq 'LogonType') {
            $ret.Add($data[$i].name, $LogonType[[uint32]$data[$i].'#text'])
        } else {
            $ret.Add($data[$i].name, $data[$i].'#text')
        }
    }
    return $ret
}

filter Convert-DateTimeFormat
{
  Param($OutputFormat='yyyy-MM-dd HH:mm:ss fff')
  try {
    ([DateTime]$_).ToString($OutputFormat)
  } catch {}
}

[xml]$xmldoc=WEVTUtil qe  $evtx /q:"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4625)] and (EventData[Data[@Name='LogonType']='3'] or EventData[Data[@Name='LogonType']='10'])]" /e:root /f:Xml  /lf

$xmlEvent=$xmldoc.root.Event

$time=Get-Date -Format h:mm:ss
write-host [+] $time Extract XML ... -ForegroundColor Green
[System.Collections.ArrayList]$results = New-Object System.Collections.ArrayList($null)
for ($i=0; $i -lt $xmlEvent.Count; $i++){
    $event = $xmlEvent[$i]
    $datas = OneEventToDict $event

    $results.Add((New-Object PSObject -Property $datas))|out-null
}



$time=Get-Date -Format h:mm:ss
write-host [+] $time Dump into CSV: $outfile ... -ForegroundColor Green
$results | Select-Object SystemTime,IpAddress,TargetDomainName,TargetUserName,EventID,LogonType | Export-Csv $outfile -NoTypeInformation -UseCulture  -Encoding Default -Force
