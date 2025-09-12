#
# Barracuda <lrosa@akdmc.com>
# Main file
#

$ScriptVersion = "1.00"

Write-Host "Reading configuration." 
try {
    . (".\barracudaconfig.ps1")
}
catch {
    Write-Host "Error reading setup file." 
	EXIT
}

Write-Host "Connecting to SQL"
# writer connection (agents)
$Connection = New-Object System.Data.SQLClient.SQLConnection
$Connection.ConnectionString = "server='$SQLserver';database='$SQLdatabase';user id='$SQLu';password='$SQLp';"
$Connection.Open()

# get the access token 
function Get-BarracudaToken {
    $uri= $CudaAPItokenurl
    $pair = "$($CudaAPIclient):$($CudaAPIsecret)"
    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
    $basicAuthValue = "Basic $encodedCreds"
    $Headers = @{ Authorization = $basicAuthValue }
    $post = @{ grant_type = 'client_credentials';
            scope = "forensics:account:read ess:account:read";
            }
    $resraw = Invoke-WebRequest -Uri $uri -Method POST -Body $post -Headers $Headers
    $res = $resraw.Content | ConvertFrom-Json
    return $res.access_token
}


# delete old records
write-host "Cleaning old data"
Invoke-Sqlcmd -Query "TRUNCATE TABLE $SQLtabledomain" -ServerInstance $SQLserver -Database $SQLdatabase -Username $SQLu -Password $SQLp -TrustServerCertificate

$token = Get-BarracudaToken
$Headers = @{'Authorization' = "Bearer $token"}

$uri = $CudaAPIbaseurl + 'beta/accounts/ess'
$ResRaw = Invoke-WebRequest -Uri $uri  -Headers $Headers
$res = $ResRaw.Content | ConvertFrom-Json
$res


<#
#
# Domains 
#
if ($DBGdomain) {
    $loopflag = $true
    $cursor = '' #at first loop cursor is empty
    do {
        $uri = $CudaAPIbaseurl + "beta/accounts/{account_id}/ess/domains"" + $cursor
        Write-Host "Invoke-WebRequest -Uri $uri  -Headers $Headers"
        $ResAgents = Invoke-WebRequest -Uri $uri  -Headers $Headers
        if ('200' -eq $ResAgents.StatusCode) {
            $Agents = $ResAgents.Content | ConvertFrom-Json
            #main table
            foreach ($agent in $Agents.data) {
                $qry = "INSERT INTO $SQLtablenetscan
                ([timestamp],[agentId],[deviceFunction],[deviceReview],[deviceReviewLog],[deviceType],[discoveryMethods],[domain],[externalIp],[firstSeen],[gatewayIpAddress],
                [gatewayMacAddress],[hasIdentity],[hasUserLabel],[hostnames],[id],[ipAddresses],[lastSeen],[localIp],[macAddress],[managedState],[manufacturer],[networkName],
                [networks],[osName],[osType],[osVersion],[siteName],[subnetAddress],[tcpPorts],[udpPorts])
                VALUES
                (CURRENT_TIMESTAMP,@agentId,@deviceFunction,@deviceReview,@deviceReviewLog,@deviceType,@discoveryMethods,@domain,@externalIp,@firstSeen,@gatewayIpAddress,
                @gatewayMacAddress,@hasIdentity,@hasUserLabel,@hostnames,@id,@ipAddresses,@lastSeen,@localIp,@macAddress,@managedState,@manufacturer,@networkName,
                @networks,@osName,@osType,@osVersion,@siteName,@subnetAddress,@tcpPorts,@udpPorts)"
                $Command = New-Object System.Data.SQLClient.SQLCommand
                $Command.Connection = $Connection
                $Command.CommandText = $qry
                $command.Parameters.Add("@agentId",           $(If ([string]::IsNullOrEmpty($agent.agentId) ) {''} Else {$agent.agentId} ))                             | Out-Null
                $command.Parameters.Add("@deviceFunction",    $(If ([string]::IsNullOrEmpty($agent.deviceFunction) ) {''} Else {$agent.deviceFunction} ))               | Out-Null
                $command.Parameters.Add("@deviceReview",      $(If ([string]::IsNullOrEmpty($agent.deviceReview) ) {''} Else {$agent.deviceReview} ))                   | Out-Null
                $command.Parameters.Add("@deviceReviewLog",   $(If ([string]::IsNullOrEmpty($agent.deviceReviewLog) ) {''} Else {$agent.deviceReviewLog -join '|'} ))   | Out-Null
                $command.Parameters.Add("@deviceType",        $(If ([string]::IsNullOrEmpty($agent.deviceType) ) {''} Else {$agent.deviceType} ))                       | Out-Null
                $command.Parameters.Add("@discoveryMethods",  $(If ([string]::IsNullOrEmpty($agent.discoveryMethods) ) {''} Else {$agent.discoveryMethods -join '|'} )) | Out-Null
                $command.Parameters.Add("@domain",            $(If ([string]::IsNullOrEmpty($agent.domain) ) {''} Else {$agent.domain} ))                               | Out-Null
                $command.Parameters.Add("@externalIp",        $(If ([string]::IsNullOrEmpty($agent.externalIp) ) {''} Else {$agent.externalIp} ))                       | Out-Null
                $command.Parameters.Add("@firstSeen",         $(If ([string]::IsNullOrEmpty($agent.firstSeen) ) {''} Else {[DateTime]$agent.firstSeen} ))               | Out-Null 
                $command.Parameters.Add("@gatewayIpAddress",  $(If ([string]::IsNullOrEmpty($agent.gatewayIpAddress) ) {''} Else {$agent.gatewayIpAddress} ))           | Out-Null
                $command.Parameters.Add("@gatewayMacAddress", $(If ([string]::IsNullOrEmpty($agent.gatewayMacAddress) ) {''} Else {$agent.gatewayMacAddress} ))         | Out-Null
                $command.Parameters.Add("@hasIdentity",       $(If ('true' -eq $agent.hasIdentity ) {1} Else {0} ))                                                     | Out-Null
                $command.Parameters.Add("@hasUserLabel",      $(If ('true' -eq $agent.hasUserLabel ) {1} Else {0} ))                                                    | Out-Null
                $command.Parameters.Add("@hostnames",         $(If ([string]::IsNullOrEmpty($agent.hostnames) ) {''} Else {$agent.hostnames -join '|'} ))               | Out-Null
                $command.Parameters.Add("@id",                $(If ([string]::IsNullOrEmpty($agent.id) ) {''} Else {$agent.id} ))                                       | Out-Null
                $command.Parameters.Add("@ipAddresses",       $(If ([string]::IsNullOrEmpty($agent.ipAddresses) ) {''} Else {$agent.ipAddresses -join '|'} ))           | Out-Null
                $command.Parameters.Add("@lastSeen",          $(If ([string]::IsNullOrEmpty($agent.lastSeen) ) {''} Else {[DateTime]$agent.lastSeen} ))                 | Out-Null 
                $command.Parameters.Add("@localIp",           $(If ([string]::IsNullOrEmpty($agent.localIp) ) {''} Else {$agent.localIp} ))                             | Out-Null
                $command.Parameters.Add("@macAddress",        $(If ([string]::IsNullOrEmpty($agent.macAddress) ) {''} Else {$agent.macAddress} ))                       | Out-Null
                $command.Parameters.Add("@managedState",      $(If ([string]::IsNullOrEmpty($agent.managedState) ) {''} Else {$agent.managedState} ))                   | Out-Null
                $command.Parameters.Add("@manufacturer",      $(If ([string]::IsNullOrEmpty($agent.manufacturer) ) {''} Else {$agent.manufacturer} ))                   | Out-Null
                $command.Parameters.Add("@networkName",       $(If ([string]::IsNullOrEmpty($agent.networkName) ) {''} Else {$agent.networkName} ))                     | Out-Null
                $command.Parameters.Add("@networks",          $(If ([string]::IsNullOrEmpty($agent.networks) ) {''} Else {$agent.networks -join '|'} ))                 | Out-Null
                $command.Parameters.Add("@osName",            $(If ([string]::IsNullOrEmpty($agent.osName) ) {''} Else {$agent.osName} ))                               | Out-Null
                $command.Parameters.Add("@osType",            $(If ([string]::IsNullOrEmpty($agent.osType) ) {''} Else {$agent.osType} ))                               | Out-Null
                $command.Parameters.Add("@osVersion",         $(If ([string]::IsNullOrEmpty($agent.osVersion) ) {''} Else {$agent.osVersion} ))                         | Out-Null  
                $command.Parameters.Add("@siteName",          $(If ([string]::IsNullOrEmpty($agent.siteName) ) {''} Else {$agent.siteName} ))                           | Out-Null
                $command.Parameters.Add("@subnetAddress",     $(If ([string]::IsNullOrEmpty($agent.subnetAddress) ) {''} Else {$agent.subnetAddress} ))                 | Out-Null 
                $command.Parameters.Add("@tcpPorts",          $(If ([string]::IsNullOrEmpty($agent.tcpPorts) ) {''} Else {$agent.tcpPorts -join '|'} ))                 | Out-Null 
                $command.Parameters.Add("@udpPorts",          $(If ([string]::IsNullOrEmpty($agent.udpPorts) ) {''} Else {$agent.udpPorts -join '|'} ))                 | Out-Null 
                $Command.ExecuteNonQuery() | Out-Null
                $command.Parameters.Clear()
            }

            # more pages to load?
            If ([string]::IsNullOrEmpty($Agents.pagination.nextCursor)) {
                $loopflag = $false
            } else {
                $cursor = "&cursor=" + $Agents.pagination.nextCursor
            }
        } else {
            write-host "Error getting agents"
            $ResAgents.StatusDescription
        }
    } while ($loopflag)
}

#>