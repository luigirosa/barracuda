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

# get the account ID 
function Get-BarracudaAccountID {
    $uri = $CudaAPIbaseurl + 'beta/accounts/ess'
    $ResRaw = Invoke-WebRequest -Uri $uri  -Headers $CommonHeaders
    $res = $ResRaw.Content | ConvertFrom-Json
    return $res.results[0].accountId
}


# delete old records
write-host "Cleaning old data"
Invoke-Sqlcmd -Query "TRUNCATE TABLE $SQLtabledomain" -ServerInstance $SQLserver -Database $SQLdatabase -Username $SQLu -Password $SQLp -TrustServerCertificate

$token = Get-BarracudaToken
$CommonHeaders = @{'Authorization' = "Bearer $token"}
$accountID = Get-BarracudaAccountID

#
# Domains 
#
if ($DBGdomain) {
    $loopflag = $true
    $uriparam = '?size=50' 
    $headers = $CommonHeaders
    do {
        $uri = $CudaAPIbaseurl + "beta/accounts/$accountID/ess/domains$uriparam"
        Write-Host "Invoke-WebRequest -Uri $uri  -Headers $headers"
        $ResRaw = Invoke-WebRequest -Uri $uri  -Headers $headers
        if ('200' -eq $ResRaw.StatusCode) {
            $res = $resRaw | ConvertFrom-Json
            $thispage = $res.pageNum
            $pagetot = $res.pagesTotal
            foreach ($rec in $res.results) {
                $qry = "INSERT INTO $SQLtabledomain
                ([timestamp],[domainId],[domainName],[status],[type])
                VALUES
                (CURRENT_TIMESTAMP,@domainId,@domainName,@status,@type)"
                $Command = New-Object System.Data.SQLClient.SQLCommand
                $Command.Connection = $Connection
                $Command.CommandText = $qry
                $command.Parameters.Add("@domainId",   $(If ([string]::IsNullOrEmpty($rec.domainId) ) {''} Else {[int]$rec.domainId} )) | Out-Null
                $command.Parameters.Add("@domainName", $(If ([string]::IsNullOrEmpty($rec.domainName) ) {''} Else {$rec.domainName} ))  | Out-Null
                $command.Parameters.Add("@status",     $(If ([string]::IsNullOrEmpty($rec.status) ) {''} Else {$rec.status} ))          | Out-Null
                $command.Parameters.Add("@type",       $(If ([string]::IsNullOrEmpty($rec.domainName) ) {''} Else {$rec.type} ))        | Out-Null
                $Command.ExecuteNonQuery() | Out-Null
                $command.Parameters.Clear()
            }

            # more pages to load?
            $thispage++
            If ($thispage -eq $pagetot) {
                $loopflag = $false
            } else {
                $uriparam = "?size=50&page=$thispage"
            }
        } else {
            write-host "Error getting domains"
            $ResRaw.StatusDescription
        }
    } while ($loopflag)
}
