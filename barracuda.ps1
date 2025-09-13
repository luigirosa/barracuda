#
# Barracuda <lrosa@akdmc.com>
# Main file
#
# https://campus.barracuda.com/doc/167976859/
# https://campus.barracuda.com/product/emailgatewaydefense/doc/167976859/api-overview
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

$token = Get-BarracudaToken
$CommonHeaders = @{'Authorization' = "Bearer $token"}
$accountID = Get-BarracudaAccountID

#
# Domains 
#
if ($DBGdomain) {
    write-host -NoNewline "Domains: "
    # delete old records
    write-host -NoNewline "cleaning old data "
    Invoke-Sqlcmd -Query "TRUNCATE TABLE $SQLtabledomain" -ServerInstance $SQLserver -Database $SQLdatabase -Username $SQLu -Password $SQLp -TrustServerCertificate
    $loopflag = $true
    $uriparam = '?size=50' 
    $headers = $CommonHeaders
    do {
        $uri = $CudaAPIbaseurl + "beta/accounts/$accountID/ess/domains$uriparam"
        Write-Host -NoNewline "#"
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
                Write-Host -NoNewline "."
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
    Write-Host "done"
}


#
# Statistics 
#
if ($DBGstats) {
    write-host -NoNewline "Email stats: "
    # delete old records
    write-host -NoNewline "cleaning old data "
    Invoke-Sqlcmd -Query "TRUNCATE TABLE $SQLtablestats" -ServerInstance $SQLserver -Database $SQLdatabase -Username $SQLu -Password $SQLp -TrustServerCertificate
    #enumerate domains
	$dtable = Invoke-Sqlcmd -Query "SELECT domainName FROM $SQLtabledomain" -ServerInstance $SQLserver -Database $SQLdatabase -Username $SQLu -Password $SQLp -TrustServerCertificate
	foreach ($domainName in $dtable) {
        write-host -NoNewline $domainid
        $uri = $CudaAPIbaseurl + "beta/accounts/$accountID/ess/domains/$domainName/statistics"
        Write-Host -NoNewline "# "
        $ResRaw = Invoke-WebRequest -Uri $uri  -Headers $CommonHeaders
        if ('200' -eq $ResRaw.StatusCode) {
            $res = $resRaw | ConvertFrom-Json
            # c'e' un girone dell'Inferno dedicato a quelli che mettono i dati nei tag JSON
            # inbound
            $ direction = 'inbound'
            Write-Host -NoNewline "inbound "
            foreach ($property in $res.inbound.PSObject.Properties) { 
                $type = $property.Name
                Write-Host -NoNewline "$type"
                foreach ($prop in $res.inbound.$type.PSObject.Properties) { 
                    # che cazzo di bordello per un JSON scritto male
                    $datetime = $prop.Name
                    $count = $prop.value
                    Write-Host -NoNewline "."
                    $qry = "INSERT INTO $SQLtablestats
                    ([timestamp],[domainName],[count],[datetime],[type],[direction])
                    VALUES
                    (CURRENT_TIMESTAMP,@domainName,@count,@datetime,@type,@direction)"
                    $Command = New-Object System.Data.SQLClient.SQLCommand
                    $Command.Connection = $Connection
                    $Command.CommandText = $qry
                    $command.Parameters.Add("@domainName", $domainName) | Out-Null
                    $command.Parameters.Add("@count",      [int]$count) | Out-Null
                    $command.Parameters.Add("@datetime",   $datetime) | Out-Null
                    $command.Parameters.Add("@type",       $type) | Out-Null
                    $command.Parameters.Add("@direction",  $direction) | Out-Null
                    $Command.ExecuteNonQuery() | Out-Null
                    $command.Parameters.Clear()
                }
            }
        }
    } 
    Write-Host "done"
}
