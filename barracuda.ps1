#
# Barracuda <lrosa@akdmc.com>
# Main file
#
# https://campus.barracuda.com/doc/167976859/
# https://campus.barracuda.com/product/emailgatewaydefense/doc/167976859/api-overview
#

$ScriptVersion = "1.20"


if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "This script requires PowerShell version 7"
    EXIT
}

Write-Host "Reading configuration."
try {
    . "$PSScriptRoot\barracudaconfig.ps1" 
} catch {
    Write-Host "Error reading config file."
    exit
}

# load Microsoft.Data.SqlClient if available
try {
    Add-Type -AssemblyName "Microsoft.Data.SqlClient" -ErrorAction Stop
    $sqlConnectionType = "Microsoft.Data.SqlClient.SqlConnection"
    $sqlCommandType    = "Microsoft.Data.SqlClient.SqlCommand"
} catch {
    Write-Warning "Microsoft.Data.SqlClient not found. Falling back to System.Data.SqlClient."
    $sqlConnectionType = "System.Data.SqlClient.SqlConnection"
    $sqlCommandType    = "System.Data.SqlClient.SqlCommand"
}

# writer connection (agents)
$connectionString = "Server=$SQLserver;Database=$SQLdatabase;User ID=$SQLu;Password=$SQLp;TrustServerCertificate=True;"
$Connection = New-Object $sqlConnectionType $connectionString
$Connection.Open()

# Barracuda Access token
function Get-BarracudaToken {
    $uri = $CudaAPItokenurl
    $pair = "$($CudaAPIclient):$($CudaAPIsecret)"
    $encodedCreds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $headers = @{
        Authorization = "Basic $encodedCreds"
    }
    $body = @{
        grant_type = "client_credentials"
        scope      = "forensics:account:read ess:account:read"
    }
    $res = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers
    return $res.access_token
}

# Barracuda account ID 
function Get-BarracudaAccountID {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )
    $uri = $CudaAPIbaseurl + 'beta/accounts/ess'
    Write-host "DEBUG: $uri"
    $res = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get
    return $res.results[0].accountId
}

$token = Get-BarracudaToken
$CommonHeaders = @{
    Authorization = "Bearer $token"
}
$accountID = Get-BarracudaAccountID -Headers $CommonHeaders


#
# Domains
#
if ($DBGdomain) {
    Write-Host -NoNewline "Domains: "
    # delete old records
    Write-Host -NoNewline "cleanup "
    Invoke-Sqlcmd `
        -Query "TRUNCATE TABLE $SQLtabledomain" `
        -ServerInstance $SQLserver `
        -Database $SQLdatabase `
        -Username $SQLu `
        -Password $SQLp `
        -TrustServerCertificate
    $loopflag = $true
    $uriparam = "?size=50"
    do {
        $uri = "$CudaAPIbaseurl`beta/accounts/$accountID/ess/domains$uriparam"
        Write-Host -NoNewline " #"
        try {
            $res = Invoke-RestMethod -Uri $uri -Headers $CommonHeaders -Method Get
            $thispage = [int]$res.pageNum
            $pagetot  = [int]$res.pagesTotal
            foreach ($rec in $res.results) {
                $qry = "INSERT INTO $SQLtabledomain
                        ([timestamp],[domainId],[domainName],[status],[type])
                        VALUES 
                        (CURRENT_TIMESTAMP,@domainId,@domainName,@status,@type)"
                $Command = New-Object $sqlCommandType
                $Command.Connection = $Connection
                $Command.CommandText = $qry
                [void]$Command.Parameters.AddWithValue("@domainId",   $(if ([string]::IsNullOrWhiteSpace($rec.domainId))   { [DBNull]::Value } else { [int]$rec.domainId }))
                [void]$Command.Parameters.AddWithValue("@domainName", $(if ([string]::IsNullOrWhiteSpace($rec.domainName)) { [DBNull]::Value } else { [string]$rec.domainName }))
                [void]$Command.Parameters.AddWithValue("@status",     $(if ([string]::IsNullOrWhiteSpace($rec.status))     { [DBNull]::Value } else { [string]$rec.status }))
                [void]$Command.Parameters.AddWithValue("@type",       $(if ([string]::IsNullOrWhiteSpace($rec.type))       { [DBNull]::Value } else { [string]$rec.type }))
                [void]$Command.ExecuteNonQuery()
                $Command.Dispose()
                Write-Host -NoNewline "+"
            }
            $thispage++
            if ($thispage -ge $pagetot) {
                $loopflag = $false
            }
            else {
                $uriparam = "?size=50&page=$thispage"
            }
        } catch {
            Write-Host "Error getting domains"
            Write-Host $_.Exception.Message
            $loopflag = $false
        }
    }
    while ($loopflag)

    Write-Host " done."
}


#
# Statistics
#
if ($DBGstats) {
    Write-Host -NoNewline "Email stats: "
    # enumerate domains
    $dtable = Invoke-Sqlcmd `
        -Query "SELECT * FROM $SQLtabledomain" `
        -ServerInstance $SQLserver `
        -Database $SQLdatabase `
        -Username $SQLu `
        -Password $SQLp `
        -TrustServerCertificate
    foreach ($domrecord in $dtable) {
        $domainName = $domrecord.domainName
        $uri = "$CudaAPIbaseurl`beta/accounts/$accountID/ess/domains/$domainName/statistics?type=email&period=daily&count=30"
        Write-Host -NoNewline " # "
        try {
            $res = Invoke-RestMethod -Uri $uri -Headers $CommonHeaders -Method Get
            Write-Host -NoNewline $domainName
            # inbound
            $direction = "inbound"
            Write-Host -NoNewline " inbound "
            foreach ($property in $res.inbound.PSObject.Properties) {
                $type = $property.Name
                Write-Host -NoNewline "$type"
                foreach ($prop in $res.inbound.$type.PSObject.Properties) {
                    $datetime = $prop.Name
                    $count = [int]$prop.Value
                    $qry = "INSERT INTO $SQLtablestats
                            ([timestamp],[domainName],[count],[datetime],[type],[direction])
                            VALUES
                            (CURRENT_TIMESTAMP,@domainName,@count,@datetime,@type,@direction)"
                    $Command = New-Object $sqlCommandType
                    $Command.Connection = $Connection
                    $Command.CommandText = $qry
                    [void]$Command.Parameters.AddWithValue("@domainName", [string]$domainName)
                    [void]$Command.Parameters.AddWithValue("@count",      $count)
                    [void]$Command.Parameters.AddWithValue("@datetime",   [string]$datetime)
                    [void]$Command.Parameters.AddWithValue("@type",       [string]$type)
                    [void]$Command.Parameters.AddWithValue("@direction",  [string]$direction)
                    [void]$Command.ExecuteNonQuery()
                    $Command.Dispose()
                    Write-Host -NoNewline "+"
                }
            }
            # outbound
            $direction = "outbound"
            Write-Host -NoNewline " outbound "
            foreach ($property in $res.outbound.PSObject.Properties) {
                $type = $property.Name
                Write-Host -NoNewline "$type"
                foreach ($prop in $res.outbound.$type.PSObject.Properties) {
                    $datetime = $prop.Name
                    $count = [int]$prop.Value
                    $qry = "INSERT INTO $SQLtablestats
                            ([timestamp],[domainName],[count],[datetime],[type],[direction])
                            VALUES
                            (CURRENT_TIMESTAMP,@domainName,@count,@datetime,@type,@direction)"
                    $Command = New-Object $sqlCommandType
                    $Command.Connection = $Connection
                    $Command.CommandText = $qry
                    [void]$Command.Parameters.AddWithValue("@domainName", [string]$domainName)
                    [void]$Command.Parameters.AddWithValue("@count",      $count)
                    [void]$Command.Parameters.AddWithValue("@datetime",   [string]$datetime)
                    [void]$Command.Parameters.AddWithValue("@type",       [string]$type)
                    [void]$Command.Parameters.AddWithValue("@direction",  [string]$direction)
                    [void]$Command.ExecuteNonQuery()
                    $Command.Dispose()
                    Write-Host -NoNewline "+"
                }
            }
        } catch {
            Write-Host "Error processing $domainName"
            Write-Host $_.Exception.Message
        }
    }
    Write-Host " done."
}

# Clean up
if ($Connection.State -eq 'Open') {
    $Connection.Close()
}
$Connection.Dispose()
