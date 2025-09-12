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
$uri= $CudaAPItokenurl
# cred
$secpasswd = ConvertTo-SecureString $CudaAPIsecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($CudaAPIclient, $secpasswd)
$post = @{ grant_type = 'client_credentials';
           scope = "scope=forensics:account:read ess:account:read";
         }
$resraw = Invoke-WebRequest -Uri $uri -Method POST -Body $post -Credential $credential
$res = $resraw.Content | ConvertFrom-Json
$token = $res.access_token

$res
$token

$Headers = @{'Authorization' = "Bearer $token"}


<#

# delete old records
	Invoke-Sqlcmd -Query "TRUNCATE TABLE $SQLtableuser" -ServerInstance $SQLserver -Database $SQLdatabase -Username $SQLu -Password $SQLp -TrustServerCertificate
	#enumerate tenants





# Get API key
$Connectionr = New-Object System.Data.SQLClient.SQLConnection
$Connectionr.ConnectionString = "server='$SQLserver';database='$SQLdatabase';user id='$SQLu';password='$SQLp';"
$Connectionr.Open()
$Commandr = New-Object System.Data.SQLClient.SQLCommand
$Commandr.Connection = $Connectionr
$Commandr.CommandText = "SELECT * FROM $SQLtablezsetup"
$reader = $Commandr.ExecuteReader()
$reader.Read()
$S1APIkey = $reader['apikey']

$Headers = @{
    'Authorization' = 'ApiToken ' + $S1APIkey
}

write-host "Cleaning old data"
$Command = New-Object System.Data.SQLClient.SQLCommand
$Command.Connection = $Connection
if ($DBGagent) {
    $Command.CommandText = "TRUNCATE TABLE $SQLtableagent"
    $Command.ExecuteNonQuery() | Out-Null
    $Command.CommandText = "TRUNCATE TABLE $SQLtableNet"
    $Command.ExecuteNonQuery() | Out-Null
    $Command.CommandText = "TRUNCATE TABLE $SQLtableapplication"
    $Command.ExecuteNonQuery() | Out-Null
}
if ($DBGnetdiscovery) {
    $Command.CommandText = "TRUNCATE TABLE $SQLtablenetscan"
    $Command.ExecuteNonQuery() | Out-Null
}
if ($DBGappriskdet) {
    $Command.CommandText = "TRUNCATE TABLE $SQLtableappriskdet"
    $Command.ExecuteNonQuery() | Out-Null
}
if ($DBGrogue) {
    $Command.CommandText = "TRUNCATE TABLE $SQLtablerogue"
    $Command.ExecuteNonQuery() | Out-Null
}

#
# Network Discovery 
#
if ($DBGnetdiscovery) {
    $loopflag = $true
    $cursor = '' #at first loop cursor is empty

    do {
        $uri = $S1APIbaseurl + "ranger/table-view?limit=666" + $cursor
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

#
# Agent
#
if ($DBGagent) {
    $loopflag = $true
    $cursor = '' #at first loop cursor is empty

    do {
        $uri = $S1APIbaseurl + "agents?limit=1000" + $cursor
        Write-Host "Invoke-WebRequest -Uri $uri  -Headers $Headers"
        $ResAgents = Invoke-WebRequest -Uri $uri  -Headers $Headers
        if ('200' -eq $ResAgents.StatusCode) {
            $Agents = $ResAgents.Content | ConvertFrom-Json
            #main table
            foreach ($agent in $Agents.data) {
                $qry = "INSERT INTO $SQLtableagent
                ([timestamp],[activeThreats],[agentVersion],[allowRemoteShell],[appsVulnerabilityStatus],[computerName],[coreCount],[cpuCount],[cpuId],[createdAt],[detectionState],
                [domain],[encryptedApplications],[externalId],[externalIp],[firewallEnabled],[firstFullModeTime],[fullDiskScanLastUpdatedAt],[groupId],[groupIp],[groupName],[id],
                [inRemoteShellSession],[infected],[installerType],[isActive],[isDecommissioned],[isPendingUninstall],[isUninstalled],[isUpToDate],[lastActiveDate],[lastIpToMgmt],
                [lastLoggedInUserName],[lastSuccessfulScanDate],[machineType],[mitigationMode],[mitigationModeSuspicious],[modelName],[networkQuarantineEnabled],[networkStatus],
                [operationalState],[osArch],[osName],[osRevision],[osStartTime],[osType],[osUsername],[proxyStates],[rangerStatus],[rangerVersion],[registeredAt],[scanAbortedAt],
                [scanFinishedAt],[scanStartedAt],[scanStatus],[serialNumber],[showAlertIcon],[siteId],[siteName],[storageName],[storageType],[threatRebootRequired],[totalMemory],
                [updatedAt],[uuid],[cloudProviders],[missingPermissions],[computerDistinguishedName],[computerMemberOf],[lastUserDistinguishedName],[lastUserMemberOf],[mail],
                [userPrincipalName])
                VALUES
                (CURRENT_TIMESTAMP,@activeThreats,@agentVersion,@allowRemoteShell,@appsVulnerabilityStatus,@computerName,@coreCount,@cpuCount,@cpuId,@createdAt,@detectionState,
                @domain,@encryptedApplications,@externalId,@externalIp,@firewallEnabled,@firstFullModeTime,@fullDiskScanLastUpdatedAt,@groupId,@groupIp,@groupName,@id,
                @inRemoteShellSession,@infected,@installerType,@isActive,@isDecommissioned,@isPendingUninstall,@isUninstalled,@isUpToDate,@lastActiveDate,@lastIpToMgmt,
                @lastLoggedInUserName,@lastSuccessfulScanDate,@machineType,@mitigationMode,@mitigationModeSuspicious,@modelName,@networkQuarantineEnabled,@networkStatus,
                @operationalState,@osArch,@osName,@osRevision,@osStartTime,@osType,@osUsername,@proxyStates,@rangerStatus,@rangerVersion,@registeredAt,@scanAbortedAt,
                @scanFinishedAt,@scanStartedAt,@scanStatus,@serialNumber,@showAlertIcon,@siteId,@siteName,@storageName,@storageType,@threatRebootRequired,@totalMemory,
                @updatedAt,@uuid,@cloudProviders,@missingPermissions,@computerDistinguishedName,@computerMemberOf,@lastUserDistinguishedName,@lastUserMemberOf,@mail,
                @userPrincipalName)"
                $Command = New-Object System.Data.SQLClient.SQLCommand
                $Command.Connection = $Connection
                $Command.CommandText = $qry
                $command.Parameters.Add("@activeThreats",             $(If ([string]::IsNullOrEmpty($agent.activeThreats) ) {''} Else {$agent.activeThreats} ))                                       | Out-Null
                $command.Parameters.Add("@agentVersion",              $(If ([string]::IsNullOrEmpty($agent.agentVersion) ) {''} Else {$agent.agentVersion} ))                                         | Out-Null
                $command.Parameters.Add("@allowRemoteShell",          $(If ('true' -eq $agent.agentVersion ) {1} Else {0} ))                                                                          | Out-Null
                $command.Parameters.Add("@appsVulnerabilityStatus",   $(If ([string]::IsNullOrEmpty($agent.appsVulnerabilityStatus) ) {''} Else {$agent.appsVulnerabilityStatus} ))                   | Out-Null
                $command.Parameters.Add("@computerName",              $(If ([string]::IsNullOrEmpty($agent.computerName) ) {''} Else {$agent.computerName} ))                                         | Out-Null
                $command.Parameters.Add("@coreCount",                 $(If ([string]::IsNullOrEmpty($agent.coreCount) ) {0} Else {$agent.coreCount} ))                                                | Out-Null
                $command.Parameters.Add("@cpuCount",                  $(If ([string]::IsNullOrEmpty($agent.cpuCount) ) {0} Else {$agent.cpuCount} ))                                                  | Out-Null
                $command.Parameters.Add("@cpuId",                     $(If ([string]::IsNullOrEmpty($agent.cpuId) ) {''} Else {$agent.cpuId} ))                                                       | Out-Null
                $command.Parameters.Add("@createdAt",                 $(If ([string]::IsNullOrEmpty($agent.createdAt) ) {''} Else {[DateTime]$agent.createdAt} ))                                     | Out-Null 
                $command.Parameters.Add("@detectionState",            $(If ([string]::IsNullOrEmpty($agent.detectionState) ) {''} Else {$agent.detectionState} ))                                     | Out-Null 
                $command.Parameters.Add("@domain",                    $(If ([string]::IsNullOrEmpty($agent.domain) ) {''} Else {$agent.domain} ))                                                     | Out-Null
                $command.Parameters.Add("@encryptedApplications",     $(If ('true' -eq $agent.encryptedApplications ) {1} Else {0} ))                                                                 | Out-Null
                $command.Parameters.Add("@externalId",                $(If ([string]::IsNullOrEmpty($agent.externalId) ) {''} Else {$agent.externalId} ))                                             | Out-Null
                $command.Parameters.Add("@externalIp",                $(If ([string]::IsNullOrEmpty($agent.externalIp) ) {''} Else {$agent.externalIp} ))                                             | Out-Null
                $command.Parameters.Add("@firewallEnabled",           $(If ('true' -eq $agent.firewallEnabled ) {1} Else {0} ))                                                                       | Out-Null
                $command.Parameters.Add("@firstFullModeTime",         $(If ([string]::IsNullOrEmpty($agent.firstFullModeTime) ) {''} Else {[DateTime]$agent.firstFullModeTime} ))                     | Out-Null 
                $command.Parameters.Add("@fullDiskScanLastUpdatedAt", $(If ([string]::IsNullOrEmpty($agent.fullDiskScanLastUpdatedAt) ) {''} Else {[DateTime]$agent.fullDiskScanLastUpdatedAt} ))     | Out-Null 
                $command.Parameters.Add("@groupId",                   $(If ([string]::IsNullOrEmpty($agent.groupId) ) {''} Else {$agent.groupId} ))                                                   | Out-Null
                $command.Parameters.Add("@groupIp",                   $(If ([string]::IsNullOrEmpty($agent.groupIp) ) {''} Else {$agent.groupIp} ))                                                   | Out-Null
                $command.Parameters.Add("@groupName",                 $(If ([string]::IsNullOrEmpty($agent.groupName) ) {''} Else {$agent.groupName} ))                                               | Out-Null
                $command.Parameters.Add("@id",                        $(If ([string]::IsNullOrEmpty($agent.id) ) {''} Else {$agent.id} ))                                                             | Out-Null
                $command.Parameters.Add("@inRemoteShellSession",      $(If ('true' -eq $agent.inRemoteShellSession ) {1} Else {0} ))                                                                  | Out-Null
                $command.Parameters.Add("@infected",                  $(If ('true' -eq $agent.infected ) {1} Else {0} ))                                                                              | Out-Null
                $command.Parameters.Add("@installerType",             $(If ([string]::IsNullOrEmpty($agent.installerType) ) {''} Else {$agent.installerType} ))                                       | Out-Null
                $command.Parameters.Add("@isActive",                  $(If ('true' -eq $agent.isActive ) {1} Else {0} ))                                                                              | Out-Null
                $command.Parameters.Add("@isDecommissioned",          $(If ('true' -eq $agent.isDecommissioned ) {1} Else {0} ))                                                                      | Out-Null
                $command.Parameters.Add("@isPendingUninstall",        $(If ('true' -eq $agent.isPendingUninstall ) {1} Else {0} ))                                                                    | Out-Null
                $command.Parameters.Add("@isUninstalled",             $(If ('true' -eq $agent.isUninstalled ) {1} Else {0} ))                                                                         | Out-Null
                $command.Parameters.Add("@isUpToDate",                $(If ('true' -eq $agent.isUpToDate ) {1} Else {0} ))                                                                            | Out-Null
                $command.Parameters.Add("@lastActiveDate",            $(If ([string]::IsNullOrEmpty($agent.lastActiveDate) ) {''} Else {[DateTime]$agent.lastActiveDate} ))                           | Out-Null 
                $command.Parameters.Add("@lastIpToMgmt",              $(If ([string]::IsNullOrEmpty($agent.lastIpToMgmt) ) {''} Else {$agent.lastIpToMgmt} ))                                         | Out-Null
                $command.Parameters.Add("@lastLoggedInUserName",      $(If ([string]::IsNullOrEmpty($agent.lastLoggedInUserName) ) {''} Else {$agent.lastLoggedInUserName} ))                         | Out-Null
                $command.Parameters.Add("@lastSuccessfulScanDate",    $(If ([string]::IsNullOrEmpty($agent.lastSuccessfulScanDate) ) {''} Else {[DateTime]$agent.lastSuccessfulScanDate} ))           | Out-Null 
                $command.Parameters.Add("@machineType",               $(If ([string]::IsNullOrEmpty($agent.machineType) ) {''} Else {$agent.machineType} ))                                           | Out-Null
                $command.Parameters.Add("@mitigationMode",            $(If ([string]::IsNullOrEmpty($agent.mitigationMode) ) {''} Else {$agent.mitigationMode} ))                                     | Out-Null
                $command.Parameters.Add("@mitigationModeSuspicious",  $(If ([string]::IsNullOrEmpty($agent.mitigationModeSuspicious) ) {''} Else {$agent.mitigationModeSuspicious} ))                 | Out-Null
                $command.Parameters.Add("@modelName",                 $(If ([string]::IsNullOrEmpty($agent.modelName) ) {''} Else {$agent.modelName} ))                                               | Out-Null
                $command.Parameters.Add("@networkQuarantineEnabled",  $(If ('true' -eq $agent.networkQuarantineEnabled ) {1} Else {0} ))                                                              | Out-Null
                $command.Parameters.Add("@networkStatus",             $(If ([string]::IsNullOrEmpty($agent.networkStatus) ) {''} Else {$agent.networkStatus} ))                                       | Out-Null
                $command.Parameters.Add("@operationalState",          $(If ([string]::IsNullOrEmpty($agent.operationalState) ) {''} Else {$agent.operationalState} ))                                 | Out-Null
                $command.Parameters.Add("@osArch",                    $(If ([string]::IsNullOrEmpty($agent.osArch) ) {''} Else {$agent.osArch} ))                                                     | Out-Null
                $command.Parameters.Add("@osName",                    $(If ([string]::IsNullOrEmpty($agent.osName) ) {''} Else {$agent.osName} ))                                                     | Out-Null
                $command.Parameters.Add("@osRevision",                $(If ([string]::IsNullOrEmpty($agent.osRevision) ) {''} Else {$agent.osRevision} ))                                             | Out-Null
                $command.Parameters.Add("@osStartTime",               $(If ([string]::IsNullOrEmpty($agent.osStartTime) ) {''} Else {[DateTime]$agent.osStartTime} ))                                 | Out-Null 
                $command.Parameters.Add("@osType",                    $(If ([string]::IsNullOrEmpty($agent.osType) ) {''} Else {$agent.osType} ))                                                     | Out-Null
                $command.Parameters.Add("@osUsername",                $(If ([string]::IsNullOrEmpty($agent.osUsername) ) {''} Else {$agent.osUsername} ))                                             | Out-Null  
                $command.Parameters.Add("@proxyStates",               $(If ([string]::IsNullOrEmpty($agent.proxyStates) ) {''} Else {$agent.proxyStates -join '|'} ))                                 | Out-Null  
                $command.Parameters.Add("@rangerStatus",              $(If ([string]::IsNullOrEmpty($agent.rangerStatus) ) {''} Else {$agent.rangerStatus} ))                                         | Out-Null
                $command.Parameters.Add("@rangerVersion",             $(If ([string]::IsNullOrEmpty($agent.rangerVersion) ) {''} Else {$agent.rangerVersion} ))                                       | Out-Null
                $command.Parameters.Add("@registeredAt",              $(If ([string]::IsNullOrEmpty($agent.registeredAt) ) {''} Else {[DateTime]$agent.registeredAt} ))                               | Out-Null 
                $command.Parameters.Add("@scanAbortedAt",             $(If ([string]::IsNullOrEmpty($agent.scanAbortedAt) ) {''} Else {[DateTime]$agent.scanAbortedAt} ))                             | Out-Null  
                $command.Parameters.Add("@scanFinishedAt",            $(If ([string]::IsNullOrEmpty($agent.scanFinishedAt) ) {''} Else {[DateTime]$agent.scanFinishedAt} ))                           | Out-Null 
                $command.Parameters.Add("@scanStartedAt",             $(If ([string]::IsNullOrEmpty($agent.scanStartedAt) ) {''} Else {[DateTime]$agent.scanStartedAt} ))                             | Out-Null 
                $command.Parameters.Add("@scanStatus",                $(If ([string]::IsNullOrEmpty($agent.scanStatus) ) {''} Else {$agent.scanStatus} ))                                             | Out-Null
                $command.Parameters.Add("@serialNumber",              $(If ([string]::IsNullOrEmpty($agent.serialNumber) ) {''} Else {$agent.serialNumber} ))                                         | Out-Null
                $command.Parameters.Add("@showAlertIcon",             $(If ('true' -eq $agent.showAlertIcon ) {1} Else {0} ))                                                                         | Out-Null
                $command.Parameters.Add("@siteId",                    $(If ([string]::IsNullOrEmpty($agent.siteId) ) {''} Else {$agent.siteId} ))                                                     | Out-Null
                $command.Parameters.Add("@siteName",                  $(If ([string]::IsNullOrEmpty($agent.siteName) ) {''} Else {$agent.siteName} ))                                                 | Out-Null
                $command.Parameters.Add("@storageName",               $(If ([string]::IsNullOrEmpty($agent.storageName) ) {''} Else {$agent.storageName} ))                                           | Out-Null 
                $command.Parameters.Add("@storageType",               $(If ([string]::IsNullOrEmpty($agent.storageType) ) {''} Else {$agent.storageType} ))                                           | Out-Null 
                $command.Parameters.Add("@threatRebootRequired",      $(If ('true' -eq $agent.threatRebootRequired ) {1} Else {0} ))                                                                  | Out-Null
                $command.Parameters.Add("@totalMemory",               $(If ([string]::IsNullOrEmpty($agent.totalMemory) ) {0} Else {$agent.totalMemory} ))                                            | Out-Null
                $command.Parameters.Add("@updatedAt",                 $(If ([string]::IsNullOrEmpty($agent.updatedAt) ) {''} Else {[DateTime]$agent.updatedAt} ))                                     | Out-Null 
                $command.Parameters.Add("@uuid",                      $(If ([string]::IsNullOrEmpty($agent.uuid) ) {''} Else {$agent.uuid} ))                                                         | Out-Null
                $command.Parameters.Add("@cloudProviders",            $(If ([string]::IsNullOrEmpty($agent.cloudProviders) ) {''} Else {$agent.cloudProviders -join '|'} ))                           | Out-Null 
                $command.Parameters.Add("@missingPermissions",        $(If ([string]::IsNullOrEmpty($agent.missingPermissions) ) {''} Else {$agent.missingPermissions -join '|'} ))                   | Out-Null 
                $command.Parameters.Add("@computerDistinguishedName", $(If ([string]::IsNullOrEmpty($agent.activeDirectory.computerDistinguishedName) ) {''} Else {$agent.activeDirectory.computerDistinguishedName} )) | Out-Null 
                $command.Parameters.Add("@computerMemberOf",          $(If ([string]::IsNullOrEmpty($agent.activeDirectory.computerMemberOf) ) {''} Else {$agent.activeDirectory.computerMemberOf -join '|'} ))         | Out-Null 
                $command.Parameters.Add("@lastUserDistinguishedName", $(If ([string]::IsNullOrEmpty($agent.activeDirectory.lastUserDistinguishedName) ) {''} Else {$agent.activeDirectory.lastUserDistinguishedName} )) | Out-Null 
                $command.Parameters.Add("@lastUserMemberOf",          $(If ([string]::IsNullOrEmpty($agent.activeDirectory.lastUserMemberOf) ) {''} Else {$agent.activeDirectory.lastUserMemberOf -join '|'} ))         | Out-Null 
                $command.Parameters.Add("@mail",                      $(If ([string]::IsNullOrEmpty($agent.mail) ) {''} Else {$agent.mail} ))                                                         | Out-Null 
                $command.Parameters.Add("@userPrincipalName",         $(If ([string]::IsNullOrEmpty($agent.userPrincipalName) ) {''} Else {$agent.userPrincipalName} ))                               | Out-Null 
                $Command.ExecuteNonQuery() | Out-Null
                $command.Parameters.Clear()

                #Networking
                foreach ($if in $agent.networkInterfaces) {
                    $qrynet = "INSERT INTO $SQLtableNet
                    ([timestamp],[id],[gatewayIp],[gatewayMacAddress],[idnet],[inet],[inet6],[name],[physical])
                    VALUES
                    (CURRENT_TIMESTAMP,@id,@gatewayIp,@gatewayMacAddress,@idnet,@inet,@inet6,@name,@physical)"
                    $Command.CommandText = $qrynet
                    $command.Parameters.Add("@id",                $agent.id)                                                                                  | Out-Null
                    $command.Parameters.Add("@gatewayIp",         $(If ([string]::IsNullOrEmpty($if.gatewayIp) ) {''} Else {$if.gatewayIp} ))                 | Out-Null 
                    $command.Parameters.Add("@gatewayMacAddress", $(If ([string]::IsNullOrEmpty($if.gatewayMacAddress) ) {''} Else {$if.gatewayMacAddress} )) | Out-Null 
                    $command.Parameters.Add("@idnet",             $(If ([string]::IsNullOrEmpty($if.id) ) {''} Else {$if.id} ))                               | Out-Null 
                    $command.Parameters.Add("@inet",              $(If ([string]::IsNullOrEmpty($if.inet) ) {''} Else {$if.inet -join '|'} ))                 | Out-Null 
                    $command.Parameters.Add("@inet6",             $(If ([string]::IsNullOrEmpty($if.inet6) ) {''} Else {$if.inet6 -join '|'} ))               | Out-Null 
                    $command.Parameters.Add("@name",              $(If ([string]::IsNullOrEmpty($if.name) ) {''} Else {$if.name} ))                           | Out-Null 
                    $command.Parameters.Add("@physical",          $(If ([string]::IsNullOrEmpty($if.physical) ) {''} Else {$if.physical} ))                   | Out-Null 
                    $Command.ExecuteNonQuery() | Out-Null
                    $command.Parameters.Clear()
                }

                #application
                $id = $agent.id
                $uria = $S1APIbaseurl + "agents/applications?ids=" + $id
                $ResApp = Invoke-WebRequest -Uri $uria  -Headers $Headers
                $Apps = $ResApp.Content | ConvertFrom-Json
                foreach ($app in $Apps.data) {
                    $qryapp = "INSERT INTO $SQLtableapplication
                    ([timestamp],[id],[publisher],[installedDate],[name],[size],[version])
                    VALUES
                    (CURRENT_TIMESTAMP,@id,@publisher,@installedDate,@name,@size,@version)"
                    $Command.CommandText = $qryapp
                    $command.Parameters.Add("@id",            $id)                                                                                  | Out-Null
                    $command.Parameters.Add("@publisher",     $(If ([string]::IsNullOrEmpty($app.publisher) ) {''} Else {$app.publisher} ))                 | Out-Null 
                    $command.Parameters.Add("@installedDate", $(If ([string]::IsNullOrEmpty($app.installedDate) ) {''} Else {[DateTime]$app.installedDate} )) | Out-Null 
                    $command.Parameters.Add("@name",          $(If ([string]::IsNullOrEmpty($app.name) ) {''} Else {$app.name} ))                               | Out-Null 
                    $command.Parameters.Add("@size",          $(If ([string]::IsNullOrEmpty($app.size) ) {''} Else {$app.size} ))                 | Out-Null 
                    $command.Parameters.Add("@version",       $(If ([string]::IsNullOrEmpty($app.version) ) {''} Else {$app.version} ))               | Out-Null 
                    $Command.ExecuteNonQuery() | Out-Null
                    $command.Parameters.Clear()
                }

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


#
# Application Risk detail 
#
if ($DBGappriskdet) {
    $loopflag = $true
    $cursor = '' #at first loop cursor is empty
    do {
        $uri = $S1APIbaseurl + "installed-applications?riskLevels=high,medium,low,critical&limit=666" + $cursor
        Write-Host "Invoke-WebRequest -Uri $uri  -Headers $Headers"
        $resapp = Invoke-WebRequest -Uri $uri  -Headers $Headers
        if ('200' -eq $resapp.StatusCode) {
            $app = $resapp.Content | ConvertFrom-Json
            #main table
            foreach ($a in $app.data) {
                $qry = "INSERT INTO $SQLtableappriskdet
                ([timestamp],[agentComputerName],[agentDomain],[agentId],[agentInfected],[agentIsActive],[agentIsDecommissioned],[agentMachineType],
                 [agentNetworkStatus],[agentOperationalState],[agentOsType],[agentUuid],[agentVersion],[createdAt],[id],[installedAt],[name],[osType],[publisher],
                 [riskLevel],[signed],[size],[type],[updatedAt],[version])
                VALUES
                (CURRENT_TIMESTAMP,@agentComputerName,@agentDomain,@agentId,@agentInfected,@agentIsActive,@agentIsDecommissioned,@agentMachineType,
                 @agentNetworkStatus,@agentOperationalState,@agentOsType,@agentUuid,@agentVersion,@createdAt,@id,@installedAt,@name,@osType,@publisher,
                 @riskLevel,@signed,@size,@type,@updatedAt,@version)"
                $Command = New-Object System.Data.SQLClient.SQLCommand
                $Command.Connection = $Connection
                $Command.CommandText = $qry
                $command.Parameters.Add("@agentComputerName",     $(If ([string]::IsNullOrEmpty($a.agentComputerName) ) {''} Else {$a.agentComputerName} )) | Out-Null
                $command.Parameters.Add("@agentDomain",           $(If ([string]::IsNullOrEmpty($a.agentDomain) ) {''} Else {$a.agentDomain} )) | Out-Null
                $command.Parameters.Add("@agentId",               $(If ([string]::IsNullOrEmpty($a.agentId) ) {''} Else {$a.agentId} )) | Out-Null
                $command.Parameters.Add("@agentInfected",         $(If ('true' -eq $a.agentInfected ) {1} Else {0} )) | Out-Null
                $command.Parameters.Add("@agentIsActive",         $(If ('true' -eq $a.agentIsActive ) {1} Else {0} )) | Out-Null
                $command.Parameters.Add("@agentIsDecommissioned", $(If ('true' -eq $a.agentIsDecommissioned ) {1} Else {0} )) | Out-Null
                $command.Parameters.Add("@agentMachineType",      $(If ([string]::IsNullOrEmpty($a.agentMachineType) ) {''} Else {$a.agentMachineType} )) | Out-Null
                $command.Parameters.Add("@agentNetworkStatus",    $(If ([string]::IsNullOrEmpty($a.agentNetworkStatus) ) {''} Else {$a.agentNetworkStatus} )) | Out-Null
                $command.Parameters.Add("@agentOperationalState", $(If ([string]::IsNullOrEmpty($a.agentOperationalState) ) {''} Else {$a.agentOperationalState} )) | Out-Null
                $command.Parameters.Add("@agentOsType",           $(If ([string]::IsNullOrEmpty($a.agentOsType) ) {''} Else {$a.agentOsType} )) | Out-Null
                $command.Parameters.Add("@agentUuid",             $(If ([string]::IsNullOrEmpty($a.agentUuid) ) {''} Else {$a.agentUuid} )) | Out-Null
                $command.Parameters.Add("@agentVersion",          $(If ([string]::IsNullOrEmpty($a.agentVersion) ) {''} Else {$a.agentVersion} )) | Out-Null
                $command.Parameters.Add("@createdAt",             $(If ([string]::IsNullOrEmpty($a.createdAt) ) {''} Else {[DateTime]$a.createdAt} )) | Out-Null
                $command.Parameters.Add("@id",                    $(If ([string]::IsNullOrEmpty($a.id) ) {''} Else {$a.id} )) | Out-Null
                $command.Parameters.Add("@installedAt",           $(If ([string]::IsNullOrEmpty($a.installedAt) ) {''} Else {[DateTime]$a.installedAt} )) | Out-Null
                $command.Parameters.Add("@name",                  $(If ([string]::IsNullOrEmpty($a.name) ) {''} Else {$a.name} )) | Out-Null
                $command.Parameters.Add("@osType",                $(If ([string]::IsNullOrEmpty($a.osType) ) {''} Else {$a.osType} )) | Out-Null
                $command.Parameters.Add("@publisher",             $(If ([string]::IsNullOrEmpty($a.publisher) ) {''} Else {$a.publisher} )) | Out-Null
                $command.Parameters.Add("@riskLevel",             $(If ([string]::IsNullOrEmpty($a.riskLevel) ) {''} Else {$a.riskLevel} )) | Out-Null
                $command.Parameters.Add("@signed",                $(If ('true' -eq $a.signed ) {1} Else {0} )) | Out-Null
                $command.Parameters.Add("@size",                  $(If ([string]::IsNullOrEmpty($a.size) ) {0} Else {$a.size} )) | Out-Null
                $command.Parameters.Add("@type",                  $(If ([string]::IsNullOrEmpty($a.type) ) {''} Else {$a.type} )) | Out-Null
                $command.Parameters.Add("@updatedAt",             $(If ([string]::IsNullOrEmpty($a.updatedAt) ) {''} Else {[DateTime]$a.updatedAt} )) | Out-Null
                $command.Parameters.Add("@version",               $(If ([string]::IsNullOrEmpty($a.version) ) {''} Else {$a.version} )) | Out-Null
                $Command.ExecuteNonQuery() | Out-Null
                $command.Parameters.Clear()
            }
            # more pages to load?
            If ([string]::IsNullOrEmpty($app.pagination.nextCursor)) {
                $loopflag = $false
            } else {
                $cursor = "&cursor=" + $app.pagination.nextCursor
            }
        } else {
            write-host "Error getting agents"
            $resapp.StatusDescription
        }
    } while ($loopflag)
}

#
# Rogue 
#
if ($DBGrogue) {
    $loopflag = $true
    $cursor = '' #at first loop cursor is empty
    do {
        $uri = $S1APIbaseurl + "rogues/table-view?limit=666" + $cursor
        Write-Host "Invoke-WebRequest -Uri $uri  -Headers $Headers"
        $resapp = Invoke-WebRequest -Uri $uri  -Headers $Headers
        if ('200' -eq $resapp.StatusCode) {
            $app = $resapp.Content | ConvertFrom-Json
            #main table
            foreach ($a in $app.data) {
                $qry = "INSERT INTO $SQLtablerogue
                ([timestamp],[deviceFunction],[deviceType],[externalIp],[firstSeen],[hostnames],[id],[lastSeen],[localIp],[macAddress],[manufacturer],
                 [osName],[osType],[osVersion])
                VALUES
                (CURRENT_TIMESTAMP,@deviceFunction,@deviceType,@externalIp,@firstSeen,@hostnames,@id,@lastSeen,@localIp,@macAddress,@manufacturer,
                 @osName,@osType,@osVersion)"
                $Command = New-Object System.Data.SQLClient.SQLCommand
                $Command.Connection = $Connection
                $Command.CommandText = $qry
                $command.Parameters.Add("@deviceFunction", $(If ([string]::IsNullOrEmpty($a.deviceFunction) ) {''} Else {$a.deviceFunction} )) | Out-Null
                $command.Parameters.Add("@deviceType",     $(If ([string]::IsNullOrEmpty($a.deviceType) ) {''} Else {$a.deviceType} )) | Out-Null
                $command.Parameters.Add("@externalIp",     $(If ([string]::IsNullOrEmpty($a.externalIp) ) {''} Else {$a.externalIp} )) | Out-Null
                $command.Parameters.Add("@firstSeen",      $(If ([string]::IsNullOrEmpty($a.firstSeen) ) {''} Else {[DateTime]$a.firstSeen} )) | Out-Null
                $command.Parameters.Add("@hostnames",      $(If ([string]::IsNullOrEmpty($a.hostnames) ) {''} Else {$a.hostnames -join '|'} )) | Out-Null
                $command.Parameters.Add("@id",             $(If ([string]::IsNullOrEmpty($a.id) ) {''} Else {$a.id} )) | Out-Null
                $command.Parameters.Add("@lastSeen",       $(If ([string]::IsNullOrEmpty($a.lastSeen) ) {''} Else {[DateTime]$a.lastSeen} )) | Out-Null
                $command.Parameters.Add("@localIp",        $(If ([string]::IsNullOrEmpty($a.localIp) ) {''} Else {$a.localIp} )) | Out-Null
                $command.Parameters.Add("@macAddress",     $(If ([string]::IsNullOrEmpty($a.macAddress) ) {''} Else {$a.macAddress} )) | Out-Null
                $command.Parameters.Add("@manufacturer",   $(If ([string]::IsNullOrEmpty($a.manufacturer) ) {''} Else {$a.manufacturer} )) | Out-Null
                $command.Parameters.Add("@osName",         $(If ([string]::IsNullOrEmpty($a.osName) ) {''} Else {$a.osName} )) | Out-Null
                $command.Parameters.Add("@osType",         $(If ([string]::IsNullOrEmpty($a.osType) ) {''} Else {$a.osType} )) | Out-Null
                $command.Parameters.Add("@osVersion",      $(If ([string]::IsNullOrEmpty($a.osVersion) ) {''} Else {$a.osVersion} )) | Out-Null
                $Command.ExecuteNonQuery() | Out-Null
                $command.Parameters.Clear()
            }
            # more pages to load?
            If ([string]::IsNullOrEmpty($app.pagination.nextCursor)) {
                $loopflag = $false
            } else {
                $cursor = "&cursor=" + $app.pagination.nextCursor
            }
        } else {
            write-host "Error getting agents"
            $resapp.StatusDescription
        }
    } while ($loopflag)
}

#>