#*
#* FUNCTIONS V.7
#*
#
# 20260415
#

# normalize DateTime
function Get-NormalizedDateTime {
	param (
  	    [string]$InString
    )
	$OutString = ''
	If ([string]::IsNullOrEmpty($InString)) {
		$OutString = ''
	} Else {
		$OutString = [DateTime]$InString
	} 
	return $OutString
}

# begin tracking
# 20260417
function Begin-Tracking {
	param (
  	    [string]$TrackingTable,
				[string]$Script,
				[string]$Table
    )
	$q = "INSERT INTO $TrackingTable 
	      ([script],[tablename],[startupdate]) 
				OUTPUT INSERTED.ID
				VALUES 
				(@script,@tablename,CURRENT_TIMESTAMP)"
  $Comm = New-Object $sqlCommandType
  $Comm.Connection = $Connection
  $Comm.CommandText = $q
  [void]$Comm.Parameters.AddWithValue("@script", $Script)
  [void]$Comm.Parameters.AddWithValue("@tablename", $Table)
  $NewId = $Comm.ExecuteScalar()
  $Comm.Dispose()
	return $NewId
}

# end tracking
# 20260417
function End-Tracking {
	param (
  	    [string]$TrackingTable,
  	    [int]$recordid,
				[string]$Table
    )
  $r = Invoke-Sqlcmd -Query "SELECT COUNT(*) AS rec FROM $Table" -ServerInstance $SQLserver -Database $SQLdatabase -Username $SQLu -Password $SQLp -TrustServerCertificate
	$records = $r.rec
  $r = Invoke-Sqlcmd -Query "UPDATE $TrackingTable SET records=$records, endupdate=CURRENT_TIMESTAMP WHERE id=$recordid" -ServerInstance $SQLserver -Database $SQLdatabase -Username $SQLu -Password $SQLp -TrustServerCertificate
}

