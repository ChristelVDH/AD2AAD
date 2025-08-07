. "$PSScriptRoot\Classes\AD2AADClasses.ps1"
$script:GraphConnection = $null
$script:GraphHeader = $null
$script:GraphRoot = "https://graph.microsoft.com/v1.0"
$script:TokenExpiry = $null
$script:AADDevices = $null
$script:AADUsers = $null
$script:AADGroups = $null
$script:ADGroups = $null
[System.IO.DirectoryInfo]$script:LogsDirectory = $null
[System.Collections.Generic.List[string]]$script:Output = @()
$script:Counters = @{"Warning" = 0; "Error" = 0 }
[int]$script:MaxGroupNameLength = 64
[datetime]$script:StartTime = Get-Date

Function Assert-InteractiveShell {
	[OutputType([Bool])]
	param()
	# Test each Arg for match of abbreviated '-NonInteractive' command
	return ([Environment]::UserInteractive -and (-not ([Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' })))) -as [bool]
}

Function Select-GraphRoot {
	param(
		[Parameter()]
		[ValidateSet('Production', 'Beta')]
		[string]$GraphEnvironment = 'Production'
	)
	switch ($GraphEnvironment) {
		'Production' { $script:GraphRoot = "https://graph.microsoft.com/v1.0" }
		'Beta' { $script:GraphRoot = "https://graph.microsoft.com/beta" }
		default { Write-LogEntry -Value "Current Graph Root is: ($script:GraphRoot)" }
	}
	Write-LogEntry -Value "Set Graph Root to: ($script:GraphRoot)"
}

Function New-GraphToken {
	<#
.SYNOPSIS
connect to the Graph environment and return the connection as an object
containing a token and it's lifecycle (expiry date/time)
.LINK
https://tech.nicolonsky.ch/explaining-microsoft-graph-access-token-acquisition/
#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory)][Validatepattern('(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})')]$TenantID,
		[Parameter(Mandatory)][string]$AppRegistrationID,
		[Parameter(Mandatory)][string]$AppSecret,
		[Parameter()][Microsoft.PowerShell.Commands.X509StoreLocation]$CertificatePath,
		[Parameter()][switch]$InitializeMGConnection,
		[Parameter(DontShow, ValueFromRemainingArguments)]$Superfluous
	)

	process {
		Write-Verbose -Message "Trying to get a REST token to be used for a connection to MS Graph..."
		try {
			$script:GraphConnection = Invoke-RestMethod @PostSplat
			$script:TokenExpiry = (Get-Date).AddSeconds($script:GraphConnection.expires_in)
			if ($InitializeMGConnection.IsPresent) {
				try { $script:GraphHeader = Get-MGConnection -GraphConnection $script:GraphConnection }
				catch { Write-Error -Message "ERROR: Failed to initialize Microsoft Graph connection" }
			}
		}
		catch { Write-Error -Message "ERROR: $($_.Exception)" -ErrorAction Stop } #triggers trap{} block
	}

	begin {
		Write-Verbose -Message "Ignoring superfluous params: $($Superfluous -join ' ')"
		#Get access without a user:
		#https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
		#https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands?view=graph-powershell-1.0
		#https://lazyadmin.nl/powershell/connect-mggraph/
		$AuthUri = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token"
		if (-not [string]::IsNullOrEmpty($CertificatePath)) {
			#use certificate for app authentication when run in production environment
			#https://learn.microsoft.com/en-us/powershell/microsoftgraph/app-only?tabs=azure-portal&view=graph-powershell-1.0
			#https://adamtheautomator.com/powershell-graph-api/#Acquire_an_Access_Token_Using_a_Certificate
			try {
				$Certificate = Get-Item $CertificatePath
				$CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash()) -replace '\+', '-' -replace '/', '_' -replace '='
			}
			catch { Write-Error -Message "Error processing certificate: $($CertificatePath), exiting script..."; exit }
			# replace/strip to match web encoding of base64
			$JWTHeader = @{
				alg = "RS256"
				typ = "JWT"
				x5t = $CertificateBase64Hash
			}
			# Create JWT timestamp for expiration
			$StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
			$Now = (Get-Date).ToUniversalTime()
			$NotBefore = [math]::Round((New-TimeSpan -Start $StartDate -End $Now).TotalSeconds, 0)
			$JWTExpiration = $NotBefore + 120 # add 2 minutes
			# Create JWT payload
			$JWTPayLoad = @{
				aud = $AuthUri # allowed endpoint to use this JWT
				exp = $JWTExpiration # Expiration timestamp
				iss = $AppRegistrationID # Issuer = your application
				jti = [guid]::NewGuid() # JWT ID: random guid
				nbf = $NotBefore # Not to be used before
				sub = $AppRegistrationID # JWT Subject
			}
			# Convert header and payload to base64
			$EncodedHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json)))
			$EncodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json)))
			# Join header and Payload with "." to create a valid (unsigned) JWT
			$JWT = [System.Text.Encoding]::UTF8.GetBytes($EncodedHeader + "." + $EncodedPayload)
			# Get the private key object of your certificate
			$PrivateKey = $Certificate.PrivateKey
			# Define RSA signature and hashing algorithm
			$RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
			$HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
			# Create a signature of the JWT
			$Signature = [Convert]::ToBase64String($PrivateKey.SignData($JWT, $HashAlgorithm, $RSAPadding)) -replace '\+', '-' -replace '/', '_' -replace '='
			# Join the signature to the JWT with "."
			$JWT = $JWT + "." + $Signature
			# Create a hash with body parameters
			$Body = @{
				Grant_Type            = "client_credentials"
				Client_Id             = $AppRegistrationID
				Client_Assertion      = $JWT
				Client_Assertion_Type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
				Scope                 = "https://graph.microsoft.com/.default"
			}
			# Use the self-generated JWT as Authorization in Headers parameter
			# Splat the parameters for Invoke-Restmethod for cleaner code
			$script:PostSplat = @{
				ContentType = 'application/x-www-form-urlencoded'
				Method      = 'POST'
				Body        = $Body
				Uri         = $AuthUri
				Headers     = @{ Authorization = "Bearer $JWT" }
			}
		}
		else {
			$body = @{
				Grant_Type    = "client_credentials"
				Client_Id     = $AppRegistrationID
				Client_Secret = $AppSecret
				Scope         = "https://graph.microsoft.com/.default"
			}
			$script:PostSplat = @{
				Uri    = $AuthUri
				Method = 'POST'
				Body   = $Body
			}
		}
	}
	end { return $script:GraphConnection }
}

Function Get-MGConnection {
	param(
		[Parameter(Mandatory, ValueFromPipeline)]$GraphConnection,
		[Parameter()][ValidateNotNullOrEmpty()]
		[string[]]$RequiredScopes = @("Group.ReadWrite.All", "GroupMember.ReadWrite.All", "Device.Read.All", "DeviceManagementManagedDevices.Read.All")
	)
	$script:GraphHeader = @{ 'Authorization' = $script:GraphConnection.access_token }
	#https://security.stackexchange.com/questions/108662/why-is-bearer-required-before-the-token-in-authorization-header-in-a-http-re
	#$script:GraphHeader = @{ 'Authorization' = "Bearer $script:GraphConnection.access_token" }
	#https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/2123 --> authentication token must be secure starting from version 2.0.0.0
	$AuthModule = Get-InstalledModule -Name Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
	if (([version]$AuthModule.Version).Major -lt 2) { $MgConnectParams = @{AccessToken = $script:GraphConnection.access_token } }
	else {
		$MgConnectParams = @{
			AccessToken = $($script:GraphConnection.access_token | ConvertTo-SecureString -AsPlainText -Force)
			NoWelcome   = $true
		}
	}
	try { Connect-MgGraph @MgConnectParams }
	catch { Write-Error -Message $_.Exception -ErrorAction Stop	}
	#minimum required scopes for this script to function properly, more is no problem :)
	$MgContext = Get-MgContext
	#[Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.Scopes
	$MissingScopes = Compare-Object -ReferenceObject $RequiredScopes -DifferenceObject $MgContext.Scopes -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
	if ($MissingScopes) { Write-LogEntry -Value "Exiting script due to missing required scopes on App Registration <$($MgContext.AppName)>:$($nl)$($MissingScopes)" -Severity 4	}
	return $script:GraphHeader
}

Function Initialize-GraphUri {
	[cmdletbinding(SupportsShouldProcess)]
	param(
		[Parameter(Mandatory)][ValidateSet('users', 'devices', 'groups', 'devicemanagement/managedDevices')][string]$Resource,
		[Parameter()][string]$ResourceAddition,
		[Parameter()][ValidateNotNullOrEmpty()][string]$Filter,
		[Parameter()][ValidateNotNullOrEmpty()][Alias('Property')][string]$Select,
		[Parameter()][ValidateNotNullOrEmpty()][Alias('ExpandProperty')][string]$Expand,
		[Parameter()][ValidateNotNullOrEmpty()][string]$OrderBy,
		[Parameter()][switch]$Count,
		[Parameter()][Alias('All')][switch]$Paging,
		[Parameter()][switch]$Consistency
	)
	$GraphUri = $script:GraphRoot + "/$($Resource)"
	if (-not [string]::IsNullOrEmpty($ResourceAddition)) { $GraphUri += "/$($ResourceAddition)"	}
	#https://learn.microsoft.com/en-us/graph/aad-advanced-queries
	if ($Filter) { $GraphUri += "?`$filter=$($Filter)" }
	if ($Select) { $GraphUri += "&`$select=$($Select)" }
	if ($Expand) { $GraphUri += "&`$expand=$($Expand)" }
	if ($OrderBy -and -not $Filter) { $GraphUri += "&`$orderby=$($OrderBy)" }
	if ($Count.IsPresent) { $GraphUri += "&`$count=true" }
	$Header = $script:GraphHeader.Clone()
	if ($Consistency.IsPresent) { $Header.Add('ConsistencyLevel', 'Eventual') }
	if ($PSCmdlet.ShouldProcess("Getting $($Script:GraphRoot)/$($Resource)", $GraphUri, "GraphData Retrieval")) {
		Write-LogEntry -Value "Retrieving Graph data using Uri: $($GraphUri) with ConsistencyLevel set to Eventual ($($Consistency.IsPresent))" -Severity 0
		$OutObj = Get-GraphQueryResults -uri $GraphUri -GraphHeader $Header -Paging:$Paging.IsPresent
	}
	else {
		#return Invoke-RestMethod params as hashtable
		$OutObj = @{
			Uri     = $GraphUri
			Headers = $Header
			Method  = 'GET'
		}
	}
	return $OutObj
}

Function Expand-RESTObject {
	param(
		[Parameter(Mandatory, ValueFromPipeline, HelpMessage = 'Must contain a property (default = AdditionalProperties) to expand ')]$InputObject,
		[string]$ExpandProperty = 'AdditionalProperties'
	)
	try {
		$InputObject.$ExpandProperty.GetEnumerator() | ForEach-Object { Add-Member -InputObject $InputObject -MemberType NoteProperty -Name $_.Key -Value $_.value -Force }
		#$InputObject.$ExpandProperty.Clear()
	}
	catch { Write-Warning -Message "No $($ExpandProperty) found in InputObject! Returning as is..." }
	return $InputObject
}

Function Assert-GroupName {
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[alias('Name', 'SamAccountName')][ValidateNotNullOrEmpty()][string]$GroupName,
		[ValidateNotNullOrEmpty()][string]$Prefix = 'INT-',
		[switch]$Enforce
	)
	#https://learn.microsoft.com/en-us/office/troubleshoot/office-suite-issues/username-contains-special-character
	#https://climbtheladder.com/10-azure-ad-group-naming-best-practices/
	#https://learn.microsoft.com/en-us/azure/devops/organizations/settings/naming-restrictions?view=azure-devops
	#https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules
	$Warnings = @()
	switch ($GroupName) {
		{ $_ -cmatch '\P{IsBasicLatin}' } { $Warnings += "non-ASCII characters" }
		{ $_ -match ('\s') } { $Warnings += "spaces" }
		{ $_ -match ('[_]') } { $Warnings += "underscores" }
		{ $_ -match ('[#]') } { $Warnings += "hashes" }
		{ $_ -match ('[@]') } { $Warnings += "@ signs" }
		{ $_ -match ('[&]') } { $Warnings += "ampersands" }
		{ $_ -match ("[']") } { $Warnings += "apostrophes" }
		{ $_ -match "^($($Prefix))" } { $Warnings += "redundant $($Prefix) prefix" }
		{ $_ -match '(-[U|D])$' } { $Warnings += "redundant -U/-D suffix" }
		{ $_.Length -gt $script:MaxGroupNameLength } { $Warnings += "length > 64 characters" }
		default { $Asserted = $true }
	}
	if ($Warnings.Count) {
		[string]$Message = "Naming violations in AD group name <{0}>: {1}" -f $GroupName, $($Warnings -join ', ')
		if ($Enforce.IsPresent) { $Asserted = $false; $Message = "Skipping groupsync due to " + $Message; $Severity = 3 }
		else { $Asserted = $true; $Message = "Found " + $Message; $Severity = 2 }
		Write-LogEntry -Value $Message -Severity $Severity
	}
	else { Write-LogEntry -Value "Group name <$($GroupName)> is compliant with current naming conventions" -Severity 0 }
	return $Asserted
}

Function Resolve-AzureGroup {
	[OutputType([System.Management.Automation.PSCustomObject])]
	[CmdletBinding(DefaultParameterSetName = 'Named')]
	param(
		[Parameter(Mandatory, ParameterSetName = 'Named', ValueFromPipeline)]
		[Alias('AzureGroupName', 'DisplayName')][ValidateNotNullOrEmpty()][string]$Name,
		[Parameter(Mandatory, ParameterSetName = 'Prefixed')][string]$Prefix,
		[Parameter()][switch]$RemoveDuplicates
	)
	process {
		$DuplicateAAdGroups = @($AzureGroups | Group-Object -Property DisplayName | Where-Object Count -gt 1)
		if ($DuplicateAAdGroups) {
			$SelectProps = @('Displayname', 'MemberCount', 'CreatedDateTime', 'Id')
			foreach ($Group in $DuplicateAAdGroups) {
				Write-LogEntry -Value "Found $($Group.Group.Count) duplicate Azure group(s) with DisplayName: $($Group.DisplayName)"
				foreach ($DuplicateAAdGroup in $Group.Group) {
					$MemberCount = Get-MgGroupMemberCount -GroupId $DuplicateAAdGroup.Id -ConsistencyLevel eventual
					Write-LogEntry -Value "Found $($MemberCount) members in: $($DuplicateAAdGroup.DisplayName) ($($DuplicateAAdGroup.Id))" -Severity 0
					Add-Member -InputObject $DuplicateAAdGroup -MemberType NoteProperty -Name "MemberCount" -Value $MemberCount
				}
				#select the group(s) with the least members and newest creation date for removal
				$Groups2Remove = $Group.Group | Sort-Object MemberCount, CreatedDateTime -Descending | Select-Object -Last ($Group.Group.Count - 1) -Property $SelectProps
				#return Azure group(s) that are not duplicate
				$AzureGroups = $AzureGroups.Where({ $_.Id -notin $Groups2Remove.Id })
				if ($RemoveDuplicates) {
					if (Assert-InteractiveShell) { 
						$Groups2Remove | Select-Object -Property $SelectProps | Out-GridView -Title 'Select duplicate group(s) to remove' -PassThru | ForEach-Object { 
							Remove-MgGroup -GroupId $_.Id -Confirm 
						}
					}
					else { $Groups2Remove | ForEach-Object { Remove-MgGroup -GroupId $_.Id -Confirm:$false } }
				}
			}
		}
	}
	begin {
		switch ($PSCmdlet.ParameterSetName) {
			'Named' { $Filter = "DisplayName eq '$($Name)'" }
			'Prefixed' { $Filter = "startsWith(DisplayName, '$($Prefix)')" }
		}
		#$AzureGroups = @(Get-MgGroup -ConsistencyLevel eventual -Count GroupCount -Filter $Filter -OrderBy DisplayName -All)
		$GroupParams = @{
			All         = $true
			Filter      = $Filter
			Property    = "Id,CreatedDateTime,DisplayName,Description"
			#OrderBy          = 'DisplayName'
			Count       = $true
			Consistency = $true
		}
		$AzureGroups = Initialize-GraphUri -Resource groups @GroupParams
		Write-LogEntry -Value "Retrieved $($AzureGroups.Count) groups using $($PSCmdlet.ParameterSetName) filter <$($Filter)>, checking for duplicates..." -Severity 0
	}
	end { return $AzureGroups }
}

Function Confirm-AzureGroup {
	[OutputType([System.Management.Automation.PSCustomObject])]
	param(
		[Parameter(Mandatory)][Alias('AzureGroupName')][string]$Name,
		[Parameter()][ValidateNotNullOrEmpty()][string]$ScriptDescription = 'Created by Sync Script',
		[switch]$CreateGroup
	)
	if ($script:AADGroups.Count -eq 0) { Write-Warning -Message "No AAD Groups cached, nothing to return..." }
	else {
		$AzureADGroup = @($script:AADGroups | Where-Object { $_.DisplayName -eq $Name })
		if (-not $AzureADGroup) {
			if ($CreateGroup.IsPresent) {
				Write-LogEntry -Value "Creating new Azure group: $($Name)" -Severity 0
				try {
					$body = [ordered]@{
						"description"     = $ScriptDescription
						"displayName"     = $Name
						"groupTypes"      = @()
						#"isAssignableToRole" = $true
						"mailEnabled"     = $false
						"mailNickname"    = $Name
						"securityEnabled" = $true
					} | ConvertTo-Json
					$NewGroupUri = "$($Script:GraphRoot)/groups"
					$NewGroup = Invoke-RestMethod -Method Post -Uri $NewGroupUri -Headers $script:GraphHeader -Body $body
				}
				catch { Write-LogEntry -Value $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $NewGroupUri) -Severity 3 }
				if ($NewGroup) {
					#$AzureADGroup = Get-MgGroup -Filter "DisplayName eq '$Name'" -ConsistencyLevel eventual -CountVariable AZgroup -All
					$GroupParams = @{
						All      = $true
						Filter   = "DisplayName eq '$($NewGroup.displayName)'"
						Property = "Id,CreatedDateTime,DisplayName,Description"
					}
					$AzureADGroup = Initialize-GraphUri -Resource groups @GroupParams -Consistency
				}
				if ($AzureADGroup) {
					$script:AADGroups += $AzureADGroup
					Write-LogEntry -Value "GroupMembership: Created new/empty Azure group: $($AzureADGroup.displayName)"
				}
			}
			else { Write-LogEntry -Value "No such Azure group <$($Name)> found nor created, use parameter -CreateGroup if this is unexpected!" -Severity 2 }
		}
		#make sure to return a single object, not an array of (eventual) duplicates
		$AzureADGroup = Resolve-AzureGroup -Name $Name
	}
	return $AzureADGroup
}

Function Confirm-GroupSync {
	[OutputType([System.Void])]
	param(
		$AzureGroups,
		[Microsoft.ActiveDirectory.Management.ADGroup[]]$ADGroups,
		[Parameter(HelpMessage = 'Prefix for Azure groupnames, eg: INT- (=default)')]
		[ValidateNotNullOrEmpty()]
		[Alias('GroupPrefix', 'Prefix')][string]$AzureGroupPrefix = 'INT-'
	)
	Write-LogEntry -Value "INFO: Checking $($AzureGroups.Count) Azure groups for existence in on-prem AD" -Severity 0
	ForEach ($AzureGroup in $AzureGroups) {
		try {
			#divide Azure Group name into named tokens = prefix + name + User/Device nominator
			[regex]$AzureAdditions = "(?i)(?'Prefix'^($($AzureGroupPrefix)))(?'Name'.*)(?'Suffix'(-[U|D])$)"
			$NameParts = $AzureAdditions.Match($AzureGroup.displayName).Groups
			if ($BaseName = $NameParts['Name'].Value) {
				switch ($NameParts['Suffix'].Value) {
					'-U' { $GroupType = 'UserGroup' }
					'-D' { $GroupType = 'DeviceGroup' }
					default { Write-LogEntry -Value "Suffix mismatch in Azure GroupName: $($AzureGroup.displayName)" -Severity 2 }
				}
				if (-not ($ADGroups | Where-Object { $_.Name -eq $BaseName })) {
					Write-LogEntry -Value "Trying to find matching AD group outside of current processing scope..." -Severity 0
					try { Get-ADGroup -Identity $BaseName }
					catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
						$Message = "$($GroupType) <$($AzureGroup.displayName)> only exists in Azure!"
						#remove Azure only group(s) but only if selected by human interaction!
						if (Assert-InteractiveShell) {
							Write-Warning -Message $Message
							try { Remove-MgGroup -ObjectId $AzureGroup.Id -Confirm }
							catch { Write-Error -Message $_.Exception }
						}
						else { Write-LogEntry -Value $Message -Severity 2 }
					}
					catch { Write-LogEntry -Message $_.Exception.Message -Severity 3 }
				}
			}
			else { Write-LogEntry -Value "Naming Convention mismatch in Azure GroupName: $($AzureGroup.displayName)" }
		}
		catch { Write-LogEntry -Value $_.Exception.Message -Severity 3 }
	}#foreach AzureGroup
}

Function Get-GraphQueryResults {
	[outputType([System.Management.Automation.PSCustomObject])]
	#boilerplate function for testing, not used in script
	#https://learn.microsoft.com/en-us/graph/best-practices-concept
	param(
		[Parameter(Mandatory)][uri]$uri,
		[Parameter(Mandatory)][hashtable]$GraphHeader,
		[Alias('All')][switch]$Paging
	)
	try {
		$Result = Invoke-RestMethod -Uri $uri -Method Get -Headers $GraphHeader
		$outobj = $Result.Value
		if ($Paging.IsPresent) {
			$NextPageUri = $Result."@odata.nextLink"
			##While there is a next page, query it and loop, append results
			While (-not [string]::IsNullOrEmpty($NextPageUri)) {
				$NextPageRequest = Invoke-RestMethod -Uri $NextPageURI -Method Get -Headers $GraphHeader
				$outobj += $NextPageRequest.Value
				$NextPageUri = $NextPageRequest."@odata.nextLink" #retrieve URI for next iteration
			}
		}
	}
	catch { Write-LogEntry -Value $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $uri) -Severity 3 }
	return $outobj
}

Function Resolve-GraphRequestError {
	param(
		[Parameter(Mandatory)]$Response,
		[Parameter(Mandatory)]$GraphUri
	)
	$HelpUri = "https://docs.microsoft.com/en-us/graph/errors"
	Write-Warning -Message "HTTP Status Code $($Response.StatusCode.value__) encountered, see $($HelpUri). "
	$reader = New-Object System.IO.StreamReader($Response.GetResponseStream())
	$reader.BaseStream.Position = 0
	$reader.DiscardBufferedData()
	$output = $reader.ReadToEnd()
	<# switch ($Response.StatusCode){
			204 {"No Content"}
			400 {"Bad Request"}
			401 {"Unauthorized, check your credentials"}
			404 {"Not Found"}
			408 {"Request Timeout"}
			429 {"Too Many Requests, throttling..."}
			500 {"Internal Server Error"}
			503 {"Service Unavailable"}
			504 {"Gateway Timeout"}
			default {"Unknown error: $_"}
		}   #>
	Write-Verbose -Message "Graph request <$($GraphUri.AbsoluteUri)> failed with HTTP Status $($Response.StatusCode) $($Response.StatusDescription)"
	return $output
}
function Write-LogEntry {
	param (
		[parameter(Mandatory, HelpMessage = "Value added to the log file.")][string]$Value,
		[parameter(HelpMessage = "Severity for the log entry. 1 for Informational (default), 2 for Warning and 3 for Error.")]
		[ValidateRange(0, 4)][int]$Severity = 1
	)
	if (-not [string]::IsNullOrEmpty($Value)) {
		switch ($Severity) {
			0 { $Message = $Value; Write-Verbose -Message $Value } #just add message as is to output
			1 { $Message = "INFO: $($Value)"; Write-Verbose -Message $Value }
			2 { $Message = "WARNING: $($Value)"; $script:Counters["Warning"]++; Write-Warning -Message $Value }
			3 { $Message = "ERROR: $($Value)"; $script:Counters["Error"]++; Write-Error -Message $Value }
			4 {
				$Message = "FATAL: $($Value)"
				$script:Counters["Error"]++
				[void]$script:Output.Add($Message) #add to output before triggering trap{}
				Write-Error -Message $Value -ErrorAction Stop #triggers trap{} block
			}
		}
		[void]$script:Output.Add($Message)
	}
}

Function Write-LogEntries {
	param(
		[Parameter()][ValidateSet('OUSync', 'GroupSync')][string]$SyncType,
		[parameter(HelpMessage = "Verbosity of log entry output. 0 for Everything, 1 for Informational (default), 2 for Warning and 3 for Error.")]
		[ValidateRange(0, 4)][int]$Verbosity = 0,
		[Parameter()][switch]$OutLog
	)
	[Void]$script:Output.add([WritePassTime]::ToSentence($Script:StartTime))
	Write-Warning -Message "All output will be cleared after returning or writing to log file!"
	$script:Output = $script:Output | Where-Object { -not [string]::IsNullOrEmpty($_) }
	$script:Output = @(switch ($Verbosity) {
			0 { $Script:Output }
			1 { $Script:Output.Where({ $_ -match '^(INFO|WARNING|ERROR|FATAL):' }) }
			2 { $Script:Output.Where({ $_ -match '^(WARNING|ERROR|FATAL):' }) }
			3 { $Script:Output.Where({ $_ -match '^(ERROR|FATAL):' }) }
			4 { $Script:Output.Where({ $_ -match '^(FATAL):' }) }
		})
	if ($OutLog.IsPresent) {
		$Now = Get-Date -Format "MM-dd-yyyy_HHumm-ss"
		switch ($SyncType) {
			'OUSync' { $LogFileName = "AD2AAD-OU_SyncReport_$($Now).log" }
			'GroupSync' { $LogFileName = "AD2AAD-Group_SyncReport_$($Now).log" }
			default { $LogFileName = "AD2AAD_SyncReport_$($Now).log" }
		}
		$LogFilePath = Join-Path -Path $script:LogsDirectory -ChildPath $LogFileName
		try { [System.IO.File]::OpenWrite($LogFilePath).close() }
		catch {
			#assuming!!! user temp folder is always writable within runtime context
			Write-Warning -Message "Unable to write to $($LogFilePath), using contextual temp folder instead"
			$LogFilePath = Join-Path -Path $env:TEMP -ChildPath $LogFileName
		}
		$script:Output | Out-File -FilePath $LogFilePath -Force
		Write-Output "Saved AD2AAD $($SyncType) output on $(Get-Date) to file: $($LogFilePath)"
	}
	else { $Script:Output }
	#reset output and counters for next run
	$script:Output = @()
	$script:Counters = @{"Warning" = 0; "Error" = 0 }
}

Function Get-MDMDeviceInfo {
	[OutputType([System.Management.Automation.PSCustomObject])]
	[CmdletBinding(DefaultParameterSetName = 'User')]
	param(
		[Parameter(Mandatory, ParameterSetName = 'User')]
		[Alias('UserPrincipalName', 'mail')][string]$UPN,
		[Parameter(Mandatory, ParameterSetName = 'Device')]
		[Alias('ComputerName')][string]$DeviceName
	)
	#https://techcommunity.microsoft.com/t5/intune-customer-success/understanding-the-intune-device-object-and-user-principal-name/ba-p/3657593
	if ($script:AADDevices.Count -eq 0) {
		$MgDeviceParams = @{
			All      = $true
			Filter   = "OperatingSystem eq 'Windows' and ManagedDeviceOwnerType eq 'company'"
			Property = 'Id,AzureAdDeviceId, DeviceName,UserPrincipalName,AzureAdRegistered'
			#ExpandProperty = 'RegisteredUsers'
		}
		$script:AADDevices = (Initialize-GraphUri -Resource 'deviceManagement/managedDevices' @MgDeviceParams -Consistency).where({ $_.AzureADRegistered -eq $true })
		if (-not $script:AADDevices.Count) { throw "No AD synced Entra devices found, cannot continue with retrieving device info!" }
		Write-LogEntry -Value "Retrieved $($script:AADDevices.Count) AD synced Windows device objects..." -Severity 0
	}
	Write-LogEntry -Value "Getting MDM device(s) for $($PSCmdlet.ParameterSetName): $($UPN)$($DeviceName)" -Severity 0
	switch ($PSCmdlet.ParameterSetName) {
		'User' { $Devices = @($script:AADDevices | Where-Object UserPrincipalName -eq $UPN) }
		'Device' { $Devices = @($script:AADDevices | Where-Object DisplayName -eq $DeviceName) }
	}
	if ($Devices) {
		Write-LogEntry -Value "Getting Owner(s) and/or Registree(s) for $($Devices.Count) device(s)..." -Severity 0
		foreach ($Device in ($Devices | Where-Object { $null -ne $_ })) {
			$DevUri = "$($Script:GraphRoot)/devices/$($Device.Id)"
			$Owner = (Invoke-RestMethod -Uri "$($DevUri)/registeredOwners" -Method Get -Headers $script:GraphHeader).Value
			$Device | Add-Member -MemberType NoteProperty 'Owner' -Value $Owner
			Write-LogEntry -Value "Owner for $($Device.displayName): $($Owner.UserPrincipalName)"
			$Registree = (Invoke-RestMethod -Uri "$($DevUri)/registeredUsers" -Method Get -Headers $script:GraphHeader).Value
			$Device | Add-Member -MemberType NoteProperty 'Registree' -Value $Registree
			Write-LogEntry -Value "Registree(s) for $($Device.displayName): $($Registree.UserPrincipalName -join ',')"
		}#foreach
	}
	switch ($Devices.Count) {
		0 { $Message = "No Intune device object found for {0}{1}" -f $UPN, $DeviceName }
		1 { $Message = "Found single Intune device object {2} with ID {3} for {0}{1}" -f $UPN, $DeviceName, $Devices.DeviceName, $Devices.Id }
		{ $_ -ge 2 } { $Message = "Multiple Intune device objects found for {0}{1}: {2}" -f $UPN, $DeviceName, $($Devices.DeviceName -join ',') }
	}
	Write-LogEntry -Value $Message -Severity 0
	return $Devices
}

Function Update-AzureGroupMembership {
	[OutputType([System.Collections.Generic.List[PSCustomObject]])]
	[CmdletBinding(DefaultParameterSetName = 'User', SupportsShouldProcess, ConfirmImpact = 'Medium')]
	<#
		Mirrors Azure AD group membership with on-prem AD group membership
		Supports both (Azure) User (= default) and Device objects thru ParameterSets
		- Users: Updates Azure group with passed user accounts
		- Devices: Updates Azure group with passed device accounts
		If CreateEmptyGroup is set, creates an empty Azure group even if there are no devices or users to be added/removed
		If Batch is set, adds members in batches (max 20 members/batch) to improve performance
	#>
	param(
		[Parameter(Mandatory)][string]$AzureGroupName,
		[Parameter(ParameterSetName = 'User')]$Users,
		[Parameter(ParameterSetName = 'Device')]$Devices,
		[Parameter()][switch]$CreateEmptyGroup,
		[switch]$Batch
	)
	#create non-existing group only if Users or Devices are present or anyway if CreateEmptyGroup is set
	[bool]$CreateEmpty = ($Users.count -bor $Devices.count -bor $CreateEmptyGroup.IsPresent)
	$AzureADGroup = Confirm-AzureGroup -Name $AzureGroupName -CreateGroup:$CreateEmpty
	if ($AzureADGroup) {
		Write-LogEntry -Value ("Getting members for Azure group: {0} ({1})" -f $AzureADGroup.displayName, $AzureADGroup.Description) -Severity 0
		$MemberParams = @{
			All         = $true
			#Select      = "Id,DisplayName,UserPrincipalName"
			Consistency = $true
		}
		$ExistingMembers = (Initialize-GraphUri -Resource 'groups' -ResourceAddition "$($AzureADGroup.Id)/members" @MemberParams)
		switch ($PSCmdlet.ParameterSetName) {
			'User' {
				$ManagedMembers = @($ExistingMembers | Where-Object { ($_.Id -in $script:AADUsers.Id) })
				$Members2Compare = $Users
			}
			'Device' {
				$ManagedMembers = @($ExistingMembers | Where-Object { ($_.Id -in $script:AADDevices.Id) })
				$Members2Compare = $Devices
			}
		}
		#unmanaged and/or stale accounts for future reporting?
		#$OtherMembers = @($ExistingMembers -notin $ManagedMembers)
		#Write-logEntry -Value "Found $($OtherMembers.Count) unmanaged members in $($AzureADGroup.displayName)!" -Severity 2
		if ($Members2Compare) {
			#compare AD <-> Azure group membership
			if ($ManagedMembers) { $Members2Sync = Compare-Object -ReferenceObject $ManagedMembers -DifferenceObject $Members2Compare -Property Id -PassThru }
			else {
				Write-LogEntry -Value "Syncing ALL AD onprem users/devices to (new) Azure group..." -Severity 0
				$Members2Sync = $Members2Compare
				#add SideIndicator explicitly for sync routine
				$Members2Sync | Add-Member -MemberType NoteProperty -Name 'SideIndicator' -Value "=>" -ErrorAction SilentlyContinue
			}
		}
		else {
			Write-LogEntry -Value "Empty AD group found, removing all (AD managed) members from Azure group..." -Severity 0
			$Members2Sync = $ManagedMembers
			#add SideIndicator explicitly for sync routine
			$Members2Sync | Add-Member -MemberType NoteProperty -Name 'SideIndicator' -Value "<=" -ErrorAction SilentlyContinue
		}
		if ($Members2Sync) {
			Write-LogEntry -Value "GroupMembership: Found $($Members2Sync.Count) $($PSCmdlet.ParameterSetName) objects to sync to $($AzureADGroup.displayName). Processing..." -Severity 0
			$Members2Add = @($Members2Sync | Where-Object { $_.SideIndicator -eq '=>' })
			$Members2Remove = @($Members2Sync | Where-Object { $_.SideIndicator -eq '<=' })
			if ($PSCmdlet.ShouldProcess("Sync membership of $($PSCmdlet.ParameterSetName)s to $($AzureGroupName)", $AzureGroupName, 'Sync GroupMembership')) {
				if ($Members2Add) {
					if (($Members2Add.Count -gt 1)-and $Batch.IsPresent) {
						#batch adding members see: https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http#request-1
						#the smallest number of members2add and 20 (= current max batch size in Graph SDK)
						$GraphBatchSize = (20, $Members2Add.Count | Measure-Object -Minimum).Minimum
						for ($i = 0; $i -lt $Members2Add.Count; $i += $GraphBatchSize) {
							$UpperBound = $i + $GraphBatchSize - 1 #subtract 1 = offset between count and index
							$MembersBatch = @($Members2Add[$i..$UpperBound]) #array upperbound retrieval is handled gracefully in POSH
							Write-LogEntry -Value "Processing $($GraphBatchSize) Members2Sync starting from index $($i) to $($UpperBound)/$($Members2Add.Count - 1)"
							if (Assert-InteractiveShell) {
								$ProgressParams = @{
									Id              = 2
									ParentId        = 1
									Activity        = "Processing $($Members2Add.Count) GroupMembers for $($AzureADGroup.displayName)"
									Status          = "Adding $($MembersBatch.Count) Members in batch mode..."
									PercentComplete = (($MembersBatch.Count / $Members2Add.Count) * 100)
								}
								Write-Progress @ProgressParams
							}
							$MembersDataBind = @()
							foreach ($Member2Add in $MembersBatch) { $MembersDataBind += "$($Script:GraphRoot)/directoryObjects/$($Member2Add.Id)" }
							$body = @{"members@odata.id" = $MembersDataBind } | ConvertTo-Json
							$GroupUri = "$($Script:GraphRoot)/groups/$($AzureADGroup.Id)"
							try {
								Update-MgGroup -GroupId $AzureADGroup.Id -BodyParameter $body
								#Invoke-RestMethod -Method Patch -Uri $GroupUri -Headers $script:GraphHeader -Body $body -ContentType application/json
								$Action = "added to"
								#Update-MgGroup -GroupId $groupId -BodyParameter $body
							}
							catch {
								#to investigate further, see: https://dev.to/kenakamu/identify-which-request-failed-in-microsoft-graph-batch-request-3a07
								Write-LogEntry -Value $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $GroupUri ) -Severity 3
								$Action = 'FAILED adding to'
							}
							Write-LogEntry -Value $("GroupMembership: {0} {1} {2}" -f $($MembersBatch.DisplayName -join ','), $Action, $AzureADGroup.displayName) -Severity 0
						}
					}
					else {
						foreach ($Member2Add in $Members2Add) {
							#add onprem user/device to Azure group
							$GroupUri = "$($Script:GraphRoot)/groups/$($AzureADGroup.Id)/members/`$ref"
							$body = [ordered]@{ "@odata.id" = "$($Script:GraphRoot)/directoryObjects/$($Member2Add.Id)" } | ConvertTo-Json
							try {
								New-MgGroupMemberByRef -GroupId $AzureADGroup.Id -BodyParameter $body
								#Invoke-RestMethod -Method Post -Uri $GroupUri -Headers $script:GraphHeader -Body $body -ContentType application/json
								$Action = 'added to'
							}
							catch {
								Write-LogEntry -Value $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $GroupUri ) -Severity 3
								$Action = 'FAILED adding to'
							}
							Write-LogEntry -Value $("GroupMembership: {0} {1} {2}" -f $Member2Add.DisplayName, $Action, $AzureADGroup.displayName) -Severity 0
						}
					}
				}
				if ($Members2Remove) {
					#no batch processing possible (yet) for removing members
					foreach ($Member2Remove in $Members2Remove) {
						if (Assert-InteractiveShell) {
							$ProgressParams = @{
								Id              = 2
								ParentId        = 1
								Activity        = "Processing GroupMembers in $($AzureADGroup.displayName)"
								Status          = "Removing $($Member2Remove.DisplayName)..."
								PercentComplete = (($Member2Remove.Index / $Members2Remove.Count) * 100)
							}
							Write-Progress @ProgressParams
						}
						#remove user/device from Azure group
						#see https://docs.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0&tabs=http
						$GroupUri = "$($Script:GraphRoot)/groups/$($AzureADGroup.Id)/members/$($Member2Remove.Id)/`$ref"
						try {
							#Remove-MgGroupMemberByRef -GroupId $AzureADGroup.Id -DirectoryObjectId $Member2Remove.Id
							Invoke-RestMethod -Method Delete -Uri $GroupUri -Headers $script:GraphHeader
							$Action = 'removed from'
						}
						catch {
							Write-LogEntry -Value $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $GroupUri ) -Severity 3
							$Action = 'FAILED removing from'
						}
						Write-LogEntry -Value $("GroupMembership: {0} {1} {2}" -f $Member2Remove.DisplayName, $Action, $AzureADGroup.displayName) -Severity 0
					}
				}
			}
			else {
				Write-LogEntry -Value "Syncing membership of $($PSCmdlet.ParameterSetName)s to $($AzureGroupName) has been skipped due to ConfirmImpact set to: $($ConfirmPreference)" -Severity 1
				if ($Members2Add) {
					foreach ($Member2Add in $members2Add) {	Write-LogEntry -value "GroupMembership: -WHATIF added $($Member2Add.DisplayName) to $($AzureADGroup.displayName)" -Severity 0 }
				}
				if ($Members2Remove) {
					foreach ($Member2Remove in $Members2Remove) { Write-LogEntry -value "GroupMembership: -WHATIF removed $($Member2Remove.DisplayName) from $($AzureADGroup.displayName)" -Severity 0 }
				}
			}
		}
		else { Write-LogEntry -Value "GroupMembership: No difference between AD and Azure members found, nothing to sync... " -Severity 1 }
	}
	else { Write-LogEntry -Value "Failure retrieving Azure group $($AzureGroupName) nor created!" -Severity 2 }
	return $Members2Sync
}

Function Sync-ADGroups2AAD {
	#Requires -Version 5.1
	[cmdletbinding(DefaultParameterSetName = "OUSync", SupportsShouldProcess, ConfirmImpact = 'Medium')]
	<#
	.SYNOPSIS
	Sync (nested) On-prem AD groups containing users and/or devices with Azure AD groups containing users and/or primary/owned/registered devices.
	.DESCRIPTION
	Used for populating Azure AD groups with users and/or devices owned or registered by on-prem AD user object
	Can process nested AD group membership into flat Azure AD group
	Note: Names of both groups must be identical without the set prefix and suffix (on Azure side)
	Note: Groupnames may not contain spaces, underscores, non-ASCII characters or the used prefix (eg: INT-) or suffixes (-U/-D) in Azure
	Uses a registered enterprise app and must have scopes as defined in local script variable <RequiredScopes>
	.EXAMPLE
	Sync-ADGroups2AAD -OU2Sync 'OU=Azure,OU=Groups,OU=Fabrikom,OU=Contoso,DC=com' -Objects2Sync 'Users' -DestinationGroupType 'UserGroup' -Outlog <-- ParameterSet = OUSync
	.EXAMPLE
	Sync-ADGroups2AAD -Group2Sync 'PWBI-Viewers' -Objects2Sync 'Users' -DestinationGroupType 'UserGroup' <-- ParameterSet = GroupSync
	.EXAMPLE
	Sync-ADGroups2AAD -Group2Sync 'INT-WindowsPilot*' -AzureGroupPrefix 'INT-' -Objects2Sync 'Devices' -DestinationGroupType All
		--> creates User AND Device INT- prefixed group(s) in Azure based on ownership in Intune using wildcard groupname lookup in on-prem AD
	.INPUTS
	Either the full DN of 1 OU or 1 (wildcard) AD group display- or SAMaccountName
	.PARAMETER TenantID
	Azure Tenant ID to connect to
	.PARAMETER AppRegistrationID
	Enterprise App Registration ID to use for authentication and management scope
	.PARAMETER AppSecret
	Secret key of Enterprise App registration
	.PARAMETER CertificatePath
	Client Certificate for securing Graph connection request
	.PARAMETER OU2Sync
	The distinguished name of the OU to look for AD groups, can be piped thru DistinguishedName property
	.PARAMETER SearchScope
	Resolve AD groups inside an OU, either directly <OneLevel> (=default) or recursively <SubTree>'
	.PARAMETER Group2Sync
	The Name (as registered in AD) of a specific group or a wildcard for multiple matches, can be piped thru Name property
	.PARAMETER Objects2Sync
	What type of AD groupmember objects need to be processed? <Users> or <Devices> (AD computer object) or both <All>
	.PARAMETER Objects2ExcludeGroup
	Optional AD group holding objects (user/computer/group) to exclude from processing
	.PARAMETER DestinationGroupType
	What type of Azure group needs to be synced? <UserGroup> or <DeviceGroup> or both <All>
	A suffix -U or -D is used respectively for User- and DeviceGroup as to identify them in Azure and for successive processing
	.PARAMETER AzureGroupPrefix
	Used prefix for retrieval / filtering of script managed Azure groups, default prefix = INT-
	.PARAMETER ConfirmGroups
	Compare groups existing on one side only and present for deletion if script runs interactively, otherwise output to log
	.PARAMETER RemoveDuplicates
	Check Azure group(s) for duplicates and remove them interactively or automatically if running as job
	.PARAMETER ProcessEmptyGroup (alias CreateEmptyGroup)
	Create (empty) Azure group even if on-prem Active Directory group has no members, otherwise skipped
	.PARAMETER EnforceGroupNamingConvention (alias InspectGroupNames)
	Enforce naming convention for Azure groups based on the corresponding on-prem AD GroupName:
		- no spaces, underscores, non-ASCII characters, periods or hyphens, no redundant pre- or suffixes, ...
	.PARAMETER BatchProcessing
	Process Add/Remove users/devices in Azure groups in batch mode to improve performance, default is single processing
	.PARAMETER RunAsJob (alias RobotJob, alias Unattended)
	Run script without interaction or prompts, mutes output to host and writes to log instead,
	Skips destructive actions like deleting groups while comparing
	.PARAMETER OutLog
	Writes script output to a logfile in runtime contextual Documents folder
	.OUTPUTS
	Verbose informational output only, no other objects are returned
	.ToDo
	call REST action in batches:
	https://learn.microsoft.com/en-us/graph/json-batching?WT.mc_id=EM-MVP-5002871
	.LINK
	https://learn.microsoft.com/en-us/graph/use-the-api
	.ROLE
	user / device admin
	.NOTES
	FileName: Sync-ADGroups2AAD
	Author: Christel Van der Herten
	Date:   1 december 2022
	Version history:
	v 1.0.0.0 - 13-12-2022 - initial commit of functional but untested script
	v 2.0.0.0 - 22-07-2025 - conversion of monolithic script into module (finally)
	v 2.0.1.0 - 07/08-2025 - replaced most MG Graph cmdlets with REST API calls
						   - ToDo: investigate difference in acceptance of Managed Device ID between Add-MgGroupMemberByRef and GRAPH API call
#>

	param(
		[Parameter(Mandatory, HelpMessage = "Azure Tenant ID to connect to")]
		[ValidatePattern('(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})')]
		[string]$TenantID,

		[Parameter(Mandatory, HelpMessage = "Enterprise App Registration ID to use for authentication and management scope")]
		[ValidateNotNullOrEmpty()]
		[string]$AppRegistrationID,

		[Parameter(Mandatory, HelpMessage = "Secret key of Enterprise App registration")]
		[ValidateNotNullOrEmpty()]
		[string]$AppSecret,

		[Parameter(HelpMessage = "Path to a Client Certificate for securing the Graph connection request")]
		[Microsoft.PowerShell.Commands.X509StoreLocation]$CertificatePath,

		[Parameter(ParameterSetName = "OUSync", Mandatory, HelpMessage = 'Must be a valid Distinguished Name')]
		[ValidatePattern("^((CN=([^,]*)),)?((((?:CN|OU)=[^,]+,?)+),)?((DC=[^,]+,?)+)$")]
		[Alias("DistinguishedName", "DN")]
		[string]$OU2Sync,

		[Parameter(ParameterSetName = "OUSync", HelpMessage = 'Resolve AD groups only directly in an OU <OneLevel> (=default) or recursively <SubTree>')]
		[ValidateNotNullOrEmpty()][ValidateSet('OneLevel', 'SubTree', '1', '2')]
		[string]$SearchScope = 'OneLevel',

		[Parameter(ParameterSetName = "GroupSync", Mandatory, HelpMessage = 'Can be a full or partial (using wildcards) group displayname')]
		[SupportsWildcards()]
		[string]$Group2Sync,

		[Parameter(HelpMessage = 'Optional AD group holding objects (user/computer/group) to exclude from processing')]
		[string]$Objects2ExcludeGroup,

		[Parameter(Mandatory, HelpMessage = 'Select which type of objects in AD group(s) to process: <Users>, <Devices> or <All>')]
		[ValidateSet('Users', 'Devices', 'All')]
		[string]$Objects2Sync,

		[Parameter(Mandatory, HelpMessage = "Add user / device to their respective Azure <UserGroup> or <DeviceGroup> or both <All>")]
		[ValidateSet('UserGroup', 'DeviceGroup', 'All')]
		[string]$DestinationGroupType,

		[Parameter(HelpMessage = 'Prefix for Azure groupnames, eg: INT- (=default)')]
		[ValidateNotNullOrEmpty()]
		[string]$AzureGroupPrefix = "INT-",

		[Parameter(ParameterSetName = "OUSync", HelpMessage = 'Check presence of both AD and Azure groups. Cleanup is only possible thru interactive selection when not running as job!!!')]
		[switch]$ConfirmGroups,

		[Parameter(ParameterSetName = "OUSync", HelpMessage = 'Check duplicate Azure groups and remove copies, either interactively or automatically if running as job.')]
		[switch]$RemoveDuplicates,

		[Parameter(HelpMessage = 'Create new empty Azure group even if on-prem AD group has no members (yet)')]
		[Alias("CreateEmptyGroup")]
		[switch]$ProcessEmptyGroup,

		[Parameter(HelpMessage = 'Check naming conventions: (multiple) spaces, periods, underscores, hyphens, redundant pre- or suffix, ...')]
		[Alias("InspectGroupNames")]
		[switch]$EnforceGroupNamingConvention,

		[Parameter(HelpMessage = 'Process Add/Remove users/devices in Azure groups in batch mode to improve performance')]
		[switch]$BatchProcessing,

		[Parameter(HelpMessage = 'Run as job means no interactive prompts or output to console')]
		[Alias("RobotJob", "Unattended")]
		[switch]$RunAsJob,

		[Parameter(HelpMessage = 'Redirect script output to logfile in My Documents (= default). Eventual location is written to output stream')]
		[switch]$OutLog,

		[Parameter(HelpMessage = "Verbosity of log entry output. 0 for Everything, 1 for Informational (default), 2 for Warning and 3 for Error.")]
		[ValidateRange(0, 4)][int]$Verbosity = 1
	)

	process {
		[int]$i = 0
		Do {
			Write-LogEntry -Value "Processing $($script:ADGroups.Count) AD groups (re)starting at index $($i)..." -Severity 0
			for (; $i -lt $script:ADGroups.Count; ) {
				$ADGroup = $script:ADGroups[$i]
				$i++ #running counter of current ADgroup array index
				if (Assert-InteractiveShell) {
					$ProgressParams = @{
						ID               = 1
						Activity         = "Processing AD Group: $($ADGroup.Name)"
						Status           = "Index $($i) of $($script:ADGroups.Count)"
						CurrentOperation = "Processing AD Group: $($ADGroup.Name)"
						PercentComplete  = ($i / $script:ADGroups.Count) * 100
					}
					Write-Progress @ProgressParams
				}
				# process only if current groupname is compliant (when enforced) else skip processing
				if (Assert-GroupName -GroupName $ADgroup.Name -Prefix $AzureGroupPrefix -Enforce:$EnforceGroupNamingConvention) {
					$ADMembers = @(Get-ADGroupMember -Identity $ADGroup -Recursive | Where-Object { $_.Name -notin @($Users2Exclude + $Devices2Exclude) })
					#Get Azure / Intune objects related to member(s) of AD Group
					$Users2Sync = [System.Collections.Generic.List[Object]]::New()
					$Devices2Sync = [System.Collections.Generic.List[Object]]::New()
					switch ($ApplyMembershipFrom) {
						'Users' {
							$AdUsers = @($ADMembers | Where-Object { $_.ObjectClass -eq "user" })
							Write-LogEntry -Value "Processing $($AdUsers.Count) AD users..." -Severity 0
							Foreach ($User in $AdUsers) {
								Write-LogEntry -Value "Retrieving Azure Userobject for AD user: $($User.Name)" -Severity 1
								$UPN = (Get-ADUser $User).UserPrincipalName
								switch ($ApplyMembershipTo) {
									'UserGroup' { $script:AADUsers | Where-Object UserPrincipalName -eq $UPN | ForEach-Object { [void]$Users2Sync.Add($_) } }
									'DeviceGroup' { $script:AADDevices | Where-Object UserPrincipalName -eq $UPN | ForEach-Object { [void]$Devices2Sync.Add($_) } }
								}
							}
						}
						'Devices' {
							$AdComputers = @($ADMembers | Where-Object { $_.ObjectClass -eq "computer" })
							Write-LogEntry -Value "Processing $($AdComputers.Count) AD Computers..." -Severity 0
							Foreach ($Device in $AdComputers) {
								$MdmDevices = @($script:AADDevices | Where-Object { $_.DeviceName -eq $Device.Name }) #multiple return by name is possible!
								Write-LogEntry -Value "Retrieving Azure Device object(s) for AD computer: $($Device.Name) matching $($MdmDevices.Count) Azure Devices" -Severity 1
								if ($MdmDevices.Count) {
									switch ($ApplyMembershipTo) {
										'UserGroup' { $script:AADUsers.where({ UserPrincipalName -in $MdmDevices.UserPrincipalName }) | ForEach-Object { [void]$Users2Sync.Add($_) } }
										'DeviceGroup' { $MdmDevices | ForEach-Object { [void]$Devices2Sync.Add($_) } }
									}
								}
							}
						}
					}
					#Add retrieved Azure / Intune objects to related AzureGroup
					$AzureGroupName = "$($AzureGroupPrefix)$($ADGroup.Name.Trim())"
					switch ($ApplyMembershipTo) {
						'UserGroup' {
							$Users2Sync = @($Users2Sync | Where-Object { $_ -ne $null } | Sort-Object -Property ID -Unique) #filter out doubles based on ID
							Write-LogEntry -Value "Found $($Users2Sync.Count) Azure User Id's" -Severity 0
							Update-AzureGroupMembership -AzureGroupName "$($AzureGroupName)-U" -Users $Users2Sync -CreateEmptyGroup:$ProcessEmptyGroup -Batch:$BatchProcessing.IsPresent
						}
						'DeviceGroup' {
							$Devices2Sync = @($Devices2Sync | Where-Object { $_ -ne $null } | Sort-Object -Property ID -Unique) #filter out doubles based on ID
							Write-LogEntry -Value "Found $($Devices2Sync.Count) Azure Device Id's" -Severity 0
							Update-AzureGroupMembership -AzureGroupName "$($AzureGroupName)-D" -Devices $Devices2Sync -CreateEmptyGroup:$ProcessEmptyGroup -Batch:$BatchProcessing.IsPresent
						}
					}
					#if less than 10 minutes token lifetime left then pause loop, renew token and connect again for further processing
					if ($script:TokenExpiry -lt $((Get-Date).AddSeconds(600))) {
						$Seconds = (5..15 | Get-Random)
						Write-LogEntry -Value "Token has expired, renewing token in $($Seconds) seconds..." -Severity 0
						Start-Sleep -Seconds $Seconds #time out between loops to prevent throttling
						break
					}
				}
				#skip processing if current AD groupname does not adhere to naming convention (when enforced)
				else { continue }
			}#foreach ADgroup
			if ($script:TokenExpiry -lt $((Get-Date).AddSeconds(600))) {
				try {
					New-GraphToken @TokenParams
					Write-LogEntry -Value "Token (re)acquired and valid until $($script:TokenExpiry)"
				}
				catch {
					$ConfirmGroups.IsPresent = $false #prevent further processing of groups
					Write-LogEntry -Value "Token renewal failed, error: $($_.Exception.Message)" -Severity 3
					break
				}
			}
		} Until ($i -ge $script:ADGroups.Count)
		if ($ConfirmGroups.IsPresent) {
			#https://learn.microsoft.com/en-us/graph/delta-query-overview#use-delta-query-to-track-changes-in-a-resource-collection --> get delta update or full refresh?
			$AzGroupParams = @{
				Filter           = "startsWith(DisplayName, '$($AzureGroupPrefix)')"
				Property         = "Id,CreatedDateTime,DisplayName,Description"
				OrderBy          = 'DisplayName'
				ConsistencyLevel = 'eventual'
				CountVariable    = 'AzGroupCount'
				All              = $true
			}
			$script:AADGroups = @(Get-MgGroup @AzGroupParams)
			Write-LogEntry -Value "Comparing $($AzGroupCount) Azure with onprem AD groups..." -Severity 0
			Confirm-GroupSync -AzureGroups $script:AADGroups -ADGroups $script:ADGroups -AzureGroupPrefix $AzureGroupPrefix
		}
	}

	begin {
		#region script variables
		$nl = [System.Environment]::NewLine
		[version]$ScriptVersion = '2.0.0.0'
		#future improvement to use localized messages
		#Import-PowerShellDataFile -BindingVariable "SyncStr"
		$ScriptDescription = "Sync-ADGroups2AAD v{0} run by {1}" -f $ScriptVersion, [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
		$Script:StartTime = Get-Date
		Write-LogEntry -Value "Starting $($ScriptDescription) on $($Script:StartTime)"
		#save connection parameters in splatted hash table to renew token if necessary during script execution
		$TokenParams = @{
			TenantID               = $TenantID
			AppRegistrationID      = $AppRegistrationID
			AppSecret              = $AppSecret
			CertificatePath        = $CertificatePath
			InitializeMGConnection = $true
		}
		if ($CertificatePath) { $TokenParams.CertificatePath = $CertificatePath }
		New-GraphToken @TokenParams
		#do not prompt for input if script is run as scheduled task
		if ($RunAsJob.IsPresent -or (-not (Assert-InteractiveShell))) { $ConfirmPreference = 'none'; $WhatIfPreference = $false; $VerbosePreference = 'silentlyContinue' }
		#else { $ConfirmPreference = 'high'; $WhatIfPreference = $true; $VerbosePreference = 'continue' }
		#interpret incoming parameters and set script local variables
		try {
			#Retrieve AD objects (without recursion!!!) to exclude them from syncing
			$Groups2Exclude = $Users2Exclude = $Devices2Exclude = @()
			if ($PSBoundParameters.ContainsKey('Objects2ExcludeGroup')) {
				if (Get-ADGroup $Objects2ExcludeGroup) {
					$Members2Exclude = Get-ADGroupMember -Identity $Objects2ExcludeGroup
					$Groups2Exclude = @($Members2Exclude | Where-Object { $_.ObjectClass -eq 'group' } | Select-Object Name -Unique) + $Objects2ExcludeGroup
					$Users2Exclude = @($Members2Exclude | Where-Object { $_.ObjectClass -eq 'user' } | Select-Object Name -Unique)
					$Devices2Exclude = @($Members2Exclude | Where-Object { $_.ObjectClass -eq 'computer' } | Select-Object Name -Unique)
					Write-LogEntry -Value "All $($Members2Exclude.Count) (direct) member objects of $($Objects2ExcludeGroup) will be excluded from syncing!"
				}
				else { Write-LogEntry -Value "Exclusion Group $($Objects2ExcludeGroup) not found! Exiting script to prevent sync of to be excluded objects..." -Severity 4 }
			}
			switch ($PSCmdlet.ParameterSetName) {
				'OUSync' {
					if (-not(Get-ADOrganizationalUnit -Identity $OU2Sync)) { Write-LogEntry -Value "OU lookup failed, skipping <$($OU2Sync)>" -Severity 2 ; break }
					$script:ADGroups = @(Get-ADGroup -Filter * -SearchBase $OU2Sync -SearchScope $SearchScope | Where-Object { $_.Name -notin $Groups2Exclude } | Sort-Object -Property Name -Unique )
					Write-LogEntry -Value "Processing $($script:ADGroups.Count) AD group(s) retrieved from OU: $($OU2Sync)"
				}
				'GroupSync' {
					$script:ADGroups = @(Get-ADgroup -Filter "Name -like '$Group2Sync'" | Where-Object { $_.Name -notin $Groups2Exclude } | Sort-Object -Property Name -Unique)
					Write-LogEntry -Value "Processing $($script:ADGroups.Count) AD group(s) matching groupname filter: $($Group2Sync)"
				}
			}
			if (-not ($script:ADGroups.Count)) { throw "No AD groups retrieved, cannot continue with AD2AAD sync!" }
		}
		catch { Write-LogEntry -Value "Failed to query Active Directory due to $($_.Exception.Message), exiting script..." -Severity 4 }
		#replace <All> with array of all objects to sync from and to
		switch ($Objects2Sync) {
			'All' { $ApplyMembershipFrom = @('Users', 'Devices') }
			Default { $ApplyMembershipFrom = @($Objects2Sync) }
		}
		switch ($DestinationGroupType) {
			'All' { $ApplyMembershipTo = @('UserGroup', 'DeviceGroup') }
			Default { $ApplyMembershipTo = @($DestinationGroupType) }
		}
		Write-LogEntry -Value "GroupMember object types to sync from: AD $([string]::Join(' & ',$ApplyMembershipFrom)) to: Azure $([string]::Join(' & ',$ApplyMembershipTo))"
		#get used UserPrincipalName(s) present in onprem AD
		$script:CompanyUPNs = @((Get-ADForest).UPNSuffixes)
		#set default logfile save location
		$script:LogsDirectory = [System.Environment]::GetFolderPath('mydocuments')
		#use for validation of Azure GroupName(s)
		[regex]$script:AzureAdditions = "(?i)(?'Prefix'^($($AzureGroupPrefix)))(?'Name'.*)(?'Suffix'(-[U|D])$)"
		#max length of Azure GroupName minus Azure prefix parameter and suffix -U or -D
		$script:MaxGroupNameLength = 64 - $AzureGroupPrefix.Length - 2
		# store AAD objects for lookups = performance boost
		# https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0
		# https://learn.microsoft.com/en-us/graph/aad-advanced-queries?
		#no need to retrieve users if only device objects are processed
		if (('UserGroup' -in $ApplyMembershipTo) -or ($ApplyMembershipFrom -contains 'Users')) {
			$MgUserParams = @{
				All      = $true
				Filter   = "OnPremisesSyncEnabled eq true and UserType eq 'Member'"
				Property = "Id,DisplayName,UserPrincipalName"
				OrderBy  = 'Id'
			}
			$script:AADUsers = (Initialize-GraphUri -Resource 'users' @MgUserParams -Consistency)
			if (-not $script:AADUsers.Count) { throw "No AD synced Entra users found, cannot continue with user group sync!" }
			Write-LogEntry -Value "Retrieved $($script:AADUsers.Count) AD synced Entra users..." -Severity 0
		}
		#no need to retrieve devices if only user objects are processed
		if (('DeviceGroup' -in $ApplyMembershipTo) -or ($ApplyMembershipFrom -contains 'Devices')) {
			#https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.devicemanagement/get-mgdevicemanagementmanageddevice?view=graph-powershell-1.0
			#https://techcommunity.microsoft.com/blog/intunecustomersuccess/understanding-the-intune-device-object-and-user-principal-name/3657593
			$MgDeviceParams = @{
				All      = $true
				Filter   = "OperatingSystem eq 'Windows' and ManagedDeviceOwnerType eq 'company'"
				#Property = 'Id,DeviceName,UserPrincipalName,IsManaged'
				#Property = 'AzureAdDeviceId, DeviceName,UserPrincipalName,AzureAdRegistered'
				Property = 'Id, DeviceName,UserPrincipalName,AzureAdRegistered'
				#ExpandProperty = 'RegisteredUsers'
			}
			#$script:AADDevices = (Initialize-GraphUri -Resource 'devices' @MgDeviceParams -Consistency).where({ $_.IsManaged })
			$script:AADDevices = (Initialize-GraphUri -Resource 'deviceManagement/managedDevices' @MgDeviceParams -Consistency).where({ $_.AzureADRegistered -eq $true })
			if (-not $script:AADDevices.Count) { throw "No AD synced Entra devices found, cannot continue with device group sync!" }
			#$script:AADDevices | ForEach-Object { Add-Member -InputObject $_ -MemberType AliasProperty -Name Id -Value AzureAdDeviceId -Force } #AzureAdDeviceId is actual Id of object in Azure to be used for group membership
			$script:AADDevices | ForEach-Object { Add-Member -InputObject $_ -MemberType AliasProperty -Name DisplayName -Value DeviceName -Force } #DeviceName equals DisplayName of object in Azure
			Write-LogEntry -Value "Retrieved $($script:AADDevices.Count) AD synced Windows device objects..." -Severity 0
		}
		$MgGroupParams = @{
			All      = $true
			Filter   = "startsWith(DisplayName, '$($AzureGroupPrefix)')"
			Property = "Id,CreatedDateTime,DisplayName,Description"
		}
		$script:AADGroups = (Initialize-GraphUri -Resource 'groups' @MgGroupParams -Consistency)
		if (-not $script:AADGroups.Count) { throw "No Azure groups found, cannot continue with group sync!" }
		Write-LogEntry -Value "Retrieved $($GroupCount) Entra groups starting with the prefix $($AzureGroupPrefix)..." -Severity 0
		#endregion script variables
		#https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_trap?view=powershell-5.1
		#trap all errors and write them to output stream
		trap {
			$Script:Output.Add("FATAL: Terminal Error occured in script $($ScriptDescription), see details below:")
			$Script:Output.Add("FATAL: $($_.InvocationInfo.PositionMessage)")
			$Script:Output.Add("FATAL: $($_.Exception.Message)$($nl)")
			return $Script:Output
			exit 1
		}
	}

	end {
		Write-LogEntry -Value "Script $($ScriptDescription) finished at $(Get-Date) with $($script:Counters["Error"]) error(s)"
		Write-LogEntries -SyncType $PSCmdlet.ParameterSetName -OutLog:$OutLog -Verbosity $Verbosity
	}
}

#Explicit export of functions to module scope
$FunctionsToExport = @(
	'Assert-InteractiveShell',
	'Assert-GroupName',
	'Confirm-AzureGroup',
	'Confirm-GroupSync',
	'Expand-RESTObject',
	'Get-GraphQueryResults',
	'Get-MDMDeviceInfo',
	'Get-MGConnection',
	'Initialize-GraphUri',
	'New-GraphToken',
	'Resolve-AzureGroup',
	'Resolve-Duplicates',
	'Resolve-GraphRequestError',
	'Select-GraphRoot',
	'Sync-ADGroups2AAD',
	'Update-AzureGroupMembership',
	'Write-LogEntry',
	'Write-LogEntries'
)
Export-ModuleMember -Function $FunctionsToExport
#Select-GraphRoot -GraphEnvironment Production
