<#
    .SYNOPSIS
    Retrieves enriched file alerts from MCAS, compares against supplied lists of trusted collaborators
    (email addresses and DNS domains), and optionally dismisses any alerts which exclusively contain those
    trusted collaborators.
    Needs an MCAS API token with sufficient privileges, which is stored on first run.

    .DESCRIPTION
    Calls get-McasAlert against TenantURI to get N most recent alerts of a specific PolicyID
    
    .PARAMETER TenantURI
    Specifies the Cloud App Security API endpoint for your token.
    -TenantURI "https://name.loc.portal.cloudappsecurity.com"

    .PARAMETER PolicyID
    Specifies one or more comma-separated policy identifiers. 
    When editing a policy in MCAS, the policy ID is shown in the address bar.

    .PARAMETER Commit
    Switch which tells the script to actually dismiss alerts; otherwise operates read-only.

    .PARAMETER ResultSetSize
    Defaults to 5

    .PARAMETER ClearCache
    Removes existing file and API cache entries. Use if results don't seem right.


    .EXAMPLE
    .\get-mcasfilealertdetails.ps1 -TenantUri "https://yourid.us3.portal.cloudappsecurity.com" -ResultSetSize 50 -PolicyID 601121c8178c67b61761bbb1, 601121c8178c67b61762bbb2
    
    Retrieves 50 alerts matching each policy and compares them with the trusted collaborators lists to recommend "defusal" (dismissal)

    .EXAMPLE
    .\get-mcasfilealertdetails.ps1 -TenantUri "https://yourid.us3.portal.cloudappsecurity.com" -ResultSetSize 50 -PolicyID 601121c8178c67b61761bbb1, 601121c8178c67b61762bbb2 -Commit

    As above, but attempts to dismiss those alerts as false positives after identifying them

    .EXAMPLE
    .\get-mcasfilealertdetails.ps1 -TenantUri "https://yourid.us3.portal.cloudappsecurity.com" -PolicyID 601121c8178c67b61761bbb1, 601121c8178c67b61762bbb2 -ClearCache
    
    Resets file and API cache files (_filecache.xml and _apicache.xml)

    .NOTES
    Original author: tristank [at] microsoft.com 2021-05-25
    
    LEGAL DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
    RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
    MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to
    reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your
    software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded;
    and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys fees, that arise or result
    from the use or distribution of the Sample Code.
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [String]
    $TenantUri, # https://name.location.portal.cloudappsecurity.com
    [Parameter(Mandatory=$true)]
    [String[]]
    $PolicyID, # policy IDs, comma separated
    [Parameter()]
    [int]
    $ResultSetSize = 5, 
    [switch]
    $ClearCache,
    [switch]
    $Commit,
    [Parameter(ParameterSetName = 'TimeRanges', Mandatory = $false)]
    [switch]
    $SinceYesterday,
    [Parameter(ParameterSetName = 'TimeRanges', Mandatory = $false)]
    [switch]
    $Last48h,
    [Parameter(ParameterSetName = 'TimeRanges', Mandatory = $false)]
    [switch]
    $Last72h,
    [Parameter(ParameterSetName = 'TimeRanges', Mandatory = $false)]
    [switch]
    $LastWeek
)

function GetSomethingFromAPI{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ApiPath,
        [string]
        $proxyUrl
        )
    
    $token = $CASCredential.GetNetworkCredential().Password

    Write-Debug "CAS Token has length $($token.Length)"
    $headers = @{'Authorization' = 'Token ' + $token; "Accept" = "*/*"}
    #$token = $CasCredential.GetNetworkCredential().Password

    sleep 2 # guarantees we'll be under the API limit

    if(($null -eq $tenanturi ) -or ([String]::IsNullOrEmpty($tenanturi))){
        Write-Error "Tenant URI not set"
        Exit
    }
    if($tenanturi.StartsWith("https://")){
        $requestURI = $tenanturi
    }
    else{
        $requestURI = "https://$tenantURI"
    }

    if($proxyUrl -contains "http://"){
        $response=Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri "$requestURI$apipath" -Proxy $proxyUrl
    }
    else{
        $response=Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri "$requestURI$apipath" #-Proxy $proxyUrl
    }

    $response.Content
    #Invoke-WebRequest -Headers @{'Authorization' = 'Token ' + $token } -Uri "$tenanturi$apipath"
}

Function get-CachedMCASFile{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $MCASFileID
    )

    $MCASFileReturn = $null
    # note inefficiency - loads every time - only OK with small sizes
    if($Script:FileCache.Count -lt 1){
        write-debug "File cache count: $($Script:FileCache.Count)"
        if(test-path $FileCacheFile){
            write-debug " Loading Cache..."
            $Script:FileCache = Import-Clixml $FileCacheFile
        }
    }

    if($FileCache.ContainsKey($MCASFileID))
    {
        # too easy!
        Write-Debug "Cache hit"
        $MCASFileReturn = $FileCache[$MCASFileID]
    }
    else{
        Write-Debug "Cache MISS for $($MCASFileID)"
        try
        {
            $MCASFileReturn = Get-MCASFile $MCASFileID
            # progressive complication!
            $Script:FileCache.Add($MCASFileID, $MCASFileReturn)
            Export-Clixml -InputObject $Script:FileCache -Path $FileCacheFile
        } catch{
            Write-Error "Error calling API, not caching result."
        }
    }
    
    write-debug "File cache count: $($FileCache.Count)"
    return $MCASFileReturn
}
Function get-CachedMCASAPI{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $LookupID
    )

    $ReturnObject = $null
    if($Script:APICache.Count -lt 1){
        write-debug "API cache count: $($Script:APICache.Count)"
        if(test-path $APICacheFile){
            write-debug " Loading Cache..."
            $Script:APICache = Import-Clixml $APICacheFile
        }
    }

    if($APICache.ContainsKey($LookupID))
    {
        write-debug "Cache hit"
        # too easy!
        $ReturnObject = $APICache[$LookupID]
    }
    else{
        Write-Debug "Cache MISS for $($LookupID)"
        try{
            $ReturnObject = GetSomethingFromAPI $LookupID
            $Script:APICache.Add($LookupID, $ReturnObject)
            Export-Clixml -InputObject $Script:APICache -Path $APICacheFile
        } catch{
            Write-Error "Error calling API, not caching result."
        }
        # progressive complication!
    }
    
    write-Debug "API cache count: $($APICache.Count)"
    return $ReturnObject
}

Function CollaboratorTrustedforPolicy{
    # return true of
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $MemberName,
        [Parameter()]
        [string]
        $PolicyID
    )
    Write-debug "Checking for match for $MemberName"
        # user checks first
        if($GlobalPolicies.ContainsKey("AlwaysTrusted")){
            Write-Debug "Checking AlwaysTrusted List..." 
            if($GlobalPolicies."AlwaysTrusted".ContainsKey($MemberName)){
                Write-Debug " AlwaysTrusted user found - $MemberName"
                return $true
            }
        }

        if($GlobalPolicies.ContainsKey("$PolicyID")){
            Write-Debug -Verbose -Message "Checking Policy $PolicyID..."
            #Write-debug $GlobalPolicies."$PolicyID".Keys
            if($GlobalPolicies."$PolicyID".ContainsKey($MemberName)){
                Write-Debug " Policy-Trusted user found - $PolicyID - $MemberName"
                return $true
            }
        }
        else{
            Write-Debug -Verbose -Message "Policy ID not found - $PolicyID"
        }

        # domain checks


        $domainBit = $membername.Split("@")[1]
        if($null -ne $domainBit)
        {
            write-debug "Domain bit is $domainbit"
            # no point checking if there's no domain!
            try{
                if($GlobalPolicies."AlwaysTrusted".ContainsKey($domainbit)){
                    Write-Debug " Always-Trusted domain found - $domainbit"
                    return $true
                }
            }
            catch{
                Write-Error -Message " Error checking trusted domains."
                return $false
            }

            try{
                if($GlobalPolicies.ContainsKey("$PolicyID")){
                    Write-Debug -Verbose -Message "Checking Policy $PolicyID..."
                    #Write-debug $GlobalPolicies."$PolicyID".Keys
                    if($GlobalPolicies."$PolicyID".ContainsKey($domainbit)){
                        Write-Debug " Policy-Trusted domain found - $PolicyID - $domainbit - $MemberName"
                        return $true
                    }
                }
            }catch{
                Write-Error -Message " Error checking policy domains."
                return $false
            }

        }else{
            Write-Debug " No Domain Found - assuming investigation needed"
            # is this an automatic $true? For future discussion
        }

        # default failure condition
        return $false
}

# Process start
$runlogs = mkdir .\RunLogs -Force
$runlogs = get-item .\RunLogs

$isodatetime = (get-date).ToString("yyyyMMdd-HHmmss")
$now = Get-Date
$EpochToNow = New-TimeSpan '01/01/1970' $now
$LastWeekTime = $now.Date.AddDays(-7)
$LastWeekToNow = new-timespan '01/01/1970' $LastWeekTime
$LastWeekMCASTime = [int]$LastWeekToNow.TotalSeconds
$Last72hTime = $now.AddHours(-72)
$Last72hToNow = new-timespan '01/01/1970' $Last72hTime
$Last72hMCASTime = [int]$Last72hToNow.TotalSeconds
$Last48hTime = $now.AddHours(-48)
$Last48hToNow = new-timespan '01/01/1970' $Last48hTime
$Last48hMCASTime = [int]$Last48hToNow.TotalSeconds
$YesterdayTime = $now.date.AddDays(-1)
$SinceYesterdayToNow = new-timespan '01/01/1970' $YesterdayTime
$SinceYesterdayMCASTime = [int]$SinceYesterdayToNow.TotalSeconds


$transcriptfilename = "$runlogs\Transcript-$isodatetime.log"

start-transcript $transcriptfilename -Force

#setup for later caching enhancement
$FileCacheFile = ".\_FileCache.xml"
$APICacheFile = ".\_APICache.xml"

if($ClearCache){
    Remove-Item $FileCacheFile -Force -ErrorAction SilentlyContinue
    Remove-Item $APICacheFile -Force -ErrorAction SilentlyContinue
}

$FileCache = @{}
$APICache = @{}

# Note Policy IDs are unique per tenant

#Global hashtable to hold master copy of trusted users
$GlobalPolicies = @{}

# users will be trusted if they're in AlwaysTrusted or in the policy-specific branch for that policy
# the intent of this script is to defuse (dismiss) obviously-OK "external" sharing alerts
# where the filters have missed some key factor.

$policyDefinitions = Get-ChildItem -Filter "Policy_*.txt"

foreach ($policyDefinitionFile in $policyDefinitions){

    $NewPolicyID = $policyDefinitionFile.Name -replace "Policy_", "" -replace ".txt", ""
    # $NewPolicyID
    Write-Debug "Policy $NewPolicyID"

    $NewPolicyLines = Get-Content $policyDefinitionFile

    $NewPolicyHashtable = @{}

    foreach ($line in $NewPolicyLines){
        if([String]::IsNullOrWhiteSpace($line)){
            continue;
        }
        $trimmed = "$line".Trim()
        if($trimmed.ToLower().Startswith("#disabled")){
            break;
        }
        if($trimmed.StartsWith("#")){
            continue;
        }
        
        Write-Debug "Adding $trimmed"
        $NewPolicyHashtable.Add("$trimmed",$true);
    }

    $GlobalPolicies.Add("$NewPolicyID", $NewPolicyHashtable)

    Write-Debug "New Policy Hashtable: $($NewPolicyHashtable.Keys)"
}

# rehydrate or store the CAS credential for this
if($null -eq $Global:CasCredential){
    Write-Debug -Verbose -Message "Credential needed (think about providing -Token param or using another technique)"
    if(test-path .\CASTOKEN.credential){
        $Global:CasCredential = Import-Clixml .\CASTOKEN.credential
    }
    else{
        $Global:CasCredential = Get-MCASCredential -PassThru 
        $Global:CasCredential | Export-Clixml .\CASTOKEN.Credential
    }
}


foreach ($SinglePolicyID in $PolicyID){ #start of policy loop

    Write-Host -ForegroundColor Yellow "===================================================================="
    Write-Host -ForegroundColor White  "  Retrieving MCAS alerts of type $SinglePolicyID"
    Write-Host -ForegroundColor Yellow "===================================================================="


    # check global policy has loaded (not fatal)
    if(! $GlobalPolicies.ContainsKey("AlwaysTrusted")){
        Write-Host -ForegroundColor Red "Warning - Always Trusted list not loaded"
        sleep 2
    }

    # check policy file has loaded (not fatal)
    if(! $GlobalPolicies.ContainsKey("$SinglePolicyID")){
        Write-Host -ForegroundColor Red "Warning - Policy file not found for $SinglePolicyID"
        sleep 2
    }

    $DefusePile = [System.Collections.ArrayList]@()
    "Get alerts..."
    if($SinceYesterday){
        $filealerts = Get-MCASAlert -Policy $SinglePolicyID -ResultSetSize $ResultSetSize -ResolutionStatus Open -After $SinceYesterdayMCASTime
    }
    elseif($Last48h){
        $filealerts = Get-MCASAlert -Policy $SinglePolicyID -ResultSetSize $ResultSetSize -ResolutionStatus Open -After $Last48hMCASTime
    }
    elseif($Last72h){
        $filealerts = Get-MCASAlert -Policy $SinglePolicyID -ResultSetSize $ResultSetSize -ResolutionStatus Open -After $Last72hMCASTime
    }
    elseif($LastWeek){
        $filealerts = Get-MCASAlert -Policy $SinglePolicyID -ResultSetSize $ResultSetSize -ResolutionStatus Open -After $LastWeekMCASTime
    }
    else {
        $filealerts = Get-MCASAlert -Policy $SinglePolicyID -ResultSetSize $ResultSetSize -ResolutionStatus Open
    }
    "Parsing alerts..."
    ""
    foreach($filealert in $filealerts){

        # note that whether something needs followup is exclusively determined by external file sharing state.
        # if something is shared internally, it's defused by default - so this script is not ideal for internal  
        # DLP policy detection defusal (similar techniques might be)

        $timestamp = ConvertFrom-MCASTimestamp $filealert.timestamp

        "$timestamp - $($filealert._id) - $($filealert.Title)"
        "================================================================================="
        $fileservice = ($filealert.entities | where type -eq "service").label
        $fileIDFromAlert = ($filealert.entities | where type -eq "file").id
        #"Alert ID  : " + $filealert._id
        "Policy ID : $SinglePolicyID" 
        "File ID   : $fileIDFromAlert" 
        "Service   : $fileservice" 

        $file = get-cachedmcasfile $fileIDFromAlert #get-mcasfile $fileIDFromAlert
        #$file = get-mcasfile ($filealert.entities | where type -eq "file").id
        "Filename  : $($file.SharePointItem.name)" 
        "Path      : $($file.filePath)" 
        "Domains   : $($file.domains)" 
        "Owner     : $($file.ownerName) ($($file.ownerAddress))"

        #next API
        $allInterestingCollabs = @{}
        $stillNeedsFollowup = $false

        $interestingCollabs = ( $file.collaborators | Where-Object accesslevel -gt 1)
        foreach ($collab in $interestingCollabs)
        {
            # probably SP/ODfB-specific, so may need mods for other apps
            "ExtCollab : $($collab.name) ($($collab.email))"

            if(! [String]::IsNullOrEmpty($collab.email)){
                # we'll need to come back and process this later
                $allInterestingCollabs.Add($collab.email, $true)
                continue
            }

            if($collab.name -like "*.AnonymousEdit.*"){
                # just an edit link! (Probably disabled by admin, but just in case not...)
                Write-Host -ForegroundColor Red "Anonymous edit link!"
                $stillNeedsFollowup = $true
            }

            # Observed: Site Collection forms part of the group ID when querying /get_group for SP/ODFB at least
            "SiteColl  : $($file.SiteCollection)"
            $groupid = [System.Web.HttpUtility]::UrlEncode("$($file.siteCollection)")
            $groupid +="%7C$($collab.id)"
            "GroupID   : $groupid" # Consolidated Group ID in ready-to-query format
            $query = "/api/v1/get_group/?appId=$($file.AppId)&groupId=$groupid"
            $query +="&limit=100" # just in case this needs to be edited at some point
            Write-Debug " **Query  : $query" # for debug purposes only
            $groupmemberjson = get-CachedMCASAPI -LookupID $query #  GetSomethingFromAPI -apipath $query
            #" ***GroupMemberJSON: $groupmemberjson" # debug only
            $groupmembers = ConvertFrom-Json $groupmemberjson

            foreach ($member in $groupmembers.group.membersList){
                if(CollaboratorTrustedforPolicy -Membername $member.emailAddress -Policy $SinglePolicyID)
                {
                    Write-Host -ForegroundColor Green " Trusted  : $($member.name) ($($member.emailAddress))"
                    # multiple users might be considered per policy, so can't
                    # defuse policy match based on one match - do nothing
                }
                else{
                    Write-Host " Member   : $($member.emailAddress)"     
                    # not-explicitly-trusted user found - so still needs review
                    $stillNeedsFollowup = $true
                }
                #" Member   : " + $member.name + " (" + $member.emailAddress + ")"
                #$allInterestingCollabs.Add($member.emailAddress, $true)
            }
        }

        # second pass for the ExtCollabs which are directly named (i.e. didn't need group expansion)
        foreach($membername in $allInterestingCollabs.Keys){
            # rules go here
            if(CollaboratorTrustedforPolicy -Membername $membername -Policy $SinglePolicyID)
            {
                # multiple users might be considered per policy, so can't
                # defuse policy match based on one match - do nothing
            }
            else{
                # not-explicitly-trusted user found - so still needs review
                $stillNeedsFollowup = $true
            }
        }
        

        if($stillNeedsFollowup -eq $false){
            
            $null=$DefusePile.Add("$($filealert._id)")
            $defusecount = $DefusePile.Count

            Write-Host -ForegroundColor Yellow "DEFUSE! (Count: $defusecount)"
        }
        "" # ya gotta keep em separated
    }
    # testing needs to get us to a place where we're happy with 100% of the Defuse Pile
    # Defuse Pile doesn't need to get to 100% *coverage*, but needs to be 100% defuse-correct by policy
    # So that if the script defuses the alerts, it doesn't defuse more than known-good ones

    ""
    "Alerts in defuse pile:"
    $DefusePile

    #$DefusePile | export-csv -NoTypeInformation .\Log-DismissAttempted-$isodatetime.csv 
    ""

    $pagesize = 100;
    $defusalcount = $DefusePile.Count

    if($defusalcount -gt 0){
        if($Commit){

            if($defusalcount -gt $pagesize){
                
                
                for($i = 0; $i -lt $defusalcount;){

                    $PagePile = [System.Collections.ArrayList]@()

                    if(($i + $pagesize) -ge $defusalcount){
                        # last batch 
                        "Defusing last batch $i to $($defusalcount) ($($defusalcount -$i) records)"
                        $PagePile.AddRange($DefusePile.GetRange($i,$defusalcount - $i));
                    } else {
                        "Defusing batch $i to $($i+$pagesize) ($pagesize) records)"
                        $PagePile.AddRange($DefusePile.GetRange($i,$pagesize))
                    }

                    # Defuse PagePile Here
                    Set-MCASAlert -BulkDismiss $PagePile
                    
                    $i += $pagesize;
                }
            } else {
            # run bulk dismiss
            "Calling Set-MCASAlert to Bulk Dismiss..."
            Set-MCASAlert -BulkDismiss $DefusePile
            }
        }
        else{
            Write-Host -ForegroundColor Magenta "Run with -Commit to action alerts"
            ""
        }
    } else{
        Write-Host -ForegroundColor Green "No alerts to defuse on this run."
        ""
    }
    write-host "Policy $SinglePolicyID done."
    ""

} #end of multi Policy loop

Stop-Transcript 
