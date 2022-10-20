<#	
  .Synopsis
    This powershell script to add Admin User Groups into Workspace ONE & set Admin Role to OG
  .NOTES
    Created:   	October, 2022
    Created by:	Phil Helmling, @philhelmling
    Organization: VMware, Inc.
    Filename:     createWS1AdminGroups.ps1
    Github:       https://github.com/helmlingp/WS1UEM_Scripts
  .DESCRIPTION
    This powershell script to add Admin User Groups into Workspace ONE & set Admin Role to OG
  .REQUIREMENTS
    1. AD / LDAP Directory integrated into WS1 Console and User Group(s) searchable  
    2. Username, Password, APIKey and Server FQDN to API Server, and ADDomain to associate with
    3. Path and filename to CSV file formatted with the following header:
      UserGroup,OGName,ADDomain
    

    Headers
      UserGroup is the AD User Group being added to as an Admin User Group
      OGName is the Organization Group where you want to enrol the device into
      Role is Console Role being added to the UserGroup at the OGName
      
  .EXAMPLE
    powershell.exe -ep bypass -file .\createWS1AdminGroups.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_APISERVER_FQDN -APIKey API_Key -OGName OGName -ADDomain ADDomain -file FilePathFileName

#script for smart group creation with AD Group as members
##create script to create smart groups for each AD group read from CSV, create smart group in OG provided in CSV and add AD Group eg SG_ADGROUP##
#>
param (
    [Parameter(Mandatory=$false)][string]$Username,
    [Parameter(Mandatory=$false)][string]$Password,
    [Parameter(Mandatory=$false)][string]$Server,
    [Parameter(Mandatory=$false)][string]$APIKey,
    [Parameter(Mandatory=$false)][string]$OGName,
    [Parameter(Mandatory=$false)][string]$ADDomain,
    [Parameter(Mandatory=$false)][string]$file
)

[string]$psver = $PSVersionTable.PSVersion

#Enable Debug Logging
$Debug = $false

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = Get-Location
} 
$DateNow = Get-Date -Format "yyyyMMdd_hhmm"
$scriptName = $MyInvocation.MyCommand.Name
$logLocation = "$current_path\$scriptName_$DateNow.log"

if($Debug){
  write-host "Current Path: $current_path"
  write-host "LogLocation: $LogLocation"
}

function Write-Log2{
  [CmdletBinding()]
  Param(
    [string]$Message,
    [Alias('LogPath')][Alias('LogLocation')][string]$Path=$Local:Path,
    [Parameter(Mandatory=$false)][ValidateSet("Success","Error","Warn","Info")][string]$Level="Info"
  )

  $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
  $FontColor = "White";
  If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
  $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Add-Content -Path $Path -Value ("$DateNow`t($Level)`t$Message")
  Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
}

Function Invoke-setupServerAuth {

  if ([string]::IsNullOrEmpty($Server)){
      $Server = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name'
      $private:Username = Read-Host -Prompt 'Enter the Username'
      $SecurePassword = Read-Host -Prompt 'Enter the Password' -AsSecureString
      $APIKey = Read-Host -Prompt 'Enter the API Key'
      $OGName = Read-Host -Prompt 'Enter the Organizational Group Name'
      $ADDomain = Read-Host -Prompt 'Enter the AD Domain as it appears in the Customer OG Enterprise Directory config'
      $file = Read-Host -Prompt 'Enter the full path and filename of the CSV file to read'

      #Convert the Password
      if($psver -lt 7){
        #Powershell 6 or below
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
      } else {
        #Powershell 7 or above
        $Password = ConvertFrom-SecureString $SecurePassword -AsPlainText
      }
    }

  #Base64 Encode AW Username and Password
  $private:combined = $Username + ":" + $Password
  $private:encoding = [System.Text.Encoding]::ASCII.GetBytes($private:combined)
  $private:encoded = [Convert]::ToBase64String($private:encoding)
  $cred = "Basic $encoded"

  $combined = $Username + ":" + $Password
  $encoding = [System.Text.Encoding]::ASCII.GetBytes($combined)
  $encoded = [Convert]::ToBase64String($encoding)
  $cred = "Basic $encoded"
  if($Debug){ 
    Write-host `n"Server Auth" 
    write-host "WS1 Host: $Server"
    write-host "Base64 creds: $cred"
    write-host "APIKey: $APIKey"
    write-host "OG Name: $OGName"
  }
}

function Invoke-GetOG {
  param(
    [Parameter(Mandatory=$true)][string]$OGName
  )
  #Search for the OG Name and return GroupUUID and GroupID attributes.
  #Present list if multiple OGs with those search characters and allow selection
  
  $url = "$server/API/system/groups/search?name=$OGName"
  
  $header = @{'aw-tenant-code' = $APIKey;'Authorization' = $cred;'accept' = 'application/json;version=2';'Content-Type' = 'application/json'}
  try {
    $OGSearch = Invoke-RestMethod -Method Get -Uri $url.ToString() -Headers $header
  }
  catch {
    throw "Server Authentication or Server Connection Failure $($_.Exception.Message)`n`n`tExiting"
  }

  $OGSearchOGs = $OGSearch.OrganizationGroups
  $OGSearchTotal = $OGSearch.TotalResults
  if($OGSearchTotal -eq 0){
    Write-Log2 -Path $LogLocation -Message "`nOGs not found. Please create OG then run script again" -Level Error
    continue
  } elseif ($OGSearchTotal -eq 1){
    $Choice = 0
  } elseif ($OGSearchTotal -gt 1) {
    $ValidChoices = 0..($OGSearchOGs.Count -1)
    $ValidChoices += 'Q'
    Write-Log2 -Path $LogLocation -Message "`nMultiple OGs found. Please select an OG from the list:" -Level Warn
    $Choice = ''
    while ([string]::IsNullOrEmpty($Choice)) {

      $i = 0
      foreach ($OG in $OGSearchOGs) {
        Write-Host ('{0}: {1}    {2}    {3}' -f $i, $OG.name, $OG.GroupId, $OG.Country)
        $i += 1
      }

      $Choice = Read-Host -Prompt 'Type the number that corresponds to the Baseline to report on or Press "Q" to quit'
      if ($Choice -in $ValidChoices) {
        if ($Choice -eq 'Q'){
          Write-Log2 -Path LogLocation -Message "Q selected, existing script" -Level Error
          exit
        } else {
          $Choice = $Choice
        }
      } else {
        [console]::Beep(1000, 300)
        Write-host ('`t[ {0} ] is NOT a valid selection.' -f $Choice)
        Write-host '`tPlease try again ...'
        pause

        $Choice = ''
      }
    }
  }
  return $OGSearchOGs[$Choice]
}

function Invoke-GetDomainGroups {
  param(
    [Parameter(Mandatory=$true)][string]$groupuuid
  )
  $json = @'
  {"organization_group_uuids":["$groupuuid"]}
'@
  $body = ConvertTo-Json -InputObject $json -Depth 100

  $url = "$server/api/system/usergroups/search"
  $header = @{'aw-tenant-code' = $APIKey;'Authorization' = $cred;'accept' = 'application/json;version=1';'Content-Type' = 'application/json'}
  try {
    $Response = Invoke-RestMethod -Method Get -Uri $url.ToString() -Headers $header
    $ADGroups = $Response
  }
  catch {
    throw "Server Authentication or Server Connection Failure $($_.Exception.Message)`n`n`tExiting"
  }
  return $ADGroups
}

function Invoke-GetSmartGroups {
  
  $url = "$server/api/mdm/smartgroups/search"
  $header = @{'aw-tenant-code' = $APIKey;'Authorization' = $cred;'accept' = 'application/json;version=2';'Content-Type' = 'application/json'}
  try {
    $Response = Invoke-RestMethod -Method Get -Uri $url.ToString() -Headers $header
    $SmartGroups = $Response.smart_groups
  }
  catch {
    throw "Server Authentication or Server Connection Failure $($_.Exception.Message)`n`n`tExiting"
  }
  return $SmartGroups
}

function Invoke-CreateSG {
  param(
    [Parameter(Mandatory=$true)][string]$newSG,
    [Parameter(Mandatory=$true)][string]$managedbyOGid,
    [Parameter(Mandatory=$true)][string]$UserGroup,
    [Parameter(Mandatory=$true)][string]$UserGroupid
  )
  Write-Log2 -Path $logLocation -Message "Creating Smart Group $newSG in $managedbyOGid OG" -Level Info
  $json = [ordered]@{
  Name= $newSG
  CriteriaType= "All"
  ManagedByOrganizationGroupId= $managedbyOGid
  UserGroups= @(
      @{
          Name= $UserGroup
          Id= $UserGroupid
        }
  )
  Tags= @()
  Ownerships= @(
    "allownerships"
  )
  Platforms= @()
  Models= @()
  OperatingSystems= @()
  UserAdditions= @()
  DeviceAdditions= @()
  UserExclusions= @()
  DeviceExclusions= @()
  UserGroupExclusions= @()
  ManagementTypes= @()
  EnrollmentCategories= @()
  OEMAndModels= @()
  CPUArchitectures= @()
}
  $body = ConvertTo-Json -InputObject $json -Depth 100
  $url = "$server/api/mdm/smartgroups"
  $header = @{'aw-tenant-code' = $APIKey;'Authorization' = $cred;'accept' = 'application/json;version=1';'Content-Type' = 'application/json'}
  try {
    $Response = Invoke-RestMethod -Method POST -Uri $url.ToString() -Headers $header -Body $body
    $SmartGroups = $Response.SmartGroups

    Write-Log2 -Path "$LogLocation" -Message "Created $newSG Smart Group with $userGroup AD Group as member in $managedbyOGid OG"
  }
  catch {
    throw "Server Authentication or Server Connection Failure $($_.Exception.Message)`n`n`tExiting"
  }
  return $SmartGroups  
}

function Main {
  if ([string]::IsNullOrEmpty($file)){
    $file = Read-Host -Prompt 'Enter the full path and filename of the CSV file to read'
   } else {
    if(Test-Path -Path $file){
      #write-host "test-path true"
    } else {
      Write-Log2 -Path "$logLocation" -Message "Please supply the path and filename to a CSV file to run the script" -Level Error
      break
    }
  }
  if(Test-Path -Path $file){
    $csv = Import-Csv $file
  }

  Invoke-setupServerAuth
  
  #get parent OG UUID
  $getOG = Invoke-GetOG -OGName $OGName
  $groupname = $getOG.Name
  $groupuuid = $getOG.Uuid
  $groupid = $getOG.Id

  #Get list of User Groups already added to WS1 UEM
  $ADGroups = Invoke-GetDomainGroups -groupuuid $groupuuid

  #Get list of Smart Groups
  $allSmartGroups = Invoke-GetSmartGroups

  foreach($item in $csv){
    $UserGroup = $item.UserGroup
    $managedbyOG = $item.OGName
    #$Role = $item.Role
    #$Domain = $item.ADDomain

    $newSG = "SG_$UserGroup"
    $SGsearch = $allSmartGroups | Where-Object {($_.Name) -eq "$newSG"}
    if($SGsearch){
      Write-Log2 -Path "$LogLocation" -Message "Smart Group $newSG exists" -Level Info
      #$addSG = $false
    } else {
      Write-Log2 -Path "$LogLocation" -Message "Smart Group $newSG does not exist" -Level Info
      #$addSG = $true
      
      if($managedbyOG -eq $OGName){
        [string]$managedbyOGid = $groupid
        #Write-Log2 -Path "$logLocation" -Message "OG $OGName exists, using ManagedbyOG $managedbyOGid / $groupid" -Level Info
      } else {
        #get target OG details for new SG
        $getOG = Invoke-GetOG -OGName $managedbyOG
        [string]$groupname = $getOG.Name
        [string]$groupuuid = $getOG.Uuid
        #[string]$groupid = $getOG.Id
        [string]$managedbyOGid = $getOG.id
      }
      
      $ADGroupsearch = $ADGroups.ResultSet | Where-Object {($_.groupName) -eq $UserGroup}
      if($ADGroupsearch){
        Write-Log2 -Path "$logLocation" -Message "AD Group $UserGroup exists" -Level Info
        $UserGroupid = $ADGroupsearch.Id
      } else {
        Write-Log2 -Path "$logLocation" -Message "AD Group ""$UserGroup"" does not exist, please add before running again" -Level Error
        continue
        #Invoke-AddADGroup -UserGroup $UserGroup
      }
      $createSG = Invoke-CreateSG -newSG $newSG -managedbyOGid $managedbyOGid -UserGroup $UserGroup -UserGroupid $UserGroupid
      
      #Get updated list of Smart Groups
      $allSmartGroups = Invoke-GetSmartGroups

    }
  }
}


Main