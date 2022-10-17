<#	
  .Synopsis
    This powershell script pre-registers devices into Workspace ONE
  .NOTES
    Created:   	October, 2022
    Created by:	Phil Helmling, @philhelmling
    Organization: VMware, Inc.
    Filename:     preRegisterWS1.ps1
    Github:       https://github.com/helmlingp/WS1UEM_Scripts
  .DESCRIPTION
    This powershell script reads a CSV file and pre-registers devices into Workspace ONE.
  .REQUIREMENTS
    Username, Password, APIKey and Server FQDN to API Server
    Path and filename to CSV file formatted with the following header:
      Device,Serial,OGName,Type,Staging

    Headers
      Device is the Device Friendly Name which is usually the computername
      Serial is the Serial Number which can be obtained on windows by running "wmic bios get serialnumber", but ideally this should be obtained from your current device management tool
      OGName is the Organization Group where you want to enrol the device into
      Type is the Device Type - Dedicated, Shared, Employee
      Staging is the staging username to pre-stage the enrolment. Can also register against the actual user
  .EXAMPLE
    powershell.exe -ep bypass -file .\preRegisterWS1.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_APISERVER_FQDN -APIKey API_Key -file FilePathFileName

    CSV Example
    Device,Serial,OGName,Type,Staging
    win10001,823972,TESTOG,CS,staging@TESTOG.com
    win10002,833972,TESTOG,CD,staging@TESTOG.com
    win10003,843972,TESTOG,EO,BYOUser1
#>
param (
    [Parameter(Mandatory=$false)][string]$Username,
    [Parameter(Mandatory=$false)][string]$Password,
    #[Parameter(Mandatory=$false)][string]$OGName,
    [Parameter(Mandatory=$false)][string]$Server,
    [Parameter(Mandatory=$false)][string]$APIKey,
    [Parameter(Mandatory=$true)][string]$file
)

[string]$psver = $PSVersionTable.PSVersion
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = ".";
}

$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$pathfile = "$current_path"
$logLocation = "$pathfile" + "/preRegister_$DateNow.log";

Function Invoke-setupServerAuth {

  if ([string]::IsNullOrEmpty($script:Server)){
      $script:Server = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name'
      $private:Username = Read-Host -Prompt 'Enter the Username'
      $SecurePassword = Read-Host -Prompt 'Enter the Password' -AsSecureString
      $script:APIKey = Read-Host -Prompt 'Enter the API Key'
      #$script:OGName = Read-Host -Prompt 'Enter the Organizational Group Name'
    
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
  $script:cred = "Basic $encoded"

  $combined = $Username + ":" + $Password
  $encoding = [System.Text.Encoding]::ASCII.GetBytes($combined)
  $encoded = [Convert]::ToBase64String($encoding)
  $cred = "Basic $encoded"
  if($Debug){ 
    Write-host `n"Server Auth" 
    write-host "WS1 Host: $script:Server"
    write-host "Base64 creds: $script:cred"
    write-host "APIKey: $script:APIKey"
    #write-host "OG Name: $script:OGName"
  }
}

function Invoke-GetOG {
  param(
    [Parameter(Mandatory=$true)]
    [string]$OGName
  )
  #Search for the OG Name and return GroupUUID and GroupID attributes.
  #Present list if multiple OGs with those search characters and allow selection

  $url = "$script:server/API/system/groups/search?name=$OGName"
  $header = @{'aw-tenant-code' = $script:APIKey;'Authorization' = $script:cred;'accept' = 'application/json;version=2';'Content-Type' = 'application/json'}
  try {
    $OGSearch = Invoke-RestMethod -Method Get -Uri $url.ToString() -Headers $header
  }
  catch {
    throw "Server Authentication or Server Connection Failure $($_.Exception.Message)`n`n`tExiting"
  }

  $OGSearchOGs = $OGSearch.OrganizationGroups
  $OGSearchTotal = $OGSearch.TotalResults
  if ($OGSearchTotal -eq 1){
    $Choice = 0
  } elseif ($OGSearchTotal -gt 1) {
    $ValidChoices = 0..($OGSearchOGs.Count -1)
    $ValidChoices += 'Q'
    Write-Host "`nMultiple OGs found. Please select an OG from the list:" -ForegroundColor Yellow
    $Choice = ''
    while ([string]::IsNullOrEmpty($Choice)) {

      $i = 0
      foreach ($OG in $OGSearchOGs) {
        Write-Host ('{0}: {1}       {2}       {3}' -f $i, $OG.name, $OG.GroupId, $OG.Country)
        $i += 1
      }

      $Choice = Read-Host -Prompt 'Type the number that corresponds to the Baseline to report on or Press "Q" to quit'
      if ($Choice -in $ValidChoices) {
        if ($Choice -eq 'Q'){
          Write-host " Exiting Script"
          exit
        } else {
          $Choice = $Choice
        }
      } else {
        [console]::Beep(1000, 300)
        Write-host ('    [ {0} ] is NOT a valid selection.' -f $Choice)
        Write-host '    Please try again ...'
        pause

        $Choice = ''
      }
    }
  }
  return $OGSearchOGs[$Choice]
}

function ValidateEmail($address) {
  $address -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$"
}

function Invoke-GetUserUUID {
  param(
    [Parameter(Mandatory=$true)]
    [string]$Staging
  )
  #test if email address provided
  if(ValidateEmail $Staging){
    $url = "$script:server/API/system/users/search?email=$Staging"
  } else {
    $url = "$script:server/API/system/users/search?username=$Staging"
  }
  $header = @{'aw-tenant-code' = $APIKey;'Authorization' = $cred;'accept' = 'application/json;version=2';'Content-Type' = 'application/json'}
  try {
    $userSearch = Invoke-RestMethod -Method Get -Uri $url.ToString() -Headers $header
  }
  catch {
    throw "Server Authentication or Server Connection Failure $($_.Exception.Message)`n`n`tExiting"
  }
  return $userSearch
}


function Write-Log2{
  [CmdletBinding()]
  Param(
      [string]$Message,
      [Alias('LogPath')]
      [Alias('LogLocation')]
      [string]$Path=$Local:Path,
      [Parameter(Mandatory=$false)]
      [ValidateSet("Success","Error","Warn","Info")]
      [string]$Level="Info"
  )

  $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
  $FontColor = "White";
  If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
  $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
  Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
}

function Main {
  if ([string]::IsNullOrEmpty($script:file)){
    $file = Read-Host -Prompt 'Enter the full path and filename of the CSV file to read'
    if(Test-Path -Path $file){
      $csv = Import-Csv $file
    } else {
      Write-Log2 -Path "$logLocation" -Message "Please supply the path and filename to a CSV file" -Level Error
      break
    }
  }
  
  Invoke-setupServerAuth
  
  foreach($item in $csv){
    $Device = $_.Device
    $Serial = $_.Serial
    $OGName = $_.OGName
    $Type = $_.Type
    $Staging = $_.Staging

    #Set device type
    if($Type -eq "CS") {
      $ownership_type = "CORPORATE_SHARED"
    } elseif($Type -eq "CD") {
      $ownership_type = "CORPORATE_DEDICATED"
    } elseif($Type -eq "EO") {
      $ownership_type = "EMPLOYEE_OWNED"
    } else {
      $ownership_type = ""
    }
    
    #get OG
    $getOG = Invoke-GetOG -OGName $OGName
    $groupuuid = $getOG.Uuid
    $groupid = $getOG.Id

    #get user UUID
    $getuserUUID = Invoke-GetUserUUID -Staging $Staging
    $userUUID = $getuserUUID.users.uuid
  
$json = @"
{
  "registration_type": "REGISTER_DEVICE",
  "device_registration_record": {
    "user_uuid": "$userUUID",
    "friendly_name": "$Device",
    "ownership_type": "$ownership_type",
    "platform_id": 12,
    "model_id": 83,
    "operating_system_id": 3,
    "device_udid": "",
    "serial_number": "$Serial",
    "to_email_address": "$Staging"
  }
}
"@
  
    $url = "$script:server/API/mdm/groups/$groupuuid/enrolment-tokens"
    $header = @{'aw-tenant-code' = $APIKey;'Authorization' = $cred;'accept' = 'application/json;version=2';'Content-Type' = 'application/json'}
    try {
      $preregister = Invoke-RestMethod -Method Put -Uri $url.ToString() -Headers $header -Body $json
      Write-Log2 -Path "$logLocation" -Message "$preregister" -Level Info
    } catch {
      throw "Server Authentication or Server Connection Failure $($_.Exception.Message)`n`n`tExiting"
    }

  }
}

Main