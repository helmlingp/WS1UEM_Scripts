<#	
  .Synopsis
    Script to remove user from local Administrators group
  .NOTES
    Created:   	    April, 2023
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       RemoveEnrolmentUserfromLocalAdmins.ps1
    GitHub:         https://github.com/helmlingp/WS1UEM_Scripts
  .DESCRIPTION
    Script to remove the enrolment user from local Administrators group
    
  .EXAMPLE
    powershell.exe -ep bypass -file .\RemoveEnrolmentUserfromLocalAdmins.ps1
#>

#Getting UPN from MDM Enrollment
$enrolid = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*" -ErrorAction SilentlyContinue).PSChildname
#loops through in case of more than one GUID on the system
foreach ($row in $enrolid) {
    $PATH2 = "HKLM:\SOFTWARE\Microsoft\Enrollments\$row"
    $upn = (Get-ItemProperty -Path $PATH2 -ErrorAction SilentlyContinue).UPN
    $SID = (Get-ItemProperty -Path $PATH2 -ErrorAction SilentlyContinue).SID
}

$process = Invoke-Command -ScriptBlock {cmd.exe /c "net localgroup Administrators $upn /delete"}
if($process -eq "The command completed successfully.") {
  exit 0
} else {
  exit 1
}