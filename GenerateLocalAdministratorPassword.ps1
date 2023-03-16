# Description: Generate a randomized strong password and set on the local Administrator account
# Execution Context: System
# Execution Architecture: EITHER64OR32BIT
# Timeout: 30
# Variables: PasswordLenght,12; AdminUser,Administrator


Function Invoke-GenerateStrongPassword {
  param (
    [Parameter(Mandatory=$true)]
    [int]$PasswordLength
  )
  Add-Type -AssemblyName System.Web
  $PassComplexCheck = $false
  do {
  $newPassword=[System.Web.Security.Membership]::GeneratePassword($PasswordLength,1)
  If ( ($newPassword -cmatch "[A-Z\p{Lu}\s]") `
  -and ($newPassword -cmatch "[a-z\p{Ll}\s]") `
  -and ($newPassword -match "[\d]") `
  -and ($newPassword -match "[^\w]")
  )
  {
  $PassComplexCheck=$True
  }
  } While ($PassComplexCheck -eq $false)
  return $newPassword
}

Functon Invoke-SetPassword {
  Param(
    [Parameter(Mandatory=$True)]
    [string]$newpwd,
    [Parameter(Mandatory=$True)]
    [string]$AdminUser
  )

  try {
    Set-LocalUser -Name $AdminUser -Password $newpwd -PasswordNeverExpires $false -UserMayChangePassword $false -Confirm $false
  }
  catch {
    Exit 1
  }
}

$newpwd = Invoke-GenerateStrongPassword -PasswordLength $env:PasswordLength
Invoke-SetPassword -newpwd $newpwd -AdminUser $env:AdminUser
