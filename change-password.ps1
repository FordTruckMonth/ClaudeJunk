# change-password.ps1 — examples of changing passwords in PowerShell.
#
# This script demonstrates the common PowerShell commands for changing
# passwords. Most operations require running PowerShell as Administrator.

# --- Method 1: Change a LOCAL user's password (Windows 10/11, Server 2016+) ---
# Uses the Microsoft.PowerShell.LocalAccounts module (built-in).
#
#   $NewPassword = Read-Host -AsSecureString "Enter new password"
#   Set-LocalUser -Name "username" -Password $NewPassword
#
# Or non-interactively (avoid in scripts checked into source control):
#
#   $NewPassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
#   Set-LocalUser -Name "username" -Password $NewPassword


# --- Method 2: Change the CURRENT user's password ---
# The classic way uses the net.exe utility:
#
#   net user $env:USERNAME *
#
# PowerShell will prompt twice for the new password.


# --- Method 3: Change a DOMAIN user's password (Active Directory) ---
# Requires the ActiveDirectory module (RSAT).
#
#   $NewPassword = Read-Host -AsSecureString "Enter new password"
#   Set-ADAccountPassword -Identity "username" -NewPassword $NewPassword -Reset
#
# Force the user to change it at next logon:
#
#   Set-ADUser -Identity "username" -ChangePasswordAtLogon $true


# --- Method 4: Change your OWN domain password (no admin rights needed) ---
#
#   $OldPassword = Read-Host -AsSecureString "Current password"
#   $NewPassword = Read-Host -AsSecureString "New password"
#   Set-ADAccountPassword -Identity $env:USERNAME `
#                         -OldPassword $OldPassword `
#                         -NewPassword $NewPassword


# --- Interactive helper ---
# Running this script prompts for a username and new password, then changes
# the LOCAL account password. Requires Administrator.

param(
    [string]$UserName
)

if (-not $UserName) {
    $UserName = Read-Host "Local username to update"
}

$user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (-not $user) {
    Write-Host "Local user '$UserName' not found." -ForegroundColor Red
    exit 1
}

$pw1 = Read-Host -AsSecureString "New password"
$pw2 = Read-Host -AsSecureString "Confirm new password"

$plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw1))
$plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw2))

if ($plain1 -ne $plain2) {
    Write-Host "Passwords do not match." -ForegroundColor Red
    exit 1
}

try {
    Set-LocalUser -Name $UserName -Password $pw1
    Write-Host "Password updated for '$UserName'." -ForegroundColor Green
} catch {
    Write-Host "Failed to update password: $_" -ForegroundColor Red
    exit 1
}
