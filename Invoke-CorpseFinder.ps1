<#
.SYNOPSIS
    CorpseFinder - Finds ownership of computer objects in Active Directory, replaces owner if requested, and can remove "Full Control" (GenericAll) permissions for a specified user.

.DESCRIPTION
    CorpseFinder allows administrators and security teams to audit and remediate owner and ACL scenarios on Active Directory computer objects. 
    It can list all computers owned by a specified user, change ownership to another user/group, and remove "Full Control" rights (GenericAll) safely. 
    The script is designed for both broad domain-wide sweeps and targeted single-object operations. Fine-grained control is provided via its parameters.
    Main reason is when employees are switching departments and the possibility for RBCD Attacks still lives on as long as the user can write specific attributes to the object.
    The Name is from the german idiom "Leichen im Keller" aka "have a skeleton in the closet" :)

.PARAMETER owner
    The user or group whose ownership or permissions you want to audit on AD computer objects. Supports domain\username format.

.PARAMETER computerName
    (Optional) Limits the search and operations to a single computer account.

.PARAMETER replace
    (Optional) If provided, replaces the AD object owner with the supplied user or group.

.PARAMETER RemoveFullControl
    (Optional) If specified and set to $true, removes "Full Control" (GenericAll) permissions for the owner account.

.EXAMPLE
    # Only search for Owner for this user
    .\CorpseFinder.ps1 -owner <USERNAME>

.EXAMPLE
    # Search for Owner of a specific computer object
    .\CorpseFinder.ps1 -owner <USERNAME> -computerName <HOST>

.EXAMPLE
    # Remove owner's "Full Control" permission from a specific computer object
    .\CorpseFinder.ps1 -owner <USERNAME> -computerName <HOST> -RemoveFullControl $true

.EXAMPLE
    # Remove "Full Control" and change owner for a specific object (Domain Admin required)
    .\CorpseFinder.ps1 -owner <USERNAME> -computerName <HOST> -RemoveFullControl $true -replace "Domain Admins"

.NOTES
    PowerShell script by Matthias Hoffmann

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>



function Invoke-CorpseFinder {
    param(
        [Parameter(Mandatory=$true)]
        [string]$owner,
        [string]$replace,
        [string]$computerName,
        [bool]$RemoveFullControl
    )

    $corpsefinderBanner = @"
_________                                 ___________.__            .___             
\_   ___ \  _________________  ______ ____\_   _____/|__| ____    __| _/___________  
/    \  \/ /  _ \_  __ \____ \/  ___// __ \|    __)  |  |/    \  / __ |/ __ \_  __ \ 
\     \___(  <_> )  | \/  |_> >___ \\  ___/|     \   |  |   |  \/ /_/ \  ___/|  | \/ 
 \______  /\____/|__|  |   __/____  >\___  >___  /   |__|___|  /\____ |\___  >__|    
        \/             |__|       \/     \/    \/            \/      \/    \/            
"@

    Import-Module ActiveDirectory
    $domain = (Get-ADDomain).NetBIOSName
    $tab_char = [char]9

    # Counters
    $Global:TotalOwnersChanged = 0
    $Global:TotalAcesRemoved   = 0
    $Global:TotalMatches       = 0

    function IsUserOwner {
        param(
            [string]$computerName,
            [string]$userName
        )
        try {
            $owner = (Get-ADComputer $computerName -Properties NTSecurityDescriptor).NTSecurityDescriptor.owner
            return $owner -like "*$userName*"
        } catch {
            Write-Warning "[!] Could not get owner for $computerName : $_"
            return $false
        }
    }


    function IsPotentiallyInactive {
        param([string]$computerName)

        try {
            $computer = Get-ADComputer -Identity $computerName -Properties pwdLastSet
            if (-not $computer) { return $false }

            
            $lastSet = [DateTime]::FromFileTimeUtc($computer.pwdLastSet)
            $hostname = $computer.Name
            $thresholdDate = (Get-Date).AddDays(-30)

            if ($lastSet -lt $thresholdDate) {
                Write-Host "`t[+] Match: $hostname - potential inactive (pwdLastSet older than 30 days)"
                return $true
            }
            return $false
        } catch {
            Write-Warning "[!] Error checking pwdLastSet for $computerName : $_"
            return $false
        }
    }

function Set-ComputerObjectOwner {
    param (
        [Parameter(Mandatory=$true)]
        [string]$NewOwner,

        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    

    
    $rootDSE = Get-ADRootDSE
    $baseDN = $rootDSE.defaultNamingContext
    $owner = Get-ADUser -Filter {SamAccountName -eq $NewOwner} -SearchBase $baseDN -ErrorAction SilentlyContinue
    
    if (-not $owner) {
        $owner = Get-ADGroup -Filter {SamAccountName -eq $NewOwner} -SearchBase $baseDN -ErrorAction SilentlyContinue
    }

    if (-not $owner) {
        Write-Error "[!] User or group '$NewOwner' not found in Active Directory."
        return
    }

    
    $computer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
    $ntAccount = New-Object System.Security.Principal.NTAccount($owner.SamAccountName)
    $acl = Get-Acl "AD:$($computer.DistinguishedName)"
    $acl.SetOwner($ntAccount)

    
    try {
        Set-Acl -Path "AD:$($computer.DistinguishedName)" -AclObject $acl
        Write-Output "`t `t[+] Ownership of computer account '$ComputerName' successfully changed to '$NewOwner'."
    }
    catch {
        Write-Error "[!] Failed to set ownership: $_"
    }
}




    function Remove-UserAclEntries {
        param(
            [Parameter(Mandatory = $true)]
            [string]$DistinguishedName,
            [Parameter(Mandatory = $true)]
            [string]$User
        )
        try {
            $domain = (Get-ADDomain).NetBIOSName
            $userAccount = (Get-ADUser -Identity $User).SamAccountName
            $userPrincipal = New-Object System.Security.Principal.NTAccount("$domain\$userAccount")

            $acl = Get-Acl -Path "AD:$DistinguishedName" -ErrorAction Stop
            $beforeCount = ($acl.Access | Where-Object { $_.IdentityReference -ieq $userPrincipal.Value }).Count

            if ($beforeCount -gt 0) {
                $acl.PurgeAccessRules($userPrincipal)
                Set-Acl -Path "AD:$DistinguishedName" -AclObject $acl -ErrorAction Stop
                $Global:TotalAcesRemoved++
                Write-Host "`t `t[+] Removed all ACEs for $($userPrincipal.Value) on $DistinguishedName"
            } else {
                Write-Host "`t `t[!] No ACEs found for $($userPrincipal.Value) on $DistinguishedName"
            }
        } catch {
            Write-Warning "[!] Failed to remove ACEs for $User : $_"
        }
    }

    Write-Host $corpsefinderBanner -ForegroundColor Cyan
    Write-Host "[*] Checking Domain =>  $domain"

    if ($computerName) {
        $computers = @(Get-ADComputer -Identity $computerName -Properties DistinguishedName)
        if (-not $computers) {
            Write-Warning "[-] Computer account '$computerName' not found."
            return
        }
    } else {
        $computers = Get-ADComputer -Filter * -Properties DistinguishedName
    }

    $SumAccounts = $computers.Count
    Write-Host "[*] Found $SumAccounts Computer accounts in domain"
    Write-Host "[*] Looking for computers where user '$owner' is the owner"

    if ($PSBoundParameters.ContainsKey('replace')) {
        Write-Host "[*] Owner replacement is enabled. Owners will be changed to '$replace'."
    }

    if ($RemoveFullControl -eq $true) {
        Write-Host "[!] RemoveFullControl is set. 'Full Control' ACE will be removed."
    }

    Write-Host "[!] This could take a while in bigger environments."
    Write-Host ""

    foreach ($computer in $computers) {
        if (IsUserOwner -computerName $computer.Name -userName $owner) {
            if (IsPotentiallyInactive -computerName $computer){
                $Global:TotalMatches++
            } else {
                Write-Host "`t[+] Match: $($computer.Name)"
                $Global:TotalMatches++
            }

            if ($PSBoundParameters.ContainsKey('replace')) {
                Set-ComputerObjectOwner -Computer $computer.Name -NewOwner $replace
                foreach ($msg in $results) { Write-Host "`t$msg" }
            }
            if ($RemoveFullControl -eq $true) {
                Remove-UserAclEntries -DistinguishedName $computer.DistinguishedName -User $owner
            }
        }
    }

    Write-Host ""
    Write-Host "===== SUMMARY ====="
    Write-Host "Total objects owned$tab_char : $Global:TotalMatches"
    Write-Host "Ownerships changed$tab_char : $Global:TotalOwnersChanged"
    Write-Host "ACE entries removed$tab_char : $Global:TotalAcesRemoved"
    Write-Host "===================="
}
