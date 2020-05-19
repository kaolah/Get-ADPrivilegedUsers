<#
.Synopsis
   Get a list of members of the Active Directory Privileged Groups in single domain forest
.DESCRIPTION
   Read a list of computer names from a file. Query each computer for the local administrators group. Output the list of local administrators to a CSV file.
.NOTE
This might not  work on 100%.
#>


$Folder = "C:\temp\AdminGroups"

If (!(Test-path $Folder)) {
	new-item -path $Folder -itemType Directory -force
    }


$PrivilegedGroups = "Domain Admins","Enterprise Admins","Server Operators","Administrators","Account Operators","Backup Operators","Print Operators","Group Policy Creator Owners"

foreach ($PrivilegedGroup in $PrivilegedGroups) {
    $list = @()
    $Users = Get-ADGroupMember -Identity $PrivilegedGroup -Recursive 
    
         
    foreach ($User in $Users) {

    $useronly = 0
    if ($user.objectClass -eq "user") {

            $user1 = get-aduser $user -Properties * 
            $useronly = 1
    
    }
    elseif ($user.objectClass -eq "computer") {
        
            $user1 = get-adcomputer $user -Properties * 
            }
    elseif ($user.objectClass -eq "msDS-GroupManagedServiceAccount") {
            
            $user1 = Get-ADServiceAccount $user -Properties * 
            }
    else {
          
            $user1 = Get-ADObject -Filter {objectsid -eq '$user.sid'} -Properties *
        }

    $object = New-Object PSObject

    $object | add-member -membertype noteproperty -Name "Forest" -Value $forest.name
    $object | add-member -membertype noteproperty -Name "Domain" -Value $domain
    $object | add-member -membertype noteproperty -Name "SamAccountName" -Value $User1.samaccountname
    $object | add-member -membertype noteproperty -Name "DisplayName" -Value $User1.name
    $object | add-member -membertype noteproperty -Name "PasswordLastSet" -Value ([datetime]::fromfiletime($user1.pwdlastset))
    $object | add-member -membertype noteproperty -Name "LastLogonTimestamp" -Value ([datetime]::fromfiletime($user1.lastlogontimestamp))
    if ($user1.AccountExpirationDate -eq $null) {
        $object | add-member -membertype noteproperty -Name "AccountExpirationDate" -Value "NotSet" }
    else {
        $object | add-member -membertype noteproperty -Name "AccountExpirationDate" -Value $user1.AccountExpirationDate
        }  
    $object | add-member -membertype noteproperty -Name "LockedOut" -Value $user1.LockedOut
    $object | add-member -membertype noteproperty -Name "Enabled" -Value $user1.Enabled  
    $object | add-member -membertype noteproperty -Name "PwdNeverExpires" -Value $user1.PasswordNeverExpires
    $object | add-member -membertype noteproperty -Name "DontRequirePreAuth" -Value $user1.DoesNotRequirePreAuth
    if ($user1.userAccountControl -band 128) {
           $object | add-member -membertype noteproperty -Name "ReversibleEncryptedPwd" -Value "TRUE" }
    else { $object | add-member -membertype noteproperty -Name "ReversibleEncryptedPwd" -Value "FALSE" }
    $object | add-member -membertype noteproperty -Name "AccountNotDelegated" -Value $user1.AccountNotDelegated
    $object | add-member -membertype noteproperty -Name "PwdNotRequired" -Value $user1.PasswordNotRequired
    If ($useronly -eq 1) {
        $object | add-member -membertype noteproperty -Name "SmartCardRequired" -Value $user1.SmartcardLogonRequired }
    else { $object | add-member -membertype noteproperty -Name "SmartCardRequired" -Value "N/A"}

    $object | add-member -membertype noteproperty -Name "UseDESKeyOnly" -Value $user1.UseDESKeyOnly
    $object | add-member -membertype noteproperty -Name "PasswordCantChange" -Value $user1.CannotChangePassword
    $object | add-member -membertype noteproperty -Name "Mail" -Value $user1.mail
    $object | add-member -membertype noteproperty -Name "SIPAddress" -Value $user1.proxyaddresses[0]
    $object | add-member -membertype noteproperty -Name "SID" -Value $User1.SID
    $object | add-member -membertype noteproperty -Name "DistinguishedName" -Value $User1.DistinguishedName
    $object | add-member -membertype noteproperty -Name "Description" -Value $User1.Description
    $object | add-member -membertype noteproperty -Name "ObjectClass" -Value $User1.objectClass
  

    $list+=$object
    
    $list |Export-Csv "$folder\$privilegedGroup.csv" -NoTypeInformation
    }
      
    }
