# inputs
$username = $env:computername + "\\" + $env:UserName
$startfolder = "C:\Program Files"
$language = GET-WinSystemLocale | Select-Object Name
$userShema = "BUILTIN\\Users"
$authShema = "NT AUTHORITY\\authenticated users"

if ($language -match "de-DE") {
    $userShema = "VORDEFINIERT\\Benutzer"
    $authShema = "NT-AUTORITÄT\\Authentifizierte Benutzer"
}


# step 1) get folder permissions
#$acl = get-acl $folder
#$acl =  Get-ChildItem $folder -Recurse -ErrorAction SilentlyContinue | where { $_.PSIsContainer -eq "TRUE"} | %{get-acl $_.FullName -ErrorAction SilentlyContinue} 

$folders = Get-ChildItem $startfolder -Recurse -ErrorAction SilentlyContinue | where { $_.PSIsContainer -eq "TRUE" } 

# foreach ($folder in $acl){

    
#     $perms = get-acl $folder -ErrorAction SilentlyContinue #| Where-Object {$_.Access -contains "Allow"} | Format-Table
#     $perms.access.where({($_.filesystemrights -match "FullControl" -OR $_.filesystemrights -match "Write") -AND ($_.AccessControlType -match "Allow") -AND ($_.IdentityReference -match "VORDEFINIERT\\Benutzer" -OR $_.IdentityReference -match $username) }) 
#     Write-Output $perms | Format-List -Property Path,Owner,Group,AccessToString
# }


$Output = @() 
foreach ($folder in $folders) {

    $FullPath = $folder.FullName
    try {
        $acl = get-acl $FullPath -ErrorAction SilentlyContinue
    }
    Catch {
        continue;
    }
    $Access = $acl.Access

    foreach ($AccessObject in $Access) {
        $User = $AccessObject.IdentityReference.value
        $Rights = $AccessObject.FileSystemRights
        $Control = $AccessObject.AccessControlType

        if ($Control -match "Allow") { 
            if ($User -match $userShema -or $User -match $username -or $User -match $authShema) {
                if ($Rights -match "FullControl" -or $Rights -match "Write" -or $Rights -match "Modify") {
                    Write-Output "Path found: $FullPath"           
                    $Line = New-Object PSObject
                    $Line | Add-Member -membertype NoteProperty -name "Path" -Value $FullPath
                    $Line | Add-Member -membertype NoteProperty -name "Group" -Value $User
                    $Line | Add-Member -membertype NoteProperty -name "Rights" -Value $Rights
                    $Output += $Line
                }
            }
        }
    }
}
Write-Output $Output | Format-Table -AutoSize 




