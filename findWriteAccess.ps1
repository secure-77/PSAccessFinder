# inputs
$startfolder = "C:\Users"
$language = GET-WinSystemLocale | Select-Object Name

$global:username = $env:computername + "\\" + $env:UserName
$global:userShema = "BUILTIN\\Users"
$global:authShema = "NT AUTHORITY\\authenticated users"
$global:verboseLevel = 1
$folders = @()
$global:Output = @() 


# Language
if ($language -match "de-DE") {
    $global:userShema = "VORDEFINIERT\\Benutzer"
    $global:authShema = "NT-AUTORITÄT\\Authentifizierte Benutzer"
}

# Get subfolders of directory
function Get-SubFolders {
    param (
        $startfolder
    )
    Return Get-ChildItem $startfolder -ErrorAction SilentlyContinue | where-object { $_.PSIsContainer -eq "TRUE" } 
}


# Check the ACLs for all subfolders
function Invoke-CheckACLs {
    param (
        $targetfolder
    )

    foreach ($folder in $targetfolder) {

        $FullPath = $folder.FullName
        try {
            $acl = get-acl $FullPath -ErrorAction SilentlyContinue
        }
        Catch {
            continue;
        }
        $Access = $acl.Access

        $check = $false
        foreach ($AccessObject in $Access) {
            $User = $AccessObject.IdentityReference.value
            $Rights = $AccessObject.FileSystemRights
            $Control = $AccessObject.AccessControlType
           
            if ($Control -match "Allow") { 
                if ($User -match $global:userShema -or $User -match $global:username -or $User -match $global:authShema) {
                    if ($Rights -match "FullControl" -or $Rights -match "Write" -or $Rights -match "Modify") {
                        
                        # Found access
                        if ($verboseLevel -gt 0) {
                            Write-Output "Path found: $FullPath"           
                        }
                        $check = $true
                        $Line = New-Object PSObject
                        $Line | Add-Member -membertype NoteProperty -name "Path" -Value $FullPath
                        $Line | Add-Member -membertype NoteProperty -name "Group" -Value $User
                        $Line | Add-Member -membertype NoteProperty -name "Rights" -Value $Rights
                        $global:Output += $Line
                    }
                }
            }         
        }
        # no access, check subfolders
        if ($check -eq $false) {
            if ($verboseLevel -gt 1) {
                Write-Output "no permission, checking subfolder of $folder"
            }

            $subfolders = Get-SubFolders -startfolder $folder
            Invoke-CheckACLs -targetfolder $subfolders
        }
    }  
}


$folders = Get-SubFolders -startfolder $startfolder
Write-Output "`n"
Write-Output "starting search for write access in subfolders of $startfolder`n"
Invoke-CheckACLs -targetfolder $folders -verboseLevel $verboseLevel

Write-Output $Output | Format-Table -AutoSize 
