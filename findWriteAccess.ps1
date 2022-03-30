<#
.SYNOPSIS
    PSAccessFinder - find folders where you can write into
.DESCRIPTION
    This Powershell script searches recursive for folders where the current user has Write, Modify or FullControl permissions. Its meant to find insufficient permissions that you can use for DLL Hijacking
.PARAMETER startfolder
    The path to the start the permission check
.PARAMETER inputCSV
    The path to the csv file, this file should contain a coloum with the header "Path" and "Process Name", like the procmon export produce it.
.PARAMETER verbose
    0 = print a table of found pathes after finishing (default)
    1 = print found folders at the moment of check + if inputCSV is set, the cleaned csv table
    2 = print found folders and folders wihtout permissions at the moment of check
.PARAMETER formatList
    If set, the output will be printed as list instead of a table
.EXAMPLE
    C:\PS>.\findWriteAccess.ps1
    
    check permissions in sub directories, starting at the current directory
    only output pahtes with permission (no verbose)
.EXAMPLE
    C:\PS>.\findWriteAccess.ps1 -startfolder "C:\Users\Admin" -verbose 1
    
    check permissions in sub directories, starting at the defined start folder
    verbose 1 will instantly print matching folders
.EXAMPLE
    C:\PS>.\findWriteAccess.ps1 -inputCSV .\Logfile.CSV -verbose 2

    use a csv containing a coloumn "Path" and "Process Name" to check, usually you will take a export from procmon.exe
    verbose 2 will instantly print matching and also folders with no permissions
.LINK
    https://github.com/secure-77/PSAccessFinder
#>


# inputs
param (
    [int]$verbose = 0,
    [String]$startfolder = "",   
    [String]$inputCSV,
    [switch]$formatList
)


if ($startfolder -eq "" -AND $inputCSV -eq "") {
    Write-Output "no start folder and no csv defined, using current folder`n"
    $startfolder = Get-Location
}

$language = GET-WinSystemLocale | Select-Object Name

$global:username = $env:computername + "\\" + $env:UserName
$global:userShema = "BUILTIN\\Users"
$global:authShema = "NT AUTHORITY\\authenticated users"
$global:verboseLevel = $verbose
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
        $targetfolder,
        $recursive = $true
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
        $Owner = $acl.Owner

        $check = $false
        foreach ($AccessObject in $Access) {
            $User = $AccessObject.IdentityReference.value
            $Rights = $AccessObject.FileSystemRights
            $Control = $AccessObject.AccessControlType
       
            if ($Control -match "Allow") { 
                if ($User -match $global:userShema -or $User -match $global:username -or $User -match $global:authShema -or $User -match $Owner) {
                    if ($Rights -match "FullControl" -or $Rights -match "Write" -or $Rights -match "Modify") {
                        
                        # Found access
                        if ($verboseLevel -gt 0) {
                            Write-Output "Path found: $FullPath"                            
                        }
                        $check = $true
                        $Line = New-Object PSObject
                        if (!$folder.ProcessName -eq "") {
                            $Line | Add-Member -membertype NoteProperty -name "Process" -Value $folder.ProcessName
                        }
                        # check if origPath is set
                        if ($folder.OrigPath) {
                            $dllFullPath = $folder.OrigPath + "\" + $folder.dllName
                            
                            # check if origPath is different to the acl one
                            if ($folder.OrigPath -ne $FullPath) {
                                
                                if ($verboseLevel -gt 0) {
                                    Write-Output "Orig Path: $FullPath"                            
                                }
                                $Line | Add-Member -membertype NoteProperty -name "AcessTo" -Value $FullPath
                            }
                            else {
                                $Line | Add-Member -membertype NoteProperty -name "AcessTo" -Value "FullPath"
                            }
                        } else {
                            
                            $dllFullPath = $FullPath + "\" + $folder.dllName
                        }
                        
                        $Line | Add-Member -membertype NoteProperty -name "FullPath" -Value $dllFullPath
                                                                
                        # if (!$folder.dllName -eq "") {
                        #     $Line | Add-Member -membertype NoteProperty -name "File" -Value $folder.dllName
                        # }

                        $Line | Add-Member -membertype NoteProperty -name "Acess" -Value $User
                        $Line | Add-Member -membertype NoteProperty -name "Rights" -Value $Rights
                        $global:Output += $Line
                    }
                }
            }         
        }
        # no access, check subfolders

        if ($verboseLevel -gt 1) {
            Write-Output "no permissions in $folder"
        }
        if ($check -eq $false -AND $recursive -eq $true) {
            if ($verboseLevel -gt 1) {
                Write-Output "recursive on, checking subfolder of $folder"
            }

            $subfolders = Get-SubFolders -startfolder $folder
            Invoke-CheckACLs -targetfolder $subfolders
        }
    }  
}



if (!$inputCSV -eq "") {
   
    Write-Output "try to parse csv and remove duplicates...`n"
    $csvFolders = Import-Csv $inputCSV | Sort-Object Path –Unique
    
    if ($verboseLevel -gt 0) {
        Write-Output "finished, using the following list:"
        Write-Output $csvFolders | Select-Object "Process Name", "Path" | Format-Table -AutoSize
    }

    $folderCount = $csvFolders.Count

    Write-Output "starting search for write access in $folderCount locations... `n"

    foreach ($dll in $csvFolders) {
        #extract path of file and add FullName Member
        $dllPath = Split-Path -Path $dll.Path
        $dllOrigPath = $dllPath

        # check if path does exist, if not step up
        $pathExist = $false
        DO {               
            if ($dllPath -ne "") {
                if (Get-Item $dllPath -ErrorAction SilentlyContinue ) {
                    $pathExist = $true
                }
                else {
                    if ($verboseLevel -gt 1) {
                        Write-Output "Path doesn't exist, checking parent: $dllPath"
                    }              
                    $dllPath = Split-Path $dllPath -Parent           
                }
            }
            else {
                $pathExist = $true
            }          

        } While ($pathExist -eq $false)

        $dllName = Split-Path -Leaf $dll.Path
        $dllPath | Add-Member -NotePropertyName origPath -NotePropertyValue $dllOrigPath
        $dllPath | Add-Member -NotePropertyName FullName -NotePropertyValue $dllPath
        $dllPath | Add-Member -NotePropertyName ProcessName -NotePropertyValue $dll."Process Name"
        $dllPath | Add-Member -NotePropertyName dllName -NotePropertyValue $dllName
        Invoke-CheckACLs -targetfolder $dllPath -recursive $false
    }

}
else {
    
    Write-Output "starting search for write access in subfolders of $startfolder`n"
    $folders = Get-SubFolders -startfolder $startfolder
    Invoke-CheckACLs -targetfolder $folders
}


if ($Output.Count -gt 0) {
    Write-Output "`nfound some folders, happy hunting :)"
    if ($formatList) {
        Write-Output $Output | Format-List
    } else {
        Write-Output $Output | Format-Table -AutoSize 
    }
}
else {
    Write-Output "`nfound no folders with permissions :("
}



