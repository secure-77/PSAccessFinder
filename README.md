# PSAccessFinder
 
This Powershell script search recursive for folders where the current user has Write, Modify or FullControl permissions. Its meant to find insufficient permissions that can be used for DLL Hijacking or to bypass AppLocker. 

If it found a folder with permissions, it skipps the subfolders of them.

## Features
- prevents some time-consuming Windows folders, modify them in the `$global:skippFolders` array
- supports german and english schemas
- check permissions for
    - Current User
    - BUILTIN Users
    - Domain Users
    - Authenticated Users
- when reading from csv input: stepping upwards until a folder exist and checks again the permissions
- check services and parent folder permissions
- check system environment variable pathes
- service filter: all, non windows, unquoted



# Syntax
```powershell

SYNTAX
    findWriteAccess.ps1 [[-startfolder] <String>] [[-inputCSV] <String>] [-services] [-envCheck] [[-serviceFilter] <Int32>] [-noRecurse] [-noSkip] [-checkParents] [[-verbose]        
    <Int32>] [-formatList] [<CommonParameters>]


PARAMETER
    -startfolder <String>
        The path to the start the permission check

    -inputCSV <String>
        The path to the csv file, this file should contain a coloum with the header "Path" and "Process Name", like the procmon export produce it.

    -services [<SwitchParameter>]
        enumerate all services and check write access to the executable pathes

    -envCheck [<SwitchParameter>]
        enumerate all machine environment variables and check write access to the executable pathes

    -serviceFilter <Int32>
        0 = no services are filtered (default)
        1 = windows services get filterd
        2 = 1 + quoted pathes in servics get filterd

    -noRecurse [<SwitchParameter>]
        Only relevant for searches from current or start folder, if set, searching in subfolders will be skipped

    -noSkip [<SwitchParameter>]
        Doesn´t skip time consuming folders (defined in $global:skippFolders) AND doesn´t break if permissions are found (it keeps searching in subfolders), use carefuly because this can take ages!
        A good approach why you want to set this, is when you want to search for writeable subfolders of a specific application location, defined with -starfolder

    -checkParents [<SwitchParameter>]
        Check also the parents folders, make sense when a startfolder which is not on root level is defined or in combination with the service parameter

    -verbose <Int32>
        0 = print a table of found pathes after finishing (default)
        1 = 0 + print instantly: found folders, if inputCSV is set, the cleaned csv table, if service is set, the services
        2 = 0 + 1 + folders without permissions

    -formatList [<SwitchParameter>]
        If set, the output will be printed as list instead of a table
```


# Examples

## Recursive Check of Subolders
check permissions in sub directories, starting at the current directory
```powershell
C:\PS>.\findWriteAccess.ps1
````
check permissions in sub directories, starting at the defined start folder, as this could take some time, add verbose 1 to instantly print matching folders
```powershell
C:\PS>.\findWriteAccess.ps1 -startfolder "C:\Users\Admin" -verbose 1
```    

## CSV Input

use a csv containing a coloumn "Path" and "Process Name" to check, usually you will take a export from procmon.exe, verbose 2 will instantly print matching and also folders with no permissions, -formatList will print the output as a list

```powershell
C:\PS>.\findWriteAccess.ps1 -procInput .\Logfile.CSV -verbose 2 -formatList
```

## System Environment Variables

Check for write access in system environment variable pathes

```powershell
C:\PS>.\findWriteAccess.ps1 -envCheck
```

## Services

retrieve all services with path to the executables and check access of these folders

```powershell
C:\PS>.\findWriteAccess.ps1 -services
```

show all unquoted non windows services and check permissons also of the parent folders

```powershell
C:\PS>.\findWriteAccess.ps1 -services -serviceFilter 2 -verbose 1 -checkParents
```

# Error Handling

if you get errors like this after copy pasting the script:

```powershell
.....char:38
    $global.authSchema = "NT-AUTORIT.."
unexpected token 'T\Authentifizerte`' in expression or statement.
```

you need to save the script with UTF-8-BOM encoding.



# Remarks
```
To see the examples, type: "Get-Help .\findWriteAccess.ps1 -Examples"
For more information, type: "Get-Help .\findWriteAccess.ps1 -Detailed"
For technical information, type: "Get-Help .\findWriteAccess.ps1 -Full"
For online help, type: "Get-Help .\findWriteAccess.ps1 -Online"
```

# Preview

![Demo 1](https://github.com/secure-77/PSAccessFinder/blob/main/WindowsClient.png "Demo 1")
![Demo 2](https://github.com/secure-77/PSAccessFinder/blob/main/WindowsServer.png "Demo 2")
