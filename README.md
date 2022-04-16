# PSAccessFinder
 
This Powershell script searches recursive for folders where the current user has Write, Modify or FullControl permissions. Its meant to find insufficient permissions that you can be used for DLL Hijacking or to bypass AppLocker. 

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
- check services and parent folders permissions
- service filter: all, non windows, unquoted



# Syntax
```powershell
C:\PS\PSAccessFinder>.\findWriteAccess.ps1 [[-startfolder] <String>] [[-inputCSV] <String>] [-services] [[-serviceFilter] <Int32>] [-noRecurse]     
    [-noSkip] [-checkParents] [[-verbose] <Int32>] [-formatList]
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

## Services

retrieve all services with path to the executables and check access of these folders

```powershell
C:\PS>.\findWriteAccess.ps1 -services
```

show all unquoted non windows services and check permissons also of the parent folders

```powershell
C:\PS>.\findWriteAccess.ps1 -services -serviceFilter 2 -verbose 1 -checkParents
```


# Remarks
```
To see the examples, type: "Get-Help findWriteAccess.ps1 -Examples"
For more information, type: "Get-Help findWriteAccess.ps1 -Detailed"
For technical information, type: "Get-Help findWriteAccess.ps1 -Full"
For online help, type: "Get-Help findWriteAccess.ps1 -Online"
```

# Preview

![Demo 1](https://github.com/secure-77/PSAccessFinder/blob/main/WindowsClient.png "Demo 1")
![Demo 2](https://github.com/secure-77/PSAccessFinder/blob/main/WindowsServer.png "Demo 2")
