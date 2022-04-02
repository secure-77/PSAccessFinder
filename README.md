# PSAccessFinder
 
This Powershell script searches recursive for folders where the current user has Write, Modify or FullControl permissions. Its meant to find insufficient permissions that you can use for DLL Hijacking or to bypass AppLocker. 

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



# SYNTAX
```powershell
C:\PS\PSAccessFinder>.\findWriteAccess.ps1 [[-verbose] <Int32>] [[-startfolder] <String>] [[-inputCSV] <String>] [-formatList]     
    [-noRecurse]
```



# EXAMPLES

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

# REMARKS
```
To see the examples, type: "Get-Help Z:\OneDrive\Coding\powershell\PSAccessFinder\findWriteAccess.ps1 -Examples"
For more information, type: "Get-Help Z:\OneDrive\Coding\powershell\PSAccessFinder\findWriteAccess.ps1 -Detailed"
For technical information, type: "Get-Help Z:\OneDrive\Coding\powershell\PSAccessFinder\findWriteAccess.ps1 -Full"
For online help, type: "Get-Help Z:\OneDrive\Coding\powershell\PSAccessFinder\findWriteAccess.ps1 -Online"
```

# Demo



[Demo 1](https://github.com/secure-77/PSAccessFinder/blob/main/WindowsClient.png)
[Demo 2](https://github.com/secure-77/PSAccessFinder/blob/main/WindowsServer.png)