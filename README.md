# PSAccessFinder
 
This Powershell script searches recursive for folders where the current user has Write, Modify or FullControl permissions. Its meant to find insufficient permissions that you can use for DLL Hijacking

If it found a folder with permissions, it skipps the subfolders of them.


# SYNTAX
```powershell
C:\PS\PSAccessFinder>.\findWriteAccess.ps1 [[-verbose] <Int32>] [[-startfolder] <String>] [[-inputCSV] <String>] [-formatList]
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

use a csv containing a coloumn "Path" and "Process Name" to check, usually you will take a export from procmon.exe, verbose 2 will instantly print matching and also folders with no permissions

```powershell
C:\PS>.\findWriteAccess.ps1 -procInput .\Logfile.CSV -verbose 2
```


