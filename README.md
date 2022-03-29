# PSAcessFinder
 
This Powershell script searches recursive for folders where the current user has Write, Modify or FullControl permissions. Its meant to find insufficient permissions that you can use for DLL Hijacking

If it found a folder with permissions, it skipps the subfolders of them.



# ToDo
- Take export from ProcessMonitor as input
- check also for file owner permissions
- define start path and verbose level as parameter
- creat help