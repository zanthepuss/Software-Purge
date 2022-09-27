Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force 
$result = gwmi win32_product -filter "Name LIKE 'Microsoft Silverlight'" | select IdentifyingNumber;
[string] $a = $result.identifyingNumber;
msiexec.exe /X $a /qn
Remove-Item -Path "HKLM:\SOFTWARE\MMSOFT Design" -Recurse