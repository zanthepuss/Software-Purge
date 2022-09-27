###################################################################################################
# Disclaimer                                                                                      #
# ==========                                                                                      #
#                                                                                                 #
# Please read this disclaimer carefully before using this script. This script is open-source and  #
# subject to the terms of the MIT license.                                                        #
#                                                                                                 #
# This script is provided as a tool for IT Administrators to programatically remove the following #
# legacy applications from End Users’ devices in both the system and user context                 #
#
# Pulse Secure versions 5.3 to 9.1
# Pulse Secure Terminal Services Client
# Pulse Secure Setup Client ActiveX
# Pulse Secure Setup Client
# Pulse Secure Host Checker
# Pulse Application Launcher
# 
# We highly recommend that you first test this script to ensure that it achieves the desired      #
# results in a test or lab environment.                                                           #
#                                                                                                 #
# We make no representation as to the script containing any errors or bugs.  Any bugs             #
# or errors in the script may produce an undesirable outcome.  Additionally, any modification or  #
# unintentional change made by you may have undesirable effects. If you discover any issue with   #
# the script, you should immediately cease use and manage the removal of Pulse Secure applications#
# manually.                                                                                       #
#                                                                                                 #
# Your use of this software is undertaken at your own risk. To the full extent permitted under    #
# law, we will not be liable for any loss or damage of whatever nature (direct, indirect,         #
# consequential or other) caused by the use of this script.                                       #
#                                                                                                 #
###################################################################################################


###################################################################################################
# Change Log                                                                                      #
# ==========                                                                                      #
# Version  Date         Reason                                                                    #
# -------  -----------  ------------------------------------------------------------------------- #
# 1.0      19-Mar-2021  Initial script created by Andy Connolly for RingCentral                   #
# 2.0      07-May-2021  New version that runs in the administrator context only                   #
# 2.1      13-May-2021  Added additional locations based on customer feedback                     #
# 2.2      01-Jun-2021  Attempt to uninstall any remaining HKLM installations                     #
# 3.0	   11-Mar-2022  Script Modified to remove Pulse Secure
# 3.1	   17-Mar-2022  Cleaned up redundant examples
#                                                                                                 #
###################################################################################################

$ErrorActionPreference = "Stop"
$logfile = "C:\temp\$(gc env:computername)-remove-PulseSecureApps.log"
$dtFormat = 'dd-MMM-yyyy HH:mm:ss'
add-content $logfile -value "----------------------------------------------------------------------------------------------------"
add-content $logfile -value "$(Get-Date -Format $dtFormat) Attempting to remove PulseSecure apps"

$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
add-content $logfile -value "$(Get-Date -Format $dtFormat) Running in Administrator context: $isAdmin"

if (!$isAdmin){
    add-content $logfile -value "$(Get-Date -Format $dtFormat) Script must be executed as an administrator: powershell.exe -noprofile -executionpolicy Bypass -file `"admin.ps1`""
    exit(-5)
}

#Stop any of the applications that may be running
get-process | where-object {$_.Company -like "*Pulse Secure*" -or $_.Path -like "*Pulse Secure*"} | stop-process -ErrorAction ignore -Force

#Uninstall any installed applications that the administrator can remove
foreach ($app in (Get-WmiObject -Class Win32_Product | Where-Object{$_.Vendor -like "*Pulse Secure*"})) {
    add-content $logfile -value "$(Get-Date -Format $dtFormat) Attempting to uninstall $($app)"
    try {
        $app.Uninstall() | Out-Null 
    } catch {
        add-content $logfile -value $_
    }
}

#Remove any system uninstall keys
$paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 
           "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
foreach($path in $paths) {
    if (test-path($path)) {
        $list = Get-ItemProperty "$path\*" | Where-Object {$_.DisplayName -like "*Pulse Secure*"} | Select-Object -Property PSPath, UninstallString
        foreach($regkey in $list) {
            add-content $logfile -value "$(Get-Date -Format $dtFormat) Examining Registry Key $($regkey.PSpath)"
            try {
                $cmd = $regkey.UninstallString
                if ($cmd -like "msiexec.exe*") {
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     Uninstall string is using msiexec.exe"
                    if ($cmd -notlike "*/X*") { 
                        add-content $logfile -value "$(Get-Date -Format $dtFormat)     no /X flag - this isn't for uninstalling"
                        $cmd = "" 
                    } #don't do anything if it's not an uninstall
                    elseif ($cmd -notlike "*/qn*") { 
                        add-content $logfile -value "$(Get-Date -Format $dtFormat)     adding /qn flag to try and uninstall quietly"
                        $cmd = "$cmd /qn" 
                    } #don't display UI
                }
                if ($cmd) {
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     executing $($cmd)"
                    cmd.exe /c "$($cmd)"
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     done"
                }
            } catch {
                add-content $logfile -value $_
            }
        }
        $list = Get-ItemProperty "$path\*" | Where-Object {$_.DisplayName -like "*Pulse Secure*"} | Select-Object -Property PSPath
        foreach($regkey in $list) {
            add-content $logfile -value "$(Get-Date -Format $dtFormat) Removing Registry Key $($regkey.PSpath)"
            try {
                remove-item $regkey.PSPath -recurse -force
            } catch {
                add-content $logfile -value $_
            }
        }
    } else { add-content $logfile -value "$(Get-Date -Format $dtFormat) Path $($item) not found" }
}

#Add shortcut to HKEY_USERS
New-PSDrive -PSProvider registry -Root HKEY_USERS        -Name HKU  | Out-Null

if (test-path(${Env:ProgramFiles(x86)})) { $pf86 = ${Env:ProgramFiles(x86)} }  else { $pf86 = "C:\Program Files (x86)" }
add-content $logfile -value "$(Get-Date -Format $dtFormat) Program Files (x86) location: $($pf86)"

if (test-path(${Env:ProgramFiles}))      { $pf = ${Env:ProgramFiles} }         else { $pf = "C:\Program Files" }
add-content $logfile -value "$(Get-Date -Format $dtFormat) Program Files location: $($pf)"

if (test-path(${Env:ProgramData}))       { $pd = ${Env:ProgramData} }          else { $pd = "C:\ProgramData" }
add-content $logfile -value "$(Get-Date -Format $dtFormat) ProgramData location: $($pd)"

if (test-path(${Env:PUBLIC}))            { $pub = ${Env:PUBLIC} }              else { $pub = "C:\Users\Public" }
add-content $logfile -value "$(Get-Date -Format $dtFormat) Public profile location: $($pub)"

if (test-path(${Env:SystemRoot}))        { $win = ${Env:SystemRoot} }          else { $win = "C:\Windows" }
add-content $logfile -value "$(Get-Date -Format $dtFormat) Windows root location: $($win)"

#Populate the lists of registry items to remove
$Brand = "Pulse Secure"  
add-content $logfile -value "$(Get-Date -Format $dtFormat) Brand set to: $($Brand)"

# if any registry keys are left over after an uninstall they can be added to this list 
#$HKLM = [System.Collections.ArrayList]@()
#$HKLM.add("HKLM:\SOFTWARE\$Brand") | Out-Null
#$HKLM.add("HKLM:\SOFTWARE\Classes\PulseSecureServicePS.DSAccessPluginMonitor") | Out-Null
#$HKLM.add("HKLM:\SOFTWARE\Classes\PulseSecureServicePS.DSAccessPluginMonit.1") | Out-Null
#$HKLM.add("HKLM:\SOFTWARE\WOW6432Node\$Brand") | Out-Null

#foreach ($regkey in $HKLM) {
#    try {
#        if (test-path($regkey)) {
#            add-content $logfile -value "$(Get-Date -Format $dtFormat) Removing Registry Key $($regkey)"
#            remove-item $regkey -recurse -force
#        } ##else { add-content $logfile -value "$(Get-Date -Format $dtFormat) Registry Key $($regkey) not found" }
#    } catch {
#        add-content $logfile -value $_
#    }
#}

# Populate the lists of folders items to remove if they are left over after an uninstall
$MachineFolders = [System.Collections.ArrayList]@()
# Examples 
# $pd = "C:\ProgramData"
# $pf86 = "C:\Program Files (x86)"
# $pf = "C:\Program Files"
# $pub = "C:\Users\Public"
# $win = "C:\Windows"
# $MachineFolders.add("$pd\Glip") | Out-Null
# $MachineFolders.add("$pd\Microsoft\Windows\Start Menu\Programs\*RingCentral*") | Out-Null
# $MachineFolders.add("$pf86\$Brand\SoftPhoneApp") | Out-Null
# $MachineFolders.add("$pf\$Brand\SoftPhoneApp") | Out-Null
# $MachineFolders.add("$pub\Desktop\RingCentral*.lnk") | Out-Null
# $MachineFolders.add("$win\Prefetch\*GLIP*.pf") | Out-Null


foreach ($item in $MachineFolders) {
    try {
        if (test-path($item)) {
            add-content $logfile -value "$(Get-Date -Format $dtFormat) Removing $($item)"
            remove-item $item -recurse -force
        } else { add-content $logfile -value "$(Get-Date -Format $dtFormat) Path $($item) not found" }
    } catch {
        add-content $logfile -value $_
    }
}

#Loop through HKLM key to remove entries
$paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
           "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\UFH\ARP",
           "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
           "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules")
foreach($path in $paths) {
    if (test-path($path)) {
        add-content $logfile -value "$(Get-Date -Format $dtFormat) Checking registry path: $($path)"
        Get-Item -Path $path | Select-Object -ExpandProperty Property | % {
            $propValue = (Get-ItemProperty -Path "$path" -Name "$_")."$_"
            if (($_ -like "*Pulse Secure*") -or ($propValue -like "*Pulse Secure*")) {
                try {
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     Removing property: $($_) containing value: $($propValue)"
                    Remove-ItemProperty -path "$path" -Name $_
                } catch {
                    add-content $logfile -value $_
                }
            }
        }
    } else { add-content $logfile -value "$(Get-Date -Format $dtFormat) Path $($item) not found" }
}

#Build list of items that need to be removed for each user profile if left behind
$HKU = [System.Collections.ArrayList]@()
# Examples 
#$HKU.add("HKU:\%SID%\SOFTWARE\$Brand") | Out-Null
#$HKU.add("HKU:\%SID%\SOFTWARE\584acf4c-ebc3-56fa-9cfd-586227f098ba") | Out-Null
#$HKU.add("HKU:\%SID%\SOFTWARE\Clients\Internet Call\RingCentral for Windows") | Out-Null
#$HKU.add("HKU:\%SID%\SOFTWARE\MozillaPlugins\@ringcentral.com/RingCentralMeetingsPlugin") | Out-Null
#$HKU.add("HKU:\%SID%\SOFTWARE\WOW6432Node\$Brand") | Out-Null
#$HKU.add("HKU:\%SID%\SOFTWARE\WOW6432Node\Classes\MIME\Database\Content Type\application/x-rcmtg-launcher") | Out-Null
#$HKU.add("HKU:\%SID%\SOFTWARE\WOW6432Node\Classes\rcapp") | Out-Null
#$HKU.add("HKU:\%SID%\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\ProtocolExecute\zoomrc") | Out-Null
#$HKU.add("HKU:\%SID%\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts\rcapp_rcapp") | Out-Null
#$HKU.add("HKU:\%SID%_classes\.rcrecord") | Out-Null
#$HKU.add("HKU:\%SID%_classes\MIME\Database\Content Type\application/x-rcmtg-launcher") | Out-Null
#$HKU.add("HKU:\%SID%_classes\RCLauncher") | Out-Null
#$HKU.add("HKU:\%SID%_classes\RingCentralMeetingsRecording") | Out-Null
#$HKU.add("HKU:\%SID%_classes\rcapp") | Out-Null
#$HKU.add("HKU:\%SID%_classes\RingCentral.callto") | Out-Null

$UserFolders = [System.Collections.ArrayList]@()
#$UserFolders.add("%desktop%\RingCentral*.lnk") | Out-Null
#$UserFolders.add("%local%\$Brand") | Out-Null
#$UserFolders.add("%local%\$Brand\SoftPhoneApp") | Out-Null
$UserFolders.add("%roaming%\Pulse Secure\Setup Client\") | Out-Null
$UserFolders.add("%roaming%\Pulse Secure\Setup Client\PulseSetupClient.ini") | Out-Null
$UserFolders.add("%roaming%\Pulse Secure\Setup Client\dsmmfres_de.dll") | Out-Null
$UserFolders.add("%roaming%\Pulse Secure\Setup Client\dsmmfres_es.dll") | Out-Null
#$UserFolders.add("%roaming%\") | Out-Null
#$UserFolders.add("%roaming%\") | Out-Null
#$UserFolders.add("%roaming%\") | Out-Null
#$UserFolders.add("%roaming%\") | Out-Null
#$UserFolders.add("%roaming%\") | Out-Null
#$UserFolders.add("%roaming%\") | Out-Null
#$UserFolders.add("%roaming%\") | Out-Null
#$UserFolders.add("%roaming%\") | Out-Null
#UserFolders.add("%roaming%\com.ringcentral.rcoutlook") | Out-Null

#Look at every user profile on the computer and remove the registry keys and associated folders for each RC application
add-content $logfile -value "$(Get-Date -Format $dtFormat) Removing applications for all user profiles"
$PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
$ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $PatternSID} | Select-Object @{name="SID";expression={$_.PSChildName}}, @{name="UserProfile";expression={"$($_.ProfileImagePath)"}}, @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
$ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Select-Object @{name="SID";expression={$_.PSChildName}}, @{name="UserProfile";expression={"$($_.ProfileImagePath)"}}, @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
$DefaultProfile = "" | Select-Object SID, UserProfile, Username
$DefaultProfile.SID = ".DEFAULT"
$DefaultProfile.UserProfile = "$pub\..\Default"
$DefaultProfile.UserName = "Default"
$ProfileList += $DefaultProfile
$LoadedHives = Get-ChildItem HKU:\ | Select-Object @{name="SID";expression={$_.PSChildName}}
$UnloadedHives = Compare-Object $ProfileList.SID $LoadedHives.SID | Select-Object @{name="SID";expression={$_.InputObject}}, UserHive, Username
foreach ($item in $ProfileList) {
    try {
        if ($item.SID -in $UnloadedHives.SID) {
            add-content $logfile -value "$(Get-Date -Format $dtFormat) Loading profile $($item.username) - located at $($item.UserProfile)\ntuser.dat"
            reg load HKU\$($item.SID) "$($item.UserProfile)\ntuser.dat" | Out-Null
        } else { 
            add-content $logfile -value "$(Get-Date -Format $dtFormat) Checking profile $($item.username)"
        }
       
        $folders = "HKU:\$($item.sid)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $desktop = (Get-Item -Path $folders).GetValue("Desktop", "$($item.UserProfile)\Desktop", "DoNotExpandEnvironmentNames") -replace "%USERPROFILE%", $item.UserProfile
        add-content $logfile -value "$(Get-Date -Format $dtFormat)     User Desktop location: $($desktop)"
        $local = (Get-Item -Path $folders).GetValue("Local AppData", "$($item.UserProfile)\AppData\Local", "DoNotExpandEnvironmentNames") -replace "%USERPROFILE%", $item.UserProfile
        add-content $logfile -value "$(Get-Date -Format $dtFormat)     User Local AppData location: $($local)"
        $roaming = (Get-Item -Path $folders).GetValue("AppData", "$($item.UserProfile)\AppData\Roaming", "DoNotExpandEnvironmentNames") -replace "%USERPROFILE%", $item.UserProfile
        add-content $logfile -value "$(Get-Date -Format $dtFormat)     User AppData location: $($roaming)"

        if ($item.SID -in $UnloadedHives.SID) {
            add-content $logfile -value "$(Get-Date -Format $dtFormat) Loading user classes for profile $($item.username) - located at $($local)\Microsoft\Windows\UsrClass.dat"
            reg load HKU\$($item.SID)_classes "$($local)\Microsoft\Windows\UsrClass.dat" | Out-Null
        }

        foreach ($regkey in $HKU) {
            try {
               $key = $regkey -replace "%SID%", $item.SID
               if (test-path($key)) {
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     Removing Registry Key $($key)"
                    remove-item $key -recurse -force
                } else { add-content $logfile -value "$(Get-Date -Format $dtFormat)     Registry Key $($key) not found" }
            } catch {
                add-content $logfile -value $_
            }
        }
        
        foreach ($path in $UserFolders) {
            $temp = (($path -replace "%roaming%", $roaming) -replace "%local%", $local) -replace "%desktop%", $desktop 
            try {
                if (test-path($temp)) {
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     Removing $($temp)"
                    remove-item $temp -recurse -force
                } else { add-content $logfile -value "$(Get-Date -Format $dtFormat)     Path $($temp) not found" }
            } catch {
                add-content $logfile -value $_
            }
        }

# Remove any user uninstall keys
$paths = @("HKU:\$($item.sid)\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKU:\$($item.sid)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        foreach($path in $paths) {
            if (test-path($path)) {
                $list = Get-ItemProperty "$path\*" | Where-Object {$_.DisplayName -like "*Pulse Secure*"} | Select-Object -Property PSPath
                foreach($regkey in $list) {
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     Removing Uninstall Registry Key $($regkey.PSPath)"
                    try {
                        remove-item $regkey.PSPath -recurse -force
                    } catch {
                        add-content $logfile -value $_
                    }
                }
            } else { add-content $logfile -value "$(Get-Date -Format $dtFormat) Path $($item) not found" }
        }

# Remove any user install keys - this is done both in the user hive and the user data part of the local machine
        $paths = @("HKU:\$($item.sid)\SOFTWARE\WOW6432Node\Microsoft\Installer\Products", "HKU:\$($item.sid)\SOFTWARE\Microsoft\Installer\Products")
        foreach($path in $paths) {
            if (test-path($path)) {
                $list = Get-ItemProperty "$path\*" | Where-Object {$_.ProductName -like "*pulse secure*"} | Select-Object -Property PSPath
                foreach($regkey in $list) {
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     Removing Install Registry Key $($regkey.PSPath)"
                    try {
                        remove-item $regkey.PSPath -recurse -force
                    } catch {
                        add-content $logfile -value $_
                    }
                }
            } else { add-content $logfile -value "$(Get-Date -Format $dtFormat) Path $($item) not found" }
        }
        $paths = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData\$($item.sid)\Products", 
                   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$($item.sid)\Products")
        foreach($path in $paths) {
            if (test-path($path)) {
                $list = Get-ItemProperty "$path\*\*" | Where-Object {$_.Publisher -like "*Pulse Secure*"} | Select-Object -Property PSParentPath
                foreach($regkey in $list) {
                    add-content $logfile -value "$(Get-Date -Format $dtFormat)     Removing Install Registry Key $($regkey.PSParentPath)"
                    try {
                        remove-item $regkey.PSParentPath -recurse -force
                    } catch {
                        add-content $logfile -value $_
                    }
                }
            } else { add-content $logfile -value "$(Get-Date -Format $dtFormat) Path $($item) not found" }
        }

        #Loop through the keys and remove any Pulse Secure entries
        $paths = @("HKU:\$($item.sid)_classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", 
                   "HKU:\$($item.sid)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated", 
                   "HKU:\$($item.sid)\SOFTWARE\Microsoft\Windows\CurrentVersion\UFH\SHC")
        foreach($path in $paths) {
            if (test-path($path)) {
                add-content $logfile -value "$(Get-Date -Format $dtFormat)     Checking registry path: $($path)"
                Get-Item -Path $path | Select-Object -ExpandProperty Property | % {
                    $propValue = (Get-ItemProperty -Path "$path" -Name "$_")."$_"
                    if (($_ -like "*Pulse Secure*") -or ($propValue -like "*Pulse Secure*")) {
                        try {
                            add-content $logfile -value "$(Get-Date -Format $dtFormat)         Removing property: $($_) containing value: $($propValue)"
                            Remove-ItemProperty -path "$path" -Name $_
                        } catch {
                            add-content $logfile -value $_
                        }
                    }
                }
            } else { add-content $logfile -value "$(Get-Date -Format $dtFormat) Path $($item) not found" }
        }

        if ($item.SID -in $UnloadedHives.SID) {
            [gc]::Collect()
            add-content $logfile -value "$(Get-Date -Format $dtFormat) Unloading profile"
            reg unload HKU\$($item.SID) | Out-Null
            reg unload HKU\$($item.SID)_classes | Out-Null
       }
    } catch {
        add-content $logfile -value $_
    }
}
add-content $logfile -value "$(Get-Date -Format $dtFormat) End of removal script"

#add-content $logfile -value "$(Get-Date -Format $dtFormat) Installing required applications"

#add-content $logfile -value "$(Get-Date -Format $dtFormat)     Installing RingCentral MSI app quietly"
#cmd.exe /c 'MSIEXEC.EXE /i "RingCentral-x64.msi" /qn'

#add-content $logfile -value "$(Get-Date -Format $dtFormat)     Installing RingCentral Meetings MSI app quietly"
#cmd.exe /c 'MSIEXEC.EXE /i "RCMeetingsClientSetup.msi" /qn'

#add-content $logfile -value "$(Get-Date -Format $dtFormat)     Installing RingCentral Phone MSI app quietly"
#cmd.exe /c 'MSIEXEC.exe /i "RingCentral-Phone-21.1.0.msi" ALLUSERS=1 /qn'

#add-content $logfile -value "$(Get-Date -Format $dtFormat) End of install script"