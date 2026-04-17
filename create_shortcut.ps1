$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut("C:\Users\CST Student\Desktop\Phishing Detector.lnk")
$lnk.TargetPath = "wscript.exe"
$lnk.Arguments = '"C:\Users\CST Student\Phishing Detector\launch.vbs"'
$lnk.WorkingDirectory = "C:\Users\CST Student\Phishing Detector"
$lnk.Description = "Phishing Email Detector"
$lnk.IconLocation = "C:\Windows\System32\shell32.dll,44"
$lnk.Save()
Write-Host "Done: C:\Users\CST Student\Desktop\Phishing Detector.lnk"
