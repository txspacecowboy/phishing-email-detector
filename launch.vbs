Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "pythonw.exe """ & WshShell.CurrentDirectory & "\src\gui.py""", 0, False
