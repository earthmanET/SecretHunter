function get_password{
    [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $result=($vault.RetrieveAll() | % { $_.RetrievePassword();$_ }) 
    foreach($item in $result){
        Write-Host ($item.resource)
        Write-Host ($item.username)
        Write-Host ($item.password)
    }
}
get_password
