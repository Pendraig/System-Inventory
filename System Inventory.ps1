function Get-WindowsProductKey {
    try {
        function Get-OSDigitalID($Key) {

            $KeyOffset = 52 
            $isWin8 = [Int]($Key[66] / 6) -bAND 1
            $HF7 = 0xF7
            $Key[66] = ($Key[66] -bAND $HF7) -bOR (($isWin8 -bAND 2) * 4)
            $i = 24
            [String]$Chars = 'BCDFGHJKMPQRTVWXY2346789'	
            do {
                $Current = 0 
                $j = 14
                do {
                    $Current = $Current * 256    
                    $Current = $Key[$j + $KeyOffset] + $Current
                    $Key[$j + $KeyOffset] = [math]::Floor([double]($Current / 24))
                    $Current = $Current % 24
                    $j = $j - 1 
                } while ($j -ge 0)
                $i = $i - 1
                $KeyOutput = $Chars.SubString($Current, 1) + $KeyOutput
                $Last = $Current
            } while ($i -ge 0)
            
            $KeyPart1 = $KeyOutput.SubString(1, $Last)
            $KeyPart2 = $KeyOutput.SubString(1, $KeyOutput.Length - 1)
            if ($Last -eq 0) {
                $KeyOutput = 'N' + $KeyPart2
            }
            else {
                $KeyOutput = $KeyPart2.Insert($KeyPart2.IndexOf($KeyPart1) + $KeyPart1.Length, 'N')
            }
            $a = $KeyOutput.SubString(0, 5)
            $b = $KeyOutput.SubString(5, 5)
            $c = $KeyOutput.SubString(10, 5)
            $d = $KeyOutput.SubString(15, 5)
            $e = $KeyOutput.SubString(20, 5)
            $KeyProduct = $a + '-' + $b + '-' + $c + '-' + $d + '-' + $e
            $KeyProduct 
        }
        
        $DigitalID = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'DigitalProductId')
        $Name = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'ProductName')
        $Build = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild')
        $Major = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentMajorVersionNumber')
        $Minor = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentMinorVersionNumber')
        $Owner = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'RegisteredOwner')
        $Install = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'InstallTime'); $Install = [datetime]::FromFileTime($Install)  
        $Type = (Get-ItemPropertyValue 'HKLM:System\CurrentControlSet\Control\Session Manager\Environment\' -Name 'PROCESSOR_ARCHITECTURE')
        if ($Type -eq 'x86') { $Type = '32-bit Operating System' } else { $Type = '64-bit Operating System' }
        $ProductID = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'ProductId')
        $ProductKey = Get-OSDigitalID $DigitalID
    
        $Results = New-Object -Type PSObject -Property @{
            'OS Name'          = $Name + ' Build ' + $Build + '.' + $Major + '.' + $Minor
            'OS Type'          = $Type
            'Registered Owner' = $Owner
            'Install Date'     = $Install
            'Product ID'       = $ProductID
            'Product Key'      = $ProductKey
        }
        $Results        
    }
    catch {
        throw "An error occurred retrieving product key information: $($_.Exception.Message)"
    }
}
