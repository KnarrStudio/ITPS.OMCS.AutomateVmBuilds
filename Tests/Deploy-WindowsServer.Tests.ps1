Describe "Deploy-WindowsServer.ps1" {
    BeforeAll {
        # Path to the script under test
        $ScriptPath = "..\Scripts\Deploy-WindowsServer.ps1"
        $MockCsvPath = "..\Tests\Mock-ServerData.csv"
    }

    Context "CSV Import" {
        It "Should import a valid CSV without error" {
            { . $ScriptPath -ServerDataFile $MockCsvPath } | Should -Not -Throw
        }
        It "Should throw an error if the CSV is missing required fields" {
            $BadCsv = "..\Tests\Bad-ServerData.csv"
            { . $ScriptPath -ServerDataFile $BadCsv } | Should -Throw
        }
    }

    Context "Add-Script Function" {
        It "Should add a script to the scripts array" {
            $global:scripts = @()
            . $ScriptPath
            Add-Script -script 'Test-Script %1' -parameters @('param')
            $scripts[0][0] | Should -Be 'Test-Script "param"'
        }
    }

    # Add more tests for other functions and scenarios as needed
}
