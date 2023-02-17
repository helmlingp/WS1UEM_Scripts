# Description: This Powershell script should be used to change the logging level of the Workspace ONE UEM Agent logs by editing the WS1 Agent config file(s) in C:\ProgramFiles(x86)\Airwatch\AgentUI
# Execution Context: SYSTEM
# Execution Architecture: EITHER64OR32BIT
# Timeout: 30
# Variables: ConfigFile,All; level,Debug

<# The default log level is set to Debug now, and it can be changed for all executables in Hub by the file :
"C:\ProgramData\Airwatch\UnifiedAgent\Logs\Logging.Default.json"
or we can change log level for each executable by creating a file :
"C:\ProgramData\Airwatch\UnifiedAgent\Logs\Logging.[ExecutableName].exe.json"  like, example :
"C:\ProgramData\Airwatch\UnifiedAgent\Logs\Logging.TaskScheduler.exe.json"

{
    "Serilog" : {
        "MinimumLevel" : {
            "Default : "Debug",
            "Override" : {
                "Microsoft" : "Warning",
                "System" : "Warning"
            }
        }
    }
}

 #>
 
$script:ConfigFile=$env:ConfigFile,
$script:Level=$env:Level

if($script:ConfigFile -eq 'All'){$script:ConfigFile='*.config'}

$path = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Airwatch\AgentUI"
Get-ChildItem $path\$script:ConfigFile -Recurse | ForEach-Object {
    [xml]$xml = Get-Content -Path $_.FullName
    #Test for old path in XML
    $node = $xml.configuration.loggingConfiguration
    if($node){
        # change attribute on selected node
        if(!$node){
            write-host "no logging config in file $_"
        }else{
            $before = $node.level
            write-host "Before: $before"
            $node.level=$script:Level
            $xml.Save($_.FullName)
            $after = $node.level
            write-host "After: $after"
        }
    } else {
        $node = $xml.configuration.appSettings.add | Where-Object {$_.key -eq "serilog:minimum-level"}
        # change attribute on selected node
        if(!$node){
            write-host "no logging config in file $_"
        }else{
            $before = $node.value
            write-host "Before: $before"
            $node.value=$script:Level
            $xml.Save($_.FullName)
            $after = $node.value
            write-host "After: $after"
        }
    }
}