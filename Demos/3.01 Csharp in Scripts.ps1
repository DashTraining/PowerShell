#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '3.01 Csharp in Scripts.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# Different ways of using C# in a PowerShell script.


# 1. Simple C# helper type

# Plain C# class
$code = @'
public static class Greeter {
    // Simple helper method that PowerShell can call
    public static string SayHello(string name) {
        return $"Hello, {name}!";
    }
}
'@

# Add the custom type
Add-Type -TypeDefinition $code -Language CSharp

# Invoke helper method from PowerShell
[Greeter]::SayHello('Paul')


# 2. A custom C# object with property and method

$objectCode = @'
public class GreetingInfo {
    // Constructor creates instance of the object
    public GreetingInfo(string name) {
        Name = name;
    }

    // Public property for storing value
    public string Name { get; set; }

    // Public method to expose an action
    public string SayHello() {
        return $"Hello, {Name}!";
    }
}
'@

# Add the custom type
Add-Type -TypeDefinition $objectCode -Language CSharp

# Create and use the C# object of that type
$greeting = New-Object -TypeName GreetingInfo -ArgumentList 'Paul'
# also works: $greeting = [GreetingInfo]::new('Paul')
$greeting
$greeting.SayHello()


# 3: Package the greeting cmdlet as a reusable C# module

$moduleCode = @'
using System.Management.Automation;

// Defines class along with verb and noun
[Cmdlet(VerbsCommon.Get, "GreetingFromModule")]
public class GetGreetingFromModule : Cmdlet {
    // Input parameter
    [Parameter(Position = 0)]
    public string Name { get; set; } = "Jane";

    // Method that loops thru pipeline and performs action
    protected override void ProcessRecord() {
        WriteObject($"Hello from module, {Name}!");
    }
}
'@

# Define path for module
$moduleAssemblyPath = Join-Path -Path (New-Item -ItemType Directory -Path (Join-Path -Path $env:TEMP -ChildPath 'GreeterModule') -Force).FullName -ChildPath 'GreeterModule.dll'
# Clean up previous versions
if (Test-Path -LiteralPath $moduleAssemblyPath) {
    Remove-Item -LiteralPath $moduleAssemblyPath -Force
}
# Compile assembly into DLL file
Add-Type -TypeDefinition $moduleCode -Language CSharp -OutputAssembly $moduleAssemblyPath

# Import the compiled module and invoke
Import-Module -Name $moduleAssemblyPath -Force
Get-GreetingFromModule -Name 'Paul'
