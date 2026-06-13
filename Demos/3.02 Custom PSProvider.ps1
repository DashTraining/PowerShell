# Simple read-only custom PSProvider that exposes local port ownership.

# Reference:
# https://github.com/MicrosoftDocs/PowerShell-Docs/blob/main/reference/docs-conceptual/developer/provider/windows-powershell-provider-overview.md
#
# Paths:
# - Port:\
# - Port:\TCP
# - Port:\UDP
# - Port:\TCP\443
# - Port:\UDP\53

$providerSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Provider;

namespace Dash.Training.Providers
{
    public class PortRecord
    {
        public string Protocol { get; set; }
        public int Port { get; set; }
        public string LocalAddress { get; set; }
        public string State { get; set; }
        public int OwningProcess { get; set; }
        public string ProcessName { get; set; }
    }

    internal static class PortData
    {
        private static DateTime _lastRefreshUtc = DateTime.MinValue;
        private static List<PortRecord> _cachedRecords = new List<PortRecord>();

        internal static List<PortRecord> GetRecords()
        {
            if ((DateTime.UtcNow - _lastRefreshUtc).TotalSeconds < 2 && _cachedRecords.Count > 0)
            {
                return _cachedRecords;
            }

            var records = new List<PortRecord>();

            using (var ps = PowerShell.Create())
            {
                ps.AddCommand("Get-NetTCPConnection");

                foreach (PSObject row in ps.Invoke())
                {
                    records.Add(new PortRecord
                    {
                        Protocol = "TCP",
                        Port = Convert.ToInt32(row.Properties["LocalPort"].Value),
                        LocalAddress = Convert.ToString(row.Properties["LocalAddress"].Value),
                        State = Convert.ToString(row.Properties["State"].Value),
                        OwningProcess = Convert.ToInt32(row.Properties["OwningProcess"].Value),
                        ProcessName = GetProcessName(Convert.ToInt32(row.Properties["OwningProcess"].Value))
                    });
                }
            }

            using (var ps = PowerShell.Create())
            {
                ps.AddCommand("Get-NetUDPEndpoint");

                foreach (PSObject row in ps.Invoke())
                {
                    records.Add(new PortRecord
                    {
                        Protocol = "UDP",
                        Port = Convert.ToInt32(row.Properties["LocalPort"].Value),
                        LocalAddress = Convert.ToString(row.Properties["LocalAddress"].Value),
                        State = "Bound",
                        OwningProcess = Convert.ToInt32(row.Properties["OwningProcess"].Value),
                        ProcessName = GetProcessName(Convert.ToInt32(row.Properties["OwningProcess"].Value))
                    });
                }
            }

            _cachedRecords = records
                .OrderBy(r => r.Protocol)
                .ThenBy(r => r.Port)
                .ThenBy(r => r.LocalAddress)
                .ToList();

            _lastRefreshUtc = DateTime.UtcNow;
            return _cachedRecords;
        }

        internal static string GetProcessName(int processId)
        {
            try
            {
                return Process.GetProcessById(processId).ProcessName;
            }
            catch
            {
                return "<exited>";
            }
        }
    }

    [CmdletProvider("NetworkPort", ProviderCapabilities.None)]
    public class NetworkPortProvider : NavigationCmdletProvider
    {
        private static string[] SplitPathParts(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || path == "\\" || path == "/")
            {
                return Array.Empty<string>();
            }

            return path.Trim('\\', '/')
                .Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        }

        private static bool IsProtocol(string value)
        {
            return value.Equals("TCP", StringComparison.OrdinalIgnoreCase)
                || value.Equals("UDP", StringComparison.OrdinalIgnoreCase);
        }

        private static IEnumerable<PortRecord> GetByProtocol(string protocol)
        {
            return PortData.GetRecords().Where(r => r.Protocol.Equals(protocol, StringComparison.OrdinalIgnoreCase));
        }

        private static bool TryGetPort(string text, out int port)
        {
            return int.TryParse(text, out port) && port >= 0 && port <= 65535;
        }

        private static IEnumerable<PortRecord> GetPortRecords(string protocol, int port)
        {
            return GetByProtocol(protocol).Where(r => r.Port == port);
        }

        protected override bool IsValidPath(string path)
        {
            string[] parts = SplitPathParts(path);

            if (parts.Length == 0)
            {
                return true;
            }

            if (parts.Length == 1)
            {
                return IsProtocol(parts[0]);
            }

            if (parts.Length == 2)
            {
                int port;
                return IsProtocol(parts[0]) && TryGetPort(parts[1], out port);
            }

            return false;
        }

        protected override bool ItemExists(string path)
        {
            string[] parts = SplitPathParts(path);

            if (parts.Length == 0)
            {
                return true;
            }

            if (parts.Length == 1)
            {
                return IsProtocol(parts[0]);
            }

            if (parts.Length == 2)
            {
                int port;
                if (!IsProtocol(parts[0]) || !TryGetPort(parts[1], out port))
                {
                    return false;
                }

                return GetPortRecords(parts[0], port).Any();
            }

            return false;
        }

        protected override bool IsItemContainer(string path)
        {
            string[] parts = SplitPathParts(path);
            return parts.Length < 2;
        }

        protected override bool HasChildItems(string path)
        {
            string[] parts = SplitPathParts(path);

            if (parts.Length == 0)
            {
                return true;
            }

            if (parts.Length == 1)
            {
                return GetByProtocol(parts[0]).Any();
            }

            return false;
        }

        protected override void GetItem(string path)
        {
            string[] parts = SplitPathParts(path);

            if (parts.Length == 0)
            {
                WriteItemObject(new PSObject(new
                {
                    Name = "Port",
                    Description = "Custom provider for local TCP/UDP port ownership"
                }), path, true);
                return;
            }

            if (parts.Length == 1)
            {
                string protocol = parts[0].ToUpperInvariant();
                var summary = new PSObject(new
                {
                    Protocol = protocol,
                    PortCount = GetByProtocol(protocol).Select(r => r.Port).Distinct().Count()
                });
                WriteItemObject(summary, path, true);
                return;
            }

            int port;
            if (parts.Length == 2 && TryGetPort(parts[1], out port))
            {
                string protocol = parts[0].ToUpperInvariant();
                foreach (PortRecord record in GetPortRecords(protocol, port))
                {
                    WriteItemObject(record, path, false);
                }
            }
        }

        protected override void GetChildItems(string path, bool recurse, uint depth)
        {
            string[] parts = SplitPathParts(path);

            if (parts.Length == 0)
            {
                WriteItemObject(new PSObject(new { Protocol = "TCP" }), MakePath(path, "TCP"), true);
                WriteItemObject(new PSObject(new { Protocol = "UDP" }), MakePath(path, "UDP"), true);

                if (recurse && depth > 0)
                {
                    GetChildItems(MakePath(path, "TCP"), true, depth - 1);
                    GetChildItems(MakePath(path, "UDP"), true, depth - 1);
                }
                return;
            }

            if (parts.Length == 1 && IsProtocol(parts[0]))
            {
                string protocol = parts[0].ToUpperInvariant();
                var protocolRecords = GetByProtocol(protocol).ToList();

                foreach (int port in protocolRecords.Select(r => r.Port).Distinct().OrderBy(p => p))
                {
                    string childPath = MakePath(path, port.ToString());
                    var portSummary = new PSObject(new
                    {
                        Protocol = protocol,
                        Port = port,
                        BindingCount = protocolRecords.Count(r => r.Port == port)
                    });
                    WriteItemObject(portSummary, childPath, false);
                }
            }
        }

        protected override void GetChildNames(string path, ReturnContainers returnContainers)
        {
            string[] parts = SplitPathParts(path);

            if (parts.Length == 0)
            {
                WriteItemObject("TCP", MakePath(path, "TCP"), true);
                WriteItemObject("UDP", MakePath(path, "UDP"), true);
                return;
            }

            if (parts.Length == 1 && IsProtocol(parts[0]))
            {
                string protocol = parts[0].ToUpperInvariant();
                foreach (int port in GetByProtocol(protocol).Select(r => r.Port).Distinct().OrderBy(p => p))
                {
                    WriteItemObject(port.ToString(), MakePath(path, port.ToString()), false);
                }
            }
        }
    }
}
'@

$providerHash = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($providerSource)
    )
).Replace('-', '').Substring(0, 12)

$providerAssemblyPath = Join-Path -Path $env:TEMP -ChildPath ("NetworkPortProvider.{0}.{1}.dll" -f $providerHash, $PID)
$providerLoaded = Get-Module | Where-Object Path -eq $providerAssemblyPath | Select-Object -First 1

if (-not $providerLoaded) {
    if (Test-Path -LiteralPath $providerAssemblyPath) {
        Remove-Item -LiteralPath $providerAssemblyPath -Force
    }

    try {
        Add-Type -TypeDefinition $providerSource `
            -Language CSharp `
            -OutputAssembly $providerAssemblyPath `
            -ErrorAction Stop
    }
    catch {
        if (Test-Path -LiteralPath $providerAssemblyPath) {
            Remove-Item -LiteralPath $providerAssemblyPath -Force -ErrorAction SilentlyContinue
        }
        throw "Failed to compile the NetworkPort provider: $($_.Exception.Message)"
    }

    Import-Module -Name $providerAssemblyPath -Force
}

if (Get-PSDrive -Name Port -ErrorAction SilentlyContinue) {
    Remove-PSDrive -Name Port -Force
}

New-PSDrive -Name Port -PSProvider NetworkPort -Root '\' | Out-Null

# Example commands for the demo:
# Get-ChildItem Port:\
# Get-ChildItem Port:\TCP
# Get-Item Port:\TCP\443
# Get-Item Port:\UDP\53
