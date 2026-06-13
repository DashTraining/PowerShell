/*
           _          _
        __| |____ ___| |__
       / _  |__  / __| '_ \           File:   '3.02 Custom PSProvider.cs'
      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
       T  R  A  I  N  I  N  G
*/

// Simple read-only custom PSProvider that exposes local port ownership.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Management.Automation;
using System.Management.Automation.Provider;

namespace Dash.Training
{
    // These are the .NET types the provider returns for the different levels of the drive.
    // PowerShell can format them differently based on their type names.
    public class NetworkProtocol
    {
        public string Protocol { get; set; }
        public int PortCount { get; set; }
    }

    public class NetworkPort
    {
        public string Protocol { get; set; }
        public int Port { get; set; }
        public int BindingCount { get; set; }
        public string StateSummary { get; set; }
        public string ProcessSummary { get; set; }
    }

    public class NetworkSocket
    {
        public string Name { get; set; }
        public string Protocol { get; set; }
        public int Port { get; set; }
        public string LocalAddress { get; set; }
        public string RemoteAddress { get; set; }
        public int? RemotePort { get; set; }
        public string State { get; set; }
        public int OwningProcess { get; set; }
        public string ProcessName { get; set; }
    }

    internal static class PortData
    {
        private static DateTime _lastRefreshUtc = DateTime.MinValue;
        private static List<NetworkSocket> _cachedRecords = new List<NetworkSocket>();
        private static readonly Dictionary<int, string> _processNameCache = new Dictionary<int, string>();

        // Port data is read from the native Windows TCP/UDP owner PID tables.
        // This avoids starting a PowerShell runspace from within the provider.
        internal static List<NetworkSocket> GetRecords()
        {
            if ((DateTime.UtcNow - _lastRefreshUtc).TotalSeconds < 2 && _cachedRecords.Count > 0)
            {
                return _cachedRecords;
            }

            var records = new List<NetworkSocket>();

            records.AddRange(GetTcpRecords());
            records.AddRange(GetUdpRecords());

            _cachedRecords = records
                .OrderBy(r => r.Protocol)
                .ThenBy(r => r.Port)
                .ThenBy(r => r.LocalAddress)
                .ToList();

            _lastRefreshUtc = DateTime.UtcNow;
            return _cachedRecords;
        }

        private static IEnumerable<NetworkSocket> GetTcpRecords()
        {
            int bufferSize = 0;
            IntPtr buffer = IntPtr.Zero;

            try
            {
                // Query the size we need for the TCP table.
                uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (result != ERROR_INSUFFICIENT_BUFFER)
                {
                    yield break;
                }

                buffer = Marshal.AllocHGlobal(bufferSize);
                result = GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (result != NO_ERROR)
                {
                    yield break;
                }

                var table = Marshal.PtrToStructure<MIB_TCPTABLE_OWNER_PID>(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, Marshal.SizeOf(table.dwNumEntries));

                for (int i = 0; i < table.dwNumEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    yield return CreateSocketRecord(
                        protocol: "TCP",
                        localAddress: new IPAddress(row.dwLocalAddr).ToString(),
                        localPort: ntohs((ushort)row.dwLocalPort),
                        remoteAddress: new IPAddress(row.dwRemoteAddr).ToString(),
                        remotePort: ntohs((ushort)row.dwRemotePort),
                        state: row.dwState.ToString(),
                        owningProcess: (int)row.dwOwningPid);

                    rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_TCPROW_OWNER_PID>());
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private static IEnumerable<NetworkSocket> GetUdpRecords()
        {
            int bufferSize = 0;
            IntPtr buffer = IntPtr.Zero;

            try
            {
                // Query the size we need for the UDP table.
                uint result = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                if (result != ERROR_INSUFFICIENT_BUFFER)
                {
                    yield break;
                }

                buffer = Marshal.AllocHGlobal(bufferSize);
                result = GetExtendedUdpTable(buffer, ref bufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                if (result != NO_ERROR)
                {
                    yield break;
                }

                var table = Marshal.PtrToStructure<MIB_UDPTABLE_OWNER_PID>(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, Marshal.SizeOf(table.dwNumEntries));

                for (int i = 0; i < table.dwNumEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    yield return CreateSocketRecord(
                        protocol: "UDP",
                        localAddress: new IPAddress(row.dwLocalAddr).ToString(),
                        localPort: ntohs((ushort)row.dwLocalPort),
                        remoteAddress: null,
                        remotePort: null,
                        state: "Bound",
                        owningProcess: (int)row.dwOwningPid);

                    rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_UDPROW_OWNER_PID>());
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private static NetworkSocket CreateSocketRecord(string protocol, string localAddress, int localPort, string remoteAddress, int? remotePort, string state, int owningProcess)
        {
            return new NetworkSocket
            {
                Protocol = protocol,
                Port = localPort,
                LocalAddress = localAddress,
                RemoteAddress = remoteAddress,
                RemotePort = remotePort,
                State = state,
                OwningProcess = owningProcess,
                ProcessName = GetProcessName(owningProcess)
            };
        }

        // Process lookup is presentation data rather than provider structure, so it is kept separate.
        // Cache only valid process names to avoid stale entries for recycled PIDs.
        internal static string GetProcessName(int processId)
        {
            if (processId <= 0)
            {
                return "<system>";
            }

            if (_processNameCache.TryGetValue(processId, out string cachedName))
            {
                return cachedName;
            }

            try
            {
                string processName = Process.GetProcessById(processId).ProcessName;
                _processNameCache[processId] = processName;
                return processName;
            }
            catch
            {
                return "<exited>";
            }
        }

        private const int AF_INET = 2;
        private const uint NO_ERROR = 0;
        private const uint ERROR_INSUFFICIENT_BUFFER = 122;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            TCP_TABLE_CLASS TableClass,
            uint Reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            UDP_TABLE_CLASS TableClass,
            uint Reserved);

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            // followed by MIB_TCPROW_OWNER_PID[dwNumEntries]
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            // followed by MIB_UDPROW_OWNER_PID[dwNumEntries]
        }

        private static ushort ntohs(ushort netshort)
        {
            return (ushort)((netshort >> 8) | (netshort << 8));
        }
    }

    // This attribute gives PowerShell the provider name used by New-PSDrive -PSProvider NetworkPort.
    // Inheriting from NavigationCmdletProvider opts into a drive that can have container-like paths.
    [CmdletProvider("NetworkPort", ProviderCapabilities.None)]
    public class NetworkPortProvider : NavigationCmdletProvider
    {
        // Providers receive paths as strings, so the first job is turning "TCP\443\1" into parts
        // the rest of the provider logic can reason about.
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

        private static IEnumerable<NetworkSocket> GetByProtocol(string protocol)
        {
            return PortData.GetRecords().Where(r => r.Protocol.Equals(protocol, StringComparison.OrdinalIgnoreCase));
        }

        private static bool TryGetPort(string text, out int port)
        {
            return int.TryParse(text, out port) && port >= 0 && port <= 65535;
        }

        private static IEnumerable<NetworkSocket> GetPortRecords(string protocol, int port)
        {
            return GetByProtocol(protocol)
                .Where(r => r.Port == port)
                .OrderBy(r => r.LocalAddress)
                .ThenBy(r => r.RemoteAddress)
                .ThenBy(r => r.RemotePort)
                .ThenBy(r => r.OwningProcess);
        }

        private static bool TryGetSocketOrdinal(string text, out int ordinal)
        {
            return int.TryParse(text, out ordinal) && ordinal >= 1;
        }

        private static NetworkSocket GetSocketRecord(string protocol, int port, int ordinal)
        {
            var record = GetPortRecords(protocol, port).Skip(ordinal - 1).FirstOrDefault();
            if (record == null)
            {
                return null;
            }

            record.Name = ordinal.ToString();
            return record;
        }

        // This creates the summary object that represents a port folder such as Port:\TCP\443.
        private static NetworkPort GetPortSummary(string protocol, int port)
        {
            var records = GetPortRecords(protocol, port).ToList();
            if (records.Count == 0)
            {
                return null;
            }

            return new NetworkPort
            {
                Protocol = protocol,
                Port = port,
                BindingCount = records.Count,
                StateSummary = string.Join(", ", records.Select(r => r.State).Distinct().OrderBy(s => s)),
                ProcessSummary = string.Join(", ", records
                    .Select(r => string.Format("{0} ({1})", r.ProcessName, r.OwningProcess))
                    .Distinct()
                    .OrderBy(s => s))
            };
        }

        // PowerShell asks the provider whether a path is syntactically valid before trying to use it.
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

            if (parts.Length == 3)
            {
                int port;
                int ordinal;
                return IsProtocol(parts[0])
                    && TryGetPort(parts[1], out port)
                    && TryGetSocketOrdinal(parts[2], out ordinal);
            }

            return false;
        }

        // ItemExists answers whether a particular path maps to real data right now.
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

            if (parts.Length == 3)
            {
                int port;
                int ordinal;
                if (!IsProtocol(parts[0]) || !TryGetPort(parts[1], out port) || !TryGetSocketOrdinal(parts[2], out ordinal))
                {
                    return false;
                }

                return GetSocketRecord(parts[0], port, ordinal) != null;
            }

            return false;
        }

        // This tells PowerShell which items behave like folders during navigation.
        protected override bool IsItemContainer(string path)
        {
            string[] parts = SplitPathParts(path);
            return parts.Length < 3;
        }

        // Providers can expose hierarchy dynamically, so PowerShell asks whether child items exist.
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

            if (parts.Length == 2)
            {
                int port;
                return TryGetPort(parts[1], out port) && GetPortRecords(parts[0], port).Any();
            }

            return false;
        }

        // GetItem is used for direct lookups such as Get-Item Port:\TCP\443.
        // WriteItemObject is the provider API that hands an object back to PowerShell together with
        // its provider path and whether it should be treated as a container.
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
                WriteItemObject(new NetworkProtocol
                {
                    Protocol = protocol,
                    PortCount = GetByProtocol(protocol).Select(r => r.Port).Distinct().Count()
                }, path, true);
                return;
            }

            int port;
            if (parts.Length == 2 && TryGetPort(parts[1], out port))
            {
                string protocol = parts[0].ToUpperInvariant();
                NetworkPort portSummary = GetPortSummary(protocol, port);
                if (portSummary != null)
                {
                    WriteItemObject(portSummary, path, true);
                }
                return;
            }

            int ordinal;
            if (parts.Length == 3 && TryGetPort(parts[1], out port) && TryGetSocketOrdinal(parts[2], out ordinal))
            {
                string protocol = parts[0].ToUpperInvariant();
                NetworkSocket socket = GetSocketRecord(protocol, port, ordinal);
                if (socket != null)
                {
                    WriteItemObject(socket, path, false);
                }
            }
        }

        // GetChildItems powers directory-style enumeration such as Get-ChildItem Port:\TCP.
        protected override void GetChildItems(string path, bool recurse, uint depth)
        {
            string[] parts = SplitPathParts(path);

            if (parts.Length == 0)
            {
                WriteItemObject(new NetworkProtocol { Protocol = "TCP", PortCount = GetByProtocol("TCP").Select(r => r.Port).Distinct().Count() }, MakePath(path, "TCP"), true);
                WriteItemObject(new NetworkProtocol { Protocol = "UDP", PortCount = GetByProtocol("UDP").Select(r => r.Port).Distinct().Count() }, MakePath(path, "UDP"), true);

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
                    WriteItemObject(GetPortSummary(protocol, port), childPath, true);
                }

                if (recurse && depth > 0)
                {
                    foreach (int port in protocolRecords.Select(r => r.Port).Distinct().OrderBy(p => p))
                    {
                        GetChildItems(MakePath(path, port.ToString()), true, depth - 1);
                    }
                }
                return;
            }

            if (parts.Length == 2 && IsProtocol(parts[0]))
            {
                string protocol = parts[0].ToUpperInvariant();
                int port;
                if (!TryGetPort(parts[1], out port))
                {
                    return;
                }

                int ordinal = 1;
                foreach (NetworkSocket record in GetPortRecords(protocol, port))
                {
                    record.Name = ordinal.ToString();
                    string childPath = MakePath(path, record.Name);
                    WriteItemObject(record, childPath, false);
                    ordinal++;
                }
            }
        }

        // GetChildNames is a lighter-weight companion to GetChildItems for commands that only need names.
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
                    WriteItemObject(port.ToString(), MakePath(path, port.ToString()), true);
                }
                return;
            }

            if (parts.Length == 2 && IsProtocol(parts[0]))
            {
                int port;
                if (!TryGetPort(parts[1], out port))
                {
                    return;
                }

                int ordinal = 1;
                foreach (NetworkSocket record in GetPortRecords(parts[0], port))
                {
                    WriteItemObject(ordinal.ToString(), MakePath(path, ordinal.ToString()), false);
                    ordinal++;
                }
            }
        }
    }
}
