using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VsDbgMcp
{
    /// <summary>
    /// Every name this product claims on the machine, in one place.
    /// </summary>
    public static class Names
    {
        public const string Product = "vsdbgmcp";

        /// <summary>
        /// Bumped when IDebugHost or IProjectSystem change shape.
        /// 2: threads and selection carry the process they belong to.
        /// 3: the shim reports each call so the panel can show what was returned.
        /// 4: module loads are their own event, tracepoints have their own sink,
        ///    and modules report how many were loaded before the filter.
        /// 5: symbols can be loaded and their search reported, modules carry the
        ///    identity of the image, a process says which machine it runs on, expand
        ///    can pick one element out of a container, every read says which frame
        ///    it came out of or why nothing there could be read, and the debuggee's
        ///    heap can be borrowed for an out-parameter.
        /// 6: a debuggee can be profiled, with the extension collecting and the shim
        ///    reading what it collected.
        /// 9: compact capture IDs; older shims require GUID-shaped capture IDs.
        /// 10: operations completing and the solution changing are pushed to the shim.
        /// 11: the shim sends the instance token before JSON-RPC starts (PipeToken).
        /// </summary>
        public const int ContractVersion = 11;

        public const string InstanceFilePrefix = "inst-";
        public const string InstanceFileSuffix = ".json";

        /// <summary>Where instances announce themselves. One file per running VS.</summary>
        public static string InstanceDir =>
            Environment.GetEnvironmentVariable("VSDBGMCP_DATA_DIR") ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Product);

        public static string InstanceFile(int pid) =>
            Path.Combine(InstanceDir, InstanceFilePrefix + pid + InstanceFileSuffix);

        /// <summary>
        /// Where the extension stages the shim. An agent names the shim by absolute
        /// path, and Visual Studio regenerates the extension's own folder on every
        /// update, so the path an agent is configured with cannot be that one.
        /// </summary>
        public static string ShimDir => Path.Combine(InstanceDir, "bin");

        public static string ShimExe => Path.Combine(ShimDir, Product + ".exe");

        /// <summary>
        /// A new pipe name for one Visual Studio process. The random part stops another
        /// process from guessing the name or creating the pipe first; shims read the
        /// name from the discovery record.
        /// </summary>
        public static string NewPipeName(int pid)
        {
            var bytes = new byte[16];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes);

            var sb = new StringBuilder(Product.Length + 48);
            sb.Append(Product).Append('-').Append(pid).Append('-');
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    /// <summary>What an instance can do. Sent at handshake so the shim can hide tools it cannot serve.</summary>
    public static class Capabilities
    {
        public const string Native = "native";
        public const string Managed = "managed";
        public const string DataBreakpoints = "dataBreakpoints";
        public const string Disassembly = "disasm";
        public const string Dumps = "dumps";
        public const string ConsoleIo = "consoleIo";
        public const string WindowCapture = "windowCapture";
    }
}
