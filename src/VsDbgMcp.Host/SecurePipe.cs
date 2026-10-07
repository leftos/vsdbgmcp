using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace VsDbgMcp.Host
{
    /// <summary>
    /// Creates the server end of the pipe and says who is on the other end.
    ///
    /// The pipe is open only to the current user, and carries a mandatory label at
    /// this process's integrity level. Windows then refuses it, for reading and for
    /// writing, to any process below that level, so the user's normal processes
    /// cannot reach a Visual Studio that runs as administrator. .NET Framework's
    /// PipeSecurity cannot carry a label, hence CreateNamedPipe directly.
    /// </summary>
    static class SecurePipe
    {
        const uint PIPE_ACCESS_DUPLEX = 0x00000003;
        const uint FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
        const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        const uint PIPE_TYPE_BYTE = 0x00000000;
        const uint PIPE_READMODE_BYTE = 0x00000000;
        const uint PIPE_WAIT = 0x00000000;
        const uint PIPE_REJECT_REMOTE_CLIENTS = 0x00000008;
        const uint PIPE_UNLIMITED_INSTANCES = 255;
        const int TokenIntegrityLevel = 25;
        const int HighIntegrity = 0x3000;
        const int BufferSize = 64 * 1024;

        // PublicationOnly: a failure is not remembered, so the next pipe instance tries again.
        static readonly Lazy<string> OwnIntegritySid = new Lazy<string>(ReadIntegritySid, System.Threading.LazyThreadSafetyMode.PublicationOnly);

        /// <summary>Only the current user; no reading or writing from below this process's integrity level.</summary>
        static readonly Lazy<string> Descriptor = new Lazy<string>(() =>
        {
            using (var identity = WindowsIdentity.GetCurrent())
                return "D:P(A;;GA;;;" + identity.User.Value + ")S:(ML;;NWNR;;;" + OwnIntegritySid.Value + ")";
        }, System.Threading.LazyThreadSafetyMode.PublicationOnly);

        /// <summary>
        /// Creates one instance of the pipe. The first instance fails if the name is
        /// already taken, so nothing else can be listening under it.
        /// </summary>
        public static NamedPipeServerStream Create(string name, bool firstInstance)
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(Descriptor.Value, 1, out var descriptor, IntPtr.Zero))
                throw new Win32Exception();

            try
            {
                var attributes = new SECURITY_ATTRIBUTES
                {
                    nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
                    lpSecurityDescriptor = descriptor,
                    bInheritHandle = 0
                };

                var openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
                var pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

                var handle = CreateNamedPipe(@"\\.\pipe\" + name, openMode, pipeMode,
                    PIPE_UNLIMITED_INSTANCES, BufferSize, BufferSize, 0, ref attributes);
                if (handle.IsInvalid) throw new Win32Exception();

                return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, safePipeHandle: handle);
            }
            finally
            {
                LocalFree(descriptor);
            }
        }

        /// <summary>Whether this process runs at high integrity, that is, as administrator.</summary>
        public static bool IsElevated()
        {
            var sid = OwnIntegritySid.Value;
            var rid = sid.Substring(sid.LastIndexOf('-') + 1);
            return int.TryParse(rid, out var level) && level >= HighIntegrity;
        }

        /// <summary>The client process, as "name (pid)", for the log and the panel.</summary>
        public static string DescribeClient(NamedPipeServerStream stream)
        {
            if (!GetNamedPipeClientProcessId(stream.SafePipeHandle, out var pid)) return "unknown process";

            try
            {
                using (var process = Process.GetProcessById((int)pid))
                    return process.ProcessName + " (" + pid + ")";
            }
            catch (ArgumentException)
            {
                return "process " + pid;
            }
            catch (InvalidOperationException)
            {
                return "process " + pid;
            }
        }

        /// <summary>This process's integrity level, as a SID such as S-1-16-8192.</summary>
        static string ReadIntegritySid()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                GetTokenInformation(identity.Token, TokenIntegrityLevel, IntPtr.Zero, 0, out var size);
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (!GetTokenInformation(identity.Token, TokenIntegrityLevel, buffer, size, out size))
                        throw new Win32Exception();

                    // TOKEN_MANDATORY_LABEL starts with a pointer to the label's SID.
                    return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode,
            uint maxInstances, int outBufferSize, int inBufferSize, uint defaultTimeout, ref SECURITY_ATTRIBUTES attributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, int revision,
            out IntPtr descriptor, IntPtr descriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr token, int informationClass, IntPtr information,
            int length, out int returnLength);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr memory);
    }
}
