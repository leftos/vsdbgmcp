using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using StreamJsonRpc;
using VsDbgMcp.Contracts;
using VsDbgMcp.Host;
using VsDbgMcp.Shim.Session;
using Xunit;

namespace VsDbgMcp.Tests
{
    /// <summary>
    /// The extension's own pipe server over real named pipes: nothing is served to a
    /// connection that has not sent the instance token, and the pipe is closed to
    /// processes below the extension's integrity level.
    /// </summary>
    public class PipeAuthenticationTests : IDisposable
    {
        const string Token = "0123456789abcdef0123456789abcdef";

        readonly string _pipe = Names.NewPipeName(Process.GetCurrentProcess().Id);
        readonly FakeHost _target;
        readonly PipeServer _server;

        public PipeAuthenticationTests()
        {
            _target = new FakeHost(_pipe, Token);
            _server = new PipeServer(_pipe, Token, _target, _target, null);
            _server.Start();
        }

        public void Dispose()
        {
            _server.Dispose();
            _target.Dispose();
        }

        InstanceRecord Record(string token, int contract = Names.ContractVersion) => new InstanceRecord
        {
            Pid = Process.GetCurrentProcess().Id,
            Pipe = _pipe,
            Token = token,
            Contract = contract,
            DebugMode = DebugModes.Break
        };

        static HostLink Link(InstanceRecord record) => new HostLink(record, new EventBus(), new VsDbgMcp.Shim.Session.EventLog());

        async Task<NamedPipeClientStream> ConnectRawAsync()
        {
            var pipe = new NamedPipeClientStream(".", _pipe, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(3000);
            return pipe;
        }

        static IDebugHost StartRpc(Stream pipe, out JsonRpc rpc)
        {
            var formatter = new JsonMessageFormatter();
            formatter.JsonSerializer.NullValueHandling = NullValueHandling.Ignore;
            rpc = new JsonRpc(new HeaderDelimitedMessageHandler(pipe, pipe, formatter));
            var debug = rpc.Attach<IDebugHost>();
            rpc.StartListening();
            return debug;
        }

        [Fact]
        public async Task A_client_with_the_token_is_served()
        {
            using (var link = Link(Record(Token)))
            {
                Assert.True(await link.ConnectAsync(CancellationToken.None), link.LastFailure?.Reason);

                var status = await link.Debug.GetStatusAsync();
                Assert.NotNull(status);
                Assert.Equal(1, _server.ConnectionCount);
            }
        }

        [Fact]
        public async Task A_client_that_skips_the_token_is_not_served()
        {
            using (var pipe = await ConnectRawAsync())
            {
                var debug = StartRpc(pipe, out var rpc);
                using (rpc)
                {
                    await Assert.ThrowsAnyAsync<Exception>(() =>
                        debug.GoAsync().WaitAsync(TimeSpan.FromSeconds(10)));
                }
            }

            Assert.DoesNotContain(nameof(IDebugHost.GoAsync), _target.Calls);
            Assert.Equal(0, _server.ConnectionCount);
        }

        [Fact]
        public async Task A_wrong_token_is_refused_with_a_reason()
        {
            using (var link = Link(Record("not-the-token")))
            {
                Assert.False(await link.ConnectAsync(CancellationToken.None));
                Assert.Contains("refused the connection token", link.LastFailure?.Reason);
            }

            Assert.Empty(_target.Calls);
            Assert.Equal(0, _server.ConnectionCount);
        }

        [Fact]
        public async Task One_client_sending_the_token_does_not_admit_another()
        {
            using (var link = Link(Record(Token)))
            using (var pipe = await ConnectRawAsync())
            {
                Assert.True(await link.ConnectAsync(CancellationToken.None), link.LastFailure?.Reason);

                var debug = StartRpc(pipe, out var rpc);
                using (rpc)
                {
                    await Assert.ThrowsAnyAsync<Exception>(() =>
                        debug.GoAsync().WaitAsync(TimeSpan.FromSeconds(10)));
                }

                Assert.DoesNotContain(nameof(IDebugHost.GoAsync), _target.Calls);
                Assert.Equal(1, _server.ConnectionCount);
            }
        }

        [Fact]
        public async Task Events_reach_only_clients_that_sent_the_token()
        {
            using (var link = Link(Record(Token)))
            using (var pipe = await ConnectRawAsync())
            {
                Assert.True(await link.ConnectAsync(CancellationToken.None), link.LastFailure?.Reason);

                var formatter = new JsonMessageFormatter();
                var rpc = new JsonRpc(new HeaderDelimitedMessageHandler(pipe, pipe, formatter));
                var stranger = new Listener();
                rpc.AddLocalRpcTarget<IShimEvents>(stranger, null);
                rpc.StartListening();
                using (rpc)
                {
                    _server.Broadcast(events => events.OnOutputAsync(new OutputEvent { Text = "secret" }));
                    await Task.Delay(500);
                    Assert.Equal(0, stranger.Received);
                }
            }
        }

        [Fact]
        public async Task A_client_that_sends_nothing_is_dropped()
        {
            using (var pipe = await ConnectRawAsync())
            {
                var buffer = new byte[1];
                var read = await pipe.ReadAsync(buffer, 0, 1)
                    .WaitAsync(PipeToken.Timeout + TimeSpan.FromSeconds(10));
                Assert.Equal(0, read);
            }
        }

        [Fact]
        public async Task An_older_host_is_reached_without_the_token_frame()
        {
            var pipe = "vsdbgmcp-legacy-" + Guid.NewGuid().ToString("N");
            using (var host = new FakeHost(pipe, Token) { ExpectsToken = false })
            {
                host.Start();
                var record = Record(Token, contract: PipeToken.FirstContract - 1);
                record.Pipe = pipe;

                using (var link = Link(record))
                {
                    Assert.True(await link.ConnectAsync(CancellationToken.None), link.LastFailure?.Reason);
                    Assert.Equal(Token, host.LastToken);
                    Assert.Empty(host.TokenChecks);
                }
            }
        }

        [Fact]
        public async Task A_client_kept_out_of_an_elevated_instance_is_told_why()
        {
            if (Environment.IsPrivilegedProcess) return;

            // Stands in for the High label: Windows refuses the pipe to this process.
            var name = "vsdbgmcp-denied-" + Guid.NewGuid().ToString("N");
            var security = new PipeSecurity();
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,
                PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Deny));
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,
                PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));

            using (var server = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security))
            {
                var record = Record(Token);
                record.Pipe = name;
                record.Elevated = true;

                using (var link = Link(record))
                {
                    Assert.False(await link.ConnectAsync(CancellationToken.None));
                    Assert.Contains("runs as administrator", link.LastFailure.Reason);
                    Assert.Contains("Run both as administrator or both without", link.LastFailure.NextStep);
                }
            }
        }

        [Fact]
        public async Task The_pipe_is_labelled_at_this_process_integrity_level()
        {
            using (var pipe = await ConnectRawAsync())
            {
                var sddl = LabelOf(pipe.SafePipeHandle);
                Assert.Matches(@"^S:[A-Z]*\(ML;;NWNR;;;(LW|ME|MP|HI|SI)\)$", sddl);
                Assert.Equal(SecurePipe.IsElevated(), sddl.Contains(";;;HI)") || sddl.Contains(";;;SI)"));
            }
        }

        [Fact]
        public void An_elevated_client_is_told_why_a_normal_instance_refused_it()
        {
            var failure = HostLink.AccessDenied(visualStudioElevated: false, clientElevated: true);
            Assert.Equal("This MCP client runs as administrator, and Visual Studio does not.", failure.Reason);
            Assert.Contains("Run both as administrator or both without", failure.NextStep);
        }

        [Fact]
        public void A_refusal_at_matching_elevation_is_not_blamed_on_elevation()
        {
            var failure = HostLink.AccessDenied(visualStudioElevated: false, clientElevated: false);
            Assert.Contains("same elevation", failure.Reason);
            Assert.DoesNotContain("administrator", failure.NextStep);
        }

        [Fact]
        public void A_refusal_by_an_older_instance_names_the_likely_cause()
        {
            var failure = HostLink.AccessDenied(visualStudioElevated: null, clientElevated: false);
            Assert.Contains("most likely run at different elevation", failure.Reason);
        }

        [Fact]
        public async Task Closing_the_server_drops_a_client_that_has_not_sent_the_token()
        {
            using (var pipe = await ConnectRawAsync())
            {
                await Task.Delay(200);
                _server.Dispose();

                var buffer = new byte[1];
                var read = await pipe.ReadAsync(buffer, 0, 1).WaitAsync(TimeSpan.FromSeconds(2));
                Assert.Equal(0, read);
            }
        }

        [Fact]
        public async Task Sending_the_token_stops_when_cancelled()
        {
            var name = "vsdbgmcp-silent-" + Guid.NewGuid().ToString("N");
            using (var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
            using (var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous))
            using (var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
            {
                var accepting = server.WaitForConnectionAsync();
                await client.ConnectAsync(3000);
                await accepting;

                // The server never answers; only cancellation can end the wait early.
                var sending = PipeToken.SendAsync(client, Token, TimeSpan.FromSeconds(30), cancel.Token);
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending.WaitAsync(TimeSpan.FromSeconds(5)));
            }
        }

        [Theory]
        [InlineData(PipeDirection.InOut)]
        [InlineData(PipeDirection.In)]
        public void A_lower_integrity_client_cannot_open_the_pipe(PipeDirection direction)
        {
            using (var low = LowIntegrityToken())
            {
                var outcome = WindowsIdentity.RunImpersonated(low, () =>
                {
                    try
                    {
                        using (var pipe = new NamedPipeClientStream(".", _pipe, direction))
                        {
                            pipe.Connect(3000);
                            return "connected";
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        return "denied";
                    }
                });

                Assert.Equal("denied", outcome);
            }
        }

        sealed class Listener : IShimEvents
        {
            public int Received;
            public Task OnStopAsync(StopEvent stop) { Received++; return Task.CompletedTask; }
            public Task OnModeChangedAsync(string instanceId, string mode) { Received++; return Task.CompletedTask; }
            public Task OnModuleLoadAsync(ModuleLoadEvent module) { Received++; return Task.CompletedTask; }
            public Task OnOutputAsync(OutputEvent output) { Received++; return Task.CompletedTask; }
            public Task OnWorkspaceChangedAsync(string instanceId) { Received++; return Task.CompletedTask; }
            public Task OnOperationChangedAsync(OperationInfo operation) { Received++; return Task.CompletedTask; }
        }

        // ---- Windows security plumbing for the label checks ----

        const int SE_KERNEL_OBJECT = 6;
        const int LABEL_SECURITY_INFORMATION = 0x10;
        const int TokenIntegrityLevel = 25;
        const uint TOKEN_ALL_ACCESS = 0xF01FF;
        const int SecurityImpersonation = 2;
        const int TokenImpersonation = 2;
        const uint SE_GROUP_INTEGRITY = 0x20;

        static string LabelOf(SafePipeHandle handle)
        {
            var error = GetSecurityInfo(handle, SE_KERNEL_OBJECT, LABEL_SECURITY_INFORMATION,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var descriptor);
            Assert.Equal(0, error);
            try
            {
                Assert.True(ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1,
                    LABEL_SECURITY_INFORMATION, out var sddl, IntPtr.Zero));
                return sddl;
            }
            finally
            {
                LocalFree(descriptor);
            }
        }

        static SafeAccessTokenHandle LowIntegrityToken()
        {
            Assert.True(OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ALL_ACCESS, out var own));
            using (own)
            {
                Assert.True(DuplicateTokenEx(own, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation,
                    TokenImpersonation, out var duplicate));

                var low = new SecurityIdentifier("S-1-16-4096");
                var sid = new byte[low.BinaryLength];
                low.GetBinaryForm(sid, 0);
                var sidPointer = Marshal.AllocHGlobal(sid.Length);
                var label = Marshal.AllocHGlobal(IntPtr.Size * 2);
                try
                {
                    Marshal.Copy(sid, 0, sidPointer, sid.Length);
                    Marshal.WriteIntPtr(label, sidPointer);
                    Marshal.WriteInt32(label, IntPtr.Size, (int)SE_GROUP_INTEGRITY);
                    Assert.True(SetTokenInformation(duplicate, TokenIntegrityLevel, label,
                        IntPtr.Size * 2 + sid.Length));
                }
                finally
                {
                    Marshal.FreeHGlobal(label);
                    Marshal.FreeHGlobal(sidPointer);
                }
                return duplicate;
            }
        }

        [DllImport("advapi32.dll")]
        static extern int GetSecurityInfo(SafeHandle handle, int objectType, int securityInfo,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor, int revision,
            int securityInfo, out string sddl, IntPtr length);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(SafeAccessTokenHandle token, uint access, IntPtr attributes,
            int impersonationLevel, int tokenType, out SafeAccessTokenHandle duplicate);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetTokenInformation(SafeAccessTokenHandle token, int informationClass,
            IntPtr information, int length);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr memory);
    }
}
