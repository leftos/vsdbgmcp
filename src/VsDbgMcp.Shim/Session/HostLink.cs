using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using StreamJsonRpc;
using VsDbgMcp.Contracts;

namespace VsDbgMcp.Shim.Session
{
    /// <summary>Why a connection failed, and what the caller can do about it.</summary>
    public sealed class ConnectFailure
    {
        public ConnectFailure(string reason, string nextStep)
        {
            Reason = reason;
            NextStep = nextStep;
        }

        public string Reason { get; }
        public string NextStep { get; }
    }

    /// <summary>
    /// One connection to one running Visual Studio. Calls go out over the pipe;
    /// debugger events come back in and land on the shared event bus.
    /// </summary>
    public sealed class HostLink : IShimEvents, IDisposable
    {
        readonly EventBus _bus;
        readonly EventLog _log;
        NamedPipeClientStream _pipe;
        JsonRpc _rpc;
        bool _disposed;
        bool _gone;

        /// <summary>
        /// Whether this ever finished connecting. A handshake that fails tears the pipe
        /// down, which raises Disconnected, and a window that never answered is not a
        /// window that closed. Reporting it as one told the model its window had gone
        /// while it sat there, open, still loading.
        /// </summary>
        bool _connected;

        public HostLink(InstanceRecord record, EventBus bus, EventLog log)
        {
            Record = record;
            _bus = bus;
            _log = log;
        }

        public InstanceRecord Record { get; private set; }
        public IDebugHost Debug { get; private set; }
        public IOperationHost Operations { get; private set; }
        public IProfileHost Profiles { get; private set; }
        public IProjectSystem Project { get; private set; }
        public string HostVersion { get; private set; }
        /// <summary>Why the last attempt to connect failed; null once connected.</summary>
        public ConnectFailure LastFailure { get; private set; }

        const string RetryLater = "The instance may still be loading. Retry, or restart Visual Studio if it persists.";

        public bool IsConnected => _rpc != null && !_rpc.IsDisposed && _pipe != null && _pipe.IsConnected;

        public string Id => Record.Id;

        /// <summary>Refreshes the record after rediscovery, keeping the live connection.</summary>
        public void UpdateRecord(InstanceRecord record)
        {
            if (record != null && record.Pid == Record.Pid) Record = record;
        }

        public async Task<bool> ConnectAsync(CancellationToken ct)
        {
            if (IsConnected) return true;
            Teardown();

            try
            {
                // CurrentUserOnly refuses a pipe whose owner is not this process's own
                // default owner. Identification stops the server from acting as us.
                _pipe = new NamedPipeClientStream(".", Record.Pipe, PipeDirection.InOut,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                    System.Security.Principal.TokenImpersonationLevel.Identification);

                await _pipe.ConnectAsync(3000, ct).ConfigureAwait(false);

                if (Record.Contract >= PipeToken.FirstContract)
                    await PipeToken.SendAsync(_pipe, Record.Token, PipeToken.Timeout, ct).ConfigureAwait(false);

                // The formatter is stated explicitly rather than left to the default,
                // because the two ends of this pipe are built against different
                // StreamJsonRpc versions and their defaults may not agree.
                var formatter = new JsonMessageFormatter();
                formatter.JsonSerializer.NullValueHandling = NullValueHandling.Ignore;

                _rpc = new JsonRpc(new HeaderDelimitedMessageHandler(_pipe, _pipe, formatter));
                _rpc.AddLocalRpcTarget<IShimEvents>(this, null);
                Debug = _rpc.Attach<IDebugHost>();
                Operations = _rpc.Attach<IOperationHost>();
                Profiles = _rpc.Attach<IProfileHost>();
                Project = _rpc.Attach<IProjectSystem>();
                // Seed before callbacks can arrive. Reconnecting invalidates observations
                // from the gap, even if the instance record still names the same PID.
                _bus.InitializeMode(Id, Record.DebugMode);
                _log.InitializeMode(Id, Record.DebugMode);

                // Visual Studio closing is the one event it cannot send. Subscribed here,
                // before listening starts, so no drop can slip past; only a link that got
                // through its handshake is allowed to report one.
                _gone = false;
                _rpc.Disconnected += (s, e) => { if (!_disposed && _connected) ReportGone(); };
                _rpc.StartListening();

                HostVersion = await Debug.HandshakeAsync(Names.ContractVersion, Record.Token).ConfigureAwait(false);
                _connected = true;
                LastFailure = null;
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                // Windows refused the pipe (integrity label), or its owner is not this
                // process's default owner (CurrentUserOnly). Records older than
                // contract 11 do not say whether Visual Studio is elevated.
                bool? elevated = Record.Contract >= PipeToken.FirstContract ? Record.Elevated : (bool?)null;
                LastFailure = AccessDenied(elevated, Environment.IsPrivilegedProcess);
                Teardown();
                return false;
            }
            catch (Exception ex)
            {
                LastFailure = new ConnectFailure(ex.Message, RetryLater);
                Teardown();
                return false;
            }
        }

        /// <summary>
        /// Explains a pipe Windows would not open. visualStudioElevated is null when
        /// the discovery record is too old to say.
        /// </summary>
        public static ConnectFailure AccessDenied(bool? visualStudioElevated, bool clientElevated)
        {
            const string SameElevation = "Run both as administrator or both without. Retrying as they are fails the same way.";
            if (visualStudioElevated == true && !clientElevated)
                return new ConnectFailure("Visual Studio runs as administrator, and this MCP client does not.", SameElevation);
            if (visualStudioElevated == false && clientElevated)
                return new ConnectFailure("This MCP client runs as administrator, and Visual Studio does not.", SameElevation);
            if (visualStudioElevated == null)
                return new ConnectFailure(
                    "Windows refused access to this Visual Studio's pipe. Visual Studio and this MCP client most likely run at different elevation.",
                    SameElevation);
            return new ConnectFailure(
                "Windows refused access to this Visual Studio's pipe, although both run at the same elevation. This MCP client may run sandboxed or with a restricted token.",
                "Run the MCP client as an ordinary process of the user running Visual Studio. Retrying as it is fails the same way.");
        }

        void Teardown()
        {
            // Cleared first, so the Disconnected this dispose raises is recognised as
            // this shim letting go rather than the window going away.
            _connected = false;

            // Disposing a connection whose far end has already gone throws from the
            // pipe. There is nothing left to salvage either way.
            try { _rpc?.Dispose(); } catch (IOException) { } catch (ObjectDisposedException) { }
            try { _pipe?.Dispose(); } catch (IOException) { } catch (ObjectDisposedException) { }
            _rpc = null;
            _pipe = null;
            Debug = null;
            Operations = null;
            Profiles = null;
            Project = null;
        }

        /// <summary>
        /// This window is gone. Both the dropped connection and the vanished discovery
        /// record lead here, and whichever arrives first is the one that is reported.
        /// </summary>
        internal void ReportGone()
        {
            if (_gone) return;
            _gone = true;
            _log.InstanceGone(Id);
        }

        // ---- pushed from Visual Studio ----

        public Task OnStopAsync(StopEvent stop)
        {
            if (stop != null)
            {
                stop.InstanceId = Id;
                _bus.ObserveStopMode(Id, stop.Mode);

                // Logged before the bus, because publishing wakes a waiter that can
                // return this stop and hide it before the entry to hide exists.
                _log.Stopped(stop);
                _bus.Publish(stop);
                if (!string.IsNullOrEmpty(stop.Mode)) Record.DebugMode = stop.Mode;
            }
            return Task.CompletedTask;
        }

        public Task OnModuleLoadAsync(ModuleLoadEvent module)
        {
            if (module != null)
            {
                module.InstanceId = Id;
                _bus.PublishModuleLoad(module);
            }
            return Task.CompletedTask;
        }

        public Task OnOutputAsync(OutputEvent output)
        {
            if (output != null)
            {
                output.InstanceId = Id;
                _bus.PublishOutput(output);
            }
            return Task.CompletedTask;
        }

        public Task OnModeChangedAsync(string instanceId, string mode)
        {
            // Every way into a debug session passes through here, whether an agent asked
            // for it or someone pressed F5, so this is where the bus is told.
            _bus.ModeChanged(Id, mode);
            _log.ModeChanged(Id, mode);
            Record.DebugMode = mode;
            return Task.CompletedTask;
        }

        public Task OnWorkspaceChangedAsync(string instanceId)
        {
            _log.SolutionChanged(Id);
            return Task.CompletedTask;
        }

        public Task OnOperationChangedAsync(OperationInfo operation)
        {
            if (operation != null)
            {
                operation.InstanceId = Id;
                _log.OperationDone(operation);
            }
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Teardown();
        }
    }
}
