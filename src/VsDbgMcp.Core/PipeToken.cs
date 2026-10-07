using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace VsDbgMcp
{
    /// <summary>What the host made of the token a client sent.</summary>
    public enum TokenCheck
    {
        Accepted,
        WrongToken,
        Malformed,
        Closed,
        TimedOut
    }

    /// <summary>
    /// The first bytes on a pipe connection, before any JSON-RPC. The client sends
    /// the instance's token as one length byte followed by the token in UTF-8; the
    /// host answers with one byte saying whether it matched. The host serves nothing
    /// on a connection until it has.
    /// </summary>
    public static class PipeToken
    {
        /// <summary>The first host contract that expects the token before JSON-RPC.</summary>
        public const int FirstContract = 11;

        public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Must stay below 67 ('C', from "Content-Length"), the first byte an older
        /// shim sends, so that its JSON-RPC is refused as malformed rather than read
        /// as a token.
        /// </summary>
        const int MaxLength = 64;
        const byte Accepted = 1;
        const byte Refused = 0;

        /// <summary>
        /// Sends the token and waits for the answer. Throws TokenRefusedException when
        /// the host refuses it and TimeoutException when the host does not answer.
        /// </summary>
        public static async Task SendAsync(Stream pipe, string token, TimeSpan timeout, CancellationToken ct = default)
        {
            var bytes = Encoding.UTF8.GetBytes(token ?? "");
            if (bytes.Length == 0 || bytes.Length > MaxLength)
                throw new TokenRefusedException("The discovery record for this Visual Studio has no usable token.");

            var frame = new byte[bytes.Length + 1];
            frame[0] = (byte)bytes.Length;
            Buffer.BlockCopy(bytes, 0, frame, 1, bytes.Length);

            var answer = new byte[1];
            var exchange = ExchangeAsync(pipe, frame, answer, ct);
            if (await Task.WhenAny(exchange, Task.Delay(timeout, ct)).ConfigureAwait(false) != exchange)
            {
                Observe(exchange);
                ct.ThrowIfCancellationRequested();
                throw new TimeoutException("Visual Studio did not answer the connection token within " + (int)timeout.TotalSeconds + " seconds.");
            }

            if (!await exchange.ConfigureAwait(false) || answer[0] != Accepted)
                throw new TokenRefusedException("Visual Studio refused the connection token. Its discovery record may be stale.");
        }

        static async Task<bool> ExchangeAsync(Stream pipe, byte[] frame, byte[] answer, CancellationToken ct)
        {
            await pipe.WriteAsync(frame, 0, frame.Length, ct).ConfigureAwait(false);
            await pipe.FlushAsync(ct).ConfigureAwait(false);
            return await ReadExactlyAsync(pipe, answer, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads a client's token, compares it with the expected one and answers. The
        /// caller must close the pipe unless this returns Accepted.
        /// </summary>
        public static async Task<TokenCheck> ReceiveAsync(Stream pipe, string expected, TimeSpan timeout)
        {
            var reading = CheckAsync(pipe, Encoding.UTF8.GetBytes(expected ?? ""));
            if (await Task.WhenAny(reading, Task.Delay(timeout)).ConfigureAwait(false) != reading)
            {
                Observe(reading);
                return TokenCheck.TimedOut;
            }

            TokenCheck check;
            try { check = await reading.ConfigureAwait(false); }
            catch (IOException) { return TokenCheck.Closed; }
            if (check == TokenCheck.Closed) return check;

            try
            {
                await pipe.WriteAsync(new[] { check == TokenCheck.Accepted ? Accepted : Refused }, 0, 1).ConfigureAwait(false);
                await pipe.FlushAsync().ConfigureAwait(false);
            }
            catch (IOException)
            {
                return TokenCheck.Closed;
            }

            return check;
        }

        static async Task<TokenCheck> CheckAsync(Stream pipe, byte[] expected)
        {
            var length = new byte[1];
            if (!await ReadExactlyAsync(pipe, length, CancellationToken.None).ConfigureAwait(false)) return TokenCheck.Closed;
            if (length[0] == 0 || length[0] > MaxLength) return TokenCheck.Malformed;

            var token = new byte[length[0]];
            if (!await ReadExactlyAsync(pipe, token, CancellationToken.None).ConfigureAwait(false)) return TokenCheck.Closed;

            return expected.Length > 0 && SameBytes(token, expected) ? TokenCheck.Accepted : TokenCheck.WrongToken;
        }

        /// <summary>Takes the same time wherever the first difference is.</summary>
        static bool SameBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            var difference = 0;
            for (var i = 0; i < a.Length; i++) difference |= a[i] ^ b[i];
            return difference == 0;
        }

        /// <summary>False when the pipe closed first.</summary>
        static async Task<bool> ReadExactlyAsync(Stream pipe, byte[] buffer, CancellationToken ct)
        {
            var read = 0;
            while (read < buffer.Length)
            {
                var n = await pipe.ReadAsync(buffer, read, buffer.Length - read, ct).ConfigureAwait(false);
                if (n == 0) return false;
                read += n;
            }
            return true;
        }

        /// <summary>The caller closes the pipe after a timeout, which faults the read.</summary>
        static void Observe(Task task) =>
            task.ContinueWith(t => { var ignored = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
    }

    /// <summary>The host did not accept the token this client sent.</summary>
    public sealed class TokenRefusedException : Exception
    {
        public TokenRefusedException(string message) : base(message) { }
    }
}
