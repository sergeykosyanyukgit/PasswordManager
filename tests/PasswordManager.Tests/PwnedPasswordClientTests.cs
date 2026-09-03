using System.Net;
using PasswordManager.Hibp;

namespace PasswordManager.Tests;

public sealed class PwnedPasswordClientTests
{
    private const string SyntheticPassword = "Synthetic-Test-Password-Only!42";
    private const string ExpectedPrefix = "31D19";
    private const string ExpectedSuffix = "B1B3A220F1B4983CA041B6412BC0B595383";

    [Fact]
    public async Task SendsOnlyFiveCharacterPrefixWithPadding()
    {
        HttpRequestMessage? captured = null;
        using var httpClient = new HttpClient(new StubHandler(request =>
        {
            captured = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(ExpectedSuffix + ":42\r\n00000000000000000000000000000000000:0\r\n"),
            };
        }))
        {
            BaseAddress = PwnedPasswordClient.ServiceBaseAddress,
        };
        var client = new PwnedPasswordClient(httpClient);

        var result = await client.CheckAsync(SyntheticPassword);

        Assert.Equal(PwnedPasswordStatus.Compromised, result.Status);
        Assert.Equal(42, result.OccurrenceCount);
        Assert.NotNull(captured);
        Assert.Equal("/range/" + ExpectedPrefix, captured.RequestUri?.AbsolutePath);
        Assert.True(captured.Headers.TryGetValues("Add-Padding", out var values));
        Assert.Equal("true", Assert.Single(values));
        Assert.DoesNotContain(ExpectedSuffix, captured.RequestUri?.OriginalString, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PaddedZeroCountIsNotCompromised()
    {
        using var httpClient = CreateClient(ExpectedSuffix + ":0\r\n");
        var result = await new PwnedPasswordClient(httpClient).CheckAsync(SyntheticPassword);
        Assert.Equal(PwnedPasswordStatus.NotFound, result.Status);
    }

    [Fact]
    public async Task RedirectAndNetworkFailureAreNotReportedSafe()
    {
        using var redirectClient = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Redirect)))
        {
            BaseAddress = PwnedPasswordClient.ServiceBaseAddress,
        };
        var redirect = await new PwnedPasswordClient(redirectClient).CheckAsync(SyntheticPassword);
        Assert.Equal(PwnedPasswordStatus.Failed, redirect.Status);

        using var failureClient = new HttpClient(new StubHandler(_ => throw new HttpRequestException("Synthetic failure")))
        {
            BaseAddress = PwnedPasswordClient.ServiceBaseAddress,
        };
        var failure = await new PwnedPasswordClient(failureClient).CheckAsync(SyntheticPassword);
        Assert.Equal(PwnedPasswordStatus.Failed, failure.Status);
    }

    [Fact]
    public async Task ChunkedResponseIsRejectedBeforeReadingBeyondLimit()
    {
        var oversizedStream = new CountingOversizedStream((2 * 1024 * 1024) + 4096);
        using var httpClient = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(oversizedStream),
        }))
        {
            BaseAddress = PwnedPasswordClient.ServiceBaseAddress,
        };

        var result = await new PwnedPasswordClient(httpClient).CheckAsync(SyntheticPassword);

        Assert.Equal(PwnedPasswordStatus.Failed, result.Status);
        Assert.Equal("ResponseTooLarge", result.FailureReason);
        Assert.Equal((2 * 1024 * 1024) + 1, oversizedStream.BytesRead);
    }

    private static HttpClient CreateClient(string response) => new(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(response),
    }))
    {
        BaseAddress = PwnedPasswordClient.ServiceBaseAddress,
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> factory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(factory(request));
    }

    private sealed class CountingOversizedStream(int length) : Stream
    {
        private int remaining = length;

        public int BytesRead { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = Math.Min(count, remaining);
            Array.Fill(buffer, (byte)'A', offset, read);
            remaining -= read;
            BytesRead += read;
            return read;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = Math.Min(buffer.Length, remaining);
            buffer.Span[..read].Fill((byte)'A');
            remaining -= read;
            BytesRead += read;
            return ValueTask.FromResult(read);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
