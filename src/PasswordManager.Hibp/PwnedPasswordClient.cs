using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace PasswordManager.Hibp;

public sealed class PwnedPasswordClient
{
    public static readonly Uri ServiceBaseAddress = new("https://api.pwnedpasswords.com/", UriKind.Absolute);
    private const int MaximumResponseBytes = 2 * 1024 * 1024;
    private readonly HttpClient httpClient;

    public PwnedPasswordClient(HttpClient httpClient)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        if (httpClient.BaseAddress is null)
        {
            httpClient.BaseAddress = ServiceBaseAddress;
        }

        if (httpClient.BaseAddress.Scheme != Uri.UriSchemeHttps ||
            !string.Equals(httpClient.BaseAddress.Host, ServiceBaseAddress.Host, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("HIBP requests must use the official HTTPS range endpoint.", nameof(httpClient));
        }
    }

    public async Task<PwnedPasswordResult> CheckAsync(string completedPassword, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(completedPassword);
        byte[]? passwordBytes = null;
        var digest = new byte[SHA1.HashSizeInBytes];
        try
        {
            passwordBytes = Encoding.UTF8.GetBytes(completedPassword.Normalize(NormalizationForm.FormC));
            // HIBP's k-anonymity protocol requires SHA-1 as a lookup identifier, not as a security primitive.
#pragma warning disable CA5350
            SHA1.HashData(passwordBytes, digest);
#pragma warning restore CA5350
            var hash = Convert.ToHexString(digest);
            var prefix = hash[..5];
            var suffix = hash[5..];

            using var request = new HttpRequestMessage(HttpMethod.Get, "range/" + prefix);
            request.Headers.Add("Add-Padding", "true");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/plain"));

            using var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            if ((int)response.StatusCode is >= 300 and < 400)
            {
                return PwnedPasswordResult.Failed("RedirectRejected");
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return PwnedPasswordResult.Failed("ServiceUnavailable");
            }

            if (response.Content.Headers.ContentLength is > MaximumResponseBytes)
            {
                return PwnedPasswordResult.Failed("ResponseTooLarge");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var responseBytes = GC.AllocateUninitializedArray<byte>(MaximumResponseBytes);
            var overflow = new byte[1];
            try
            {
                var consumed = 0;
                while (consumed < responseBytes.Length)
                {
                    var read = await stream.ReadAsync(
                        responseBytes.AsMemory(consumed, responseBytes.Length - consumed),
                        cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    consumed += read;
                }

                if (consumed == responseBytes.Length &&
                    await stream.ReadAsync(overflow, cancellationToken).ConfigureAwait(false) != 0)
                {
                    return PwnedPasswordResult.Failed("ResponseTooLarge");
                }

                return ParseBoundedResponse(responseBytes.AsSpan(0, consumed), suffix);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBytes);
                CryptographicOperations.ZeroMemory(overflow);
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TaskCanceledException)
        {
            return PwnedPasswordResult.Failed("NetworkFailure");
        }
        finally
        {
            if (passwordBytes is not null)
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }

            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static PwnedPasswordResult ParseBoundedResponse(ReadOnlySpan<byte> response, ReadOnlySpan<char> suffix)
    {
        var offset = 0;
        while (offset < response.Length)
        {
            var remaining = response[offset..];
            var newline = remaining.IndexOf((byte)'\n');
            var line = newline >= 0 ? remaining[..newline] : remaining;
            if (!line.IsEmpty && line[^1] == (byte)'\r')
            {
                line = line[..^1];
            }

            if (line.Length <= 64)
            {
                var separator = line.IndexOf((byte)':');
                if (separator == 35 && HashSuffixEquals(line[..separator], suffix))
                {
                    if (!TryParseNonNegativeCount(line[(separator + 1)..], out var count))
                    {
                        return PwnedPasswordResult.Failed("MalformedResponse");
                    }

                    return count == 0 ? PwnedPasswordResult.NotFound : PwnedPasswordResult.Compromised(count);
                }
            }

            if (newline < 0)
            {
                break;
            }

            offset += newline + 1;
        }

        return PwnedPasswordResult.NotFound;
    }

    private static bool HashSuffixEquals(ReadOnlySpan<byte> candidate, ReadOnlySpan<char> expected)
    {
        if (candidate.Length != expected.Length)
        {
            return false;
        }

        for (var index = 0; index < candidate.Length; index++)
        {
            var actual = candidate[index];
            if (actual is >= (byte)'a' and <= (byte)'f')
            {
                actual -= (byte)('a' - 'A');
            }

            if (actual != expected[index])
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryParseNonNegativeCount(ReadOnlySpan<byte> value, out long count)
    {
        count = 0;
        if (value.IsEmpty)
        {
            return false;
        }

        foreach (var digit in value)
        {
            if (digit is < (byte)'0' or > (byte)'9')
            {
                return false;
            }

            try
            {
                count = checked((count * 10) + digit - (byte)'0');
            }
            catch (OverflowException)
            {
                return false;
            }
        }

        return true;
    }
}

public readonly record struct PwnedPasswordResult(PwnedPasswordStatus Status, long OccurrenceCount, string? FailureReason)
{
    public static PwnedPasswordResult NotFound => new(PwnedPasswordStatus.NotFound, 0, null);

    public static PwnedPasswordResult Compromised(long count) => new(PwnedPasswordStatus.Compromised, count, null);

    public static PwnedPasswordResult Failed(string reason) => new(PwnedPasswordStatus.Failed, 0, reason);
}

public enum PwnedPasswordStatus
{
    NotFound,
    Compromised,
    Failed,
}
