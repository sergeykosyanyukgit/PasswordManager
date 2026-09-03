using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PasswordManager.Security;

public sealed unsafe partial class SecureBuffer : IDisposable
{
    private IntPtr pointer;
    private readonly bool isLocked;
    private readonly bool usesVirtualAllocation;
    private bool disposed;

    private SecureBuffer(ReadOnlySpan<byte> value)
    {
        Length = value.Length;
        if (OperatingSystem.IsWindows())
        {
            pointer = NativeMethods.VirtualAlloc(
                IntPtr.Zero,
                (nuint)Length,
                NativeMethods.MemCommit | NativeMethods.MemReserve,
                NativeMethods.PageReadWrite);
            if (pointer == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Secure memory allocation failed.");
            }

            usesVirtualAllocation = true;
            value.CopyTo(new Span<byte>((void*)pointer, Length));
            isLocked = NativeMethods.VirtualLock(pointer, (nuint)Length);
            if (!isLocked)
            {
                var error = Marshal.GetLastPInvokeError();
                CryptographicOperations.ZeroMemory(new Span<byte>((void*)pointer, Length));
                _ = NativeMethods.VirtualFree(pointer, 0, NativeMethods.MemRelease);
                pointer = IntPtr.Zero;
                throw new Win32Exception(error, "Secure memory could not be locked.");
            }
        }
        else
        {
            pointer = Marshal.AllocHGlobal(Length);
            value.CopyTo(new Span<byte>((void*)pointer, Length));
        }
    }

    public int Length { get; }

    public bool IsMemoryLocked => isLocked;

    public static SecureBuffer Create(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("A secure buffer cannot be empty.", nameof(value));
        }

        return new SecureBuffer(value);
    }

    public void CopyTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (destination.Length < Length)
        {
            throw new ArgumentException("The destination is too small.", nameof(destination));
        }

        new ReadOnlySpan<byte>((void*)pointer, Length).CopyTo(destination);
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        if (pointer != IntPtr.Zero)
        {
            CryptographicOperations.ZeroMemory(new Span<byte>((void*)pointer, Length));
            if (isLocked && OperatingSystem.IsWindows())
            {
                _ = NativeMethods.VirtualUnlock(pointer, (nuint)Length);
            }

            if (usesVirtualAllocation)
            {
                _ = NativeMethods.VirtualFree(pointer, 0, NativeMethods.MemRelease);
            }
            else
            {
                Marshal.FreeHGlobal(pointer);
            }

            pointer = IntPtr.Zero;
        }

        GC.SuppressFinalize(this);
    }

    ~SecureBuffer()
    {
        Dispose();
    }

    private static partial class NativeMethods
    {
        internal const uint MemCommit = 0x00001000;
        internal const uint MemReserve = 0x00002000;
        internal const uint MemRelease = 0x00008000;
        internal const uint PageReadWrite = 0x04;

        [LibraryImport("kernel32.dll", SetLastError = true)]
        internal static partial IntPtr VirtualAlloc(IntPtr address, nuint size, uint allocationType, uint protect);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool VirtualFree(IntPtr address, nuint size, uint freeType);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool VirtualLock(IntPtr address, nuint size);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool VirtualUnlock(IntPtr address, nuint size);
    }
}
