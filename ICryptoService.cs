namespace nocscienceat.Aes256GcmRsaCryptoService;

public interface ICryptoService
{
    public byte[] Encrypt(ReadOnlySpan<byte> plainTextSpan);
    public byte[] Decrypt(ReadOnlySpan<byte> cipherTextSpan);
}