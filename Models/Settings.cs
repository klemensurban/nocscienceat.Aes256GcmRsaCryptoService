namespace nocscienceat.Aes256GcmRsaCryptoService.Models;

internal class Settings
{
    public string EncryptionCertificateThumbprint { get; set; } = string.Empty;
    public string SigningCertificateThumbprint { get; set; } = string.Empty;
    public bool LocalMachine { get; set; } = true;
}