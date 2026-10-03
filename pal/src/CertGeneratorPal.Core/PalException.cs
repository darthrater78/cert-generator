namespace CertGeneratorPal.Core;

/// <summary>An error whose message is written for the person using the app.</summary>
public sealed class PalException : Exception
{
    public int? Status { get; }

    public PalException() { }

    public PalException(string message) : base(message) { }

    public PalException(string message, Exception inner) : base(message, inner) { }

    public PalException(string message, int status) : base(message) => Status = status;
}
