namespace AppRoteiros.Auth.Web.Dtos.Auth
{
    /// <summary>
    /// Response do register.
    /// Em DEV retornamos token de confirmação para facilitar teste via Postman.
    /// Em PROD isso deve ser enviado por e-mail.
    /// </summary>
    public class RegisterResponse
    {
        public string Message { get; set; } = "Usuário criado com sucesso.";

        // Em DEV: útil para confirmar e-mail via Postman
        public string? UserId { get; set; }
        public string? ConfirmEmailToken { get; set; }
    }
}
