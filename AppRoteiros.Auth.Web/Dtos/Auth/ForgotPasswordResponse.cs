namespace AppRoteiros.Auth.Web.Dtos.Auth
{
    /// <summary>
    /// Response do fluxo de forgot-password.
    /// Em ambiente DEV, o token pode ser retornado para facilitar testes.
    /// Em PROD, o token deve ser enviado por e-mail.
    /// </summary>
    public class ForgotPasswordResponse
    {
        /// <summary>
        /// Mensagem genérica para evitar enumeração de usuários.
        /// </summary>
        public string Message { get; set; } =
            "Se o e-mail existir, enviaremos instruções para redefinir a senha.";

        /// <summary>
        /// Token de reset de senha.
        /// IMPORTANTE: usar apenas em DEV para testes.
        /// </summary>
        public string? ResetToken { get; set; }
    }
}
