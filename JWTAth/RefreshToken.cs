namespace JWTAth
{
    public class RefreshToken
    {
        public string Token { get; set; } = string.Empty;
        public DateTime CreatedTime { get; set; } = DateTime.Now;

        public DateTime Expires { get; set; }
    }
}
