namespace AdfsPlugin.Models
{
    public class HttpClientConfig
    {
        public string Url { get; set; } = "http://localhost:5005/";
        public int Timeout { get; set; } 

        public static HttpClientConfig Default => new HttpClientConfig
        {
            Timeout = 10,
            Url = "http://localhost:5005/"
        };
    }
}
