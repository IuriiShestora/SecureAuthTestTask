using System;
using System.Text;
using System.Net;
using System.Threading.Tasks;

namespace DummyHttpServer
{
    /// <summary>
    /// Dummy Server listening of localhost:5005 for incoming requests.
    /// Responds randomly with True or False.
    /// Can be run on a Hosting Machine for testing purpose.
    /// </summary>
    class HttpServer
    {
        public static HttpListener listener;
        public static string url = "http://localhost:5005/";

        public static async Task Handle()
        {
            while (true)
            {
                HttpListenerContext ctx = await listener.GetContextAsync();

                HttpListenerRequest req = ctx.Request;
                HttpListenerResponse resp = ctx.Response;

                string reponseText = (new Random().Next(2) == 1).ToString();

                Console.WriteLine(DateTime.Now.ToLongTimeString());
                Console.WriteLine(req.Url.ToString());
                Console.WriteLine(reponseText);
                Console.WriteLine();

                byte[] data = Encoding.UTF8.GetBytes(reponseText);
                resp.ContentType = "text/html";
                resp.ContentEncoding = Encoding.UTF8;
                resp.ContentLength64 = data.LongLength;

                await resp.OutputStream.WriteAsync(data, 0, data.Length);
                resp.Close();
            }
        }

        public static void Main(string[] args)
        {
            listener = new HttpListener();
            listener.Prefixes.Add(url);
            listener.Start();
            Console.WriteLine("Listening for connections on {0}", url);

            Task listenTask = Handle();
            listenTask.GetAwaiter().GetResult();

            listener.Close();
        }
    }
}