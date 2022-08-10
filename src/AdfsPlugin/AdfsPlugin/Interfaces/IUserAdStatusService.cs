namespace AdfsPlugin.Interfaces
{
    public interface IUserAdStatusService
    {
        bool? IsEnabled(string userName);
    }
}
