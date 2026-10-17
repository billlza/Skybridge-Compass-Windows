using Microsoft.UI.Xaml.Controls;
using Skybridge.WinClient.Services;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private readonly WindowDialogCoordinator _dialogs;

    private sealed class NativeWindowDialog(ContentDialog dialog) : IWindowDialogOperation
    {
        public async Task<WindowDialogResult> ShowAsync() => (await dialog.ShowAsync().AsTask()) switch
        {
            ContentDialogResult.None => WindowDialogResult.None,
            ContentDialogResult.Primary => WindowDialogResult.Primary,
            ContentDialogResult.Secondary => WindowDialogResult.Secondary,
            _ => throw new InvalidOperationException("The window dialog returned an unknown result.")
        };
        public void Hide() => dialog.Hide();
    }
}
