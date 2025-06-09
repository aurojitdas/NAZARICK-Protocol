using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace NAZARICK_Protocol
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        private void NavigationTab_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton radioButton && radioButton.Tag is string tag)
            {
                // Hide all pages
                HomePage.Visibility = Visibility.Collapsed;
                ScanPage.Visibility = Visibility.Collapsed;
                SettingsPage.Visibility = Visibility.Collapsed;
                AboutPage.Visibility = Visibility.Collapsed;

                // Show selected page
                switch (tag)
                {
                    case "Home":
                        HomePage.Visibility = Visibility.Visible;
                        break;
                    case "Scan":
                        ScanPage.Visibility = Visibility.Visible;
                        break;
                    case "Settings":
                        SettingsPage.Visibility = Visibility.Visible;
                        break;
                    case "About":
                        AboutPage.Visibility = Visibility.Visible;
                        break;
                }
            }
        }

        private async void MainScanButton_Click(object sender, RoutedEventArgs e)
        {
            // Update scan info
            ScanInfoTextBox.Text = "Starting quick scan...";

            // Simulate scan process
            await Task.Delay(2000);
            ScanInfoTextBox.Text = $"Quick scan completed at {DateTime.Now:HH:mm:ss}. No threats detected.";
        }

        private void ChangeRulesButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Scan rules configuration will be implemented here.",
                          "Scan Rules",
                          MessageBoxButton.OK,
                          MessageBoxImage.Information);
        }
    }
}