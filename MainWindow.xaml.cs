using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using NAZARICK_Protocol.service;
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
        PatternWeaver? pw;
        public MainWindow()
        {
            InitializeComponent();
            pw= new PatternWeaver(this);
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
            ScanInfoTextBox.Text = "Starting quick scan...\n";

            // Simulate scan process
            await Task.Delay(2000);
            ScanInfoTextBox.AppendText( pw.initialize_YARA()+"\n");
            //getFilePath();
            rulesFolderSelect();
        }

        private void ChangeRulesButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Scan rules configuration will be implemented here.",
                          "Scan Rules",
                          MessageBoxButton.OK,
                          MessageBoxImage.Information);
        }


        public String getFilePath()
        {
            String? file_Path = null;
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
            bool? result = openFileDialog.ShowDialog();            
            if (result == true)
            {
                
                file_Path = openFileDialog.FileName;
                ScanInfoTextBox.Text = file_Path;
            }
            else
            {
                ScanInfoTextBox.Text = "File Selection Cancelled\n";
            }
            return file_Path;
        }


        public String rulesFolderSelect()
        {
            String? folder_Path = null;
            CommonOpenFileDialog dialog = new CommonOpenFileDialog();
            dialog.IsFolderPicker = true;

            dialog.Title = "Select YARA Rules Folder";
            CommonFileDialogResult result = dialog.ShowDialog();
            if (result == CommonFileDialogResult.Ok)            {
                
                folder_Path = dialog.FileName;              
                ScanInfoTextBox.Text = folder_Path;
            }
            else
            {
                ScanInfoTextBox.Text = "Folder selection cancelled.";
            }

            return folder_Path;
        }

    }
}