using System;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Windows;

namespace WpfDesktopApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private HttpClient httpClient = new HttpClient();

        public MainWindow()
        {
            InitializeComponent();
        }
        
        private void AddClaims(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null)
                return;

            StringBuilder sb = new StringBuilder();

            foreach (Claim claim in claimsPrincipal.Claims)
            {
                sb.AppendLine($"{claim.Type} - {claim.Value}");
            }

            AppendLogData(sb.ToString());
        }

        private async void SignIn(object sender = null, RoutedEventArgs args = null)
        {
            textBox.Text = string.Empty;
            var interactiveLogon = new InteractiveLogon(AppendLogData);
            AuthenticationResult authenticationResult = await interactiveLogon.DoLogon(this);
            if (authenticationResult == null)
                return;

            // Can do: use authenticationResult.AccessToken to access a resource server
            AddClaims(authenticationResult.ClaimsPrincipal);
        }

        private void AppendLogData(string newLine)
        {
            this.textBox.Text += Environment.NewLine;
            this.textBox.Text += "----------------------------";
            this.textBox.Text += Environment.NewLine;
            this.textBox.Text += newLine;
        }
    }
}
