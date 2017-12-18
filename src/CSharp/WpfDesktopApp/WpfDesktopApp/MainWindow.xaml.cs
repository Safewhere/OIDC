using System.Net.Http;
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
            //GetTodoList(true);
        }
        
        private async void AddTodoItem(object sender, RoutedEventArgs e)
        {
            //if (string.IsNullOrEmpty(TodoText.Text))
            //{
            //    MessageBox.Show("Please enter a value for the To Do item name");
            //    return;
            //}

            ////
            //// Get an access token to call the To Do service.
            ////
            //AuthenticationResult result = null;
            //try
            //{
            //    result = await authContext.AcquireTokenAsync(todoListResourceId, clientId, redirectUri, new PlatformParameters(PromptBehavior.Never));
            //}
            //catch (AdalException ex)
            //{
            //    // There is no access token in the cache, so prompt the user to sign-in.
            //    if (ex.ErrorCode == "user_interaction_required")
            //    {
            //        MessageBox.Show("Please sign in first");
            //        SignInButton.Content = "Sign In";
            //    }
            //    else
            //    {
            //        // An unexpected error occurred.
            //        string message = ex.Message;
            //        if (ex.InnerException != null)
            //        {
            //            message += "Error Code: " + ex.ErrorCode + "Inner Exception : " + ex.InnerException.Message;
            //        }

            //        MessageBox.Show(message);
            //    }

            //    return;
            //}

            ////
            //// Call the To Do service.
            ////

            //// Once the token has been returned by ADAL, add it to the http authorization header, before making the call to access the To Do service.
            //httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);

            //// Forms encode Todo item, to POST to the todo list web api.
            //HttpContent content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("Title", TodoText.Text) });

            //// Call the To Do list service.
            //HttpResponseMessage response = await httpClient.PostAsync(todoListBaseAddress + "/api/todolist", content);

            //if (response.IsSuccessStatusCode)
            //{
            //    TodoText.Text = "";
            //    GetTodoList();
            //}
            //else
            //{
            //    MessageBox.Show("An error occurred : " + response.ReasonPhrase);
            //}
        }

        private async void SignIn(object sender = null, RoutedEventArgs args = null)
        {
            var interactiveLogon = new InteractiveLogon();
            await interactiveLogon.DoLogon(this);
        }
    }
}
