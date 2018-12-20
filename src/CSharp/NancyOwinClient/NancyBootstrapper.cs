using System;
using System.Collections.Generic;
using System.IO;
using Nancy;
using Nancy.Bootstrapper;
using Nancy.ViewEngines.Razor;

namespace NancyOwinClient
{
    public class NancyBootstrapper : DefaultNancyBootstrapper
    {
        protected override IRootPathProvider RootPathProvider => new NancyRootPathProvider();

        protected override IEnumerable<Type> ViewEngines
        {
            get { yield return typeof(RazorViewEngine); }
        }
    }

    public class NancyRootPathProvider : IRootPathProvider
    {
        public string GetRootPath()
        {
            return Path.GetDirectoryName(AppDomain.CurrentDomain.SetupInformation.ConfigurationFile);
        }
    }

    public class RazorViewEngineRegistrations : Registrations
    {
        public RazorViewEngineRegistrations()
        {
            RegisterWithDefault<IRazorConfiguration>(typeof(DefaultRazorConfiguration));
        }
    }
}
