using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Channels;

namespace Authentication
{
    public class AuthenticationSuccessEventArgs : EventArgs
    {
        public string Username
        {
            get;
            private set;
        }
        public SecureChannel Channel
        {
            get;
            private set;
        }
        public AuthenticationSuccessEventArgs(string username, SecureChannel channel)
        {
            Username = username;
            Channel = channel;
        }
    }
}
