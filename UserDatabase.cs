using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.IO;
using System.Security.Cryptography;

namespace Authentication
{
    public class UserToken
    {
        public string Username
        {
            get;
            private set;
        }
        public UserToken(string username)
        {
            Username = username;
        }
    }
    public class UserDatabase
    {
        private const int _READ_BLOCK_SIZE = 512;
        private class __User
        {
            public string Username
            {
                get;
                set;
            }
            public string PasswordHash
            {
                get;
                set;
            }
        }
        private ReaderWriterLockSlim _UsersLock;
        private List<__User> _Users;
        public UserDatabase()
        {
            _Users = new List<__User>();
            _UsersLock = new ReaderWriterLockSlim(); 
        }
        public UserDatabase(string path)
        {
            _Users = new List<__User>();
            _UsersLock = new ReaderWriterLockSlim();
            _Load(path);
        }

        public List<string> GetUsernames()
        {
            _UsersLock.EnterReadLock();
            List<string> usernames = new List<string>();
            foreach (__User u in _Users)
            {
                usernames.Add(u.Username);
            }
            _UsersLock.ExitReadLock();
            return usernames;
        }

        private void _Load(string path)
        {
            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            MemoryStream ms = new MemoryStream();
            byte[] buffer = new byte[_READ_BLOCK_SIZE];
            int read = fs.Read(buffer, 0, _READ_BLOCK_SIZE);
            while (read > 0)
            {
                ms.Write(buffer, 0, read);
                read = fs.Read(buffer, 0, _READ_BLOCK_SIZE);
            }
            bool success = false;
            _Users = _TryDeserialiseDatabase(ms.ToArray(), out success);
            if (!success)
            {
                fs.Close();
                fs.Dispose();
                throw new FormatException("Count not parse database");
            }
            fs.Close();
            fs.Dispose();
        }
        public bool AddUser(string username, string passwordhash)
        {
            _UsersLock.EnterWriteLock();
            if (_Users.Count(u => u.Username.ToUpperInvariant() == username.ToUpperInvariant()) == 0)
            {
                __User u = new __User();
                u.Username = username;
                u.PasswordHash = passwordhash;
                _Users.Add(u);
                _UsersLock.ExitWriteLock();
                return true;
            }
            else
            {
                _UsersLock.ExitWriteLock();
                return false;
            }
        }
        public void Save(string path)
        {
            byte[] buffer = _SerialiseDatabase();
            FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write);
            fs.Write(buffer, 0, buffer.Length);
            fs.Flush();
            fs.Close();
        }
        private List<__User> _TryDeserialiseDatabase(byte[] buffer, out bool success)
        {
            List<__User> users = new List<__User>();
            int cindex = 0;
            while (true)
            {
                int len = 0;
                string username = "";
                string passwordhash = "";
                if (cindex + sizeof(int) <= buffer.Length)
                {
                    len = BitConverter.ToInt32(buffer, cindex);
                    cindex += sizeof(int);
                }
                else
                {
                    success = false;
                    return null;
                }
                if (len + cindex <= buffer.Length)
                {
                    username = ASCIIEncoding.ASCII.GetString(buffer, cindex, len);
                    cindex += len;
                }
                else
                {
                    success = false;
                    return null;
                }
                if (cindex + sizeof(int) <= buffer.Length)
                {
                    len = BitConverter.ToInt32(buffer, cindex);
                    cindex += sizeof(int);
                }
                else
                {
                    success = false;
                    return null;
                }
                if (cindex + len <= buffer.Length)
                {
                    passwordhash = ASCIIEncoding.ASCII.GetString(buffer, cindex, len);
                    cindex += len;
                }
                __User u = new __User();
                u.PasswordHash = passwordhash;
                u.Username = username;
                users.Add(u);
                if (cindex == buffer.Length)
                {
                    success = true;
                    return users;
                }
            }
        }

        //Note that neither username nor passwordhash are case sensitive.
        public UserToken ValidateUser(string username, string passwordhash, out bool valid)
        {
            _UsersLock.EnterReadLock();
            List<__User> matches = _Users.FindAll(u => u.Username.ToUpperInvariant() == username.ToUpperInvariant() && u.PasswordHash.ToUpperInvariant() == passwordhash.ToUpperInvariant());
            if (matches.Count == 1)
            {
                valid = true;
                _UsersLock.ExitReadLock();
                return new UserToken(matches[0].Username);
            }
            else
            {
                valid = false;
                _UsersLock.ExitReadLock();
                return null;
            }
        }

        public bool RemoveUser(string username)
        {
            _UsersLock.EnterWriteLock();
            if (_Users.RemoveAll(u => u.Username.ToUpperInvariant() == username.ToUpperInvariant()) > 0)
            {
                _UsersLock.ExitWriteLock();
                return true;
            }
            else
            {
                _UsersLock.ExitWriteLock();
                return false;
            }
        }

        public static string HashPassword(string password)
        {
            SHA256 hasher = SHA256.Create();
            byte[] inbuf = ASCIIEncoding.ASCII.GetBytes(password);
            byte[] outbuf = hasher.ComputeHash(inbuf);
            string hex = BitConverter.ToString(outbuf);
            hex = hex.Replace("-", "");
            return hex;
        }

        public bool ChangePassword(string username, string passwordhash)
        {
            _UsersLock.EnterWriteLock();
            List<__User> matches = _Users.FindAll(u => u.Username.ToUpperInvariant() == username.ToUpperInvariant());
            if (matches.Count == 1)
            {
                matches[0].PasswordHash = passwordhash;
                _UsersLock.ExitWriteLock();
                return true;
            }
            else
            {
                _UsersLock.ExitWriteLock();
                return false;
            }
        }
        private byte[] _SerialiseDatabase()
        {
            _UsersLock.EnterReadLock();
            int cindex = 0;
            byte[] buffer = new byte[_CalculateLength()];
            foreach (__User u in _Users)
            {
                byte[] buf = BitConverter.GetBytes(u.Username.Length);
                Array.Copy(buf, 0, buffer, cindex, buf.Length);
                cindex += buf.Length;
                buf = ASCIIEncoding.ASCII.GetBytes(u.Username);
                Array.Copy(buf, 0, buffer, cindex, buf.Length);
                cindex += buf.Length;
                buf = BitConverter.GetBytes(u.PasswordHash.Length);
                Array.Copy(buf, 0, buffer, cindex, buf.Length);
                cindex += buf.Length;
                buf = ASCIIEncoding.ASCII.GetBytes(u.PasswordHash);
                Array.Copy(buf, 0, buffer, cindex, buf.Length);
                cindex += buf.Length;
            }
            _UsersLock.ExitReadLock();
            return buffer;
        }
        private int _CalculateLength()
        {
            int length = 0;
            foreach (__User u in _Users)
            {
                length += 2*sizeof(int);
                length += u.Username.Length;
                length += u.PasswordHash.Length;
            }
            return length;
        }
    }
}
