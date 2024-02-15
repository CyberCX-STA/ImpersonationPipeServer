// See https://aka.ms/new-console-template for more information
using ImpersonationPipeServer;

if (args.Length < 2)
{
    Console.WriteLine("Usage: server.exe {pipeName} {command}");
    Console.WriteLine("Pipe name must not include //./pipe/");
}
else
{
    Functions.Initialisation(args);
}

