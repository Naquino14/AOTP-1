using ADIS;
using System.Text;

internal class Program {
    static void Main(string[] args) {
        Console.WriteLine("Enter a key:");
        string? line = Console.ReadLine() ?? "";
        if (line.Length != 16) {
            Console.WriteLine("Must be 16 bytes!");
            return;
        }
        byte[] key = Encoding.ASCII.GetBytes(line);

        Console.WriteLine("Enter an epoch (leave empty to get current epoch):");
        line = Console.ReadLine() ?? "";
        long epoch;
        if (line == "") {
            epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Console.WriteLine($"Epoch: {epoch}");
        }
        else if (!long.TryParse(line, out epoch)) {
            Console.WriteLine("Not a valid epoch number.");
            return;
        }

        Console.WriteLine("Enter a duration (default 30 seconds):");
        line = Console.ReadLine() ?? "30";
        if (!int.TryParse(line, out int duration)) {
            Console.WriteLine("Not a valid time number.");
            return;
        }

        Console.WriteLine();


        for (; ; ) {
            AOTP1 aotp = new(key, epoch, duration);
            Console.WriteLine($"Code: {aotp.OTP[0]:X}{aotp.OTP[1]:X}{aotp.OTP[2]:X}{aotp.OTP[3]:X}\r");
            Thread.Sleep(1000);
        }
    }
}