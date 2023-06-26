using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;


namespace ParseGameDll
{
    internal class Program
    {
        static Regex vtable_get_regex1 = new Regex(@"\w+\W+(.*?)::`vftable.*?&sub_(\w+);");
        static Regex vtable_get_regex2 = new Regex(@"\w+\W+off_(\w+).*?=.*?&(.*?)::`vftable");
        static Regex vtable_get_regex3 = new Regex(@"\/\/\s+(\w+):\s+using\s+guessed\s+type\s+\w+\W+(.*?)::`vftable");

        static Regex funcaddr_get = new Regex(@"sub_(\w+)");


        static void FillFunctions(string[] data)
        {
            foreach (string s in data)
            {
                Match math = funcaddr_get.Match(s);
                if (math.Success)
                {
                    File.AppendAllText("Functions.txt", math.Groups[1].Value + "\n");
                }
                if (s.Contains("Data declarations"))
                    break;
            }
        }

        static void FillAllVtables(string[] data)
        {
            foreach (string s in data)
            {
                Match math = vtable_get_regex1.Match(s);
                if (math.Success)
                {
                    File.AppendAllText("VTABLES.txt", math.Groups[2].Value + "=" + math.Groups[1].Value + "\n");
                    continue;
                }
                math = vtable_get_regex2.Match(s);
                if (math.Success)
                {
                    File.AppendAllText("VTABLES.txt", math.Groups[1].Value + "=" + math.Groups[2].Value + "\n");
                    continue;
                }
                math = vtable_get_regex3.Match(s);
                if (math.Success)
                {
                    File.AppendAllText("VTABLES.txt", math.Groups[1].Value + "=" + math.Groups[2].Value + "\n");
                    continue;
                }
            }
        }

        static void Main(string[] args)
        {
            string[] data = File.ReadAllLines("Game.c");
            FillFunctions(data);
            FillAllVtables(data);
        }
    }
}
